import os
import json
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent
    from drillagent.config import AgentConfig
    from drillagent.models import LLM
    from drillagent.utils.tools import AgentTool

from drillagent.prompts.PathExplorationAgent_prompt import PEA_generate_testcase_prompt, PEA_system_prompt
from drillagent.utils.llvm_cov import LLVMCovUtils

# 
# Currently we assume that the PathExplorationAgent **has** usable call trace. (LHY)
# TODO: Need to support the case without call trace in the future.
# 
class PathExplorationAgent:
    # Responsible for exploring paths leading to vulnerabilities, fully utilizing the coverage feedback.
    # LHY: The goal of this agent is to at least generate a PoV that can reach the vulnerable function, better if in branch-level.

    def __init__(self, drill_agent: 'DrillAgent'):
        self.drill_agent = drill_agent
        self.config = drill_agent.config
        self.logger = drill_agent.logger
        self.llm = drill_agent.llm
        self.tools = drill_agent.agent_tools

        # LHY: In each exploration, the agent will generate a PoV test case, execute it, and collect coverage feedback.
        # After LLM reasoning about the current status, the agent will repeat the above process until stopped.
        self.max_exp_iterations = 15
        self.current_iteration = 0

        # LHY: Based on the call trace we extratced from the sanitizer report, we can record which nodes have been covered.
        # self.call_trace = None
        self.vuln_call_trace = self.drill_agent.vulnerability_info.call_trace # Obtained from VulnAnalysisAgent directly
        self.coverage_state = dict()  # e.g., covered functions/branches # TODO: May split into several finer-grained states.
        self.uncovered_callsites = [] # TODO

        # LHY: All of the intermediate PoV results should be stored, and we should maintain a best PoV candidate.
        self.history_pov_candidates = []  # List of XXX
        self.best_pov_candidate = None    # XXX

    def run(self):
        # Run the path exploration process to generate PoV candidates that can reach the vulnerable function.
        self.logger.info("  [PathExplorationAgent] Starting path exploration analysis...")

        for iteration in range(self.max_exp_iterations):
            self.logger.info(f"  [PathExplorationAgent] Iteration {iteration+1}/{self.max_exp_iterations}")
            self.current_iteration = iteration + 1

            # Create roundN subdirectory and clear its contents
            round_dir = os.path.join(self.drill_agent.work_dir, f"round{self.current_iteration}")
            os.makedirs(round_dir, exist_ok=True)
            for item in os.listdir(round_dir):
                item_path = os.path.join(round_dir, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)

            self.logger.debug(f"  [PathExplorationAgent] Created and cleared round directory: {round_dir}")

            # Substep1: Generate initial test case
            # Returned test_case should be the path to the file within the drill_agent.work_dir (workspace).
            test_case_path = self._generate_test_case()

            # Substep2: Execute test case dynamically (using actual repo path)
            # This will also generate a profraw/profdata file.
            exit_code, exec_output, profdata = self._execute_test_case(test_case_path)
            # 

            # Substep3: Collect coverage feedback along the vulnerable call trace
            # a. function-level coverage
            # b. source-line-level coverage
            # c. find the first uncovered callsite A
            self._collect_coverage_feedback(profdata)

            # Substep4: Analyze coverage feedback around the first uncovered point A in the call trace
            # Output: reachability failure analysis, test case adjustment suggestion.
            self._analyze_coverage_feedback()

            # Check early-stop in each iteration
            self._detect_stop_status()


    def _generate_test_case(self) -> str:
        # 1. 获取drill_agent.vulnerability_info.format_output返回的漏洞信息字符串。
        # 2. 实例化PEA_generate_testcase_prompt，将驱动LLM (with tools)在roundN子目录下生成能够到达漏洞函数甚至触发漏洞crash的测试用例。
        # 3. 检查test case文件是否是纯粹的输入文件（不包含LLM返回的一些分析文字），返回该文件路径。
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_iteration} Substep1: Generating test case...")

        # Step 1: Get vulnerability information and roundN subdirectory
        vuln_info_str = self.drill_agent.vulnerability_info.format_output()
        round_dir = os.path.join(self.drill_agent.work_dir, f"round{self.current_iteration}")

        # Step 2: LLM test case generation.
        # Set up the prompt with vulnerability info.
        prompt = PEA_generate_testcase_prompt.format(
            vulnerability_info=vuln_info_str,
            round_dir=round_dir,
            iteration=self.current_iteration
        )

        # Invoke LLM to generate test case (with tools)
        response, tool_calls = self.llm.generate_with_tools(
            prompt=prompt,
            tools=self.tools,
            system_prompt=PEA_system_prompt,
            temperature=0.7,
            max_tokens=4096
        )

        # TODO: Extract test case from LLM response, or rely on tool calls to save the test case file???
        self.logger.debug(f"  [PathExplorationAgent] LLM response: {response}")

        # Execute tool calls
        if tool_calls and len(tool_calls) > 0:
            self.logger.info(f"  [PathExplorationAgent] Executing {len(tool_calls)} tool calls...")
            for tool_call in tool_calls:
                tool_name = tool_call.get('name')
                tool_args = tool_call.get('arguments', {})
                self.logger.debug(f"      {tool_name}({json.dumps(tool_args)})")

                for tool in self.tools:
                    if tool.name() == tool_name:
                        try:
                            result = tool.execute(**tool_args)
                            self.logger.debug(f"      Result: {str(result)[:200]}")
                        except Exception as e:
                            self.logger.error(f"      Tool error: {e}")
                        break

        # Step 3: Check generated test case file
        # Look for test case files in the roundN directory (commonly named test_case, input, poc, etc.)
        # TODO: Fix the test case file name. Should be a pre-defined name.
        test_case_path = None
        possible_names = ['test_case', 'input', 'poc', 'testcase', 'test_input', 'test.txt']
        for filename in os.listdir(round_dir):
            file_path = os.path.join(round_dir, filename)
            if os.path.isfile(file_path):
                # Check if the file is a pure input file (binary or text, without analysis content)
                # If the filename matches common test case naming patterns, consider it the test case file
                if any(name in filename.lower() for name in possible_names):
                    test_case_path = file_path
                    break

        # If no matching filename is found, take the first file (assuming only one test case file was generated)
        if not test_case_path:
            files = [f for f in os.listdir(round_dir) if os.path.isfile(os.path.join(round_dir, f))]
            if files:
                test_case_path = os.path.join(round_dir, files[0])

        if not test_case_path:
            raise FileNotFoundError(f"No test case file generated in {round_dir}")

        self.logger.info(f"  [PathExplorationAgent] Test case generated at: {test_case_path}")
        return test_case_path

    def _execute_test_case(self, test_case_path: str) -> Tuple[int, str, str]:
        # 1. 从drill_agent.vulnerability_info中获取到binary_path和refined_harness_command，结合test_case_path，整理成一个在roundN目录下可执行的命令。
        # 2. 进入roundN子目录执行该命令，记录stdout和stderr，同时生成profraw文件。
        # 3. 利用LLVMCovUtils把profraw文件转换成profdata文件，连同exit code和exec output(包括stdout和stderr)返回给调用者。
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_iteration} Substep2: Executing test case...")

        # Step 1: Prepare the command
        binary_path = self.drill_agent.vulnerability_info.binary_path
        harness_command = self.drill_agent.vulnerability_info.refined_harness_command
        round_dir = os.path.join(self.drill_agent.work_dir, f"round{self.current_iteration}")

        if not binary_path:
            raise ValueError("Binary path not found in vulnerability_info")
        if not harness_command:
            raise ValueError("Refined harness command not found in vulnerability_info")

        # Construct the test case path relative to round_dir (needed?)
        rel_test_case_path = os.path.basename(test_case_path)
        # Replace placeholders (<path/to/testcase>) in the harness command
        command = harness_command.replace('<path/to/testcase>', rel_test_case_path)
        # command = command.replace('{test_case}', rel_test_case_path)
        # command = command.replace('@@', rel_test_case_path)
        # command = command.replace('$INPUT', rel_test_case_path)

        # Step 2: Set environment variable to generate profraw file
        profraw_path = os.path.join(round_dir, f"test_{self.current_iteration}.profraw")
        env = os.environ.copy()
        env['LLVM_PROFILE_FILE'] = profraw_path

        # Step 3: Execute the command
        self.logger.info(f"  [PathExplorationAgent] Executing command: {command}")
        self.logger.debug(f"  [PathExplorationAgent] Working directory: {round_dir}")
        self.logger.debug(f"  [PathExplorationAgent] LLVM_PROFILE_FILE: {profraw_path}")

        try:
            # Use subprocess to execute the command, set timeout to avoid hang
            result = subprocess.run(
                command,
                shell=True,
                cwd=round_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=30  # 30 seconds timeout
            )

            exit_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr

            # Merge stdout and stderr as exec_output
            exec_output = f"[STDOUT]\n{stdout}\n\n[STDERR]\n{stderr}"

        except subprocess.TimeoutExpired as e:
            self.logger.warning(f"  [PathExplorationAgent] Command execution timeout after 30s")
            exit_code = -1
            exec_output = f"[TIMEOUT] Command execution exceeded 30 seconds\n[STDOUT]\n{e.stdout}\n\n[STDERR]\n{e.stderr}"

        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Command execution failed: {e}")
            exit_code = -1
            exec_output = f"[ERROR] Command execution failed: {str(e)}"

        self.logger.info(f"  [PathExplorationAgent] Command exit code: {exit_code}")

        # Step 4: Check if profraw file is generated
        if not os.path.exists(profraw_path):
            self.logger.warning(f"  [PathExplorationAgent] profraw file not generated at {profraw_path}")
            self.logger.warning(f"  [PathExplorationAgent] This might indicate the binary was not instrumented or the execution failed early")
            # Return empty profdata path
            return exit_code, exec_output, ""

        # Step 5: Use LLVMCovUtils to convert profraw to profdata
        try:
            # LLVMCovUtils will automatically convert profraw to profdata upon construction
            llvm_cov_utils = LLVMCovUtils(
                binary_path=binary_path,
                profraw_path=profraw_path
            )
            profdata_path = llvm_cov_utils.profdata_path

            self.logger.info(f"  [PathExplorationAgent] profdata file generated at: {profdata_path}")

            return exit_code, exec_output, profdata_path

        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Failed to convert profraw to profdata: {e}")
            return exit_code, exec_output, ""

    def _collect_coverage_feedback(self, profdata: str):
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_iteration} Substep3: Collecting coverage feedback...")
        pass

    def _analyze_coverage_feedback(self):
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_iteration} Substep4: Analyzing coverage feedback...")
        pass

    def _detect_stop_status(self):
        # LHY: Check if we should stop path exploration.
        # For example, if a PoV is found, or max iterations reached.
        pass
