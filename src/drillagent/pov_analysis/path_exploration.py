import os
import json
import logging
import subprocess
import shutil
import re
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
        self.current_exp_iteration = 0

        # LHY: Based on the call trace we extratced from the sanitizer report, we can record which nodes have been covered.
        # self.call_trace = None
        self.llvm_cov_utils : LLVMCovUtils = None
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
            self.current_exp_iteration = iteration + 1

            # Create roundN subdirectory and clear its contents
            round_dir = os.path.join(self.drill_agent.work_dir, f"round{self.current_exp_iteration}")
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
        # 2. 实例化PEA_generate_testcase_prompt，将驱动LLM (with tools)在roundN子目录下生成能够到达漏洞函数甚至触发漏洞crash的测试用例。（可以带tool calls多轮交互）
        # 3. 检查test case文件是否是纯粹的输入文件（不包含LLM返回的一些分析文字），返回该文件路径。
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_exp_iteration} Substep1: Generating test case...")

        # Step 1: Get vulnerability information and roundN subdirectory
        vuln_info_str = self.drill_agent.vulnerability_info.format_output()
        round_dir = os.path.join(self.drill_agent.work_dir, f"round{self.current_exp_iteration}")

        # Step 2: LLM test case generation with multi-turn interaction (up to 5 turns)
        # Possible TODOs:
        # 1.Each round should include a prompt (even a short continuation prompt).
        # 2.Provide different guidance depending on the previous round’s behavior (whether tools were invoked or not).
        max_generation_turns = 5
        conversation_history = [] # Self maintained conversation history for multi-turn interaction
        testcase_content = None   # What we want in _generate_test_case.

        for turn in range(1, max_generation_turns + 1):
            self.logger.info(f"  [PathExplorationAgent] LLM interaction turn {turn}/{max_generation_turns}")

            # Create prompt for first turn, empty for subsequent turns (rely on conversation history)
            if turn == 1:
                current_prompt = PEA_generate_testcase_prompt.format(
                    vulnerability_info=vuln_info_str,
                    project_name=self.drill_agent.config.project_name,
                    generation_turn=turn,
                    max_generation_turns=max_generation_turns
                )
            else:
                current_prompt = ""

            # Invoke LLM to generate test case (with tools)
            response, tool_calls = self.llm.generate_with_tools(
                prompt=current_prompt,
                tools=self.tools,
                system_prompt=PEA_system_prompt,
                temperature=0.7,
                max_tokens=4096,
                conversation_history=conversation_history
            )

            self.logger.debug(f"  [PathExplorationAgent] Turn {turn} LLM response: {response[:500]}...")

            # Add LLM response to conversation history
            conversation_history.append({
                "role": "assistant",
                "content": response
            })

            # Step 3: Check if response contains testcase code block
            testcase_pattern = r'```testcase\s*\n(.*?)\n```'
            match = re.search(testcase_pattern, response, re.DOTALL)
            if not match:
                # Fallback: try to find any code block and extract test case content
                fallback_pattern = r'```\s*\n(.*?)\n```'
                match = re.search(fallback_pattern, response, re.DOTALL)
            if match:
                testcase_content = match.group(1)
                self.logger.info(f"  [PathExplorationAgent] Testcase extracted from turn {turn}. Break from the generation loop!")
                break

            # Step 4: Execute tool calls if any
            if tool_calls and len(tool_calls) > 0:
                self.logger.info(f"  [PathExplorationAgent] Executing {len(tool_calls)} tool calls...")
                tool_results = []

                for tool_call in tool_calls:
                    tool_name = tool_call.get('name')
                    tool_args = tool_call.get('arguments', {})
                    self.logger.debug(f"      {tool_name}({json.dumps(tool_args)})")

                    result = None
                    for tool in self.tools:
                        if tool.name() == tool_name:
                            try:
                                result = tool.execute(**tool_args)
                                self.logger.debug(f"      Result: {str(result)[:200]}...")
                            except Exception as e:
                                self.logger.error(f"      Tool error: {e}")
                                result = f"Error: {str(e)}"
                            break

                    tool_results.append({
                        "tool": tool_name,
                        "result": str(result) if result else "No result"
                    })

                # Add tool results to conversation history for next turn
                tool_results_text = "\n\n".join([
                    f"Tool: {tr['tool']}\nResult: {tr['result']}"
                    for tr in tool_results
                ])
                conversation_history.append({
                    "role": "user",
                    "content": f"Tool execution results:\n\n{tool_results_text}\n\nPlease continue. Remember to return the testcase in a ```testcase code block when ready."
                })
            else:
                # No tool calls and no testcase found - ask LLM to provide testcase
                if turn < max_generation_turns:
                    conversation_history.append({
                        "role": "user",
                        "content": "Please provide the testcase in a ```testcase code block now."
                    })

        # Step 5: Verify testcase was extracted
        if not testcase_content:
            raise ValueError(f"No testcase code block found after {max_generation_turns} turns of LLM interaction")

        # Step 6: Save test case to fixed filename: testcase-round{N}
        test_case_filename = f"testcase-round{self.current_exp_iteration}"
        test_case_path = os.path.join(round_dir, test_case_filename)

        with open(test_case_path, 'w') as f:
            f.write(testcase_content)

        self.logger.debug(f"  [PathExplorationAgent] Saved testcase content ({len(testcase_content)} bytes) to {test_case_path}!")
        self.logger.info (f"  [PathExplorationAgent] Test case generated at: {test_case_path}")
        return test_case_path

    def _execute_test_case(self, test_case_path: str) -> Tuple[int, str, str]:
        # 1. 从drill_agent.vulnerability_info中获取到binary_path和refined_harness_command，结合test_case_path，整理成一个在roundN目录下可执行的命令。
        # 2. 进入roundN子目录执行该命令，记录stdout和stderr，同时生成profraw文件。
        # 3. 利用LLVMCovUtils把profraw文件转换成profdata文件，连同exit code和exec output(包括stdout和stderr)返回给调用者。
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_exp_iteration} Substep2: Executing test case...")

        # Step 1: Prepare the command
        binary_path = self.drill_agent.vulnerability_info.binary_path
        harness_command = self.drill_agent.vulnerability_info.refined_harness_command
        round_dir = os.path.join(self.drill_agent.work_dir, f"round{self.current_exp_iteration}")

        if not binary_path:
            raise ValueError("Binary path not found in vulnerability_info")
        if not harness_command:
            raise ValueError("Refined harness command not found in vulnerability_info")

        # Use absolute path for test case to ensure it works regardless of cwd changes in harness_command
        abs_test_case_path = os.path.abspath(test_case_path)

        # Replace placeholders (<path/to/testcase>) in the harness command
        command = harness_command.replace('<path/to/testcase>', abs_test_case_path)

        # Step 2: Set environment variable to generate profraw file
        profraw_path = os.path.join(round_dir, f"test_{self.current_exp_iteration}.profraw")
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
            if self.llvm_cov_utils is None:
                self.llvm_cov_utils = LLVMCovUtils(
                    binary_path=binary_path,
                    profraw_path=profraw_path
                )
            else:
                # LLVMCovUtils will automatically convert profraw to profdata
                self.llvm_cov_utils.update_profile_data(profraw_path)
            profdata_path = self.llvm_cov_utils.profdata_path
            self.logger.info(f"  [PathExplorationAgent] current profdata file generated at: {profdata_path}")
            return exit_code, exec_output, profdata_path
        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Failed to convert profraw to profdata: {e}")
            return exit_code, exec_output, ""

    def _collect_coverage_feedback(self, profdata: str):
        # TODOO：
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_exp_iteration} Substep3: Collecting coverage feedback...")
        pass

    def _analyze_coverage_feedback(self):
        # TODOO: 这里的分析结果需要整理并返回，作为参数传递给_generate_test_case的下一轮调用。
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_exp_iteration} Substep4: Analyzing coverage feedback...")
        pass

    def _detect_stop_status(self):
        # LHY: Check if we should stop path exploration.
        # For example, if a PoV is found, or max iterations reached.
        pass
