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

from drillagent.prompts.PathExplorationAgent_prompt import (
    PEA_generate_testcase_prompt,
    PEA_system_prompt,
    PEA_feedback_section_prompt
)
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
        self.max_exp_iterations = 8
        self.current_exp_iteration = 0

        # LHY: Based on the call trace we extratced from the sanitizer report, we can record which nodes have been covered.
        # self.call_trace = None
        self.llvm_cov_utils : LLVMCovUtils = None
        self.vuln_call_trace = self.drill_agent.vulnerability_info.call_trace # Obtained from VulnAnalysisAgent directly
        self.coverage_state = dict()  # e.g., covered functions/branches # TODO: May split into several finer-grained states.
        # self.uncovered_callsites = [] # TODO

        # LHY: All of the intermediate PoV results should be stored, and we should maintain a best PoV candidate.
        self.history_pov_candidates = []  # List of XXX
        self.best_pov_candidate = None    # XXX

    def run(self):
        # Run the path exploration process to generate PoV candidates that can reach the vulnerable function.
        self.logger.info("  [PathExplorationAgent] Starting path exploration analysis...")

        # Maintain feedback from previous iteration to guide next iteration's testcase generation
        previous_feedback = None

        for iteration in range(1, self.max_exp_iterations + 1):
            print("\n\n")
            self.logger.info(f"  [PathExplorationAgent] Iteration {iteration}/{self.max_exp_iterations}")
            self.current_exp_iteration = iteration

            # Create roundN subdirectory and clear its contents
            round_dir = self.get_round_dir(self.current_exp_iteration)
            os.makedirs(round_dir, exist_ok=True)
            for item in os.listdir(round_dir):
                item_path = os.path.join(round_dir, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            self.logger.debug(f"  [PathExplorationAgent] Created and cleared round directory: {round_dir}")

            # Substep1: Generate test case (with feedback from previous iteration if available)
            # Returned test_case should be the path to the file within the drill_agent.work_dir (workspace).
            print("\n")
            test_case_path = self._generate_test_case(previous_feedback=previous_feedback)

            # Substep2: Execute test case dynamically (using actual repo path)
            # This will also generate a profraw/profdata file.
            print("\n")
            exit_code, exec_output = self._execute_test_case(test_case_path)
            #

            # Substep3: Collect coverage feedback along the vulnerable call trace
            # a. function-level coverage ✅
            # b. source-line-level coverage
            # c. find the first uncovered callsite A
            print("\n")
            func_level_cov_info = self._collect_coverage_feedback()

            # Substep4: Analyze coverage feedback around the first uncovered point A in the call trace
            # Output: reachability failure analysis, test case adjustment suggestion.
            print("\n")
            feedback_analysis_results = self._analyze_coverage_feedback(exit_code, exec_output, func_level_cov_info)

            # Store feedback for next iteration
            previous_feedback = feedback_analysis_results

            # Check early-stop in each iteration
            self._detect_stop_status()

    def get_round_dir(self, round_num: int) -> str:
        # assert os.path.exists(self.drill_agent.work_dir), "DrillAgent work_dir does not exist!!!"
        return os.path.join(self.drill_agent.work_dir, f"round{round_num}")

    def _generate_test_case(self, previous_feedback: str = None) -> str:
        # 1. 获取drill_agent.vulnerability_info.format_output返回的漏洞信息字符串。
        # 2. 实例化PEA_generate_testcase_prompt，将驱动LLM (with tools)在roundN子目录下生成能够到达漏洞函数甚至触发漏洞crash的测试用例。（可以带tool calls多轮交互）
        # 3. 检查test case文件是否是纯粹的输入文件（不包含LLM返回的一些分析文字），返回该文件路径。
        # 4. If previous_feedback is provided, include it in the prompt to guide the LLM with coverage information.
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_exp_iteration} Substep1: Generating test case...")
        round_dir = self.get_round_dir(self.current_exp_iteration)

        # Step 1: Get vulnerability information and roundN subdirectory
        vuln_info_str = self.drill_agent.vulnerability_info.format_output()
        
        # Step 2: LLM test case generation with multi-turn interaction (up to 5 turns)
        # Possible TODOs:
        # 1.Each round should include a prompt (even a short continuation prompt).
        # 2.Provide different guidance depending on the previous round's behavior (whether tools were invoked or not).
        max_generation_turns = 10 # LHY: Need to have enough tool call turns...
        conversation_history = [] # Self maintained conversation history for multi-turn LLM interaction within this function
        testcase_content = None   # What we want in _generate_test_case.

        for turn in range(1, max_generation_turns + 1):
            self.logger.info(f"  [PathExplorationAgent] LLM interaction turn {turn}/{max_generation_turns}")

            # Prepare current user prompt
            current_prompt = ""
            if turn == 1:
                # First turn: create full prompt
                current_prompt = PEA_generate_testcase_prompt.format(
                    vulnerability_info=vuln_info_str,
                    project_name=self.drill_agent.config.project_name,
                    generation_turn=turn,
                    max_generation_turns=max_generation_turns
                )
                # Add previous iteration feedback if available (from round 2 onwards)
                # `previous_feedback` is from the outer loop. Here, `turn` is the inner loop.
                if previous_feedback:
                    self.logger.info(f"  [PathExplorationAgent] Including feedback from iteration {self.current_exp_iteration - 1}")
                    feedback_section = PEA_feedback_section_prompt.format(
                        previous_iteration=self.current_exp_iteration - 1,
                        current_iteration=self.current_exp_iteration,
                        previous_feedback=previous_feedback
                    )
                    current_prompt = current_prompt + "\n\n" + feedback_section
            elif turn == max_generation_turns:
                if conversation_history and conversation_history[-1]["role"] == "user":
                    current_prompt = conversation_history.pop()["content"]
                current_prompt += "\nPlease generate the final test case in a ```testcase code block now, since it is already the last turn."
            else:
                # Subsequent turns: pop the last user message from conversation_history as current_prompt
                # This message was added at the end of previous turn (tool results or continuation prompt)
                if conversation_history and conversation_history[-1]["role"] == "user":
                    current_prompt = conversation_history.pop()["content"]
                else:
                    current_prompt = ""

            # Invoke LLM to generate test case (with tools)
            response, tool_calls, assistant_message = self.llm.generate_with_tools(
                prompt=current_prompt,
                tools=self.tools,
                system_prompt=PEA_system_prompt,
                temperature=0.7,
                max_tokens=4096,
                conversation_history=conversation_history
            )

            self.logger.debug(f"  [PathExplorationAgent] _generate_test_case turn {turn}, LLM response: {response[:500]}...")

            # Add current turn's user prompt to conversation history
            conversation_history.append({
                "role": "user",
                "content": current_prompt
            })

            # Add assistant's complete response (in official API format) to conversation history
            conversation_history.append(assistant_message)

            # Step 3: Check if response contains testcase code block
            testcase_pattern = r'```testcase\s*\n(.*?)\n```'
            match = re.search(testcase_pattern, response, re.DOTALL)
            # if not match:
            #     # Fallback: try to find any code block and extract test case content
            #     fallback_pattern = r'```\s*\n(.*?)\n```'
            #     match = re.search(fallback_pattern, response, re.DOTALL)
            if match:
                testcase_content = match.group(1)
                self.logger.info(f"  [PathExplorationAgent] Testcase extracted from turn {turn}. Break from the generation loop!")
                break # exit the `max_generation_turns` loop

            # Step 4: Execute tool calls if any
            if tool_calls and len(tool_calls) > 0:
                self.logger.info(f"  [PathExplorationAgent] Executing {len(tool_calls)} tool calls...")
                tool_results = []

                # Traverse and execute each tool call
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

                    # Store raw result (not dict, just the result object)
                    tool_results.append(result if result is not None else "No result")

                # Create tool result message in official API format
                tool_result_msg = self.llm.create_tool_result_message(tool_calls, tool_results)

                # FIX: TODO: We should handle different LLM providers in llm.py instead of here.
                # Handle OpenAI special case (multiple tool messages)
                if "_openai_tool_messages" in tool_result_msg:
                    # OpenAI: add each tool result message separately
                    for msg in tool_result_msg["_openai_tool_messages"]:
                        conversation_history.append(msg)
                    # Add continuation prompt as the last user message
                    conversation_history.append({
                        "role": "user",
                        "content": "Please continue. Remember to return the testcase in a ```testcase code block when ready."
                    })
                else:
                    # Claude: single user message with tool_result blocks
                    # Append continuation prompt to the tool result message
                    tool_result_msg["content"].append({
                        "type": "text",
                        "text": "Please continue. Remember to return the testcase in a ```testcase code block when ready."
                    })
                    conversation_history.append(tool_result_msg)
            else:
                # No tool calls and no testcase found - ask LLM to provide testcase
                if turn < max_generation_turns:
                    conversation_history.append({
                        "role": "user",
                        "content": "Please provide the testcase in a ```testcase code block now."
                    })
        # End for loop

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

    def _execute_test_case(self, test_case_path: str) -> Tuple[int, str, str]: # No LLM needed
        # 1. 从drill_agent.vulnerability_info中获取到binary_path和refined_harness_command，结合test_case_path，整理成一个在roundN目录下可执行的命令。
        # 2. 进入roundN子目录执行该命令，记录stdout和stderr，同时生成profraw文件。
        # 3. 利用LLVMCovUtils把profraw文件转换成profdata文件，连同exit code和exec output(包括stdout和stderr)返回给调用者。
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_exp_iteration} Substep2: Executing test case...")
        round_dir = self.get_round_dir(self.current_exp_iteration)

        # Step 1: Prepare the command
        repo_path = self.drill_agent.config.target_repo_path
        binary_path = self.drill_agent.vulnerability_info.binary_path
        binary_abs_path = os.path.abspath(os.path.join(repo_path, binary_path))
        harness_command = self.drill_agent.vulnerability_info.refined_harness_command
        if not binary_path:
            raise ValueError("Binary path not found in vulnerability_info")
        if not harness_command:
            raise ValueError("Refined harness command not found in vulnerability_info")

        # Transform general harness command to executable command
        abs_test_case_path = os.path.abspath(test_case_path)
        command = harness_command.replace('<path/to/testcase>', abs_test_case_path)
        # TODO: LHY: Should be more smart, maybe still need to use LLM here...
        # if f"./{binary_path} " in command:
        #     command = command.replace(f"./{binary_path} ", f"{binary_abs_path} ")
        # elif f"{binary_path} " in command:
        #     command = command.replace(f"{binary_path} ", f"{binary_abs_path} ")

        # Step 2: Set environment variable to generate profraw file
        profraw_path = os.path.join(round_dir, f"test_{self.current_exp_iteration}.profraw")
        env = os.environ.copy()
        env['LLVM_PROFILE_FILE'] = profraw_path

        # Step 3: Execute the command
        self.logger.info (f"  [PathExplorationAgent] Executing command: {command} in {round_dir}")
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

        # Step 4: After each execution, use LLVMCovUtils to store the coverage profile data.
        if not os.path.exists(profraw_path): # Check if profraw file is generated
            self.logger.warning(f"  [PathExplorationAgent] profraw file not generated at {profraw_path}")
            self.logger.warning(f"  [PathExplorationAgent] This might indicate the binary was not instrumented or the execution failed early")
            # Return without initializing llvm_cov_utils (coverage collection will handle this gracefully)
            return exit_code, exec_output

        try:
            if self.llvm_cov_utils is None:
                self.llvm_cov_utils = LLVMCovUtils(
                    binary_path=binary_abs_path, # absolute path to the instrumented binary
                    profraw_path=profraw_path    # absolute path?
                )
            else:
                # LLVMCovUtils will automatically convert profraw to profdata
                self.llvm_cov_utils.update_profile_data(profraw_path) # absolute path?
            self.logger.info(f"  [PathExplorationAgent] current profdata file generated at: {self.llvm_cov_utils.profdata_path}")
            return exit_code, exec_output
        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Failed to convert profraw to profdata: {e}")
            return exit_code, exec_output

    def _collect_coverage_feedback(self) -> str: # No LLM needed
        # Collect function-level coverage feedback along the vulnerable call trace.
        # 1. Extract function information from self.vuln_call_trace
        # 2. Query coverage using self.llvm_cov_utils.get_multi_functions_coverage()
        # 3. Format and return the coverage information as a string for analysis
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_exp_iteration} Substep3: Collecting coverage feedback...")

        assert self.llvm_cov_utils is not None, "LLVMCovUtils not initialized before collecting coverage!"

        # Check if we have a valid call trace
        if not self.vuln_call_trace or len(self.vuln_call_trace) == 0:
            self.logger.warning(f"  [PathExplorationAgent] No vulnerability call trace available")
            return "ERROR: No vulnerability call trace available for coverage analysis"

        # Step 1: Extract function information from vulnerable call trace
        # Build a list of (function_name, file_path) tuples for batch query
        functions_to_query = []
        callsite_info = []  # Store (sequence_num, function_name, file_path, line_number) for each callsite

        for frame in self.vuln_call_trace:
            sequence_num = frame.get('sequence_num', -1)
            function_name = frame.get('function_name', '')
            file_path = frame.get('file_path', '')
            line_number = frame.get('line_number', 0)
            is_external = frame.get('is_external', False)

            # Skip external functions and frames without function names
            if is_external or not function_name or not file_path:
                self.logger.debug(f"  [PathExplorationAgent] Skipping frame #{sequence_num}: external or incomplete info")
                continue

            # Convert file_path to absolute path (if it's relative to repo)
            abs_file_path = os.path.abspath(os.path.join(self.drill_agent.config.target_repo_path, file_path))

            functions_to_query.append((function_name, abs_file_path))
            callsite_info.append({
                'sequence_num': sequence_num,
                'function_name': function_name,
                'file_path': abs_file_path,
                'line_number': line_number
            })

        if not functions_to_query:
            self.logger.warning(f"  [PathExplorationAgent] No valid functions to query in call trace")
            return "WARNING: No valid functions found in call trace (all external or incomplete)"

        self.logger.info(f"  [PathExplorationAgent] Querying coverage for {len(functions_to_query)} functions in call trace")

        # Step 2: Batch query function coverage using LLVMCovUtils
        try:
            # `coverage_results` is a dict mapping (function_name, file_path) to coverage info dict
            coverage_results = self.llvm_cov_utils.get_multi_functions_coverage(functions_to_query)
        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Failed to query function coverage: {e}")
            return f"ERROR: Coverage query failed - {str(e)}"

        # Step 3: Analyze coverage results and build formatted output
        functions_covered = []
        functions_uncovered = []
        first_uncovered_callsite = None

        for callsite in callsite_info:
            func_name = callsite['function_name']
            file_path = callsite['file_path']
            seq_num = callsite['sequence_num']
            line_num = callsite['line_number']

            cov_info = coverage_results.get( (func_name, file_path), {} )
            if not cov_info.get('found', False):
                self.logger.debug(f"  [PathExplorationAgent] Frame #{seq_num} {func_name} not found in coverage data")
                functions_uncovered.append({
                    'sequence_num': seq_num,
                    'function_name': func_name,
                    'file_path': file_path,
                    'line_number': line_num,
                    'status': 'not_found'
                })
                if first_uncovered_callsite is None:
                    first_uncovered_callsite = {
                        'sequence_num': seq_num,
                        'function_name': func_name,
                        'file_path': file_path,
                        'line_number': line_num,
                        'reason': 'function_not_found_in_coverage_data'
                    }
                continue

            is_executed = cov_info.get('is_executed', False)
            exec_count = cov_info.get('execution_count', 0)
            regions_covered = cov_info.get('regions_covered', 0)
            regions_total = cov_info.get('regions_total', 0)

            if is_executed:
                self.logger.debug(f"  [PathExplorationAgent] ✓ Frame #{seq_num} {func_name} - executed {exec_count} times, regions {regions_covered}/{regions_total}")
                functions_covered.append({
                    'sequence_num': seq_num,
                    'function_name': func_name,
                    'file_path': file_path,
                    'line_number': line_num,
                    'execution_count': exec_count,
                    'regions_covered': regions_covered,
                    'regions_total': regions_total
                })
            else:
                self.logger.debug(f"  [PathExplorationAgent] ✗ Frame #{seq_num} {func_name} - NOT executed")
                functions_uncovered.append({
                    'sequence_num': seq_num,
                    'function_name': func_name,
                    'file_path': file_path,
                    'line_number': line_num,
                    'status': 'not_executed',
                    'regions_covered': regions_covered,
                    'regions_total': regions_total
                })
                if first_uncovered_callsite is None:
                    first_uncovered_callsite = {
                        'sequence_num': seq_num,
                        'function_name': func_name,
                        'file_path': file_path,
                        'line_number': line_num,
                        'reason': 'function_not_executed'
                    }

        # Step 4: Update coverage state for this round (for internal tracking)
        self.coverage_state[f'round{self.current_exp_iteration}'] = {
            'functions_covered': functions_covered,
            'functions_uncovered': functions_uncovered,
            'first_uncovered_callsite': first_uncovered_callsite,
            'coverage_summary': {
                'total_callsites': len(callsite_info),
                'covered_count': len(functions_covered),
                'uncovered_count': len(functions_uncovered)
            }
        }

        # Step 5: Build formatted output string
        output_lines = []
        output_lines.append("=" * 80)
        output_lines.append("FUNCTION-LEVEL COVERAGE FEEDBACK")
        output_lines.append("=" * 80)

        # Summary
        covered_count = len(functions_covered)
        total_count = len(callsite_info)
        coverage_percentage = (covered_count / total_count * 100) if total_count > 0 else 0
        output_lines.append(f"\n[COVERAGE SUMMARY]")
        output_lines.append(f"  Total callsites in trace: {total_count}")
        output_lines.append(f"  Functions executed:       {covered_count} ({coverage_percentage:.1f}%)")
        output_lines.append(f"  Functions not executed:   {len(functions_uncovered)}")

        # Covered functions
        if functions_covered:
            output_lines.append(f"\n[COVERED FUNCTIONS] ({len(functions_covered)} total)")
            for func in functions_covered:
                output_lines.append(f"  ✓ #{func['sequence_num']}: {func['function_name']} @ {func['file_path']}:{func['line_number']}")
                output_lines.append(f"      Executed: {func['execution_count']} times, Regions: {func['regions_covered']}/{func['regions_total']} covered")

        # Uncovered functions
        if functions_uncovered:
            output_lines.append(f"\n[UNCOVERED FUNCTIONS] ({len(functions_uncovered)} total)")
            for func in functions_uncovered:
                status = func.get('status', 'not_executed')
                if status == 'not_found':
                    output_lines.append(f"  ✗ #{func['sequence_num']}: {func['function_name']} @ {func['file_path']}:{func['line_number']}")
                    output_lines.append(f"      Status: NOT FOUND in coverage data")
                else:
                    output_lines.append(f"  ✗ #{func['sequence_num']}: {func['function_name']} @ {func['file_path']}:{func['line_number']}")
                    output_lines.append(f"      Status: NOT EXECUTED, Regions: {func.get('regions_covered', 0)}/{func.get('regions_total', 0)} covered")

        # First uncovered callsite (critical for next iteration)
        if first_uncovered_callsite:
            output_lines.append(f"\n[FIRST UNCOVERED CALLSITE]")
            output_lines.append(f"  Sequence: #{first_uncovered_callsite['sequence_num']}")
            output_lines.append(f"  Function: {first_uncovered_callsite['function_name']}")
            output_lines.append(f"  Location: {first_uncovered_callsite['file_path']}:{first_uncovered_callsite['line_number']}")
            output_lines.append(f"  Reason:   {first_uncovered_callsite['reason']}")
        else:
            output_lines.append(f"\n[FIRST UNCOVERED CALLSITE]")
            output_lines.append(f"  All callsites in the trace were executed!")

        output_lines.append("=" * 80)

        print('\n'.join(output_lines)) # For debug

        formatted_output = '\n'.join(output_lines)

        # Log summary
        self.logger.info(f"  [PathExplorationAgent] Coverage along call trace: {covered_count}/{total_count} functions executed ({coverage_percentage:.1f}%)")
        if first_uncovered_callsite:
            self.logger.info(f"  [PathExplorationAgent] First uncovered: #{first_uncovered_callsite['sequence_num']} "
                           f"{first_uncovered_callsite['function_name']} @ "
                           f"{first_uncovered_callsite['file_path']}:{first_uncovered_callsite['line_number']}")

        return formatted_output

    def _analyze_coverage_feedback(self, exit_code: int, exec_output: str, func_level_cov_info: str) -> str:
        # TODOO: 这里的分析结果需要整理并返回，作为参数传递给_generate_test_case的下一轮调用。
        self.logger.info(f"  [PathExplorationAgent] Round {self.current_exp_iteration} Substep4: Analyzing coverage feedback...")
        feedback_analysis_results  = f"For the finished execution, exit code: {exit_code}\n\nexecution output:\n{exec_output}\n\n"
        feedback_analysis_results += f"Function-level coverage feedback along the vulnerable call trace:\n{func_level_cov_info}\n\n"
        
        # TODO: Currently we just return the raw information.
        return feedback_analysis_results

    def _detect_stop_status(self):
        # LHY: Check if we should stop path exploration.
        # For example, if a PoV is found, or max iterations reached.
        pass
