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
    from drillagent.utils.tools import AgentTool

from drillagent.prompts.PathExplorationAgent_prompt import (
    PEA_system_prompt,
    PEA_generate_testcase_prompt,
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
        self.best_pov_candidate = None    # Type:XXX
        self.crash_input_pov = None       # Type:XXX

    def run(self) -> None:
        # Run the path exploration process to generate PoV candidates that can reach the vulnerable function.
        self.logger.info("  [PathExplorationAgent] Starting path exploration analysis...")

        # Maintain feedback from previous iteration to guide next iteration's testcase generation
        previous_feedback = None # From coverage feedback analysis
        for iteration in range(1, self.max_exp_iterations + 1):
            print("\n\n"+"=" * 80)
            self.logger.info(f"  [PathExplorationAgent] Iteration {iteration}/{self.max_exp_iterations}")
            self.current_exp_iteration = iteration

            # Prepare: Create roundN subdirectory and clear its contents
            round_dir = self._get_round_dir(self.current_exp_iteration)
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
            print("")
            test_case_path = self._generate_test_case(previous_feedback=previous_feedback)

            # Substep2: Execute test case dynamically (using actual repo path)
            # This will also generate a profraw/profdata file.
            print("")
            exit_code, exec_output = self._execute_test_case(test_case_path)

            # Special: Check early-stop after each execution
            # TODO: If all callsites are covered, we can also stop early(?).
            found_pov = self._detect_stop_status(exit_code, exec_output)
            if found_pov:
                self.logger.info(f"  [PathExplorationAgent] Crash-inducing PoV found! Triggered early stop.")
                break

            # Substep3: Collect coverage feedback along the vulnerable call trace
            # a. function-level coverage ✅
            # b. source-line-level coverage
            # c. find the first uncovered callsite A
            print("")
            func_level_cov_info = self._collect_coverage_feedback()

            # Substep4: Analyze coverage feedback around the first uncovered point A in the call trace
            # Output: reachability failure analysis, test case adjustment suggestion.
            print("")
            previous_feedback = self._analyze_coverage_feedback(exit_code, exec_output, func_level_cov_info) # Also store feedback for next iteration

        self.logger.info(f"  [PathExplorationAgent] Just left the path exploration loop ({self.current_exp_iteration}/{self.max_exp_iterations}).")

    def _get_round_dir(self, round_num: int) -> str:
        # assert os.path.exists(self.drill_agent.work_dir), "DrillAgent work_dir does not exist!!!"
        return os.path.join(self.drill_agent.work_dir, f"round{round_num}")

    def _generate_test_case(self, previous_feedback: str = None) -> str:
        # Generate test case using LLMInterface with automatic agent loop
        # 1. Get vulnerability information
        # 2. Use LLMInterface to generate test case (with tools and multi-turn interaction)
        # 3. Extract testcase content from LLM response
        # 4. If previous_feedback is provided, include it in the prompt to guide the LLM with coverage information.
        self.logger.info(f"  [PathExplorationAgent] [Round {self.current_exp_iteration}] Substep1: Generating test case...")
        round_dir = self._get_round_dir(self.current_exp_iteration)

        # Step 1: Get vulnerability information
        vuln_info_str = self.drill_agent.vulnerability_info.format_output()

        # Step 2: Prepare the full prompt
        prompt = PEA_generate_testcase_prompt.format(
            vulnerability_info=vuln_info_str,
            project_name=self.drill_agent.config.project_name,
            generation_turn=1,
            max_generation_turns=10
        )

        # Add previous iteration feedback if available (from round 2 onwards)
        if previous_feedback:
            self.logger.info(f"  [PathExplorationAgent] Including feedback from iteration {self.current_exp_iteration - 1}")
            feedback_section = PEA_feedback_section_prompt.format(
                previous_iteration=self.current_exp_iteration - 1,
                current_iteration=self.current_exp_iteration,
                previous_feedback=previous_feedback
            )
            prompt = prompt + "\n\n" + feedback_section

        # Step 3: Use LLMInterface for automatic tool calling and conversation management
        self.logger.info("  [PathExplorationAgent] Using LLMInterface to generate test case...")
        result = self.drill_agent.basic_llm.run_agent_loop(
            task=prompt,
            tools=self.tools,
            system_prompt=PEA_system_prompt,
            max_iterations=10,  # Allow up to 10 rounds of tool usage
            temperature=0.7,  # Higher temperature for creative test case generation
            max_tokens=8192,
            continuation_prompt="Please continue exploring the repository and generate the final test case in a ```testcase code block."
        )

        if not result['success']:
            error_msg = result.get('error', 'Unknown error')
            self.logger.error(f"  [PathExplorationAgent] LLM agent loop failed: {error_msg}")
            raise RuntimeError(f"Failed to generate test case: {error_msg}")

        response = result['final_response']
        self.logger.info(f"  [PathExplorationAgent] LLM completed in {result['iterations']} iteration(s)")
        self.logger.info(f"  [PathExplorationAgent] Stop reason: {result['stop_reason']}")
        self.logger.debug(f"  [PathExplorationAgent] LLM Response: {response[:500]}...")

        # Step 4: Extract testcase content from response
        testcase_pattern = r'```testcase\s*\n(.*?)\n```'
        match = re.search(testcase_pattern, response, re.DOTALL)

        if not match:
            # Fallback: try to find any code block
            self.logger.warning("  [PathExplorationAgent] No ```testcase block found, trying generic code block...")
            fallback_pattern = r'```(?:\w+)?\s*\n(.*?)\n```'
            match = re.search(fallback_pattern, response, re.DOTALL)

        if not match:
            raise ValueError(f"No testcase code block found in LLM response after {result['iterations']} iterations")

        testcase_content = match.group(1)
        self.logger.info(f"  [PathExplorationAgent] Testcase extracted successfully!")

        # Step 5: Save test case to fixed filename: testcase-round{N}
        test_case_filename = f"testcase-round{self.current_exp_iteration}"
        test_case_path = os.path.join(round_dir, test_case_filename)
        with open(test_case_path, 'w') as f:
            f.write(testcase_content)

        self.logger.debug(f"  [PathExplorationAgent] Saved testcase content ({len(testcase_content)} bytes) to {test_case_path}!")
        self.logger.info (f"  [PathExplorationAgent] Test case generated at: {test_case_path}")
        return test_case_path

    def _execute_test_case(self, test_case_path: str) -> Tuple[int, str]: # No LLM needed
        # 1. 从drill_agent.vulnerability_info中获取到binary_path和refined_harness_command，结合test_case_path，整理成一个在roundN目录下可执行的命令。
        # 2. 进入roundN子目录执行该命令，记录stdout和stderr，同时生成profraw文件。
        # 3. 利用LLVMCovUtils把profraw文件转换成profdata文件，连同exit code和exec output(包括stdout和stderr)返回给调用者。
        self.logger.info(f"  [PathExplorationAgent] [Round {self.current_exp_iteration}] Substep2: Executing test case...")
        round_dir = self._get_round_dir(self.current_exp_iteration)

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
        self.logger.info(f"  [PathExplorationAgent] [Round {self.current_exp_iteration}] Substep3: Collecting coverage feedback...")

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
        # Build a unified list with coverage status for each callsite in call trace order
        callsite_coverage_list = []
        first_uncovered_callsite = None
        covered_count = 0

        for callsite in callsite_info:
            func_name = callsite['function_name']
            file_path = callsite['file_path']
            seq_num = callsite['sequence_num']
            line_num = callsite['line_number']

            cov_info = coverage_results.get( (func_name, file_path), {} )

            if not cov_info.get('found', False):
                # Function not found in coverage data
                self.logger.debug(f"  [PathExplorationAgent] Frame #{seq_num} {func_name} not found in coverage data")
                callsite_coverage_list.append({
                    'sequence_num': seq_num,
                    'function_name': func_name,
                    'file_path': file_path,
                    'line_number': line_num,
                    'is_covered': False,
                    'status': 'not_found',
                    'execution_count': 0,
                    'regions_covered': 0,
                    'regions_total': 0
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
                callsite_coverage_list.append({
                    'sequence_num': seq_num,
                    'function_name': func_name,
                    'file_path': file_path,
                    'line_number': line_num,
                    'is_covered': True,
                    'execution_count': exec_count,
                    'regions_covered': regions_covered,
                    'regions_total': regions_total
                })
                covered_count += 1
            else:
                self.logger.debug(f"  [PathExplorationAgent] ✗ Frame #{seq_num} {func_name} - NOT executed")
                callsite_coverage_list.append({
                    'sequence_num': seq_num,
                    'function_name': func_name,
                    'file_path': file_path,
                    'line_number': line_num,
                    'is_covered': False,
                    'status': 'not_executed',
                    'execution_count': 0,
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
        uncovered_count = len(callsite_coverage_list) - covered_count
        self.coverage_state[f'round{self.current_exp_iteration}'] = {
            'callsite_coverage_list': callsite_coverage_list,
            'first_uncovered_callsite': first_uncovered_callsite,
            'coverage_summary': {
                'total_callsites': len(callsite_info),
                'covered_count': covered_count,
                'uncovered_count': uncovered_count
            }
        }

        # Step 5: Build formatted output string
        output_lines = []
        output_lines.append("=" * 80)
        output_lines.append("FUNCTION-LEVEL COVERAGE FEEDBACK")
        output_lines.append("=" * 80)

        # Summary
        total_count = len(callsite_coverage_list)
        coverage_percentage = (covered_count / total_count * 100) if total_count > 0 else 0
        output_lines.append(f"[COVERAGE SUMMARY]")
        output_lines.append(f"  Total callsites in trace: {total_count}")
        output_lines.append(f"  Functions executed:       {covered_count} ({coverage_percentage:.1f}%)")
        output_lines.append(f"  Functions not executed:   {uncovered_count}")

        # Output all callsites in call trace order
        output_lines.append(f"\n[CALL TRACE COVERAGE] (in order)")
        for callsite in callsite_coverage_list:
            if callsite['is_covered']:
                # Covered function - print with checkmark
                output_lines.append(f"  ✓ #{callsite['sequence_num']}: {callsite['function_name']} @ {callsite['file_path']}:{callsite['line_number']}")
                output_lines.append(f"      Executed: {callsite['execution_count']} times, Regions: {callsite['regions_covered']}/{callsite['regions_total']} covered")
            else:
                # Uncovered function - print with cross
                status = callsite.get('status', 'not_executed')
                if status == 'not_found':
                    output_lines.append(f"  ✗ #{callsite['sequence_num']}: {callsite['function_name']} @ {callsite['file_path']}:{callsite['line_number']}")
                    output_lines.append(f"      Status: NOT FOUND in coverage data")
                else:
                    output_lines.append(f"  ✗ #{callsite['sequence_num']}: {callsite['function_name']} @ {callsite['file_path']}:{callsite['line_number']}")
                    output_lines.append(f"      Status: NOT EXECUTED, Regions: {callsite['regions_covered']}/{callsite['regions_total']} covered")

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
        self.logger.info(f"  [PathExplorationAgent] [Round {self.current_exp_iteration}] Substep4: Analyzing coverage feedback...")

        feedback_analysis_results  = f"For the finished execution, exit code: {exit_code}\n\nexecution output:\n{exec_output}\n\n"
        feedback_analysis_results += f"Function-level coverage feedback along the vulnerable call trace:\n{func_level_cov_info}\n\n"
        
        # TODO: Currently we just return the raw information.
        return feedback_analysis_results

    def _detect_stop_status(self, exit_code: int, exec_output: str) -> bool:
        """
        Check if we should stop path exploration based on execution results.
        Handles:
        - Exit code 127: Command not found (raises error)
        - Exit code 139/-11: Segmentation fault/crash (updates crash_input_pov)
        - Other potential stop conditions
        Args:
            exit_code: The exit code from test case execution
            exec_output: The output from test case execution (stdout + stderr)
        Returns:
            bool: True if a crash input pov is found, False otherwise
        Raises:
            RuntimeError: If command not found (exit code 127)
        """
        # Check for command not found - this is a fatal error
        if exit_code == 127:
            self.logger.error(f"  [PathExplorationAgent] Command not found (exit code 127)")
            self.logger.error(f"  [PathExplorationAgent] Execution output:\n{exec_output}")
            raise RuntimeError(
                "Command not found during test case execution of PathExplorationAgent (exit code 127). "
                "Please check if the binary path and harness command are correct."
            )

        # Check for segmentation fault (crash) - this is our target!
        # Exit code 139 = 128 + 11 (SIGSEGV signal)
        # Exit code -11 = SIGSEGV on some systems
        if exit_code == 139 or exit_code == -11:
            self.logger.warning(f"  [PathExplorationAgent] *** SEGMENTATION FAULT detected (exit code {exit_code}) ***")

            # Get current test case path
            current_testcase_path = os.path.join(
                self._get_round_dir(self.current_exp_iteration),
                f"testcase-round{self.current_exp_iteration}"
            )

            # Read and store the crashing input
            try:
                with open(current_testcase_path, 'rb') as f:
                    crash_input_content = f.read()

                # Update crash_input_pov with detailed information
                self.crash_input_pov = {
                    'testcase_path': current_testcase_path,
                    'content': crash_input_content,
                    'iteration': self.current_exp_iteration,
                    'exit_code': exit_code,
                    'exec_output': exec_output
                }

                # Log the crash discovery
                self.logger.info(f"  [PathExplorationAgent] *** CRASH INPUT POV FOUND ***")
                self.logger.info(f"  [PathExplorationAgent] Test case: {current_testcase_path}")
                self.logger.info(f"  [PathExplorationAgent] Iteration: {self.current_exp_iteration}")
                self.logger.info(f"  [PathExplorationAgent] Content size: {len(crash_input_content)} bytes")

                # Print crash information to console for visibility
                print("\n")
                print("=" * 80)
                print("CRASH INPUT POV DISCOVERED")
                print("=" * 80)
                print(f"PathExplorationAgent has discovered a crashing input that triggers a segmentation fault!")
                print(f"Iteration:       {self.current_exp_iteration}/{self.max_exp_iterations}")
                print(f"Exit Code:       {exit_code}")
                print(f"Test Case Path:  {current_testcase_path}")
                print(f"Content Size:    {len(crash_input_content)} bytes")
                print(f"\n--- Test Case Content (hex) ---")
                # Print hex representation for binary data
                hex_str = crash_input_content.hex()
                for i in range(0, min(len(hex_str), 512), 64):  # Print first 256 bytes in hex
                    print(hex_str[i:i+64])
                if len(hex_str) > 512:
                    print(f"... ({len(crash_input_content) - 256} more bytes)")

                # Try to print as text if it's printable
                try:
                    text_content = crash_input_content.decode('utf-8', errors='replace')
                    if text_content.isprintable() or '\n' in text_content:
                        print(f"\n--- Test Case Content (text) ---")
                        print(text_content)  # Print all!
                        # print(text_content[:500])  # Print first 500 chars
                        # if len(text_content) > 500:
                        #     print(f"... ({len(text_content) - 500} more chars)")
                except:
                    pass

                print(f"\n--- Execution Output ---")
                print(exec_output[:1000])  # Print first 1000 chars of output
                if len(exec_output) > 1000:
                    print(f"... ({len(exec_output) - 1000} more chars)")
                print("=" * 80)
                print("\n")
                return True  # Indicate that we found a crash input pov

            except Exception as e:
                self.logger.error(f"  [PathExplorationAgent] Failed to read crash input: {e}")

        # Check for other interesting exit codes
        elif exit_code == -6 or exit_code == 134:  # SIGABRT
            self.logger.warning(f"  [PathExplorationAgent] Program aborted (exit code {exit_code})")
            self.logger.debug(f"  [PathExplorationAgent] This may indicate assertion failure or abort() call")
        elif exit_code == -9 or exit_code == 137:  # SIGKILL
            self.logger.warning(f"  [PathExplorationAgent] Program killed (exit code {exit_code})")
        elif exit_code < 0 or exit_code > 128:  # Signal-based exit
            self.logger.debug(f"  [PathExplorationAgent] Program terminated with signal (exit code {exit_code})")

        return False  # No crash input pov found

