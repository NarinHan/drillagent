import os
import subprocess
import shutil
import re
import resource
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent

from drillagent.prompts.PathExplorationAgent_prompt import (
    PEA_system_prompt,
    PEA_testcase_generation_prompt,
    PEA_feedback_results_template,
    PEA_coverage_analysis_system_prompt,
    PEA_coverage_analysis_prompt,
)
from drillagent.utils.llvm_cov import LLVMCovUtils
from drillagent.utils.utils import set_memory_limit

# 
# Currently we assume that the PathExplorationAgent **has** usable call trace. (LHY)
# 
class PathExplorationAgent:
    # Responsible for exploring paths leading to vulnerabilities, fully utilizing the coverage feedback.
    # The goal of this agent is to at least generate a PoV that can reach the vulnerable function, better if in branch-level.

    def __init__(self, drill_agent: 'DrillAgent'):
        self.drill_agent = drill_agent
        self.config = drill_agent.config
        self.logger = drill_agent.logger
        self.tools = drill_agent.agent_tools

        # In each exploration, the agent will generate a PoV test case, execute it, and collect coverage feedback.
        # The outermost-loop counters:
        self.max_exp_iterations = 8
        self.current_exp_iteration = 0

        # Fields for coverage collection
        self.llvm_cov_utils : LLVMCovUtils = None
        self.vuln_call_trace = self.drill_agent.vulnerability_info.call_trace # Obtained from VulnAnalysisAgent directly
        # self.coverage_state = dict()  # e.g., covered functions/branches

        # All of the intermediate PoV results should be stored, and can be passed to next agent easily.
        self.history_testcases = []       # List of file paths to all generated test cases.
        self.vfunc_reached_testcases = [] # List of file paths to test cases that reached the vulnerable function.
        self.crash_input_pov = None       # A dict initialized when triggering segmentation fault.
        ## crash_input_pov['saved_pov_path']: The path where the crash PoV is saved in output_dir.

    def run(self) -> None:
        # Run the path exploration process to generate test cases that can reach the vulnerable function.
        self.logger.info("  [PathExplorationAgent] Starting path exploration analysis...")

        # Clear all the previous roundN directories if exist
        for i in range(1, self.max_exp_iterations+1+4):
            round_dir = self._get_round_dir(i)
            if os.path.exists(round_dir):
                shutil.rmtree(round_dir)

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
            test_case_path = self._generate_test_case(previous_feedback)
            self.history_testcases.append(test_case_path)

            # Substep2: Execute test case dynamically (using actual repo path)
            # This will also generate a profraw/profdata file.
            exit_code, exec_output = self._execute_test_case(test_case_path)

            ## Special A: Check segmentation fault early-stop after each execution
            found_pov = self._detect_stop_status(exit_code, exec_output)
            if found_pov:
                self._record_current_pov(test_case_path, exit_code, exec_output)
                self.logger.info(f"  [PathExplorationAgent] Crash-triggering PoV found! Triggered early stop.")
                break

            # Substep3: Collect useful coverage feedback along the vulnerable call trace
            sorted_cov_frames, first_uncovered_frame, detailed_func_cov_data = self._collect_coverage_feedback()
            ## Store the collected coverage data into roundN dir.
            coverage_record = f"Exit code: {exit_code}\n" + f"Execution output:\n{exec_output}\n" + "\n"
            coverage_record += self._format_coverage_feedback(sorted_cov_frames, first_uncovered_frame, detailed_func_cov_data)
            with open(os.path.join(round_dir, "coverage_record.md"), "w") as f:
                f.write(coverage_record)

            ## Special B: Check vuln_func reached early-stop after inspecting coverage
            ## If we disable here's "break", the agent will continue to explore branch-level coverage.
            if first_uncovered_frame is None:
                self.logger.info(f"  [PathExplorationAgent] All callsites in the call trace have been covered. Stopping early.")
                self.vfunc_reached_testcases.append(test_case_path)
                # If there are at least 3 test cases that have reached the vulnerable function, we can also stop early.
                if len(self.vfunc_reached_testcases) >= 3:
                    self.logger.info(f"  [PathExplorationAgent] Multiple test cases have reached the vulnerable function. Stopping early.")
                    break

            # Substep4: Analyze coverage feedback around the first uncovered point A in the call trace
            # Output: reachability failure analysis, test case adjustment suggestion.
            previous_feedback = self._analyze_coverage_feedback(
                test_case_path, exit_code, exec_output, 
                sorted_cov_frames, first_uncovered_frame, detailed_func_cov_data
            ) # Also store feedback for next iteration

            # FIX: LLVMCovUtils.clear_data should be called to avoid memory leak!!! (conservative operation)
            if self.llvm_cov_utils:
                self.llvm_cov_utils.clear_data()
        
        self.logger.info(f"  [PathExplorationAgent] Just left the path exploration loop ({self.current_exp_iteration}/{self.max_exp_iterations}).")

        if not self.crash_input_pov:
            self.logger.info(f"  [PathExplorationAgent] Although no crash-triggering PoV generated during path exploration, we get closer ^^")
            usable_testcases = max(len(self.history_testcases), len(self.vfunc_reached_testcases))
            assert usable_testcases >= 3, "Failed to obtain enough useful test cases during path exploration!"
        else:
            self.logger.info(f"  [PathExplorationAgent] Crash-triggering PoV successfully generated during path exploration!")

    def _get_round_dir(self, round_num: int) -> str:
        # assert os.path.exists(self.drill_agent.work_dir), "DrillAgent work_dir does not exist!!!"
        # By default, work_dir is a relative path (./workspace). So round_dir is also relative.
        return os.path.join(self.drill_agent.work_dir, f"round{round_num}") 

    # TODO: Support generating separate binary-encoded test case files in the future.
    def _generate_test_case(self, previous_feedback: Tuple = None) -> str:
        # Generate test case using LLMInterface with automatic agent loop
        # 1. Get vulnerability information. If previous_feedback is provided, include it in the prompt to guide the LLM with coverage information.
        # 2. Use LLMInterface to generate test case (with tools and multi-turn interaction).
        # 3. Extract testcase content from LLM response.
        print("")
        self.logger.info(f"  [PathExplorationAgent] [Round {self.current_exp_iteration}] Substep1: Generating test case...")
        round_dir = self._get_round_dir(self.current_exp_iteration)
        max_generation_turns = 20 # We can set this parameter.

        # Step 1: Construct the prompt for test case generation
        vuln_info_str = self.drill_agent.vulnerability_info.format_output(skip_rca_result=True)
        vuln_info_str += "\n" + self.drill_agent.vulnerability_info.get_full_root_cause()

        # Build feedback section if we have previous iteration results
        feedback_section = ""
        if previous_feedback:
            if len(previous_feedback) == 3:  # Parse the feedback information tuple
                refined_feedback = f"{previous_feedback[0]}\n\n" \
                    + f"## Coverage Stagnation Reasons\n{previous_feedback[1]}\n\n" \
                    + f"## Input Adjustment Suggestion\n{previous_feedback[2]}"
            elif len(previous_feedback) == 1:  # Partial feedback
                refined_feedback = previous_feedback[0]
            else: # Fallback: just convert to string
                refined_feedback = str(previous_feedback)

            self.logger.info(f"  [PathExplorationAgent] Adding feedback to current prompt from iteration {self.current_exp_iteration - 1}")
            feedback_section = PEA_feedback_results_template.format(
                loop_progress=f"{self.current_exp_iteration - 1}/{self.max_exp_iterations}",
                previous_feedback=refined_feedback
            )
        else: # e.g., previous_feedback is None
            feedback_section = ""

        # Format the unified task prompt. (now root cause is included in vuln_info_str)
        user_prompt = PEA_testcase_generation_prompt.format(
            vulnerability_info=vuln_info_str,
            project_name=self.config.project_name,
            actual_repo_path=self.config.target_repo_path,
            feedback_section=feedback_section # If this is empty, prompt will still work fine.
        )

        # Step 2: Use LLMInterface for automatic tool calling and conversation management
        self.logger.info("  [PathExplorationAgent] Using LLMInterface to generate test case...")
        result = self.drill_agent.basic_llm.run_agent_loop(
            task=user_prompt,
            tools=self.tools, # When generating test case, LLM is encouraged to use tools. 
            system_prompt=PEA_system_prompt,
            max_iterations=max_generation_turns,  # Allow up to 10 rounds of tool usage
            temperature=0.7,  # Higher temperature for creative test case generation
            max_tokens=8192,
            continuation_prompt="Please continue exploring the repository and generate the final test case to reach or trigger the vulnerability in a ```testcase code block."
        )

        if not result['success']:
            error_msg = result.get('error', 'Unknown error')
            self.logger.error(f"  [PathExplorationAgent] LLM agent loop failed: {error_msg}")
            raise RuntimeError(f"Failed to generate test case: {error_msg}")

        response = result['final_response']
        self.logger.info(f"  [PathExplorationAgent] LLM completed in {result['iterations']} iteration(s)")
        # self.logger.info(f"  [PathExplorationAgent] Stop reason: {result['stop_reason']}")
        self.logger.debug(f"  [PathExplorationAgent] LLM Response: {response[:500]}...")

        # Step 3: Extract testcase content from response and save to file
        # testcase_pattern = r'```testcase\s*\n(.*?)\n```'
        testcase_pattern = r'```testcase\s*\n([\s\S]*?)```'
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

        # Save test case to fixed filename: testcase-round{N}
        test_case_filename = f"testcase-round{self.current_exp_iteration}"
        test_case_path = os.path.join(round_dir, test_case_filename)
        with open(test_case_path, 'w') as f:
            f.write(testcase_content)

        self.logger.debug(f"  [PathExplorationAgent] Saved testcase content ({len(testcase_content)} bytes) to {test_case_path}!")
        self.logger.info (f"  [PathExplorationAgent] Test case generated at: {test_case_path}")
        return test_case_path

    def _execute_test_case(self, test_case_path: str) -> Tuple[int, str]: # No LLM needed
        print("")
        self.logger.info(f"  [PathExplorationAgent] [Round {self.current_exp_iteration}] Substep2: Executing test case...")
        round_dir = self._get_round_dir(self.current_exp_iteration)

        # Step 1: Prepare the command
        repo_path = self.drill_agent.config.target_repo_path
        binary_path = self.drill_agent.vulnerability_info.binary_path
        binary_abs_path = os.path.abspath(os.path.join(repo_path, binary_path)) # Pass to LLVMCovUtils
        harness_command = self.drill_agent.vulnerability_info.refined_harness_command
        if not binary_path:
            raise ValueError("Binary path not found in vulnerability_info")
        if not harness_command:
            raise ValueError("Refined harness command not found in vulnerability_info")

        # Transform general harness command to executable command in current round directory
        ## Since we use "absolute path" in _refine_harness_command, here we just need to replace the testcase path.
        abs_test_case_path = os.path.abspath(test_case_path)
        command = harness_command.replace('<path/to/testcase>', abs_test_case_path)

        # Step 2: Set environment variable to generate profraw file
        profraw_path = os.path.join(round_dir, f"test_{self.current_exp_iteration}.profraw")
        env = os.environ.copy()
        env['LLVM_PROFILE_FILE'] = profraw_path 

        # Step 3: Execute the command with memory limit
        self.logger.info (f"  [PathExplorationAgent] Executing command: {command} in {round_dir}")
        try:
            # Use subprocess to execute the command, set timeout to avoid hang
            result = subprocess.run(
                command,
                shell=True,
                cwd=round_dir, # Path to instrumented binary is absolute, so we can execute anywhere.
                env=env,
                capture_output=True,
                text=True,
                timeout=30,  # 30 seconds timeout
                preexec_fn=set_memory_limit  # Apply memory limit to subprocess
            )
            exit_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr
            # Merge stdout and stderr as exec_output
            exec_output = f"[STDOUT]\n{stdout}\n[STDERR]\n{stderr}"
            self.logger.info(f"  [PathExplorationAgent] Command exit code: {exit_code}")
        except subprocess.TimeoutExpired as e:
            self.logger.warning(f"  [PathExplorationAgent] Command execution timeout after 30s")
            exit_code = -1
            exec_output = f"[TIMEOUT] Command execution exceeded 30 seconds\n[STDOUT]\n{e.stdout}\n\n[STDERR]\n{e.stderr}"
        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Command execution failed: {e}")
            exit_code = -1
            exec_output = f"[ERROR] Command execution failed: {str(e)}"

        # Step 4: After each execution, use LLVMCovUtils to transform profraw and store the coverage profile data.
        self.logger.debug(f"  [PathExplorationAgent] LLVM_PROFILE_FILE: {profraw_path}")
        if not os.path.exists(profraw_path): # Check if profraw file has been generated
            self.logger.warning(f"  [PathExplorationAgent] profraw file not generated at {profraw_path}")
            self.logger.warning(f"  [PathExplorationAgent] This might indicate the binary was not instrumented or the execution failed early!")
            # Return without initializing llvm_cov_utils! If None, next step will return directly.
            return exit_code, exec_output

        try:   # Here we already have llvm profraw file in current round directory.
            if self.llvm_cov_utils is None:
                # First time init
                self.llvm_cov_utils = LLVMCovUtils(
                    binary_path=binary_abs_path, # absolute path to the instrumented binary
                    profraw_path=profraw_path    # relative path (by default)
                )
            else:
                # LLVMCovUtils will replace last round's coverage data with new execution results.
                # And automatically convert profraw to profdata inside.
                self.llvm_cov_utils.update_profile_data(profraw_path) # relative path (by default)
            self.logger.info(f"  [PathExplorationAgent] Current profdata file generated/updated at: {self.llvm_cov_utils.profdata_path}")
            return exit_code, exec_output

        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Failed to convert profraw to profdata: {e}")
            return exit_code, exec_output

    def _collect_coverage_feedback(self) -> tuple[List[Dict], Dict, str]: # No LLM needed
        # Collect function-level coverage feedback along the vulnerable call trace.
        # 1. Extract function information from self.vuln_call_trace
        # 2. Query coverage using self.llvm_cov_utils.get_multi_functions_coverage()
        # 3. Format and return the coverage information as a string for analysis
        print("")
        self.logger.info(f"  [PathExplorationAgent] [Round {self.current_exp_iteration}] Substep3: Collecting coverage feedback...")

        # Check LLVMCovUtils and if we have a valid call trace
        assert self.llvm_cov_utils is not None, "LLVMCovUtils not initialized before collecting coverage!"
        if not self.vuln_call_trace or len(self.vuln_call_trace) == 0:
            self.logger.warning(f"  [PathExplorationAgent] No vulnerability call trace available")
            return "ERROR: No vulnerability call trace available for coverage analysis"

        # Substep 1: Extract function information from vulnerable call trace
        # Build a list of (function_name, file_path) tuples for batch query
        valid_frames: List[Tuple[Dict, Any]] = []  # Store (frame, abs_file_path) tuples for frames we'll query
        repo_path = self.drill_agent.config.target_repo_path
        for frame in self.vuln_call_trace:
            # Skip external functions and frames without complete info
            if frame.get('is_external', False) or not frame.get('function_name') or not frame.get('file_path'):
                self.logger.debug(f"  [PathExplorationAgent] Skipping frame #{frame.get('sequence_num', -1)}: external or incomplete info")
                continue
            # Convert file_path to absolute path
            abs_file_path = os.path.abspath(os.path.join(repo_path, frame['file_path']))
            valid_frames.append((frame, abs_file_path))

        # Batch query function coverage using LLVMCovUtils
        # self.logger.info(f"  [PathExplorationAgent] Querying coverage for {len(functions_to_query)} functions in call trace")
        # functions_to_query = []
        # for frame, abs_file_path in valid_frames:
        #     functions_to_query.append((frame['function_name'], abs_file_path))
        # if not functions_to_query:
        #     self.logger.warning(f"  [PathExplorationAgent] No valid functions to query in call trace")
        #     return "WARNING: No valid functions found in call trace (all external or incomplete)"
        # try:
        #     # `coverage_results` is a dict mapping (function_name, file_path) to coverage info dict
        #     coverage_results = self.llvm_cov_utils.get_multi_functions_coverage(functions_to_query)
        # except Exception as e:
        #     self.logger.error(f"  [PathExplorationAgent] Failed to query function coverage: {e}")
        #     return f"ERROR: Coverage query failed - {str(e)}"

        # Substep 2: Collecting current execution's coverage data using LLVMCovUtils.
        # Use get_function_coverage, get_line_coverage.
        cov_frames: List[Dict] = []
        for frame, abs_file_path in valid_frames:
            updated_frame = frame.copy()
            try:
                func_cov = self.llvm_cov_utils.get_function_coverage(
                    file_path=abs_file_path,
                    function_name=frame['function_name']
                )
                updated_frame.update({
                    'func_executed'        : func_cov['is_executed'],
                    'func_execution_count' : func_cov['execution_count']
                })
            except Exception as e:
                # TODO: FIX: Here we meet too many failures/fallbacks!!! Jepordizes the analysis...
                self.logger.warning(f"  [PathExplorationAgent] Failed to get function coverage: {e}.  Maybe caused by compiler optimizations (omitted)...")
                updated_frame.update({
                    'failed_getting_cov'   : True,
                    'func_executed'        : False, # Placeholder values
                    'func_execution_count' : 0      # Placeholder values
                })

            # Only if the stack frame's line number is verified, it is meaningful to get line coverage, or it would be inaccurate.
            if not updated_frame.get('failed_getting_cov', False) and frame.get("is_verified", False):
                line_cov = self.llvm_cov_utils.get_line_coverage(
                    file_path=abs_file_path,
                    line_number=frame['line_number']
                )
                updated_frame.update({
                    'callsite_line_executed'        : line_cov['is_executed'],
                    'callsite_line_execution_count' : line_cov['execution_count'],
                })
            else:
                pass
            
            cov_frames.append(updated_frame)

        # Sort cov_frames by sequence_num in descending order (from caller to callee, largest sequence_num first)
        sorted_frames = sorted(cov_frames, key=lambda f: f['sequence_num'], reverse=True)

        # Substep 3: Identify the first un-executed critical callsite. And get detailed function coverage in source-line level for branch-level analysis.
        first_uncovered_frame  = None
        for frame in sorted_frames:
            # Check if we can get function coverage for this frame
            if frame.get('failed_getting_cov', False):
                # Compromise: Cannot obtain function coverage - skip this frame
                continue

            # Check if function was executed
            if not frame.get('func_executed', False):
                # Function not executed - this is the first uncovered critical callsite
                first_uncovered_frame = frame
                self.logger.info(f"  [PathExplorationAgent] Found first uncovered callsite (function-level): {frame['function_name']} at {frame['file_path']}:{frame.get('line_number', 'N/A')}")
                break

            # Function was executed, check if the callsite line accuracy was verified
            if not frame.get('is_verified', False):
                # Compromise: Couldn't verify callsite line, treat as covered and continue
                continue

            # Check if callsite line was executed
            if frame.get('is_verified', False) and not frame.get('callsite_line_executed', False):
                # Callsite line not executed - this is the first uncovered critical callsite
                first_uncovered_frame = frame
                self.logger.info(f"  [PathExplorationAgent] Found first uncovered callsite (line-level): {frame['function_name']} at {frame['file_path']}:{frame['line_number']}")
                break

            # Both function and callsite line executed, continue to next frame
            continue

        detailed_func_cov_data = None
        # If there is no uncovered callsite, maybe we have already reached the vulnerable function!!!
        if not first_uncovered_frame:
            self.logger.info(f"  [PathExplorationAgent] All callsites in the call trace have been covered!!!!!")

        # 2026.01.03: We don't hard-encode detailed function coverage results here.
        # # If we found an uncovered callsite, get detailed function coverage for branch-level analysis
        # if first_uncovered_frame:
        #     try:
        #         # Get detailed line-by-line coverage for the uncovered function
        #         abs_file_path = os.path.abspath(os.path.join(repo_path, first_uncovered_frame['file_path']))
        #         detailed_func_cov_data = self.llvm_cov_utils.get_detailed_function_coverage(
        #             file_path=abs_file_path,
        #             function_name=first_uncovered_frame['function_name']
        #         )
        #         self.logger.info(f"  [PathExplorationAgent] Retrieved detailed coverage for '{first_uncovered_frame['function_name']}'")
        #     except Exception as e:
        #         self.logger.warning(f"  [PathExplorationAgent] Failed to get detailed function coverage for '{first_uncovered_frame['function_name']}': {e}")
        #         detailed_func_cov_data = None

        # If first_uncovered_frame is still None here, it means all callsites are covered!
        return sorted_frames, first_uncovered_frame, detailed_func_cov_data

    def _format_coverage_feedback(self, sorted_cov_frames: List[Dict], first_uncovered_frame: Dict|None, detailed_func_cov_data: str|None) -> str:
        output_lines = [
            "=" * 80,
            f"COVERAGE FEEDBACK - Iteration {self.current_exp_iteration}/{self.max_exp_iterations}",
            "=" * 80,
            ""
        ]

        # # Calculate coverage statistics
        # total_count = len(sorted_cov_frames)
        # covered_count = 0
        # line_level_covered_count = 0
        # # When calculating cov statistics, we are strict (LHY).
        # for frame in sorted_cov_frames:
        #     if frame['func_executed']:
        #         covered_count += 1
        #         # Also count line-level coverage for verified frames
        #         if frame.get('is_verified', False) and frame.get('callsite_line_executed', False):
        #             line_level_covered_count += 1
        # coverage_percentage = (covered_count / total_count * 100) if total_count > 0 else 0.0
        # # Add summary statistics
        # output_lines.append(f"Call Trace Coverage Summary:")
        # output_lines.append(f"  Total frames in call trace: {total_count}")
        # output_lines.append(f"  Functions executed: {covered_count}/{total_count} ({coverage_percentage:.1f}%)")
        # output_lines.append(f"  Callsite lines executed (verified frames): {line_level_covered_count}/{sum(1 for f in sorted_cov_frames if f.get('is_verified', False))}")
        # output_lines.append("")

        # Add detailed frame-by-frame coverage information
        output_lines.append("Function-Level Frame-by-Frame Coverage (from caller to callee):") #####
        output_lines.append("")

        for i, frame in enumerate(sorted_cov_frames, 1):
            seq_num = frame['sequence_num']
            func_name = frame['function_name']
            file_path = frame.get('file_path', 'N/A')
            line_num = frame.get('line_number', 'N/A')

            # Function execution status
            # When displaying feedback cov status, we consider unsupported frames as EXECUTED for simplicity (LHY). 
            # This also aligns first un-executed frame identification logic.
            if frame.get('func_executed', False):
                func_exec_status = "✓ FUNC EXECUTED"
            elif frame.get('failed_getting_cov', False):
                func_exec_status = "✓ FUNC EXECUTED ***"
            else:
                func_exec_status = "✗ FUNC NOT EXECUTED"
            # func_exec_status = "✓ EXECUTED" if frame['func_executed'] else "✗ NOT EXECUTED"
            # func_exec_count = frame.get('func_execution_count', 0)

            output_lines.append(f"#{seq_num:2d} | {func_name} ({func_exec_status})")
            output_lines.append(f"     Location: {file_path}:{line_num}")
            # output_lines.append(f"     Function: {func_exec_status} (count: {func_exec_count})")

            # Mark if this is the first uncovered callsite
            if first_uncovered_frame and frame['sequence_num'] == first_uncovered_frame['sequence_num']:
                output_lines.append(f"     >>> FIRST UNCOVERED CALLSITE <<<")

            # output_lines.append("")

        # Add detailed line-by-line coverage for the first uncovered callsite
        if first_uncovered_frame:
            output_lines.append("-" * 80)
            output_lines.append(f"Line-Level First Un-executed Callsite:") #####
            output_lines.append(f"  Function: #{first_uncovered_frame['sequence_num']} {first_uncovered_frame['function_name']}")
            output_lines.append(f"  Location: {first_uncovered_frame['file_path']}:{first_uncovered_frame.get('line_number', 'N/A')} (the un-executed line in the func body)")
            # output_lines.append(f"    Based on the provided call trace, determine which callee was not invoked here and explain why it was not called.")
            output_lines.append("")
            # if detailed_func_cov_data: # Add the detailed coverage output directly
            #     output_lines.append("Function Body Code with Coverage:")
            #     output_lines.append("  - The leftmost column shows the source code line numbers.)")
            #     output_lines.append("  - The middle column shows the execution counts.")
            #     output_lines.append("  - The rightmost column contains the source code.")
            #     output_lines.append(detailed_func_cov_data)
        else:
            output_lines.append("-" * 80)
            output_lines.append(f"Line-Level First Un-executed Callsite: (if any)") #####
            output_lines.append("  All callsites in the call trace have been covered!")
            output_lines.append("")

        output_lines.append("=" * 80)
        formatted_output = '\n'.join(output_lines)

        self.logger.info(f"  [PathExplorationAgent] Formatted coverage feedback!")
        return formatted_output

    def _analyze_coverage_feedback(
        self, test_case_path: str, exit_code: int, exec_output: str, 
        sorted_cov_frames: List[Dict], first_uncovered_frame: Dict|None, detailed_func_cov_data: str|None
    ) -> Tuple:
        # Organize the collected coverage results, after LLM analysis, feed the results back for the next invocation of _generate_test_case.
        # For input parameters, `sorted_cov_frames` contains most of the information we need.
        print("")
        self.logger.info(f"  [PathExplorationAgent] [Round {self.current_exp_iteration}] Substep4: Analyzing coverage feedback...")

        formatted_cov_info = ""
        coverage_stagnation_reasons = ""
        input_adjustment_suggestion = ""
        
        # Step 1: Aggregate basic execution and coverage info
        basic_info = [
            "=" * 80,
            f"BASIC EXECUTION INFO - Iteration {self.current_exp_iteration}/{self.max_exp_iterations}",
            "=" * 80,
            f"exit code: {exit_code}\n"
            f"execution output:\n{exec_output}\n"
        ]
        basic_info = '\n'.join(basic_info)
        cov_feedback = self._format_coverage_feedback(sorted_cov_frames, first_uncovered_frame, detailed_func_cov_data)
        formatted_cov_info = basic_info + cov_feedback
        
        print(formatted_cov_info) # For debug
        return (formatted_cov_info)

        # 2025.12.25: It seems that this part is not very stable or effective yet, we can temporarily disable it.
        # Step 2: Utilize LLM to analyze coverage feedback and provide suggestions
        self.logger.info("  [PathExplorationAgent] Using LLM to analyze coverage feedback...")
        try:
            # Use LLM to analyze coverage and generate suggestions
            analysis_prompt = PEA_coverage_analysis_prompt.format(
                formatted_cov_info=formatted_cov_info,
                test_case_path=test_case_path
            )
            result = self.drill_agent.basic_llm.run_agent_loop(
                task=analysis_prompt,
                tools=self.tools,   # Allow tool usage if needed
                system_prompt=PEA_coverage_analysis_system_prompt,
                max_iterations=5,
                temperature=0.5,
                max_tokens=8192
            )

            if not result['success']: # Failure in LLM analysis
                error_msg = result.get('error', 'Unknown error')
                self.logger.error(f"  [PathExplorationAgent] Coverage analysis failed: {error_msg}")
                # Fallback: return error messages
                coverage_stagnation_reasons = "ERROR: Failed to analyze coverage feedback"
                input_adjustment_suggestion = "ERROR: Failed to generate suggestions"
            else:
                response = result['final_response']
                self.logger.info (f"  [PathExplorationAgent] Coverage analysis completed")
                self.logger.debug(f"  [PathExplorationAgent] Analysis response: {response[:300]}...")
                
                # Extract the analysis content from code block
                code_block_pattern = r'```\s*\n(.*?)\n```'
                code_block_match = re.search(code_block_pattern, response, re.DOTALL)
                if code_block_match:
                    analysis_content = code_block_match.group(1)
                    # Extract the two sections from the analysis
                    reasons_pattern = r'## COVERAGE STAGNATION REASONS\s*\n(.*?)(?=## INPUT ADJUSTMENT SUGGESTION|$)'
                    suggestion_pattern = r'## INPUT ADJUSTMENT SUGGESTION\s*\n(.*?)(?=$)'
                    reasons_match = re.search(reasons_pattern, analysis_content, re.DOTALL)
                    suggestion_match = re.search(suggestion_pattern, analysis_content, re.DOTALL)
                    coverage_stagnation_reasons = reasons_match.group(1).strip() if reasons_match else "Could not extract stagnation reasons"
                    input_adjustment_suggestion = suggestion_match.group(1).strip() if suggestion_match else "Could not extract input suggestions"
                    self.logger.info("  [PathExplorationAgent] Successfully extracted all coverage analysis sections")
                else:
                    # Fallback: try to extract directly without code block wrapper
                    self.logger.warning("  [PathExplorationAgent] No code block found, trying direct extraction...")
                    reasons_pattern = r'## COVERAGE STAGNATION REASONS\s*\n(.*?)(?=## INPUT ADJUSTMENT SUGGESTION|$)'
                    suggestion_pattern = r'## INPUT ADJUSTMENT SUGGESTION\s*\n(.*?)(?=$)'
                    reasons_match = re.search(reasons_pattern, response, re.DOTALL)
                    suggestion_match = re.search(suggestion_pattern, response, re.DOTALL)
                    if reasons_match and suggestion_match:
                        coverage_stagnation_reasons = reasons_match.group(1).strip()
                        input_adjustment_suggestion = suggestion_match.group(1).strip()
                        self.logger.info("  [PathExplorationAgent] Successfully extracted all sections from direct response")
                    else:
                        # Last resort: use the full response
                        self.logger.warning("  [PathExplorationAgent] Could not parse structured response, using full response")
                        coverage_stagnation_reasons = response
                        input_adjustment_suggestion = "See stagnation reasons for full analysis"

        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Exception during coverage analysis: {e}")
            coverage_stagnation_reasons = f"ERROR: Exception during analysis - {str(e)}"
            input_adjustment_suggestion = "ERROR: Could not generate suggestions due to exception"

        print("***\nCOVERAGE STAGNATION REASONS(debug)\n***\n" + coverage_stagnation_reasons)
        print("\n***\nINPUT ADJUSTMENT SUGGESTION(debug)\n***\n" + input_adjustment_suggestion)
        return (formatted_cov_info, coverage_stagnation_reasons, input_adjustment_suggestion)

    def _detect_stop_status(self, exit_code: int, exec_output: str) -> bool:
        """
        Check if we should stop path exploration based on execution results.
        - Exit code 127: Command not found (raises error)
        - Exit code 139/-11: Segmentation fault/crash (updates crash_input_pov, also stores test case to files in output_dir)
        - Other potential stop conditions
        Returns:
            bool: True if a crash-triggering pov is found, False otherwise
        Raises:
            RuntimeError: If command not found (exit code 127)
        """
        # Check for "command not found" - this is a fatal error
        if exit_code == 127:
            self.logger.error(f"  [PathExplorationAgent] Command not found (exit code 127)")
            self.logger.error(f"  [PathExplorationAgent] Execution output:\n{exec_output}")
            raise RuntimeError(
                "Command not found during test case execution of PathExplorationAgent (exit code 127). "
                "Please check if the binary path and harness command are correct."
            )

        # Check for "segmentation fault" (crash) - this is our target!
        # Exit code 139 = 128 + 11 (SIGSEGV signal) (-11 = SIGSEGV on some systems)
        if exit_code == 139 or exit_code == -11:
            self.logger.warning(f"  [PathExplorationAgent] *** SEGMENTATION FAULT detected (exit code {exit_code}) ***")
            return True  # Crash input pov found

        # Check for other interesting exit codes
        elif exit_code == -6 or exit_code == 134:  # SIGABRT
            self.logger.warning(f"  [PathExplorationAgent] Program aborted (exit code {exit_code}).")
            if "core dumped" in exec_output.lower() or "segmentation fault" in exec_output.lower():
                self.logger.warning(f"  [PathExplorationAgent]   Core dump also detected in execution output!")
                return True

        elif exit_code == -9 or exit_code == 137:  # SIGKILL
            self.logger.warning(f"  [PathExplorationAgent] Program killed (exit code {exit_code}).")
        
        elif exit_code < 0 or exit_code > 128:  # Signal-based exit
            self.logger.debug(f"  [PathExplorationAgent] Program terminated with signal (exit code {exit_code}).")

        return False  # No crash input pov found

    def _record_current_pov(self, test_case_path: str, exit_code: int, exec_output: str) -> None:
        # Record the current crash-triggering PoV.
        # This function handles all the storage and logging operations when a crash is detected.
        try:
            with open(test_case_path, 'rb') as f:
                crash_input_content = f.read()

            # Update crash_input_pov with detailed information
            self.crash_input_pov = {
                'testcase_path': test_case_path,
                'exit_code': exit_code,
                'exec_output': exec_output,
                'iteration': self.current_exp_iteration,
                'max_iterations': self.max_exp_iterations
            }

            # Copy the crash PoV to output directory with timestamped name
            timestamp = datetime.now().strftime("%y%m%d-%H%M")
            pov_filename = f"pov-{self.drill_agent.project_name}-{timestamp}-PEA"
            pov_output_path = os.path.join(self.drill_agent.output_dir, pov_filename)
            os.makedirs(self.drill_agent.output_dir, exist_ok=True)
            shutil.copy(test_case_path, pov_output_path)
            self.logger.info(f"  [PathExplorationAgent] Crash PoV saved to output directory: {pov_output_path}")
            # Update crash_input_pov with the saved path
            self.crash_input_pov['saved_pov_path'] = pov_output_path

            # Log the crash discovery
            self.logger.info(f"  [PathExplorationAgent] *** CRASH INPUT POV FOUND ***")
            self.logger.info(f"  [PathExplorationAgent] Test case: {test_case_path}")
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
            print(f"Test Case Path:  {test_case_path}")
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

        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Failed to read crash input: {e}")
