import os
import glob
import shutil
import subprocess
from datetime import datetime

from typing import Dict, Any, List, Tuple, TYPE_CHECKING
if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent
    from drillagent.tools.basic_tools import AgentTool

from drillagent.prompts.PathExplorationAgent_prompt import (
    PEA_system_prompt,
    PEA_testcase_generation_prompt,
    PEA_cov_feedback_info_template,
    PEA_previous_roundir_template
)
from drillagent.utils.llvm_cov import LLVMCovUtils
from drillagent.utils.utils import *

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

        self.tools_for_generation: List['AgentTool'] = self.drill_agent.basic_tools + self.drill_agent.ast_grep_tools + self.drill_agent.cov_tools

        # In each exploration, the agent will generate a PoV test case, execute it, and collect coverage feedback.
        # The outermost-loop counters:
        self.max_exp_iterations = 8
        self.current_exp_iteration = 0
        # Control test case generation turns.
        self.max_generation_turns = 15 # 10 or 15 or 20

        # For coverage collection
        binary_abs_path = os.path.abspath(os.path.join(
            self.config.target_repo_path, 
            self.drill_agent.vulnerability_info.actual_binary_path # Must use actual binary here!
        ))
        self.llvm_cov_utils = LLVMCovUtils(binary_abs_path=binary_abs_path)
        self.vuln_crash_trace = self.drill_agent.vulnerability_info.crash_trace # Obtained from VulnAnalysisAgent directly
        # self.coverage_state = dict()  # e.g., covered functions/branches

        # All of the intermediate PoV results should be stored, and can be passed to next agent easily.
        self.history_testcases = []       # List of file paths to all generated test cases.
        self.vfunc_reached_testcases = [] # List of file paths to test cases that reached the vulnerable function.
        self.crash_input_pov: Dict[str, Any] = None # A dict initialized when triggering segmentation fault.
        self.crash_command: str = None              # The command that triggered the crash.
        ## crash_input_pov['saved_pov_path']: The path where the crash PoV is saved in output_dir.

        # Mapping from iteration number to testcase path (similar to CrashTriggerAgent.generated_candidates)
        self.generated_testcases = {}     # {iteration_num: testcase_path}

    def run(self) -> None:
        # Run the path exploration process to generate test cases that can reach the vulnerable function.
        self.logger.info(f"  [PathExplorationAgent] Starting path exploration analysis... (tools num: {len(self.tools_for_generation)})")

        # Clear all the previous roundN directories if exist
        for i in range(1, self.max_exp_iterations+1+4):
            round_dir = self._get_round_dir(i)
            if os.path.exists(round_dir):
                shutil.rmtree(round_dir)

        # Maintain feedback from previous iteration to guide next iteration's testcase generation
        previous_feedback = None # From coverage feedback analysis
        for iteration in range(1, self.max_exp_iterations + 1):
            print("")
            self.logger.info(f"[PathExplorationAgent] Iteration {iteration}/{self.max_exp_iterations}")
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
            
            # FIXED: clear_data should also be called to avoid memory leak!!! (conservative operation)
            if self.llvm_cov_utils:
                self.llvm_cov_utils.clear_data()

            try:
                # Step1: Generate test case (with feedback from previous iteration if available)
                # Returned test_case should be the path to the file within the drill_agent.work_dir (workspace).
                test_case_path = self._generate_test_case(previous_feedback)
                self.history_testcases.append(test_case_path)
                self.generated_testcases[self.current_exp_iteration] = test_case_path  # Record for feedback in next iteration

                # Step2: Execute test case dynamically
                # Transform general harness command to executable command in current round directory
                ## Since we use "absolute path" in _refine_harness_command, here we just need to replace the testcase path.
                harness_command = self.drill_agent.vulnerability_info.refined_harness_command
                abs_test_case_path = os.path.abspath(test_case_path)
                command = harness_command.replace('<path/to/testcase>', abs_test_case_path)
                # Exec! This will also generate a profraw/profdata file.
                exit_code, exec_output = self._execute_test_case(command)

                # Step2.5:
                # Check segmentation fault or sanitizer crash to detect early-stop after each execution
                found_pov = self._detect_stop_status(exit_code, exec_output)
                if found_pov:
                    self._record_current_pov(test_case_path, command, exit_code, exec_output)
                    self.logger.info(f"  [PathExplorationAgent] Crash-triggering PoV found! Triggered early stop due to segmentation fault.")
                    break
                # Also check if current test case can trigger sanitizer crash. (optional) (any crash type here is acceptable)
                _, is_valid = self.drill_agent.validate_pov(command)
                if is_valid:
                    self._record_current_pov(test_case_path, command, exit_code, exec_output)
                    self.logger.info(f"  [PathExplorationAgent] Crash-triggering PoV found! Passed sanitizer validation!")
                    break

                # Step3: Collect useful coverage feedback along the vulnerable call trace
                ## sorted_cov_frames: from caller to callee
                cov_report, sorted_cov_frames = self._collect_coverage_feedback()
                # If the last 3 frames (or fewer if not enough) are all covered, add current testcase to vfunc_reached_testcases.
                if sorted_cov_frames:
                    innermost_frames = sorted_cov_frames[-3:] if len(sorted_cov_frames) >= 3 else sorted_cov_frames
                    # A frame is considered covered if func_executed=True or failed_getting_cov=True (compromise)
                    all_innermost_covered = all(
                        f.get('func_executed', False) or f.get('failed_getting_cov', False)
                        for f in innermost_frames
                    )
                    if all_innermost_covered:
                        self.logger.info(f"  [PathExplorationAgent] Innermost {len(innermost_frames)} frame(s) are covered. Adding to vfunc_reached_testcases.")
                        self.vfunc_reached_testcases.append(test_case_path)
                
                # If there are at least 3 test cases that have reached the vulnerable function, stop early
                if len(self.vfunc_reached_testcases) >= 3:
                    self.logger.info(f"  [PathExplorationAgent] Multiple test cases have reached the vulnerable function. Stopping early.")
                    break

                # Step4: Analyze coverage feedback, also store feedback for next phase.
                # Returns coverage feedback for next round's test case generation.
                previous_feedback = self._analyze_coverage_feedback(
                    test_case_path, exit_code, exec_output, 
                    cov_report, sorted_cov_frames
                )

            except Exception as e:
                self.logger.error(f"  [PathExplorationAgent] Iteration {iteration} failed with error: {e}")
                self.logger.warning(f"  [PathExplorationAgent] Continuing to next iteration...")
                if self.llvm_cov_utils:
                    self.llvm_cov_utils.clear_data()
                continue # If we meet any error during generation and coverage analysis, just continue to next iteration.
        
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

    def _generate_test_case(self, previous_feedback: str = "") -> str:
        # Generate test case using LLMInterface with automatic agent loop
        self.logger.info(f"  [PathExplorationAgent] Step1: Generating test case...")
        round_dir = self._get_round_dir(self.current_exp_iteration)

        # Substep 1: Construct the task prompt for test case generation
        # 1.1. Get vulnerability information string (vuln basic info + root cause)
        vuln_info_str = self.drill_agent.vulnerability_info.format_output(skip_rca_result=True)
        vuln_info_str += "\n\n" + self.drill_agent.vulnerability_info.get_full_root_cause()

        # 1.2. Construct the instructions on previous round directory to guide LLM review last attempt.
        previous_roundir_section = "N/A"
        if self.current_exp_iteration > 1:
            self.logger.info(f"  [PathExplorationAgent] Adding previous round dir path to prompt: {previous_round_dir}")
            previous_round_dir = self._get_round_dir(self.current_exp_iteration - 1)
            assert os.path.exists(previous_round_dir), f"Previous round dir does not exist: {previous_round_dir}!"
            # Get coverage-instrumented binary path
            vuln_info = self.drill_agent.vulnerability_info
            bin_rel_path = vuln_info.actual_binary_path or vuln_info.binary_path
            cov_binary_path = os.path.join(self.config.target_repo_path, bin_rel_path)
            previous_roundir_section = "\n" + PEA_previous_roundir_template.format(
                previous_iteration=self.current_exp_iteration - 1,
                previous_round_dir=previous_round_dir,
                cov_binary_path=cov_binary_path
            )

        # 1.3. Construct coverage feedback section if we have previous iteration results.
        cov_feedback_section = "N/A"
        if previous_feedback:
            self.logger.info(f"  [PathExplorationAgent] Adding cov feedback to current prompt from iteration {self.current_exp_iteration - 1}")
            cov_feedback_section = PEA_cov_feedback_info_template.format(previous_feedback=previous_feedback)

        # Prepare the target test case file path. Also add file suffix if available from vulnerability info
        file_suffix = getattr(self.drill_agent.vulnerability_info, 'input_file_suffix', '') or ''
        test_case_filename = f"testcase-round{self.current_exp_iteration}{file_suffix}"
        test_case_path = os.path.join(round_dir, test_case_filename)
        abs_test_case_path = os.path.abspath(test_case_path)
        if file_suffix:
            self.logger.debug(f"  [PathExplorationAgent] Using file suffix from vulnerability info: {file_suffix}")

        # Format the unified task prompt. (now root cause is included in vuln_info_str)
        loop_progress=f"{self.current_exp_iteration - 1}/{self.max_exp_iterations}",
        user_prompt = PEA_testcase_generation_prompt.format(
            loop_progress=loop_progress,
            project_name=self.config.project_name,
            actual_repo_path=self.config.target_repo_path,
            target_testcase_path=abs_test_case_path, # Target file path for LLM to write into.
            # Designed context sections
            vulnerability_info=vuln_info_str,                 # Necessary
            previous_roundir_section=previous_roundir_section, # If this is empty, prompt will still work fine.
            cov_feedback_section=cov_feedback_section          # If this is empty, prompt will still work fine.
        )

        # Substep 2: Use LLMInterface for automatic tool calling and conversation management
        self.logger.info("  [PathExplorationAgent] Using LLMInterface to generate test case...")
        try:
            # FIXED: We should not use cheaper model here, gpt-5-mini prefers to invoke only one tool call each time...
            result = self.drill_agent.basic_llm.run_agent_loop(
                task=user_prompt,
                tools=self.tools_for_generation, # When generating test case, LLM is encouraged to use tools
                system_prompt=PEA_system_prompt,
                max_iterations=self.max_generation_turns, # tunable parameter
                temperature=0.7,  # Higher temperature for creative test case generation
                max_tokens=30720,
                continuation_prompt="Please continue exploring the repository and craft the final test case after you get enough information." + \
                  "If you already generated the file, call `finish` tool to end the process."
            )

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.warning(f"  [PathExplorationAgent] LLM agent loop did not complete successfully: {error_msg}")
                # Don't raise error here - continue to Step 3 to check if the file was still generated

            self.logger.info(f"  [PathExplorationAgent] LLM completed in {result.get('iterations', 'N/A')} iteration(s)")
            # Show the current round directory contents.
            _, output = list_directory(round_dir)
            self.logger.debug(f"  [PathExplorationAgent] ls -lh {round_dir}:\n{output}")
            # response = result.get('final_response', '')
            # if response: # 2026.01.17: Mute for output simplicity
            #     self.logger.debug(f"  [PathExplorationAgent] LLM Response: {response[:500]}...")
        except Exception as e:
            self.logger.warning(f"  [PathExplorationAgent] Exception during LLM agent loop: {e}")
            # Don't raise error here - continue to Step 3 to check if the file was still generated

        # Substep 3: Verify that the test case file was written and is non-empty
        # Check if the exact path exists first
        if not os.path.exists(test_case_path):
            # If not found, search for files matching the pattern (with potential extensions)
            self.logger.debug(f"  [PathExplorationAgent] Exact path {test_case_path} not found, searching for pattern...")
            search_pattern = f"{test_case_path}*"
            matching_files = glob.glob(search_pattern)
            if not matching_files:
                raise RuntimeError(
                    f"Test case file was not created. Expected: {test_case_path}"
                )
            # Update the path using the first matching file (should only be one)
            test_case_path = matching_files[0]
            self.logger.info(f"  [PathExplorationAgent] Found test case with extension: {test_case_path}")

        file_size = os.path.getsize(test_case_path)
        if file_size == 0:
            raise RuntimeError(f"Test case file at {test_case_path} is empty. LLM may have failed to write content.")

        self.logger.info(f"  [PathExplorationAgent] Test case successfully written to: {test_case_path}")
        self.logger.debug(f"  [PathExplorationAgent] Test case file size: {file_size} bytes")
        return test_case_path

    def _execute_test_case(self, command: str) -> Tuple[int, str]: # No LLM needed
        # Execute the program with llvm-cov instrumentation, return exit code and output.
        print("")
        self.logger.info(f"  [PathExplorationAgent] Step2: Executing test case...")
        round_dir = self._get_round_dir(self.current_exp_iteration)

        # Substep 1: Set environment variable to generate profraw file
        profraw_path = os.path.join(round_dir, f"test_{self.current_exp_iteration}.profraw")
        env = os.environ.copy()
        env['LLVM_PROFILE_FILE'] = profraw_path 

        # Substep 2: Execute the command with memory limit
        self.logger.info (f"  [PathExplorationAgent] Executing command: {command} in {round_dir}")
        try:
            # Use subprocess to execute the command, set timeout to avoid hang
            result = subprocess.run(
                command,
                shell=True,
                cwd=round_dir, # Path to instrumented binary is absolute, so we can execute anywhere.
                env=env,       # LLVM_PROFILE_FILE is set
                capture_output=True,
                text=True,
                timeout=30,    # 30 seconds timeout
                preexec_fn=set_memory_limit  # Apply memory limit to subprocess
            )
            exit_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr
            # Merge stdout and stderr as exec_output
            exec_output = f"[STDOUT]\n{stdout}\n[STDERR]\n{stderr}"
            self.logger.info(f"  [PathExplorationAgent] Command exit code: {exit_code}")
            if exit_code != 0:
                self.logger.info(f"  [PathExplorationAgent] stderr: {stderr[:500]}...") # Log first 500 chars of stderr if error
            # Show the current round directory contents.
            _, output = list_directory(round_dir)
            self.logger.debug(f"  [PathExplorationAgent] ls -lh {round_dir}:\n{output}")
        except subprocess.TimeoutExpired as e:
            self.logger.warning(f"  [PathExplorationAgent] Command execution timeout after 30s")
            exit_code = -1
            exec_output = f"[TIMEOUT] Command execution exceeded 30 seconds\n[STDOUT]\n{e.stdout}\n\n[STDERR]\n{e.stderr}"
        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Command execution failed: {e}")
            exit_code = -1
            exec_output = f"[ERROR] Command execution failed: {str(e)}"

        # Substep 3: Use LLVMCovUtils to transform profraw and store the coverage profile data (after each execution).
        self.logger.debug(f"  [PathExplorationAgent] LLVM_PROFILE_FILE = {profraw_path}")
        if not os.path.exists(profraw_path): # Check if profraw file has been generated
            self.logger.warning(f"  [PathExplorationAgent] Failed to find this profraw file!!") # Maybe the binary was not well-instrumented or the execution failed early...
            return exit_code, exec_output

        try:
            # Here we should already have llvm profraw file in current round directory.
            self.llvm_cov_utils.update_profile_data(profraw_path) # Transform profraw to profdata internally, but the JSON _coverage_data will be lazy-loaded.
            self.logger.info(f"  [PathExplorationAgent] Current cov profdata file at: {self.llvm_cov_utils.profdata_path}")
            return exit_code, exec_output
        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Failed to convert profraw to profdata: {e}")
            return exit_code, exec_output

    def _collect_coverage_feedback(self) -> Tuple[str, List[Dict]]: # No LLM needed
        # Collect function-level coverage feedback along the vulnerable crash backtrace.
        # Update: Now we only return two items.
        print("")
        self.logger.info(f"  [PathExplorationAgent] Step3: Collecting coverage feedback...")
        assert self.llvm_cov_utils is not None, "LLVMCovUtils not initialized before collecting coverage!" # Should never happen

        # Substep 1: Use `llvm-cov report` to get overall coverage summary. 
        # This is helpful for examining if we have usable coverage data at all.
        try:
            cov_report = self.llvm_cov_utils.generate_full_report()
        except Exception as e:
            self.logger.warning(f"  [PathExplorationAgent] \"self.llvm_cov_utils.generate_full_report()\" {e}")
            cov_report = "None"  # Placeholder if report generation fails

        # Substep 2.1: Extract function frames from vulnerable call trace
        # Check if we have a valid call trace
        if not self.vuln_crash_trace or len(self.vuln_crash_trace) == 0:
            self.logger.warning(f"  [PathExplorationAgent] No vulnerability call trace available")
            raise ValueError("No vulnerability call trace available for coverage analysis") # We assume there should be vuln_crash_trace.

        # Build a list of (function_name, file_path) tuples -> valid_frames
        valid_frames: List[Tuple[Dict, Any]] = []  # Store (frame, abs_file_path) tuples for frames we'll query
        for frame in self.vuln_crash_trace:
            # Skip external functions and frames without complete info
            if frame.get('is_external', False) or not frame.get('function_name') or not frame.get('file_path'):
                self.logger.debug(f"  [PathExplorationAgent] Skipping frame #{frame.get('sequence_num', -1)}: external or incomplete info")
                continue
            # Convert file_path to absolute path
            abs_file_path = os.path.abspath(os.path.join(self.config.target_repo_path, frame['file_path']))
            valid_frames.append((frame, abs_file_path))

        # Substep 2.2: Collecting current execution's coverage data at function level -> cov_frames
        ## Update: No need to dig into call-site-line level here, let LLM analyze it if needed.

        # Batch query function coverage (more efficient than calling get_function_coverage one by one)
        try:
            # Build query list: (file_path, function_name) tuples
            functions_to_query = [(abs_file_path, frame['function_name']) for frame, abs_file_path in valid_frames]
            # Here, `coverage_results` is a dict mapping (file_path, function_name) to coverage info dict
            coverage_results = self.llvm_cov_utils.get_multi_functions_coverage(functions_to_query)
        except Exception as e:
            self.logger.error(f"  [PathExplorationAgent] Failed to query function coverage: {e}")
            coverage_results = {}

        # Build cov_frames from coverage results
        cov_frames: List[Dict] = []
        for frame, abs_file_path in valid_frames:
            updated_frame = frame.copy()
            tmp_key = (abs_file_path, frame['function_name'])
            func_cov = coverage_results.get(tmp_key, {})
            if func_cov.get('found', False):
                updated_frame.update({
                    'func_executed'        : func_cov['is_executed'],
                    'func_execution_count' : func_cov['execution_count']
                })
            else:
                # Function not found in coverage data - maybe caused by compiler optimizations
                # TODO: FIX: Here we meet too many failures/fallbacks!!! Jepordizes the analysis...
                self.logger.warning(f"  [PathExplorationAgent] Failed to get function coverage: {e} for {frame['function_name']}.  Maybe caused by compiler optimizations (omitted)...")
                updated_frame.update({
                    'failed_getting_cov'   : True,
                    'func_executed'        : False,  # Placeholder values
                    'func_execution_count' : 0       # Placeholder values
                })
            cov_frames.append(updated_frame)

        # Sort cov_frames by sequence_num in descending order (from caller to callee, largest sequence_num first)
        sorted_cov_frames = sorted(cov_frames, key=lambda f: f['sequence_num'], reverse=True)
        # print(repr(sorted_cov_frames)) # For debug

        return cov_report, sorted_cov_frames

    def _format_vtrace_cov_info(self, sorted_cov_frames: List[Dict]) -> str:
        # Construct frame-by-frame coverage information
        output_lines = []
        for i, frame in enumerate(sorted_cov_frames, 1):
            seq_num = frame['sequence_num']
            func_name = frame['function_name']
            file_path = frame.get('file_path', 'N/A')
            line_num = frame.get('line_number', 'N/A')

            # Set function execution status.
            if frame.get('func_executed', False):
                func_exec_status = "✓ FUNC EXECUTED"
            elif frame.get('failed_getting_cov', False):
                # Compromise: when displaying feedback cov status, we consider unsupported frames as EXECUTED for simplicity. 
                func_exec_status = "✓ FUNC EXECUTED ***"
            else:
                func_exec_status = "✗ FUNC NOT EXECUTED"

            output_lines.append(f"#{seq_num:2d} | {func_name} ({func_exec_status})")
            output_lines.append(f"     Location: {file_path}:{line_num}")

        formatted_output = '\n'.join(output_lines)
        return formatted_output

    def _analyze_coverage_feedback(
        self, test_case_path: str, exit_code: int, exec_output: str,
        cov_report: str, sorted_cov_frames: List[Dict]
    ) -> str:
        print("")
        self.logger.info(f"  [PathExplorationAgent] Step4: Analyzing coverage feedback...")
        
        # All belongs to "## PREVIOUS EXECUTION FEEDBACK"
        # Part1
        basic_info = [
            f"### BASIC EXECUTION INFO - Iteration {self.current_exp_iteration}/{self.max_exp_iterations}\n",
            f"Executed test case file: {test_case_path}\n"
            f"Exit code: {exit_code}\n"
            f"Execution output:\n{exec_output}\n"
        ]
        basic_info = '\n'.join(basic_info)

        # Part2
        cov_feedback = [
            f"### COVERAGE FEEDBACK - Iteration {self.current_exp_iteration}/{self.max_exp_iterations}\n",
            # f"Overall Coverage Report:\n{cov_report}\n\n", # No need to provide this to LLM
            f"Function-Level Coarse-Grained Coverage (from caller to callee):\n",
            self._format_vtrace_cov_info(sorted_cov_frames)
        ]
        cov_feedback = '\n'.join(cov_feedback)

        # Aggregate basic execution and coverage info
        formatted_cov_info = basic_info + '\n' + cov_feedback

        # Store the collected coverage data into roundN dir.
        round_dir = self._get_round_dir(self.current_exp_iteration)
        with open(os.path.join(round_dir, "coverage_record.md"), "w") as f:
            f.write(formatted_cov_info)
        
        print(formatted_cov_info)
        print(f"Overall Coverage Report:\n{cov_report}") # For debug
        return formatted_cov_info


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

        elif exit_code == -9 or exit_code == 137:  # SIGKILL
            self.logger.warning(f"  [PathExplorationAgent] Program killed (exit code {exit_code}).")
        
        elif exit_code < 0 or exit_code > 128:  # Signal-based exit
            self.logger.debug(f"  [PathExplorationAgent] Program terminated with signal (exit code {exit_code}).")

        return False  # No crash input pov found

    def _record_current_pov(self, test_case_path: str, command: str, exit_code: int, exec_output: str) -> None:
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
            self.crash_command = command

            # Copy the crash PoV to output directory with timestamped name
            # As long as exit code is 139, we should consider it a crash PoV.
            timestamp = datetime.now().strftime("%y%m%d-%H%M")
            pov_filename = f"pov-{self.drill_agent.project_name}-{timestamp}-PEA-round{self.current_exp_iteration}"
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
