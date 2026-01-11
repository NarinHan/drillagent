import os
import re
import subprocess
import shutil
from datetime import datetime

from typing import Tuple, Dict, Any, TYPE_CHECKING
if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent

from drillagent.prompts.CrashTriggerAgent_prompt import (
    CTA_system_prompt,
    CTA_useful_testcase_and_cov_template,
    CTA_coverage_config_template,
    CTA_final_pov_generation_prompt,
)

from drillagent.utils.llvm_cov import LLVMCovUtils
from drillagent.utils.utils import *
class CrashTriggerAgent:
    # Responsible for triggering crashes based on analyzed paths
    def __init__(self, drill_agent: 'DrillAgent'):
        self.drill_agent = drill_agent
        self.config = drill_agent.config
        self.logger = drill_agent.logger

        # The outermost-loop counters.
        self.max_trigger_iterations = 8
        self.current_trigger_iteration = 0

        # Input files. (three files should be enough)
        self.useful_testcase_paths  = []  # List of file paths to useful test cases from path exploration.
        # Output files.
        ## Mapping from iteration number to a dict including: "testcase_path", "profdata_path".
        self.generated_candidates = {i: {} for i in range(1, self.max_trigger_iterations + 1)}  
        ## The final PoV that successfully triggers a crash.
        self.final_pov = None
        ## final_pov['saved_pov_path']: The path where the final validated PoV is saved in output_dir.

        # Init the LLVM coverage util. Set the profdata_path later after each execution.
        repo_path = self.drill_agent.config.target_repo_path
        binary_relative_path = self.drill_agent.vulnerability_info.binary_path
        binary_abs_path = os.path.abspath(os.path.join(repo_path, binary_relative_path))
        self.llvm_cov_utils = LLVMCovUtils(binary_path=binary_abs_path)

    def run(self) -> None:
        self.logger.info("  [CrashTriggerAgent] Starting running. Checking previous path exploration results...")

        # Clear all the previous roundN directories if exist
        for i in range(1, self.max_trigger_iterations+1+4):
            round_dir = self._get_round_dir(i)
            if os.path.exists(round_dir):
                shutil.rmtree(round_dir)

        # Before all: Examine the progress from previous path exploration.
        path_agent = self.drill_agent.path_agent
        if path_agent is not None:
            # Check if we already have a crash input
            if path_agent.crash_input_pov is not None:
                is_validated = self._validate_pov(path_agent.crash_input_pov, path_agent.crash_command)
                if is_validated:
                    self.logger.info("  [CrashTriggerAgent] Valid crash input found from path exploration phase! Using it as final PoV.")
                    # Save the crash input as final PoV
                    crash_pov_path = path_agent.crash_input_pov.get('saved_pov_path')
                    assert crash_pov_path is not None, "Crash input PoV path from PathExplorationAgent not found!"
                    self._record_final_pov(path_agent.crash_input_pov, crash_pov_path)
                    return
                else:
                    self.logger.info("  [CrashTriggerAgent] Crash input from path exploration did not validate successfully. Proceeding with crash triggering attempts...")
            else:
                self.logger.info("  [CrashTriggerAgent] Starting crash triggering attempts...")

            # Fill useful_testcase_paths with up to 3 testcases (used for the first round generation)
            # First from vfunc_reached_testcases (reversed), then from history_testcases (reversed)
            if path_agent.vfunc_reached_testcases:
                self.useful_testcase_paths.extend(list(reversed(path_agent.vfunc_reached_testcases)))
            if len(self.useful_testcase_paths) < 3 and path_agent.history_testcases:
                remaining = 3 - len(self.useful_testcase_paths)
                self.useful_testcase_paths.extend(list(reversed(path_agent.history_testcases))[:remaining])
            # Ensure we have at most 3 testcases
            self.useful_testcase_paths = self.useful_testcase_paths[:3]
            assert len(self.useful_testcase_paths) > 0, "No useful test cases found from path exploration!"

        # Main loop for crash triggering attempts.
        for iteration in range(1, self.max_trigger_iterations + 1):
            print("\n" + "=" * 80)
            self.logger.info(f"  [CrashTriggerAgent] Iteration {iteration}/{self.max_trigger_iterations}")
            self.current_trigger_iteration = iteration

            # Create round directory.
            round_dir = self._get_round_dir(self.current_trigger_iteration)
            os.makedirs(round_dir, exist_ok=True)
            for item in os.listdir(round_dir): # Clear previous contents
                item_path = os.path.join(round_dir, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            self.logger.debug(f"  [CrashTriggerAgent] Created and cleared round directory: {round_dir}")

            try:# Main operations!
                # Step 1: Generate final PoV.
                pov_path = self._generate_final_pov()
                self.generated_candidates[iteration]["testcase_path"] = pov_path

                # Step 2: Execute PoV candidate for cov-instr program (to collect coverage).
                # Transform general harness command to executable command
                harness_command = self.drill_agent.vulnerability_info.refined_harness_command
                if not harness_command:
                    raise ValueError("Refined harness command not found in vulnerability_info")
                abs_test_case_path = os.path.abspath(pov_path)
                command = harness_command.replace('<path/to/testcase>', abs_test_case_path) # the path is to cov-instr binary
                exit_code, exec_output = self._execute_pov_candidate(command)

                # Step 3: Validate PoV (using sanitizer-instrumented binary if available).
                pov_data = {
                    'testcase_path': abs_test_case_path,
                    'exit_code': exit_code,
                    'exec_output': exec_output,
                    'iteration': iteration,
                    'max_iterations': self.max_trigger_iterations
                }
                is_valid = self._validate_pov(pov_data, command)

                # If valid PoV found, save it and stop
                if is_valid:
                    self.logger.info(f"  [CrashTriggerAgent] *** Valid PoV found at iteration {iteration}! ***")
                    # Save the final PoV to output directory
                    self._record_final_pov(pov_data, pov_path)
                    break
                else: # validation failed
                    self.logger.info(f"  [CrashTriggerAgent] PoV at iteration {iteration} did not trigger crash, continuing...")

            except Exception as e:
                self.logger.error(f"  [CrashTriggerAgent] Error in iteration {iteration}: {e}", exc_info=True)
                continue

        # Summary
        if self.final_pov:
            self.logger.info(f"  [CrashTriggerAgent] Successfully generated valid PoV!")
        else:
            self.logger.info(f"  [CrashTriggerAgent] No valid PoV found after {self.current_trigger_iteration} iterations.")

    def _get_round_dir(self, round_num: int) -> str: # usually relative path
        # assert os.path.exists(self.drill_agent.work_dir), "DrillAgent work_dir does not exist!!!"
        return os.path.join(self.drill_agent.work_dir, f"triggering", f"round{round_num}")

    def _generate_final_pov(self) -> str:
        # Generate final PoV using LLM with vulnerability analysis and path exploration feedback
        # Returns path to the generated PoV file
        self.logger.info(f"  [CrashTriggerAgent] Generating final PoV using LLM...")
        max_generation_turns = 20  # Allow LLM multiple turns to generate PoV
        round_dir = self._get_round_dir(self.current_trigger_iteration)
        os.makedirs(round_dir, exist_ok=True)

        # Substep 1: Gather all necessary information for PoV generation
        vuln_info_str = self.drill_agent.vulnerability_info.format_output(skip_rca_result=True)
        root_cause_str = self.drill_agent.vulnerability_info.get_full_root_cause()

        # For history exec info, we provide path exploration progress to the first round and previous CTA-generated testcase for later rounds.
        if self.current_trigger_iteration == 1:
            # Try to prepare and provide previously-generated useful test cases.
            if len(self.useful_testcase_paths) > 0:
                # Transform self.useful_testcase_paths into a string containing several test case paths.
                # Each testcase path and its corresponding coverage_record.md are included.
                tmp_paths = []
                for testcase_path in self.useful_testcase_paths:
                    # LHY: Currently, we don't add "test_N.profdata" into prompt. All cov data is already organized.
                    dir_path = os.path.dirname(testcase_path)
                    coverage_path = os.path.join(dir_path, "coverage_record.md")
                    tmp_paths.append(testcase_path)
                    tmp_paths.append(coverage_path)
                    tmp_paths.append("")
                # Format the useful test cases and coverage info into previous_progress.
                previous_progress = CTA_useful_testcase_and_cov_template.format(
                    testcase_and_cov_paths="\n".join(tmp_paths)
                )
            else:
                previous_progress = "No useful test cases available from path exploration. You have to generate PoV from current knowledge."
        else:
            last_round_info = self.generated_candidates.get(self.current_trigger_iteration - 1, {})
            last_testcase_path = last_round_info.get("testcase_path", "N/A")
            last_profdata_path = last_round_info.get("profdata_path", "N/A")
            # Format the cov tool usage instructions with pre-round info.
            previous_progress = CTA_coverage_config_template.format(
                testcase_path=last_testcase_path,
                profdata_path=last_profdata_path
            )

        # Substep 2: Use LLMInterface to generate the final PoV
        # Format the user prompt for PoV generation
        user_prompt = CTA_final_pov_generation_prompt.format(
            project_name=self.config.project_name,
            actual_repo_path=self.config.target_repo_path,
            vulnerability_info=vuln_info_str,   # Including vuln type, call trace, etc.
            root_cause_analysis=root_cause_str, # Markdown format content
            previous_pov_gen_progress=previous_progress # 🤔
        )

        # For crash triggering, we also provide ast-grep and coverage tools.
        cur_tools = self.drill_agent.agent_tools + self.drill_agent.ast_grep_tools + self.drill_agent.agent_cov_tools

        self.logger.info("  [CrashTriggerAgent] Using LLMInterface to generate final PoV...")
        result = self.drill_agent.basic_llm.run_agent_loop(
            task=user_prompt,
            tools=cur_tools,  # Allow LLM to use tools for exploration
            system_prompt=CTA_system_prompt,
            max_iterations=max_generation_turns,
            temperature=0.7,  # Higher temperature for creative PoV generation
            max_tokens=20480,
            continuation_prompt="Please continue your analysis and generate the final PoV in a ```pov code block."
        )

        if not result['success']:
            error_msg = result.get('error', 'Unknown error')
            self.logger.error(f"  [CrashTriggerAgent] LLM agent loop failed: {error_msg}")
            raise RuntimeError(f"Failed to generate final PoV: {error_msg}")

        response = result['final_response']
        self.logger.info (f"  [CrashTriggerAgent] LLM completed in {result['iterations']} iteration(s)")
        self.logger.info (f"  [CrashTriggerAgent] Stop reason: {result['stop_reason']}")
        self.logger.debug(f"  [CrashTriggerAgent] LLM Response: {response[:500]}...")

        # Substep 3: Extract PoV content from response
        # pov_pattern = r'```pov\s*\n(.*?)\n```'
        pov_pattern = r'```pov\s*\n([\s\S]*?)```' # more general and robust
        match = re.search(pov_pattern, response, re.DOTALL)
        if not match:
            # Fallback: try to find any code block
            self.logger.warning("  [CrashTriggerAgent] No ```pov block found, trying generic code block...")
            fallback_pattern = r'```(?:\w+)?\s*\n(.*?)\n```'
            match = re.search(fallback_pattern, response, re.DOTALL)
        if not match:
            raise ValueError(f"No PoV code block found in LLM response after {result['iterations']} iterations")
        pov_content = match.group(1)
        self.logger.info(f"  [CrashTriggerAgent] PoV candidate extracted!")

        # Substep 4: Save PoV candidate to file
        pov_filename = f"testcase-round{self.current_trigger_iteration}" # "testcase-roundN"
        pov_path = os.path.join(round_dir, pov_filename)
        with open(pov_path, 'w') as f:
            f.write(pov_content)

        self.logger.debug(f"  [CrashTriggerAgent] Saved PoV candidate content ({len(pov_content)} bytes) to {pov_path}")
        self.logger.info(f"  [CrashTriggerAgent] PoV candidate generated at: {pov_path}")
        return pov_path

    def _execute_pov_candidate(self, command: str) -> Tuple[int, str]: # No LLM needed
        # Execute the program with llvm-cov instrumentation, return exit code and output.
        self.logger.info(f"  [CrashTriggerAgent] Executing PoV candidate...")
        round_dir = self._get_round_dir(self.current_trigger_iteration)

        # Prepare environment for LLVM coverage data collection
        profraw_path = os.path.join(round_dir, f"test_{self.current_trigger_iteration}.profraw")
        env = os.environ.copy()
        env['LLVM_PROFILE_FILE'] = profraw_path 

        # Execute the command
        self.logger.info(f"  [CrashTriggerAgent] Executing command: {command} (in {round_dir})")
        try:
            # Use subprocess to execute the command, set timeout to avoid hang
            result = subprocess.run(
                command,
                shell=True,
                cwd=round_dir,
                env=env, # Specify environment with LLVM_PROFILE_FILE
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
        except subprocess.TimeoutExpired as e:
            self.logger.warning(f"  [CrashTriggerAgent] Command execution timeout after 30s")
            exit_code = -1
            exec_output = f"[TIMEOUT] Command execution exceeded 30 seconds\n[STDOUT]\n{e.stdout}\n\n[STDERR]\n{e.stderr}"
        except Exception as e:
            self.logger.error(f"  [CrashTriggerAgent] Command execution failed: {e}")
            exit_code = -1
            exec_output = f"[ERROR] Command execution failed: {str(e)}"

        # After execution finished, convert the profraw to profdata, and update the file path.
        if os.path.exists(profraw_path):
            self.llvm_cov_utils.update_profile_data(profraw_path)
            self.generated_candidates[self.current_trigger_iteration]["profdata_path"] = self.llvm_cov_utils.profdata_path
        else:
            self.logger.error(f"  [CrashTriggerAgent] Expected profraw file not found: {profraw_path}")

        self.logger.info (f"  [CrashTriggerAgent] Command exit code: {exit_code}")
        self.logger.debug(f"  [CrashTriggerAgent] Command execution output:\n{exec_output[:500]}")
        return exit_code, exec_output

    def _validate_pov(self, pov_data: Dict, command: str) -> bool:
        # Validate the generated PoV by checking if it can violate the memory sanitizer as expected.
        # pov_data: dict containing 'testcase_path', 'exit_code', 'exec_output', etc.
        # Returns True if PoV is valid (triggers crash), False otherwise

        if not pov_data:
            self.logger.warning("  [CrashTriggerAgent] No PoV data provided for validation")
            return False

        # Extract information from pov_data
        # exit_code = pov_data.get('exit_code', 0)
        # exec_output = pov_data.get('exec_output', '')
        # testcase_path = pov_data.get('testcase_path', '')
        # self.logger.info(f"  [CrashTriggerAgent] Validating PoV: {testcase_path}")
        # self.logger.info(f"  [CrashTriggerAgent] Exit code: {exit_code}")

        # Use llvm-cov instrumented program cmds as basis, but replace repo path to sanitizer-instr repo path.
        if command is None or command.strip() == "":
            self.logger.error("  [CrashTriggerAgent] No harness command provided for PoV validation.")
            return False
        
        llvm_cov_repo = self.drill_agent.config.target_repo_path
        saninstr_repo = self.drill_agent.config.saninstr_repo_path
        if llvm_cov_repo in command:
            command = command.replace(llvm_cov_repo, saninstr_repo) # We want to execute the program in sanitizer-instr repo.
        else:
            self.logger.error("  [CrashTriggerAgent] TODO: Cannot map llvm-cov repo path to sanitizer-instr repo path in command.")
            return False

        # Disable the use of alternate signal stack (only for mruby?) and limit memory usage for ASAN.
        env = os.environ.copy()
        env['ASAN_OPTIONS'] = 'use_sigaltstack=0:hard_rss_limit_mb=12000' # Options ref: https://github.com/google/sanitizers/wiki/SanitizerCommonFlags
        if "ASAN_OPTIONS=" in command:
            prefix = env['ASAN_OPTIONS'].rstrip(':')
            if "ASAN_OPTIONS=" in command:
                if 'ASAN_OPTIONS="' in command: # Handle double quotation marks
                    command = re.sub(
                        r'ASAN_OPTIONS="([^"]*)"',
                        r'ASAN_OPTIONS="' + prefix + r':\1"',
                        command,
                        count=1
                    )
                else:
                    command = re.sub(
                        r'ASAN_OPTIONS=([^\s]+)',
                        r'ASAN_OPTIONS=' + prefix + r':\1',
                        command,
                        count=1
                    )

        # Execute the PoV using sanitizer-instrumented binary, and check if the sanitizer is triggered.
        self.logger.info(f"  [CrashTriggerAgent] Validation exec command: {command}")
        exit_code, exec_output = execute_command(command, env)
        if detect_sanitizer_triggered(exec_output):
            # TODO: Compare here output and the original sanitizer report to see if they match (optional).
            self.logger.info(f"  [CrashTriggerAgent] PoV validation successful: Sanitizer error detected! Exit code: {exit_code}")
            print(exec_output)
            return True
        else:
            self.logger.info(f"  [CrashTriggerAgent] PoV validation: No sanitizer error detected. Exit code: {exit_code}")

        return False

    def _record_final_pov(self, pov_data: Dict[str, Any], pov_path: str) -> str:
        """
        Record and save the final validated PoV to the output directory.

        Args:
            pov_data: Dictionary containing PoV information (exit_code, exec_output, iteration, etc.)
            pov_path: Path to the original PoV file to be saved

        Returns:
            The path where the final PoV is saved
        """
        # Generate timestamp and filename for the final PoV
        timestamp = datetime.now().strftime("%y%m%d-%H%M")
        final_pov_filename = f"final-pov-{self.drill_agent.project_name}-{timestamp}-CTA-round{self.current_trigger_iteration}"
        final_pov_path = os.path.join(self.drill_agent.output_dir, final_pov_filename)

        # Create output directory if it doesn't exist
        os.makedirs(self.drill_agent.output_dir, exist_ok=True)

        # Copy the PoV file to the output directory
        shutil.copy(pov_path, final_pov_path)

        # Update the final_pov record with all necessary information
        self.final_pov = pov_data.copy()
        self.final_pov['saved_pov_path'] = final_pov_path

        self.logger.info(f"  [CrashTriggerAgent] Final PoV saved to: {final_pov_path}")

        return final_pov_path