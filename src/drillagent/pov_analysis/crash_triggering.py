import os
import re
import glob
import shutil
import signal
import subprocess
from datetime import datetime

from typing import Tuple, List, Dict, Any, TYPE_CHECKING
if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent
    from drillagent.tools.basic_tools import AgentTool

from drillagent.tools.basic_tools import WriteFileTool
from drillagent.prompts.CrashTriggerAgent_prompt import (
    CTA_system_prompt,
    CTA_useful_testcase_and_cov_template,
    CTA_previous_roundir_template,
    CTA_final_pov_generation_prompt,
)

from drillagent.utils.llvm_cov import LLVMCovUtils
from drillagent.utils.utils import *
from drillagent.models.llm_price_config import MODEL_PRICE_PER_MTOK_USD
from drillagent.models import BudgetExceededError, VulnTypeGuidanceSampler
class CrashTriggerAgent:
    # Responsible for triggering crashes based on analyzed paths
    def __init__(self, drill_agent: 'DrillAgent'):
        self.drill_agent = drill_agent
        self.config = drill_agent.config
        self.logger = drill_agent.logger

        self.tools_for_generation: List['AgentTool'] = self.drill_agent.basic_tools + self.drill_agent.ast_grep_tools + self.drill_agent.cov_tools

        # The outermost-loop counters.
        self.current_trigger_iteration = 0
        # Control test case generation turns.
        if self.config.model_provider.lower() == "claude":
            self.max_trigger_iterations = 8
            self.max_generation_turns   = 4 # Larger turns will cause input context explosion.
        else:
            self.max_trigger_iterations = 8
            self.max_generation_turns   = 6

        # Input files. (three files should be enough)
        self.useful_testcase_paths  = []  # List of file paths to useful test cases from path exploration.
        # Output files.
        ## Mapping from iteration number to a dict including: "testcase_path", "profdata_path".
        self.generated_candidates = {i: {} for i in range(1, self.max_trigger_iterations + 1)}  
        ## The final PoV that successfully triggers a crash.
        self.final_pov = None    ## final_pov['saved_pov_path']: The path where the final validated PoV is saved in output_dir.
        ## Similar to final_pov, but for variant crashes.
        self.variants_povs = [] 

        # Init the LLVM coverage util. Set the profdata_path later after each execution.
        binary_abs_path = os.path.abspath(os.path.join(
            self.drill_agent.config.target_repo_path,
            self.drill_agent.vulnerability_info.actual_binary_path # Must use actual binary here!
        ))
        self.llvm_cov_utils = LLVMCovUtils(binary_abs_path=binary_abs_path)

        # Init the vulnerability type guidance sampler for type-specific PoV generation hints.
        self.vuln_type_sampler = VulnTypeGuidanceSampler(
            llm_interface=self.drill_agent.low_cost_llm,
            logger=self.logger
        )

    def _accumulate_token_usage(self, result: Dict[str, Any], model_name: str) -> None:
        usage = result.get("usage_stats") if isinstance(result, dict) else None
        if not usage:
            return
        overall = getattr(self.drill_agent, "overall_token_usage", None)
        if not overall or "CTA" not in overall:
            return
        input_tokens = usage.get("input_tokens", usage.get("prompt_tokens", 0))
        output_tokens = usage.get("output_tokens", usage.get("completion_tokens", 0))
        overall["CTA"].add(input_tokens=input_tokens, output_tokens=output_tokens)
        price = MODEL_PRICE_PER_MTOK_USD.get(model_name)
        if price:
            cost_input = (input_tokens / 1_000_000) * price["input"]
            cost_output = (output_tokens / 1_000_000) * price["output"]
            overall["CTA"].add_cost(cost_input_usd=cost_input, cost_output_usd=cost_output)
        else:
            self.logger.warning(f"[CrashTriggerAgent] No price config for model: {model_name}")

    def run(self) -> None:
        self.logger.info(f"  [CrashTriggerAgent] Starting running. (tools num: {len(self.tools_for_generation)})")

        # Clear all the previous roundN directories if exist (using regex pattern matching)
        triggering_dir = os.path.join(self.drill_agent.work_dir, "triggering")
        round_dir_pattern = re.compile(r'^round\d+$')
        if os.path.exists(triggering_dir):
            for item in os.listdir(triggering_dir):
                if round_dir_pattern.match(item):
                    round_dir = os.path.join(triggering_dir, item)
                    if os.path.isdir(round_dir):
                        shutil.rmtree(round_dir)

        # Before all: Examine the progress from previous path exploration.
        path_agent = self.drill_agent.path_agent
        if path_agent is not None:
            # Check if we already have a crash input
            if path_agent.crash_input_pov is not None:
                self.logger.info("  [CrashTriggerAgent] Checking for previous crash input from path exploration phase...")
                cur_crash_type, is_valid = self.drill_agent.validate_pov(path_agent.crash_command)
                if is_valid:
                    PEA_pov_data = path_agent.crash_input_pov
                    PEA_pov_data['crash_type'] = cur_crash_type
                    crash_pov_path = path_agent.crash_input_pov.get('saved_pov_path')
                    if cur_crash_type == self.drill_agent.gt_crash_type:
                        # Save the crash input as final PoV
                        self.logger.info(f"  [CrashTriggerAgent] Valid crash input found from path exploration phase! Crash: {cur_crash_type}")
                        self._record_final_pov(PEA_pov_data, crash_pov_path)
                        return
                    else:
                        # Unexpected sanitizer crash is also valuable to us.
                        self.logger.info(f"  [CrashTriggerAgent] *** Variant PoV found from path exploration phase! Crash: {cur_crash_type} (expect {self.drill_agent.gt_crash_type}) ***")
                        self._record_variant_pov(PEA_pov_data, crash_pov_path)
                        self.logger.info("  [CrashTriggerAgent] Proceeding with crash triggering attempts to craft target-type PoV...")
                        # Heuristic: Since we have a variant PoV, we reduce the max_trigger_iterations to speed up.
                        self.max_trigger_iterations = max(1, self.max_trigger_iterations // 2)
                else:
                    self.logger.info("  [CrashTriggerAgent] Crash input from path exploration failed to pass validation. Proceeding with crash triggering attempts...")
            else:
                self.logger.info("  [CrashTriggerAgent] Starting crash triggering attempts...")

            # Fill useful_testcase_paths with up to 3 testcases (used for the first round generation)
            # First from vfunc_reached_testcases (reversed), then from history_testcases (reversed)
            if path_agent.vfunc_reached_testcases:
                self.useful_testcase_paths.extend(list(reversed(path_agent.vfunc_reached_testcases)))
            if len(self.useful_testcase_paths) < 3 and path_agent.history_testcases:
                remaining = 3 - len(self.useful_testcase_paths)
                self.useful_testcase_paths.extend(list(reversed(path_agent.history_testcases))[:remaining])
            # We only use 3 testcases at most.
            self.useful_testcase_paths = self.useful_testcase_paths[:3]
            # If no useful test cases found, raise error 🤔
            if len(self.useful_testcase_paths) == 0:
                raise RuntimeError("No useful test cases found from path exploration!")

        # Main loop for crash triggering attempts.
        for iteration in range(1, self.max_trigger_iterations + 1):
            self.logger.debug("\n" + "=" * 60)
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
            # self.logger.debug(f"  [CrashTriggerAgent] Created and cleared round directory: {round_dir}")

            # Clear previous coverage data to avoid memory leak (conservative operation)
            if self.llvm_cov_utils:
                self.llvm_cov_utils.clear_data()

            try:# Main operations!
                # Step 1: Generate final PoV.
                pov_path = self._generate_pov_candidate()
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
                # If valid PoV found, save it and stop
                cur_crash_type, is_valid = self.drill_agent.validate_pov(command)
                if is_valid:
                    pov_data = {
                        'testcase_path': abs_test_case_path,
                        'exit_code': exit_code,
                        'exec_output': exec_output,
                        'iteration': iteration,
                        'max_iterations': self.max_trigger_iterations,
                        'crash_type': cur_crash_type
                    }
                    if cur_crash_type == self.drill_agent.gt_crash_type:
                        # Save the qualified final PoV to output directory.
                        self.logger.info(f"  [CrashTriggerAgent] *** Valid PoV found at iteration {iteration}! Crash: {cur_crash_type} ***")
                        self._record_final_pov(pov_data, pov_path)
                        break
                    else:
                        # Unexpected sanitizer crash is also valuable to us.
                        self.logger.info(f"  [CrashTriggerAgent] *** Variant PoV found at iteration {iteration}! Crash: {cur_crash_type} (expect {self.drill_agent.gt_crash_type}) ***")
                        self._record_variant_pov(pov_data, pov_path)
                        continue  # Crash type mismatch, continue crafting qualified PoV
                else:
                    self.logger.info(f"  [CrashTriggerAgent] PoV at iteration {iteration} did not trigger crash, continuing...")

            except BudgetExceededError:
                # Budget exceeded - re-raise to terminate analysis
                raise
            except Exception as e:
                self.logger.error(f"  [CrashTriggerAgent] Error in iteration {iteration}: {e}", exc_info=True)
                self.logger.info(f"  [CrashTriggerAgent] Continuing to next iteration...")
                continue

        # Summary
        if self.final_pov:
            self.logger.info(f"  [CrashTriggerAgent] Successfully generated valid PoV!")
        else:
            self.logger.info(f"  [CrashTriggerAgent] No valid PoV found after {self.current_trigger_iteration} iterations.")

    def _get_round_dir(self, round_num: int) -> str: # usually relative path
        return os.path.join(self.drill_agent.work_dir, f"triggering", f"round{round_num}")

    def _generate_pov_candidate(self) -> str:
        # Generate final PoV using LLM with vulnerability analysis and path exploration feedback
        # Returns path to the generated PoV file
        self.logger.info(f"  [CrashTriggerAgent] Generating final PoV candidate...")
        round_dir = self._get_round_dir(self.current_trigger_iteration)
        os.makedirs(round_dir, exist_ok=True)

        # Substep 1: Gather all necessary information for PoV generation
        vuln_info_str = self.drill_agent.vulnerability_info.format_output(skip_rca_result=True)
        root_cause_str = self.drill_agent.vulnerability_info.get_full_root_cause()

        # Get vulnerability-type-specific guidance for PoV generation
        vuln_type_guidance = self.vuln_type_sampler.get_vuln_type_guidance(
            root_cause=root_cause_str,
            reported_vuln_type=self.drill_agent.gt_crash_type or self.drill_agent.vulnerability_info.vuln_type
        )

        # For history exec info, we provide path exploration progress to the first round and previous CTA-generated testcase for later rounds.
        if self.current_trigger_iteration == 1:
            # Try to prepare and provide PEA-generated useful test cases.
            if len(self.useful_testcase_paths) > 0:
                # Transform self.useful_testcase_paths into a string containing several test case paths.
                # Each testcase path and its corresponding coverage_record.md are included.
                tmp_paths = []
                for testcase_path in self.useful_testcase_paths:
                    tmp_paths.append(testcase_path)
                    # Currently: we don't add "test_N.profdata" into prompt. All cov data is already organized.
                    # dir_path = os.path.dirname(testcase_path)
                    # coverage_path = os.path.join(dir_path, "coverage_record.md")
                    # tmp_paths.append(coverage_path)
                    # tmp_paths.append("")
                # Format the useful test cases and coverage info into previous_progress.
                previous_progress = CTA_useful_testcase_and_cov_template.format(
                    testcase_file_paths="\n".join(tmp_paths)
                )
            else:
                previous_progress = "No useful test cases available from path exploration. You have to generate PoV from current knowledge."
        else:
            # Provide previous round directory to guide LLM
            previous_round_dir = self._get_round_dir(self.current_trigger_iteration - 1)
            if os.path.exists(previous_round_dir):
                # Get coverage-instrumented binary path
                vuln_info = self.drill_agent.vulnerability_info
                bin_rel_path = vuln_info.actual_binary_path or vuln_info.binary_path
                cov_binary_path = os.path.join(self.config.target_repo_path, bin_rel_path)
                previous_progress = CTA_previous_roundir_template.format(
                    previous_iteration=self.current_trigger_iteration - 1,
                    previous_round_dir=previous_round_dir,
                    cov_binary_path=cov_binary_path
                )
            else:
                previous_progress = "Previous round directory not found. Generate PoV based on current knowledge."

        # Prepare the target PoV file path
        # Add file suffix if available from vulnerability info
        file_suffix = getattr(self.drill_agent.vulnerability_info, 'input_file_suffix', '') or ''
        pov_filename = f"testcase-round{self.current_trigger_iteration}{file_suffix}"
        pov_path = os.path.join(round_dir, pov_filename)
        abs_pov_path = os.path.abspath(pov_path)
        if file_suffix:
            self.logger.debug(f"  [CrashTriggerAgent] Using file suffix from vulnerability info: {file_suffix}")

        # Substep 2: Use LLMInterface to generate the final PoV
        # Format the user prompt for PoV generation
        user_prompt = CTA_final_pov_generation_prompt.format(
            current_iteration=self.current_trigger_iteration,
            max_iterations=self.max_trigger_iterations,
            project_name=self.config.project_name,
            actual_repo_path=self.config.target_repo_path,
            current_round_dir=round_dir,
            target_pov_path=abs_pov_path,  # Target file path for LLM to write into.
            # Designed context sections
            vulnerability_info=vuln_info_str,   # Including vuln type, call trace, etc.
            root_cause_analysis=root_cause_str, # Markdown format content
            vuln_type_guidance=vuln_type_guidance, # Type-specific PoV generation guidance
            previous_pov_gen_progress=previous_progress
        )

        # For crash triggering, we also provide ast-grep and coverage tools.
        self.logger.info(f"  [CrashTriggerAgent] Using LLMInterface to generate final PoV candidate (max rounds={self.max_generation_turns})...")

        # Update WriteFileTool's basic_dir to current round_dir before running agent loop
        for tool in self.tools_for_generation:
            if isinstance(tool, WriteFileTool):
                tool.update_basic_dir(round_dir)
                self.logger.debug(f"  [CrashTriggerAgent] Updated WriteFileTool basic_dir to: {round_dir}")
                break

        try:
            result = self.drill_agent.basic_llm.run_agent_loop(
                task=user_prompt,
                tools=self.tools_for_generation,  # Allow LLM to use tools for exploration, including write_file
                system_prompt=CTA_system_prompt,
                max_iterations=self.max_generation_turns,
                temperature=0.7,  # Higher temperature for creative PoV generation
                # max_tokens=30720,
                continuation_prompt="Please continue your analysis and craft the final PoV candidate after you get enough information. " + \
                  "If you already generated the file, call `finish` tool to end the process."
            )
            self._accumulate_token_usage(result, self.drill_agent.basic_llm.model_name)

            # Check for budget exceeded - raise exception to terminate analysis
            if result.get('stop_reason') == 'budget_exceeded':
                current_cost = self.drill_agent.get_current_total_cost()
                max_budget = self.drill_agent.config.max_budget_usd
                raise BudgetExceededError(
                    f"Budget exceeded in CrashTriggerAgent: ${current_cost:.4f} >= ${max_budget:.2f}"
                )

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.warning(f"  [CrashTriggerAgent] LLM agent loop did not complete: {error_msg}")
                # Don't raise error here - continue to Substep 3 to check if the file was still generated

            self.logger.info(f"  [CrashTriggerAgent] LLM completed in {result.get('iterations', 'N/A')} iteration(s)")
            self.logger.info(f"  [CrashTriggerAgent] Stop reason: {result.get('stop_reason', 'N/A')}")
            # response = result.get('final_response', '')
            # if response:
            #     self.logger.debug(f"  [CrashTriggerAgent] LLM Response: {response[:500]}...")
            # Show the current round directory contents.
            _, output = list_directory(round_dir)
            self.logger.debug(f"  [CrashTriggerAgent] ls -lh {round_dir}:\n{output}")
        except Exception as e:
            self.logger.warning(f"  [CrashTriggerAgent] Exception during LLM agent loop: {e}")
            # Don't raise error here - continue to Substep 3 to check if the file was still generated

        # Substep 3: Verify that the PoV file was written and is non-empty
        # Check if the exact path exists first
        if not os.path.exists(pov_path):
            # If not found, search for files matching the pattern (with potential extensions)
            self.logger.debug(f"  [CrashTriggerAgent] Exact path {pov_path} not found, searching for pattern...")
            search_pattern = f"{pov_path}*"
            matching_files = glob.glob(search_pattern)
            if not matching_files:
                raise RuntimeError(
                    f"PoV candidate file was not created (should continue). \nExpected: {pov_path} or {pov_path}.* "
                    f"LLM may have failed to use write_file tool."
                )
            # Prioritize files with the expected suffix if available
            if len(matching_files) > 1 and file_suffix:
                suffix_matches = [f for f in matching_files if f.endswith(file_suffix)]
                if suffix_matches:
                    matching_files = suffix_matches
                else: # Not find perfect match, just use original matching files
                    pass
            pov_path = matching_files[0]
            self.logger.info(f"  [CrashTriggerAgent] Found PoV candidate with extension: {pov_path}")

        file_size = os.path.getsize(pov_path)
        if file_size == 0:
            raise RuntimeError(f"PoV candidate file is empty at {pov_path}. LLM may have failed to write content.")

        self.logger.info(f"  [CrashTriggerAgent] PoV candidate successfully written to: {pov_path}")
        self.logger.debug(f"  [CrashTriggerAgent] PoV candidate file size: {file_size} bytes")
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
        # Use process group to ensure all child processes can be properly killed on timeout
        self.logger.info(f"  [CrashTriggerAgent] Executing command: {command}")
        process = None
        try:
            # Use Popen with start_new_session to create a new process group
            # This ensures we can kill all child processes on timeout
            process = subprocess.Popen(
                command,
                shell=True,
                cwd=round_dir,
                env=env,  # Specify environment with LLVM_PROFILE_FILE
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,      # Create new process group to avoid orphan processes
                preexec_fn=set_memory_limit  # Apply memory limit to subprocess
            )
            stdout, stderr = process.communicate(timeout=30)
            exit_code = process.returncode
            # Merge stdout and stderr as exec_output
            exec_output = f"[STDOUT]\n{stdout}\n[STDERR]\n{stderr}"
            # Show the current round directory contents.
            _, output = list_directory(round_dir)
            self.logger.debug(f"  [CrashTriggerAgent] ls -lh {round_dir}:\n{output}")
        except subprocess.TimeoutExpired:
            self.logger.warning(f"  [CrashTriggerAgent] Command execution timeout after 30s, killing process group...")
            exit_code = -1
            partial_stdout, partial_stderr = "", ""
            if process is not None:
                # Kill the entire process group first to release pipe write ends
                try:
                    pgid = os.getpgid(process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                    try:
                        process.wait(timeout=2)  # Give it 2 seconds to terminate gracefully
                    except subprocess.TimeoutExpired:
                        os.killpg(pgid, signal.SIGKILL)  # Force kill if still alive
                        process.wait()
                except (ProcessLookupError, OSError):
                    pass  # Process already terminated
                # Now read any remaining output from pipes (safe after process termination)
                try:
                    if process.stdout:
                        partial_stdout = process.stdout.read() or ""
                    if process.stderr:
                        partial_stderr = process.stderr.read() or ""
                except Exception:
                    pass  # Ignore read errors
            exec_output = f"[TIMEOUT] Command execution exceeded 30 seconds\n[STDOUT]\n{partial_stdout}\n[STDERR]\n{partial_stderr}"
        except Exception as e:
            self.logger.error(f"  [CrashTriggerAgent] Command execution failed: {e}")
            exit_code = -1
            exec_output = f"[ERROR] Command execution failed: {str(e)}"
            # Ensure process is cleaned up on any exception
            if process is not None and process.poll() is None:
                try:
                    pgid = os.getpgid(process.pid)
                    os.killpg(pgid, signal.SIGKILL)
                    process.wait()
                except (ProcessLookupError, OSError):
                    pass
        finally:
            # Explicitly close pipes to prevent resource leaks
            if process is not None:
                if process.stdout:
                    process.stdout.close()
                if process.stderr:
                    process.stderr.close()

        # After execution finished, convert the profraw to profdata, and update the file path.
        if os.path.exists(profraw_path):
            self.llvm_cov_utils.update_profile_data(profraw_path)
            self.generated_candidates[self.current_trigger_iteration]["profdata_path"] = self.llvm_cov_utils.profdata_path
        else:
            self.logger.error(f"  [CrashTriggerAgent] Expected profraw file not found: {profraw_path}")

        self.logger.info (f"  [CrashTriggerAgent] Command exit code: {exit_code}")
        self.logger.debug(f"  [CrashTriggerAgent] Command execution output:\n{exec_output}")
        return exit_code, exec_output

    def _record_final_pov(self, pov_data: Dict[str, Any], pov_path: str) -> str:
        """
        Record and save the final validated PoV to the output directory.

        Args:
            pov_data: Dictionary containing PoV information (exit_code, exec_output, iteration, etc.)
            pov_path: Path to the original PoV file to be saved

        Returns:
            The path where the final PoV is saved
        """
        if pov_path is None:
            raise ValueError(f"Crash input PoV path ({pov_path}) not found!")
        # Generate timestamp and filename for the final PoV
        timestamp = datetime.now().strftime("%y%m%d-%H%M")
        final_pov_filename = f"final-pov-{self.drill_agent.project_name}-{timestamp}-CTA-round{self.current_trigger_iteration}"
        final_pov_path = os.path.join(self.drill_agent.output_dir, final_pov_filename)

        # Copy the PoV file to the output directory
        os.makedirs(self.drill_agent.output_dir, exist_ok=True)
        shutil.copy(pov_path, final_pov_path)

        # Update the final_pov record with all necessary information
        self.final_pov = pov_data.copy()
        self.final_pov['saved_pov_path'] = final_pov_path

        self.logger.info(f"  [CrashTriggerAgent] Final PoV saved to: {final_pov_path}")
        return final_pov_path

    def _record_variant_pov(self, pov_data: Dict[str, Any], pov_path: str) -> str:
        """
        Record and save the PoV with unexpected sanitizer crash to the output directory.
        """
        if pov_path is None:
            raise ValueError(f"Crash input PoV path ({pov_path}) not found!")
        # Generate timestamp and filename for the final PoV
        timestamp = datetime.now().strftime("%y%m%d-%H%M")
        cur_pov_filename = f"variant-pov-{self.drill_agent.project_name}-{timestamp}-CTA-round{self.current_trigger_iteration}"
        cur_pov_path = os.path.join(self.drill_agent.output_dir, cur_pov_filename)

        # Copy the PoV file to the output directory
        os.makedirs(self.drill_agent.output_dir, exist_ok=True)
        shutil.copy(pov_path, cur_pov_path)

        # Update the final_pov record with all necessary information
        tmp_pov_data = pov_data.copy()
        tmp_pov_data['saved_pov_path'] = cur_pov_path
        self.variants_povs.append(tmp_pov_data)

        self.logger.info(f"  [CrashTriggerAgent] Variant PoV saved to: {cur_pov_path}")
        return cur_pov_path
