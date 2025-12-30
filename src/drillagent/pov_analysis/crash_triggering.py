import os
import subprocess
import shutil
import re
import resource
from datetime import datetime

from typing import Tuple, Dict, Any, TYPE_CHECKING
if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent

from drillagent.prompts.CrashTriggerAgent_prompt import (
    CTA_system_prompt,
    CTA_final_pov_generation_prompt,
)

class CrashTriggerAgent:
    # Responsible for triggering crashes based on analyzed paths
    def __init__(self, drill_agent: 'DrillAgent'):
        self.drill_agent = drill_agent
        self.config = drill_agent.config
        self.logger = drill_agent.logger
        self.tools = []
        self.tools.extend(drill_agent.agent_tools)
        self.tools.extend(drill_agent.agent_cov_tools) # For crash triggering, we also provide coverage tools.

        # The outermost-loop counters.
        self.max_trigger_iterations = 8
        self.current_trigger_iteration = 0

        # Input files. (three files should be enough)
        self.useful_testcase_paths  = []  # List of file paths to useful test cases from path exploration.
        # Output files.
        self.history_pov_candidates = []  # List of file paths to all test cases generated during crash triggering.
        self.final_pov = None             # The final PoV that successfully triggers a crash.

    def run(self) -> None:
        self.logger.info("  [CrashTriggerAgent] Starting running. Checking previous path exploration results...")

        # Before all: Examine the progress from previous path exploration.
        path_agent = self.drill_agent.path_agent
        if path_agent is not None:
            # Check if we already have a crash input
            if path_agent.crash_input_pov is not None:
                is_validated = self._validate_pov(path_agent.crash_input_pov)
                if is_validated:
                    self.logger.info("  [CrashTriggerAgent] Valid crash input found from path exploration phase! Using it as final PoV.")
                    self.final_pov = path_agent.crash_input_pov
                    return
                else:
                    self.logger.info("  [CrashTriggerAgent] Crash input from path exploration did not validate successfully. Proceeding with crash triggering attempts...")
            else:
                self.logger.info("  [CrashTriggerAgent] Starting crash triggering attempts...")

            # Fill useful_testcase_paths with up to 3 testcases
            # First from vfunc_reached_testcases (reversed), then from history_testcases (reversed)
            if path_agent.vfunc_reached_testcases:
                self.useful_testcase_paths.extend(list(reversed(path_agent.vfunc_reached_testcases)))
            if len(self.useful_testcase_paths) < 3 and path_agent.history_testcases:
                remaining = 3 - len(self.useful_testcase_paths)
                self.useful_testcase_paths.extend(list(reversed(path_agent.history_testcases))[:remaining])
            # Ensure we have at most 3 testcases
            self.useful_testcase_paths = self.useful_testcase_paths[:3]
            assert len(self.useful_testcase_paths) > 0, "No useful test cases found from path exploration!"

        # Main loop for crash triggering attempts
        for iteration in range(1, self.max_trigger_iterations + 1):
            print("\n" + "=" * 80)
            self.logger.info(f"  [CrashTriggerAgent] Iteration {iteration}/{self.max_trigger_iterations}")
            self.current_trigger_iteration = iteration

            # Create round directory
            round_dir = self._get_round_dir(self.current_trigger_iteration)
            os.makedirs(round_dir, exist_ok=True)

            try:
                # Step 1: Generate final PoV
                pov_path = self._generate_final_pov()
                self.history_pov_candidates.append(pov_path)

                # Step 2: Execute PoV candidate
                exit_code, exec_output = self._execute_pov_candidate(pov_path)

                # Step 3: Validate PoV
                pov_data = {
                    'testcase_path': pov_path,
                    'exit_code': exit_code,
                    'exec_output': exec_output,
                    'iteration': iteration
                }
                is_valid = self._validate_pov(pov_data)

                # If valid PoV found, save it and stop
                if is_valid:
                    self.logger.info(f"  [CrashTriggerAgent] *** Valid PoV found at iteration {iteration}! ***")
                    # Save the final PoV to output directory
                    timestamp = datetime.now().strftime("%y%m%d-%H%M")
                    final_pov_filename = f"final-pov-{self.config.project_name}-{timestamp}"
                    final_pov_path = os.path.join(self.drill_agent.output_dir, final_pov_filename)
                    os.makedirs(self.drill_agent.output_dir, exist_ok=True)
                    shutil.copy(pov_path, final_pov_path)

                    self.final_pov = {
                        'pov_path': final_pov_path,
                        'exit_code': exit_code,
                        'exec_output': exec_output,
                        'iteration': iteration
                    }
                    self.logger.info(f"  [CrashTriggerAgent] Final PoV saved to: {final_pov_path}")
                    break
                else:
                    self.logger.info(f"  [CrashTriggerAgent] PoV at iteration {iteration} did not trigger crash, continuing...")

            except Exception as e:
                self.logger.error(f"  [CrashTriggerAgent] Error in iteration {iteration}: {e}", exc_info=True)
                continue

        # Summary
        if self.final_pov:
            self.logger.info(f"  [CrashTriggerAgent] Successfully generated valid PoV!")
        else:
            self.logger.info(f"  [CrashTriggerAgent] No valid PoV found after {self.max_trigger_iterations} iterations.")

    def _get_round_dir(self, round_num: int) -> str:
        # assert os.path.exists(self.drill_agent.work_dir), "DrillAgent work_dir does not exist!!!"
        return os.path.join(self.drill_agent.work_dir, f"triggering", f"round{round_num}")

    def _generate_final_pov(self) -> str:
        # Generate final PoV using LLM with vulnerability analysis and path exploration feedback
        # Returns path to the generated PoV file
        self.logger.info(f"  [CrashTriggerAgent] Generating final PoV using LLM...")
        max_generation_turns = 10  # Allow LLM multiple turns to generate PoV
        round_dir = self._get_round_dir(self.current_trigger_iteration)
        os.makedirs(round_dir, exist_ok=True)

        # Step 1: Gather all necessary information for PoV generation
        vuln_info_str = self.drill_agent.vulnerability_info.format_output(skip_rca_result=True)
        root_cause_str = self.drill_agent.vulnerability_info.get_full_root_cause()

        # Try to prepare and provide previously-generated useful test cases.
        if len(self.useful_testcase_paths) > 0:
            # Transform self.useful_testcase_paths into a string containing several test case paths.
            # Each testcase path and its corresponding coverage_record.md are included.
            tmp_paths = []
            for testcase_path in self.useful_testcase_paths:
                tmp_paths.append(testcase_path)
                dir_path = os.path.dirname(testcase_path)
                coverage_path = os.path.join(dir_path, "coverage_record.md")
                tmp_paths.append(coverage_path)
            path_exploration_progress = "\n".join(tmp_paths)
        else:
            path_exploration_progress = "No useful test cases available from path exploration. You have to generate PoV from current knowledge."

        # Step 2: Use LLMInterface to generate the final PoV
        # Format the prompt for PoV generation
        prompt = CTA_final_pov_generation_prompt.format(
            project_name=self.config.project_name,
            actual_repo_path=self.config.target_repo_path,
            vulnerability_info=vuln_info_str,   # Including vuln type, call trace, etc.
            root_cause_analysis=root_cause_str,
            path_exploration_progress=path_exploration_progress
        )

        self.logger.info("  [CrashTriggerAgent] Using LLMInterface to generate final PoV...")
        # TODO: The llvm-cov tool usage should be further taught out.
        result = self.drill_agent.basic_llm.run_agent_loop(
            task=prompt,
            tools=self.tools,  # Allow LLM to use tools for exploration
            system_prompt=CTA_system_prompt,
            max_iterations=max_generation_turns,
            temperature=0.7,  # Higher temperature for creative PoV generation
            max_tokens=8192,
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

        # Step 3: Extract PoV content from response
        pov_pattern = r'```pov\s*\n(.*?)\n```'
        match = re.search(pov_pattern, response, re.DOTALL)
        if not match:
            # Fallback: try to find any code block
            self.logger.warning("  [CrashTriggerAgent] No ```pov block found, trying generic code block...")
            fallback_pattern = r'```(?:\w+)?\s*\n(.*?)\n```'
            match = re.search(fallback_pattern, response, re.DOTALL)
        if not match:
            raise ValueError(f"No PoV code block found in LLM response after {result['iterations']} iterations")

        pov_content = match.group(1)
        self.logger.info(f"  [CrashTriggerAgent] PoV extracted successfully!")

        # Step 4: Save PoV to file
        pov_filename = f"pov-round{self.current_trigger_iteration}"
        pov_path = os.path.join(round_dir, pov_filename)
        with open(pov_path, 'w') as f:
            f.write(pov_content)

        self.logger.debug(f"  [CrashTriggerAgent] Saved PoV content ({len(pov_content)} bytes) to {pov_path}")
        self.logger.info(f"  [CrashTriggerAgent] Final PoV generated at: {pov_path}")
        return pov_path

    def _execute_pov_candidate(self, test_case_path: str) -> Tuple[int, str]: # No LLM needed
        # Execute a PoV candidate and return exit code and execution output
        # Similar to PathExplorationAgent._execute_test_case but without coverage collection
        self.logger.info(f"  [CrashTriggerAgent] Executing PoV candidate: {test_case_path}")
        round_dir = self._get_round_dir(self.current_trigger_iteration)

        # Prepare the command
        # repo_path = self.drill_agent.config.target_repo_path
        binary_path = self.drill_agent.vulnerability_info.binary_path
        harness_command = self.drill_agent.vulnerability_info.refined_harness_command
        if not binary_path:
            raise ValueError("Binary path not found in vulnerability_info")
        if not harness_command:
            raise ValueError("Refined harness command not found in vulnerability_info")

        # Transform general harness command to executable command
        abs_test_case_path = os.path.abspath(test_case_path)
        command = harness_command.replace('<path/to/testcase>', abs_test_case_path)

        # Execute the command (no coverage collection needed for PoV validation)
        self.logger.info(f"  [CrashTriggerAgent] Executing command: {command} in {round_dir}")
        # self.logger.info(f"  [CrashTriggerAgent] Memory limit set to 12GB for subprocess")
        def set_memory_limit():
            """Set memory limit to 12GB for the subprocess to prevent memory leaks"""
            max_memory_bytes = 12 * 1024 * 1024 * 1024  # 12GB in bytes
            # RLIMIT_AS limits the address space (total virtual memory)
            resource.setrlimit(resource.RLIMIT_AS, (max_memory_bytes, max_memory_bytes))

        try:
            # Use subprocess to execute the command, set timeout to avoid hang
            result = subprocess.run(
                command,
                shell=True,
                cwd=round_dir,
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

        self.logger.info(f"  [CrashTriggerAgent] Command exit code: {exit_code}")
        return exit_code, exec_output

    def _validate_pov(self, pov_data: Dict) -> bool:
        # Validate the generated PoV by checking if it triggers a crash (segmentation fault, memory errors, etc.)
        # pov_data: dict containing 'testcase_path', 'exit_code', 'exec_output', etc.
        # Returns: True if PoV is valid (triggers crash), False otherwise
        # TODO: This should be further thought out and improved (LHY).

        if not pov_data:
            self.logger.warning("  [CrashTriggerAgent] No PoV data provided for validation")
            return False

        # Extract information from pov_data
        exit_code = pov_data.get('exit_code', 0)
        exec_output = pov_data.get('exec_output', '')
        testcase_path = pov_data.get('testcase_path', '')

        self.logger.info(f"  [CrashTriggerAgent] Validating PoV: {testcase_path}")
        self.logger.info(f"  [CrashTriggerAgent] Exit code: {exit_code}")

        # Check for segmentation fault (SIGSEGV) - exit code 139 or -11
        if exit_code == 139 or exit_code == -11:
            self.logger.info(f"  [CrashTriggerAgent] *** PoV VALID: Segmentation fault detected (exit code {exit_code}) ***")
            return True

        # Check for SIGABRT (assertion failure, abort()) - exit code 134 or -6
        if exit_code == -6 or exit_code == 134:
            self.logger.info(f"  [CrashTriggerAgent] *** PoV VALID: Program aborted (exit code {exit_code}) ***")
            # Check if this is a memory sanitizer error in the output
            if any(keyword in exec_output for keyword in ['AddressSanitizer', 'MemorySanitizer', 'heap-use-after-free', 'heap-buffer-overflow', 'stack-buffer-overflow']):
                self.logger.info(f"  [CrashTriggerAgent] Memory sanitizer detected vulnerability!")
                return True
            return True  # Still consider SIGABRT as valid crash

        # Check for other crash-related signals
        if exit_code == -9 or exit_code == 137:  # SIGKILL
            self.logger.warning(f"  [CrashTriggerAgent] Program killed (exit code {exit_code})")
            return True  # Consider SIGKILL as valid crash

        # Check for sanitizer error messages in output even with non-crash exit codes
        sanitizer_keywords = [
            'AddressSanitizer', 'MemorySanitizer', 'UndefinedBehaviorSanitizer',
            'heap-use-after-free', 'heap-buffer-overflow', 'stack-buffer-overflow',
            'use-after-free', 'buffer-overflow', 'null-dereference', 'SEGV'
        ]
        if any(keyword in exec_output for keyword in sanitizer_keywords):
            self.logger.info(f"  [CrashTriggerAgent] *** PoV VALID: Memory error detected in output ***")
            return True

        # Check for general signal-based termination (exit code > 128 or < 0)
        if exit_code < 0 or exit_code > 128:
            self.logger.info(f"  [CrashTriggerAgent] PoV potentially valid: Signal-based termination (exit code {exit_code})")
            return True

        # No crash detected
        self.logger.info(f"  [CrashTriggerAgent] PoV invalid: No crash detected (exit code {exit_code})")
        return False


