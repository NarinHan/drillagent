import os
import json
import shutil
import logging
from typing import Dict, Any, List, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field
from drillagent.utils.utils import *
from drillagent.prompts.VulnAnalysisAgent_prompt import (
    VAA_system_prompt,
    VAA_sanitizer_extraction_prompt,
    VAA_call_trace_transform_prompt,
    VAA_call_trace_linenum_refine_prompt,
    VAA_harness_refine_prompt,
    VAA_root_cause_analysis_prompt,
    VAA_find_actual_binary_prompt
)
from drillagent.models.llm_interface import LLMInterface
from drillagent.models.llm_price_config import MODEL_PRICE_PER_MTOK_USD

if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent
    from drillagent.config import AgentConfig
    from drillagent.tools.basic_tools import AgentTool

class VulnAnalysisAgent:
    # Analyzes vulnerabilities using LLM with code exploration tools

    def __init__(self, drill_agent: 'DrillAgent'):
        self.drill_agent: 'DrillAgent' = drill_agent
        self.config: 'AgentConfig' = drill_agent.config
        self.logger: logging.Logger = drill_agent.logger
        self.basic_tools: List['AgentTool']    = drill_agent.basic_tools
        self.enhanced_tools: List['AgentTool'] = drill_agent.basic_tools + drill_agent.ast_grep_tools
        # Sometimes ast-grep may not be usable, so we keep both basic and enhanced toolsets.

        # Max run_agent_loop rounds for root cause analysis
        if self.config.model_provider.lower() == "claude":
            # Really should control budget here, since sonnet is too expensive.
            self.max_rca_turns: int = 8
            # self.normal_task_llm = self.drill_agent.low_cost_llm # Maybe use low-cost LLM for more sub-tasks.
        else:
            self.max_rca_turns: int = 15
            # self.normal_task_llm = self.drill_agent.basic_llm

        # Vulnerability information container!!!!!
        self.vuln_info = VulnInfo() # This will be returned to the caller class (DrillAgent).
        self.loaded_from_cache = False  # Flag to indicate if results were loaded from cache

    def _accumulate_token_usage(self, result: Dict[str, Any], model_name: str) -> None:
        usage = result.get("usage_stats") if isinstance(result, dict) else None
        if not usage:
            return
        overall = getattr(self.drill_agent, "overall_token_usage", None)
        if not overall or "VAA" not in overall:
            return
        input_tokens = usage.get("input_tokens", usage.get("prompt_tokens", 0))
        output_tokens = usage.get("output_tokens", usage.get("completion_tokens", 0))
        overall["VAA"].add(input_tokens=input_tokens, output_tokens=output_tokens)
        price = MODEL_PRICE_PER_MTOK_USD.get(model_name)
        if price:
            cost_input = (input_tokens / 1_000_000) * price["input"]
            cost_output = (output_tokens / 1_000_000) * price["output"]
            overall["VAA"].add_cost(cost_input_usd=cost_input, cost_output_usd=cost_output)
        else:
            self.logger.warning(f"[VulnAnalysisAgent] No price config for model: {model_name}")

    def load_from_cache(self) -> bool:
        # Load vulnerability analysis results from cache if available.
        # True if cache was successfully loaded, False otherwise
        try:
            project_name = self.config.project_name
            cve_id       = self.config.cve_id
            base_commit  = self.config.base_commit
            if cve_id:
                identifier = f"{project_name}_{cve_id}"
            else:
                identifier = f"{project_name}_{base_commit}"
            # Construct cache file path using identifier
            cache_filepath = os.path.join(self.drill_agent.cache_dir, f"vuln_info_{identifier}.json")

            # Check if cache file exists
            if not os.path.exists(cache_filepath):
                self.logger.info(f"  [VulnAnalysisAgent] No cache file found at: {cache_filepath}")
                return False
            # Check if file has content
            if os.path.getsize(cache_filepath) == 0:
                self.logger.warning(f"  [VulnAnalysisAgent] Cache file is empty: {cache_filepath}")
                return False

            # Read and parse cache file
            # Note that root cause analysis results are also in the json, so no need to read "root_cause_xx.md".
            with open(cache_filepath, 'r', encoding='utf-8') as f:
                vuln_data = json.load(f)

            # Validate that we have data
            if not vuln_data:
                self.logger.warning(f"  [VulnAnalysisAgent] Cache file contains no data: {cache_filepath}")
                return False

            # Load data into vuln_info using from_dict
            self.vuln_info = VulnInfo.from_dict(vuln_data)
            self.logger.info(f"  [VulnAnalysisAgent] Loaded successfully cache from: {cache_filepath}")
            return True

        except json.JSONDecodeError as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to parse cache file: {e}", exc_info=True)
            return False
        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to load cache: {e}", exc_info=True)
            return False

    def store_to_cache(self):
        # Store vulnerability analysis results to cache directory as JSON file for future use.
        try:
            # Ensure cache directory exists
            os.makedirs(self.drill_agent.cache_dir, exist_ok=True)

            project_name = self.config.project_name
            cve_id       = self.config.cve_id
            base_commit  = self.config.base_commit
            if cve_id:
                identifier = f"{project_name}_{cve_id}"
            else:
                identifier = f"{project_name}_{base_commit}"

            # Write to cache file with pretty formatting
            cache_filepath = os.path.join(self.drill_agent.cache_dir, f"vuln_info_{identifier}.json")
            vuln_data = self.vuln_info.to_dict()
            with open(cache_filepath, 'w', encoding='utf-8') as f:
                json.dump(vuln_data, f, indent=2, ensure_ascii=False)

            # Also write root cause analysis results to a file separately for easy access.
            root_cause_filepath = os.path.join(self.drill_agent.cache_dir, f"root_cause_{identifier}.md")
            with open(root_cause_filepath, 'w', encoding='utf-8') as f:
                f.write(self.vuln_info.root_cause)

            # Also write critical steps to a separate JSON file for easy access.
            if self.vuln_info.critical_steps:
                critical_steps_filepath = os.path.join(self.drill_agent.cache_dir, f"critical_steps_{identifier}.json")
                with open(critical_steps_filepath, 'w', encoding='utf-8') as f:
                    json.dump(self.vuln_info.critical_steps, f, indent=2, ensure_ascii=False)
                self.logger.info(f"  [VulnAnalysisAgent] Critical steps cached to: {critical_steps_filepath}")

            self.logger.info(f"  [VulnAnalysisAgent] Vulnerability analysis cached to: {cache_filepath}")

        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to store cache: {e}", exc_info=True)

    def clear_cache(self):
        # Clear the entire cache directory and its contents.
        # Called when force_clear_cache is True.
        try:
            tmp_dir = self.drill_agent.cache_dir
            if os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir)
                self.logger.info(f"  [VulnAnalysisAgent] Cleared cache directory: {tmp_dir}")
            else:
                self.logger.info(f"  [VulnAnalysisAgent] Cache directory does not exist: {tmp_dir}")
        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to clear cache: {e}", exc_info=True)

    def run(self) -> 'VulnInfo':
        # Run vulnerability analysis with a VulnInfo object returned.
        self.logger.info("  [VulnAnalysisAgent] Starting vulnerability analysis...")

        # The analysis is based on the following basic information.
        project_name     = self.config.project_name
        actual_repo_path = self.config.target_repo_path
        sanitizer_report = self.config.sanitizer_report
        # raw_vuln_location    = self.config.vuln_location    # won't use
        raw_harness_command  = self.config.harness_command
        self.logger.info(f"  [VulnAnalysisAgent] Actual repo path: {actual_repo_path}")

        # Handle force_clear_cache: delete cache files if requested (then analyze from scratch).
        if self.config.force_clear_cache:
            self.clear_cache()
        # Try to examine if there is already a cached result and load from cache first.
        elif self.load_from_cache():
                self.loaded_from_cache = True
                self.logger.info("  [VulnAnalysisAgent] Loaded vulnerability analysis from cache. Skipping analysis steps.")
                return self.vuln_info
        
        # Substep1: Extract basic vulnerability information (if sanitizer report is available)
        if len(sanitizer_report) > 0:
            self.logger.info(f"  [VulnAnalysisAgent] Extracting basic vulnerability information from report...")
            self.logger.info(f"  [VulnAnalysisAgent] Sanitizer report: {len(sanitizer_report)} chars.")
            # Extracted vuln data will be stored into self.vuln_info
            self._extract_sanitizer_report(project_name, actual_repo_path, sanitizer_report)

            # Transform raw crash trace to structured format for PathExplorationAgent
            if len(self.vuln_info.raw_crash_trace) > 0:
                self.vuln_info.crash_trace = self._transform_raw_call_trace(self.vuln_info.raw_crash_trace, trace_type="crash")

            # Transform allocation_trace if present (optional)
            raw_alloc_trace = self.vuln_info.allocation_trace[0]
            if raw_alloc_trace and len(raw_alloc_trace) > 0:
                self.logger.info(f"  [VulnAnalysisAgent] Transforming allocation trace...")
                structured_alloc_trace = self._transform_raw_call_trace(raw_alloc_trace, trace_type="allocation")
                self.vuln_info.allocation_trace = (raw_alloc_trace, structured_alloc_trace)

            # Transform free_trace if present (optional)
            raw_free_trace = self.vuln_info.free_trace[0]
            if raw_free_trace and len(raw_free_trace) > 0:
                self.logger.info(f"  [VulnAnalysisAgent] Transforming free trace...")
                structured_free_trace = self._transform_raw_call_trace(raw_free_trace, trace_type="free")
                self.vuln_info.free_trace = (raw_free_trace, structured_free_trace)

            self.logger.info(f"  [VulnAnalysisAgent] Extraction of sanitizer report complete!")
        
        # Substep2: Refine harness command (now this is a static refinement, not dependent on the completed compilation)
        if raw_harness_command and len(raw_harness_command) > 0:
            self.logger.info(f"  [VulnAnalysisAgent] Refining harness command...")
            self.logger.info(f"  [VulnAnalysisAgent] Raw harness command: {raw_harness_command}")
            self._refine_harness_command(project_name, actual_repo_path, raw_harness_command)
            
            self.logger.info(f"  [VulnAnalysisAgent] Refining harness command complete!")

        # Substep3: Perform root cause analysis
        if not self.config.disable_root_cause_analysis:
            self.logger.info("  [VulnAnalysisAgent] Performing root cause analysis...")
            self._root_cause_analysis()
        else:
            self.logger.info("  [VulnAnalysisAgent] Root cause analysis is disabled by configuration. Skipping!")

        # Store results to cache for future use
        self.store_to_cache()

        return self.vuln_info

    def _extract_sanitizer_report(self, project_name, actual_repo_path, sanitizer_report) -> None:
        # Extract vulnerability information from sanitizer report using LLM with tools
        # LLM: Using new LLMInterface with automatic agent loop
        try:
            # Use LLMInterface for automatic tool calling and conversation management
            self.logger.info("  [VulnAnalysisAgent] Using LLMInterface to extract sanitizer report...")

            result = self.drill_agent.basic_llm.run_agent_loop(
                task=VAA_sanitizer_extraction_prompt.format(
                    project_name=project_name,
                    actual_repo_path=actual_repo_path,
                    sanitizer_report=sanitizer_report
                ),
                tools=self.basic_tools,
                system_prompt=VAA_system_prompt,
                max_iterations=5,  # Allow up to 5 rounds of tool usage
                temperature=0.1,  # Low temperature for precise extraction
                max_tokens=8192,
                continuation_prompt="Please continue extracting the vulnerability information and provide the final JSON output."
            )
            self._accumulate_token_usage(result, self.drill_agent.basic_llm.model_name)

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.error(f"  [VulnAnalysisAgent] LLM agent loop failed: {error_msg}")
                raise RuntimeError(f"Failed to extract sanitizer report: {error_msg}")

            response = result['final_response']
            self.logger.info(f"  [VulnAnalysisAgent] LLM completed in {result['iterations']} iteration(s)")
            self.logger.info(f"  [VulnAnalysisAgent] Stop reason: {result['stop_reason']}")
            self.logger.info(f"  [VulnAnalysisAgent] LLM Response size: {len(response)} chars")
            # self.logger.debug(f"\n{response}") # for tmp debug

            # Extract JSON from response
            extracted_info = LLMInterface.extract_json_from_response(response)
            if not extracted_info:
                raise ValueError("Could not extract JSON from LLM response")

            # Store extracted information
            self.vuln_info.vuln_type = extracted_info.get('vuln_type', '')
            self.vuln_info.crash_function = extracted_info.get('crash_function', '')
            self.vuln_info.crash_location = extracted_info.get('crash_location', '')
            self.vuln_info.entry_function = extracted_info.get('entry_function', '')
            self.vuln_info.entry_location = extracted_info.get('entry_location', '')
            # Handle crash_trace (new field name) with fallback to call_trace (old field name)
            self.vuln_info.raw_crash_trace = extracted_info.get('crash_trace', '') or extracted_info.get('call_trace', '')
            # Store raw allocation_trace and free_trace (structured versions will be filled later)
            raw_allocation_trace = extracted_info.get('allocation_trace', '')
            raw_free_trace       = extracted_info.get('free_trace', '')
            self.vuln_info.allocation_trace = (raw_allocation_trace, [])
            self.vuln_info.free_trace = (raw_free_trace, [])

            self.logger.info(f"    ✓ Extracted vulnerability information:")
            self.logger.info(f"      Type: {self.vuln_info.vuln_type}")
            self.logger.info(f"      Crash: {self.vuln_info.crash_function} @ {self.vuln_info.crash_location}")
            self.logger.info(f"      Entry: {self.vuln_info.entry_function} @ {self.vuln_info.entry_location}")
            if raw_allocation_trace:
                self.logger.info(f"      Allocation trace: {len(raw_allocation_trace)} chars")
            if raw_free_trace:
                self.logger.info(f"      Free trace: {len(raw_free_trace)} chars")

        except Exception as e:
            self.logger.error(f"    Failed to extract sanitizer report: {e}", exc_info=True)
            # Return empty values on failure

    def _transform_raw_call_trace(self, raw_call_trace: str, trace_type: str = "crash") -> List[Dict[str, Any]]:
        # Transform raw call trace string to structured format using LLM. Also check and adjust the line numbers if needed.
        # Args:
        #   raw_call_trace: The raw call trace string from sanitizer report
        #   trace_type: Type of trace - "crash" (main error trace), "allocation", or "free"
        #               For "allocation" and "free", line number refinement and trimming are skipped.
        # Returns: List of structured call trace entries with validated file paths, from entry_function to crash_function.

        try:
            repo_path = self.config.target_repo_path
            entry_function, crash_function = self.vuln_info.entry_function, self.vuln_info.crash_function
            is_crash_trace = (trace_type == "crash")

            # Substep 1: Transform raw call trace to structured format
            self.logger.info(f"  [VulnAnalysisAgent] Using LLMInterface to transform {trace_type} backtrace...")
            result = self.drill_agent.basic_llm.run_agent_loop(
                task=VAA_call_trace_transform_prompt.format(
                    project_name=self.config.project_name,
                    actual_repo_path=repo_path,
                    raw_call_trace=raw_call_trace
                ),
                tools=self.basic_tools,  # Provide tools to locate files if needed
                system_prompt=VAA_system_prompt,
                max_iterations=5,  # Allow a few iterations for file location
                temperature=0.1,
                max_tokens=4096,
                continuation_prompt="Please continue transforming the call trace and provide the final JSON output."
            )
            self._accumulate_token_usage(result, self.drill_agent.basic_llm.model_name)

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.error(f"  [VulnAnalysisAgent] LLM agent loop failed: {error_msg}")
                raise RuntimeError(f"Failed to transform call trace: {error_msg}")

            response = result['final_response']
            self.logger.info(f"  [VulnAnalysisAgent] LLM completed in {result['iterations']} iteration(s)")
            self.logger.info(f"  [VulnAnalysisAgent] Stop reason: {result['stop_reason']}")
            # self.logger.info(f"  [VulnAnalysisAgent] LLM Response: {response[:300]}...")

            parsed_data = LLMInterface.extract_json_from_response(response)
            if not parsed_data or 'call_trace' not in parsed_data:
                raise ValueError("Could not extract call trace from LLM response")
            parsed_trace = parsed_data['call_trace']

            # Substep 2: Validate file paths and filter out invalid/external frames (from `parsed_trace`)
            validated_trace = []
            for entry in parsed_trace:
                if entry.get('is_external', False):
                    self.logger.debug(f"    ~ Skipping external frame #{entry.get('sequence_num')}: {entry.get('function_name')} @ {entry.get('file_path')}")
                    continue

                if not entry.get('file_path'):
                    self.logger.warning(f"    ✗ Missing file path for frame #{entry.get('sequence_num')}, skipping")
                    continue

                file_path = entry['file_path']
                # Convert to relative path if absolute
                if os.path.isabs(file_path) and repo_path in file_path:
                    file_path = os.path.relpath(file_path, repo_path)

                abs_path = file_path if os.path.isabs(file_path) else os.path.join(repo_path, file_path)
                if os.path.exists(abs_path):
                    entry['file_path'] = file_path
                    validated_trace.append(entry)
                else:
                    self.logger.warning(f"    ✗ File not found for frame #{entry.get('sequence_num')}: {abs_path}")
            self.logger.info(f"Validated file paths in call trace: {len(validated_trace)} valid frames (from {len(parsed_trace)} total)")

            # Print trace before line number adjustment (for debug)
            validated_tmp_trace = '\n'.join(f"#{e.get('sequence_num', 'N/A')}: {e.get('function_name', 'N/A')} @ {e.get('file_path', 'N/A')}:{e.get('line_number', 'N/A')}" for e in validated_trace)
            self.logger.debug(f"{trace_type.capitalize()} trace before line number adjustment:\n{validated_tmp_trace}")

            # Substep 3: Refine line numbers using LLM with tools (from `validated_trace`) (frame-by-frame approach)
            # TODO: Only perform line number refinement for crash trace (maybe with a cache method, it is faster to do this)
            if is_crash_trace:
                self.logger.info("  [VulnAnalysisAgent] Refining call trace line numbers frame by frame...")
                try:
                    # Process frames from outermost (entry_function) to innermost (crash_function)
                    # Sort by sequence_num in descending order
                    sorted_trace = sorted(validated_trace, key=lambda x: x.get('sequence_num', 0), reverse=True)

                    refined_frames = []
                    total_frames = len(sorted_trace)
                    for idx, current_frame in enumerate(sorted_trace):
                        seq_num = current_frame.get('sequence_num', 'N/A')
                        func_name = current_frame.get('function_name', 'N/A')

                        # Skip the innermost frame (#0) - it's the crash point, no callee to verify
                        if idx == total_frames - 1:
                            self.logger.info(f"  Processing frame #{seq_num} {func_name}: Innermost frame, keeping original line number")
                            refined_frames.append(current_frame)
                            continue

                        # Get callee frame (next frame in the sorted list, which has smaller sequence_num)
                        callee_frame = sorted_trace[idx + 1]
                        callee_func_name = callee_frame.get('function_name', '')
                        self.logger.info(f"  Processing frame #{seq_num} {func_name} -> callee: {callee_func_name}")
                        current_frame_json = json.dumps(current_frame, indent=2)

                        # Invoke low-cost LLM (faster) to refine the line number of each stack frame
                        self.logger.info(f"  [VulnAnalysisAgent] Using LLMInterface to refine line number of stack frame #{seq_num}...")
                        result = self.drill_agent.low_cost_llm.run_agent_loop(
                            task=VAA_call_trace_linenum_refine_prompt.format(
                                project_name=self.config.project_name,
                                actual_repo_path=repo_path,
                                current_frame_json=current_frame_json,
                                callee_function_name=callee_func_name
                            ),
                            tools=self.enhanced_tools, # Allow the usage of ast-grep
                            system_prompt=VAA_system_prompt,
                            max_iterations=4,
                            temperature=0.1,
                            max_tokens=4096,
                            continuation_prompt="Please continue verifying the line number using the tools and provide the final JSON output."
                        )
                        self._accumulate_token_usage(result, self.drill_agent.low_cost_llm.model_name)

                        if result['success']:
                            refined_frame = LLMInterface.extract_json_from_response(result['final_response'])
                            if refined_frame and 'line_number' in refined_frame and refined_frame.get('line_number', 0) > 0:
                                old_linenum = current_frame['line_number']
                                # Merge refined data back to current frame
                                current_frame.update(refined_frame)
                                new_linenum = current_frame['line_number']
                                original = current_frame.get('is_original_linenum', True)
                                verified = current_frame.get('is_verified', False)
                                self.logger.info(f"        ✓ Frame #{seq_num}: Linenum refined from {old_linenum} to {new_linenum} (original: {original}, verified: {verified})")
                            else:
                                self.logger.warning(f"        ✗ Frame #{seq_num}: Could not extract valid line number, keeping original")
                        else:
                            self.logger.warning(f"        ✗ Frame #{seq_num}: Refinement failed, keeping original")

                        refined_frames.append(current_frame)

                    # Sort refined frames back to original order (by sequence_num ascending)
                    validated_trace = sorted(refined_frames, key=lambda x: x.get('sequence_num', 0))
                    self.logger.info(f"    ✓ Line numbers refined for {len(refined_frames)} frames")
                except Exception as e:
                    self.logger.error(f"  [VulnAnalysisAgent] Failed to refine line numbers: {e}", exc_info=True)
                    self.logger.warning(f"  [VulnAnalysisAgent] Using original line numbers")

                # Log trace after line number adjustment (for debug)
                trace_lines = ["Crash trace after line number adjustment:"]
                for entry in validated_trace:
                    trace_lines.append(f"#{entry.get('sequence_num', 'N/A')}: {entry.get('function_name', 'N/A')} @ {entry.get('file_path', 'N/A')}:{entry.get('line_number', 'N/A')}")
                self.logger.debug("\n".join(trace_lines))
            else:
                self.logger.info(f"  [VulnAnalysisAgent] Skipping line number refinement for {trace_type} trace")

            # Substep 4: Trim trace from crash_function to entry_function (only for crash trace)
            if is_crash_trace:
                if not (validated_trace and entry_function and crash_function):
                    self.logger.debug("      No entry/crash function specified, keeping full trace")
                    trimmed_trace = validated_trace
                else:
                    crash_idx = next((i for i, f in enumerate(validated_trace) if f.get('function_name') == crash_function), None)
                    entry_idx = next((i for i, f in enumerate(validated_trace) if f.get('function_name') == entry_function), None)

                    if crash_idx is not None and entry_idx is not None:
                        trimmed_trace = validated_trace[crash_idx:entry_idx+1] if crash_idx <= entry_idx else validated_trace
                        if crash_idx <= entry_idx:
                            self.logger.debug(f"     Trimmed trace from frame #{entry_idx} ({entry_function}) to frame #{crash_idx} ({crash_function})")
                        else:
                            self.logger.warning(f"      Unexpected: crash_idx ({crash_idx}) > entry_idx ({entry_idx}), keeping full trace")
                    elif crash_idx is not None:
                        trimmed_trace = validated_trace[crash_idx:]
                        self.logger.debug(f"      Entry function '{entry_function}' not found, keeping from crash function onwards")
                    elif entry_idx is not None:
                        trimmed_trace = validated_trace[:entry_idx+1]
                        self.logger.debug(f"      Crash function '{crash_function}' not found, keeping up to entry function")
                    else:
                        trimmed_trace = validated_trace
                        self.logger.warning(f"      Neither entry '{entry_function}' nor crash '{crash_function}' found in trace, keeping full trace")

                if entry_function and crash_function:
                    self.logger.info(f"    Successfully trimmed from entry '{entry_function}' to crash '{crash_function}'!")

                    # Update crash_location based on crash_function frame
                    crash_frame = next((f for f in trimmed_trace if f.get('function_name') == crash_function), None)
                    if crash_frame:
                        crash_file = crash_frame.get('file_path', '')
                        crash_line = crash_frame.get('line_number', 0)
                        if crash_file and crash_line > 0:
                            old_vuln_location = self.vuln_info.crash_location
                            self.vuln_info.crash_location = f"{crash_file}:{crash_line}"
                            self.logger.info(f"      Updated crash_location: {old_vuln_location} -> {self.vuln_info.crash_location}")

                    # Update entry_location based on entry_function frame
                    entry_frame = next((f for f in trimmed_trace if f.get('function_name') == entry_function), None)
                    if entry_frame:
                        entry_file = entry_frame.get('file_path', '')
                        entry_line = entry_frame.get('line_number', 0)
                        if entry_file and entry_line > 0:
                            old_entry_location = self.vuln_info.entry_location
                            self.vuln_info.entry_location = f"{entry_file}:{entry_line}"
                            self.logger.info(f"      Updated entry_location: {old_entry_location} -> {self.vuln_info.entry_location}")
            else:
                # For allocation/free traces, no trimming needed
                trimmed_trace = validated_trace

            self.logger.info(f"    ✓ Transformed {trace_type} trace: {len(trimmed_trace)} frames (from {len(validated_trace)} valid, {len(parsed_trace)} total)")
            return trimmed_trace

        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to transform call trace: {e}", exc_info=True)
            return []

    def _refine_harness_command(self, project_name, actual_repo_path, raw_harness_command):
        # Refine harness command to use actual paths using LLM with tools
        # LLM: Using new LLMInterface with automatic agent loop
        try:
            # Use LLMInterface for automatic tool calling and conversation management
            self.logger.info("  [VulnAnalysisAgent] Using LLMInterface to refine harness command...")
            result = self.drill_agent.basic_llm.run_agent_loop(
                task=VAA_harness_refine_prompt.format(
                    project_name=project_name,
                    actual_repo_path=actual_repo_path,
                    harness_command=raw_harness_command if raw_harness_command else "Not provided"
                ),
                tools=self.basic_tools,
                system_prompt=VAA_system_prompt,
                max_iterations=4,
                temperature=0.1,
                max_tokens=4096,
                continuation_prompt="Please continue exploring the repository and provide the final JSON output with the refined harness command."
            )
            self._accumulate_token_usage(result, self.drill_agent.basic_llm.model_name)

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.error(f"  [VulnAnalysisAgent] LLM agent loop failed: {error_msg}")
                raise RuntimeError(f"Failed to refine harness command: {error_msg}")

            response = result['final_response']
            self.logger.info(f"  [VulnAnalysisAgent] LLM completed in {result['iterations']} iteration(s)")
            self.logger.info(f"  [VulnAnalysisAgent] Stop reason: {result['stop_reason']}")
            self.logger.info(f"  [VulnAnalysisAgent] LLM Final Response: {response[:300]}...")

            # Extract JSON from response
            refined_info = LLMInterface.extract_json_from_response(response)
            if not refined_info:
                raise ValueError("Could not extract JSON from LLM response")

            # Store refined information
            self.vuln_info.binary_path = refined_info.get('binary_path', '')
            self.vuln_info.refined_harness_command = refined_info.get('refined_harness_command', '')
            self.vuln_info.input_file_suffix = refined_info.get('input_file_suffix', '')

            self.logger.info(f"    ✓ Refined harness information:")
            self.logger.info(f"      Binary: {self.vuln_info.binary_path}")
            self.logger.info(f"      Command: {self.vuln_info.refined_harness_command}")
            self.logger.info(f"      Input file suffix: {self.vuln_info.input_file_suffix if self.vuln_info.input_file_suffix else '(none)'}")

        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to refine harness command: {e}", exc_info=True)
            self.logger.error(f"  [VulnAnalysisAgent] Fallback to use raw harness command.")
            # Fallback: use original harness command
            self.vuln_info.refined_harness_command = raw_harness_command if raw_harness_command else ""
            self.vuln_info.input_file_suffix = ""  # No suffix info in fallback
            # Try to extract binary path from original command
            if raw_harness_command:
                parts = raw_harness_command.split()
                if parts:
                    self.vuln_info.binary_path = parts[0]

    def _root_cause_analysis(self):
        # Perform root cause analysis using LLM with tools.
        # Core idea: let LLM explore the codebase along call trace with tools.
        # Results will be stored in a markdown file in store_to_cache().
        # LLM: Using new LLMInterface with automatic agent loop
        try:
            # Prepare allocation and free trace strings for the prompt
            crash_trace_str = self.vuln_info.format_trace((self.vuln_info.raw_crash_trace, self.vuln_info.crash_trace))
            allocation_trace_str = self.vuln_info.format_trace(self.vuln_info.allocation_trace)
            free_trace_str = self.vuln_info.format_trace(self.vuln_info.free_trace)

            # Prepare the initial prompt
            user_prompt = VAA_root_cause_analysis_prompt.format(
                project_name=self.config.project_name,
                actual_repo_path=self.config.target_repo_path,
                vuln_type=self.vuln_info.vuln_type,
                crash_location=self.vuln_info.crash_location,
                crash_function=self.vuln_info.crash_function,
                entry_location=self.vuln_info.entry_location,
                entry_function=self.vuln_info.entry_function,
                refined_harness_command=self.vuln_info.refined_harness_command,
                refined_call_trace=crash_trace_str,
                allocation_trace=allocation_trace_str,
                free_trace=free_trace_str
            )

            # Run more powerful reasoning LLM than basic LLMs. (update: too expensive, still use basic_llm)
            self.logger.info("    Using LLMInterface to conduct root cause analysis...")
            result = self.drill_agent.basic_llm.run_agent_loop(
                task=user_prompt,
                tools=self.enhanced_tools,  # Allow usage of enhanced code browsing tools for code exploration
                system_prompt=VAA_system_prompt,
                max_iterations=self.max_rca_turns,
                temperature=0.3,
                max_tokens=30720, # Modern LLMs can handle larger contexts.
                continuation_prompt="Please continue your root cause analysis based on the code you examined."
            )
            self._accumulate_token_usage(result, self.drill_agent.reasoning_llm.model_name)

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.error(f"    LLM agent loop failed: {error_msg}")
                raise RuntimeError(f"Failed to perform root cause analysis: {error_msg}")

            # Store the root cause analysis
            self.vuln_info.root_cause = result['final_response']
            self.logger.info(f"    ✓ Root cause analysis complete in {result['iterations']} iteration(s)")
            self.logger.info(f"    Stop reason: {result['stop_reason']}")
            self.logger.info(f"    RCA Results: {self.vuln_info.root_cause[:200]}...")

        except Exception as e:
            self.logger.error(f"    Failed to perform root cause analysis: {e}", exc_info=True)
            self.vuln_info.root_cause = f"Root cause analysis failed: {e}"

    def find_actual_binary_path(self, target_repo_path: str, entry_program_path: str) -> str:
        """
        Find the actual ELF binary path from a wrapper script.\n
        Arg entry_program_path: Absolute path to the wrapper script file.\n
        Returns Relative path to the actual ELF binary (relative to repo root).\n
        Raises RuntimeError: If the actual binary cannot be determined or verified.
        """
        # Return cached result if available
        if self.vuln_info.actual_binary_path and len(self.vuln_info.actual_binary_path) > 0:
            return self.vuln_info.actual_binary_path

        self.logger.info(f"  [VulnAnalysisAgent] Finding actual binary from wrapper script: {entry_program_path}")

        # Substep 1: Read the script content. Invoke LLM to analyze the script and find the actual binary.
        if not os.path.exists(entry_program_path):
            raise RuntimeError(f"Wrapper script not found: {entry_program_path}")
        with open(entry_program_path, 'r', encoding='utf-8', errors='ignore') as f:
            script_content = f.read()
        if not script_content.strip():
            raise RuntimeError(f"Wrapper script is empty: {entry_program_path}")
        self.logger.info(f"  [VulnAnalysisAgent] Script content length: {len(script_content)} chars")

        self.logger.info("    Using LLMInterface to find actual binary path...")
        script_rel_path = os.path.relpath(entry_program_path, target_repo_path)
        result = self.drill_agent.basic_llm.run_agent_loop(
            task=VAA_find_actual_binary_prompt.format(
                project_name=self.config.project_name,
                actual_repo_path=target_repo_path,
                script_path=script_rel_path,
                script_content=script_content
            ),
            tools=self.basic_tools,
            system_prompt=VAA_system_prompt,
            max_iterations=4,
            temperature=0.1,
            max_tokens=4096,
            continuation_prompt="Please continue analyzing the script and provide the final JSON output with the actual binary path."
        )
        self._accumulate_token_usage(result, self.drill_agent.basic_llm.model_name)

        if not result['success']:
            error_msg = result.get('error', 'Unknown error')
            self.logger.error(f"  [VulnAnalysisAgent] LLM agent loop failed: {error_msg}")
            raise RuntimeError(f"Failed to analyze wrapper script: {error_msg}")

        response = result['final_response']
        self.logger.info(f"  [VulnAnalysisAgent] LLM completed in {result['iterations']} iteration(s)")

        # Substep 2: Extract the actual binary path from LLM response
        extracted_info = LLMInterface.extract_json_from_response(response)
        if not extracted_info:
            raise RuntimeError("Could not extract JSON from LLM response")
        actual_binary_path = extracted_info.get('actual_binary_path', '')
        reasoning = extracted_info.get('reasoning', '')
        if not actual_binary_path:
            raise RuntimeError(f"LLM could not determine actual binary path. Reasoning: {reasoning}")

        # self.logger.info(f"  [VulnAnalysisAgent] LLM identified binary: {actual_binary_path}")
        # self.logger.info(f"  [VulnAnalysisAgent] Reasoning: {reasoning}")

        # Substep 3: Verify the actual binary exists and is an ELF file
        actual_binary_abs_path = os.path.join(target_repo_path, actual_binary_path)
        if not os.path.exists(actual_binary_abs_path):
            raise RuntimeError(f"Actual binary not found: {actual_binary_abs_path}")
        if not os.path.isfile(actual_binary_abs_path):
            raise RuntimeError(f"Actual binary path is not a file: {actual_binary_abs_path}")
        if not is_binary_file(actual_binary_abs_path):
            raise RuntimeError(f"File is not an ELF binary: {actual_binary_abs_path}")

        self.vuln_info.actual_binary_path = actual_binary_path
        self.logger.info(f"  [VulnAnalysisAgent] ✓ Found actual binary: {actual_binary_path}")

        # Update offline cache with the new actual_binary_path
        self.store_to_cache()

        return actual_binary_path

@dataclass
class VulnInfo:
    """Container for vulnerability analysis information"""
    # vuln details
    # crash_location should be a relative path after the repo_name
    crash_location: str = ""  # Refined vulnerability crash location (file:line)
    crash_function: str = ""  # Function in which the crash occurs (i.e., the caller of the sink point)
    entry_location: str = ""  # Entry location (file:line)
    entry_function: str = ""  # Entry function leading to the vulnerability (usually the main function of the project)
    raw_crash_trace: str = ""  # Call trace leading to the vulnerability crash
    # Structured call trace: List of {sequence_num, function_name, file_path(relative), line_number, is_external}
    crash_trace: List[Dict[str, Any]] = field(default_factory=list)
    # Additional traces for heap-related vulnerabilities (optional)
    # Each trace is stored as Tuple[raw_text, structured_list]
    allocation_trace: Tuple[str, List[Dict[str, Any]]] = field(default_factory=lambda: ("", [])) # (heap-buffer-overflow, heap-use-after-free, double-free)
    free_trace: Tuple[str, List[Dict[str, Any]]] = field(default_factory=lambda: ("", []))       # (heap-use-after-free, double-free)
    # harness details
    refined_harness_command: str = ""  # Refined harness command
    binary_path: str       = ""  # Relative path to the target program. It may be text script, but for compatibility we still call it "binary". # TODO: rename.
    input_file_suffix: str = ""  # Input file suffix (e.g., .xml, .png)
    actual_binary_path: str = ""  # If extracted entry "binary_path" is a text script, this field is the actual binary it calls, which will be instrumented.
                                  # Else, "actual_binary_path" will be the same as the entry program ("binary_path"), since it's already a binary executable.
    # vuln semantics
    vuln_type: str = ""  # Type of vulnerability (e.g., buffer overflow, use-after-free)
    root_cause: str = ""  # Root cause analysis result
    critical_steps: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert VulnInfo to dictionary"""
        return {
            'crash_location': self.crash_location,
            'crash_function': self.crash_function,
            'entry_location': self.entry_location,
            'entry_function': self.entry_function,
            'raw_crash_trace': self.raw_crash_trace,
            'crash_trace': self.crash_trace,
            'allocation_trace': {
                'raw': self.allocation_trace[0],
                'structured': self.allocation_trace[1]
            },
            'free_trace': {
                'raw': self.free_trace[0],
                'structured': self.free_trace[1]
            },
            'refined_harness_command': self.refined_harness_command,
            'binary_path': self.binary_path,
            'input_file_suffix': self.input_file_suffix,
            'actual_binary_path': self.actual_binary_path,
            'vuln_type': self.vuln_type,
            'root_cause': self.root_cause,
            'critical_steps': self.critical_steps
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnInfo':
        """Create VulnInfo instance from dictionary"""
        # Handle allocation_trace (compatible with old cache format)
        alloc_data = data.get('allocation_trace', {})
        if isinstance(alloc_data, dict):
            allocation_trace = (alloc_data.get('raw', ''), alloc_data.get('structured', []))
        else:
            allocation_trace = ("", [])

        # Handle free_trace (compatible with old cache format)
        free_data = data.get('free_trace', {})
        if isinstance(free_data, dict):
            free_trace = (free_data.get('raw', ''), free_data.get('structured', []))
        else:
            free_trace = ("", [])

        return cls(
            crash_location=data.get('crash_location', ''),
            crash_function=data.get('crash_function', ''),
            entry_location=data.get('entry_location', ''),
            entry_function=data.get('entry_function', ''),
            raw_crash_trace=data.get('raw_crash_trace', '') or data.get('raw_call_trace', ''),
            crash_trace=data.get('crash_trace', []) or data.get('call_trace', []),
            allocation_trace=allocation_trace,
            free_trace=free_trace,
            refined_harness_command=data.get('refined_harness_command', ''),
            binary_path=data.get('binary_path', ''),
            input_file_suffix=data.get('input_file_suffix', ''),
            actual_binary_path=data.get('actual_binary_path', ''),
            vuln_type=data.get('vuln_type', ''),
            root_cause=data.get('root_cause', ''),
            critical_steps=data.get('critical_steps', {}),
        )

    def format_output(self, skip_rca_result=False) -> str:
        # Returns the basic vulnerability information as a formatted string. Including crash trace and allocation/free traces.
        lines = []
        lines.append("## BASIC VULNERABILITY INFO")
        lines.append("")
        # Section 1: Vulnerability Details
        lines.append("[VULNERABILITY DETAILS]")
        lines.append(f"  Vuln Type:              {self.vuln_type if self.vuln_type else 'N/A'}")
        lines.append(f"  Crash Location:    {self.crash_location if self.crash_location else 'N/A'}")
        lines.append(f"  Crash Function:    {self.crash_function if self.crash_function else 'N/A'}")
        lines.append(f"  Entry Location:    {self.entry_location if self.entry_location else 'N/A'}")
        lines.append(f"  Entry Function:    {self.entry_function if self.entry_function else 'N/A'}")
        # Section 2: Harness Information
        lines.append("\n[HARNESS INFORMATION]")
        lines.append(f"  Entry Program Path:    {self.binary_path if self.binary_path else 'N/A'}")
        if self.actual_binary_path:
            lines.append(f"  Actual Binary Path:    {self.actual_binary_path}")
        else:
            lines.append(f"  Actual Binary Path:    (To be determined)")
        if self.refined_harness_command:
            lines.append(f"  Harness Command:")
            # Handle multi-line commands
            if '\n' in self.refined_harness_command:
                for cmd_line in self.refined_harness_command.split('\n'):
                    lines.append(f"    {cmd_line}")
            else:
                lines.append(f"    {self.refined_harness_command}")
        else:
            lines.append(f"  Harness Command:   N/A")
        if self.input_file_suffix:
            lines.append(f"  PoV File Suffix: {self.input_file_suffix}")
        else:
            lines.append(f"  PoV File Suffix: N/A")
        # Section 3: Call Trace
        lines.append("\n[CRASH TRACE]")
        if self.crash_trace and len(self.crash_trace) > 0:
            lines.append("  (Refined CRASH Trace):")
            for entry in self.crash_trace:
                seq_num = entry.get('sequence_num', 'N/A')
                func_name = entry.get('function_name', 'N/A')
                file_path = entry.get('file_path', 'N/A')
                line_number = entry.get('line_number', 'N/A')
                lines.append(f"  #{seq_num}: {func_name} @ {file_path}:{line_number}")
        elif self.raw_crash_trace:
            lines.append("  (Raw CRASH Trace):")
            trace_lines = self.raw_crash_trace.split('\n')
            for trace_line in trace_lines:
                if trace_line.strip():
                    lines.append(f"  {trace_line}")
        else:
            lines.append("  N/A")
        # Section 3.5: Allocation Trace (if available)
        alloc_trace_str = self.format_trace(self.allocation_trace)
        if alloc_trace_str != "N/A":
            lines.append("\n[ALLOCATION TRACE]")
            for line in alloc_trace_str.split('\n'):
                if line.strip():
                    lines.append(f"  {line.strip()}")
        # Section 3.6: Free Trace (if available)
        free_trace_str = self.format_trace(self.free_trace)
        if free_trace_str != "N/A":
            lines.append("\n[FREE TRACE]")
            for line in free_trace_str.split('\n'):
                if line.strip():
                    lines.append(f"  {line.strip()}")
        
        # Section 4: Root Cause Analysis
        if self.root_cause and not skip_rca_result:
            # lines.append("\n[ROOT CAUSE ANALYSIS]")
            # Handle multi-line root cause descriptions
            root_cause_lines = self.root_cause.split('\n') # all lines
            # first 20 lines for simplicity (update: should not limit here, full details needed)
            # root_cause_lines = root_cause_lines[:20] #
            # root_cause_lines.append("...") if len(self.root_cause.split('\n')) > 20 else None #
            for rc_line in root_cause_lines:
                if not rc_line.strip(): continue # skip empty lines
                if rc_line.startswith("## "):    # Handle section title "## VULNERABILITY ROOT CAUSE"
                    lines.append(f"\n{rc_line}")
                else:
                    lines.append(f"  {rc_line}")
        # Section 5: Critical Steps (if available)
        # if self.critical_steps and len(self.critical_steps) > 0:
        #     lines.append("\n[CRITICAL STEPS]")
        #     for idx, step in enumerate(self.critical_steps, 1):
        #         lines.append(f"  {idx}. {step}")
        
        return '\n'.join(lines)

    def get_full_root_cause(self) -> str:
        # Get the full root cause analysis text
        return self.root_cause if self.root_cause else "N/A"

    def format_trace(self, trace_tuple: Tuple[str, List[Dict[str, Any]]]) -> str:
        """
        Format a trace tuple (raw_text, structured_list) as a string.
        Returns structured format if available, otherwise raw text, or "N/A" if empty.
        """
        raw_text, structured_list = trace_tuple
        if structured_list and len(structured_list) > 0:
            lines = []
            for entry in structured_list:
                seq_num = entry.get('sequence_num', 'N/A')
                func_name = entry.get('function_name', 'N/A')
                file_path = entry.get('file_path', 'N/A')
                line_number = entry.get('line_number', 'N/A')
                lines.append(f"  #{seq_num}: {func_name} @ {file_path}:{line_number}")
            return '\n'.join(lines)
        elif raw_text and len(raw_text) > 0:
            return raw_text
        return "N/A"
