import os
import json
import logging
from typing import Dict, Any, List, TYPE_CHECKING
from dataclasses import dataclass, field
from drillagent.prompts.VulnAnalysisAgent_prompt import (
    VAA_system_prompt,
    VAA_sanitizer_extraction_prompt,
    VAA_call_trace_transform_prompt,
    VAA_call_trace_linenum_refine_prompt,
    VAA_harness_refine_prompt,
    VAA_root_cause_analysis_prompt,
    VAA_critical_step_identification_prompt
)

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
        self.enhanced_tools: List['AgentTool'] = drill_agent.basic_tools + drill_agent.cov_tools + drill_agent.ast_grep_tools
        # Sometimes ast-grep may not be usable, so we keep both basic and enhanced toolsets.

        # Vulnerability information container!!!!! 
        self.vuln_info = VulnInfo() # This will be returned to the caller class (DrillAgent).
        self.cache_dir = os.path.join(self.config.work_dir, "cache_drillagent")

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
            cache_filepath = os.path.join(self.cache_dir, f"vuln_info_{identifier}.json")

            # Check if cache file exists
            if not os.path.exists(cache_filepath):
                self.logger.info(f"  [VulnAnalysisAgent] No cache file found at: {cache_filepath}")
                return False
            # Check if file has content
            if os.path.getsize(cache_filepath) == 0:
                self.logger.warning(f"  [VulnAnalysisAgent] Cache file is empty: {cache_filepath}")
                return False

            # Read and parse cache file
            with open(cache_filepath, 'r', encoding='utf-8') as f:
                vuln_data = json.load(f)

            # Validate that we have data
            if not vuln_data:
                self.logger.warning(f"  [VulnAnalysisAgent] Cache file contains no data: {cache_filepath}")
                return False

            # Load data into vuln_info using from_dict
            self.vuln_info = VulnInfo.from_dict(vuln_data)
            self.logger.info(f"  [VulnAnalysisAgent] Successfully loaded cache from: {cache_filepath}")
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
            os.makedirs(self.cache_dir, exist_ok=True)

            project_name = self.config.project_name
            cve_id       = self.config.cve_id
            base_commit  = self.config.base_commit
            if cve_id:
                identifier = f"{project_name}_{cve_id}"
            else:
                identifier = f"{project_name}_{base_commit}"

            # Write to cache file with pretty formatting
            cache_filepath = os.path.join(self.cache_dir, f"vuln_info_{identifier}.json")
            vuln_data = self.vuln_info.to_dict()
            with open(cache_filepath, 'w', encoding='utf-8') as f:
                json.dump(vuln_data, f, indent=2, ensure_ascii=False)

            # Also write root cause analysis results to a file separately for easy access.
            root_cause_filepath = os.path.join(self.cache_dir, f"root_cause_{identifier}.md")
            with open(root_cause_filepath, 'w', encoding='utf-8') as f:
                f.write(self.vuln_info.root_cause)

            # Also write critical steps to a separate JSON file for easy access.
            if self.vuln_info.critical_steps:
                critical_steps_filepath = os.path.join(self.cache_dir, f"critical_steps_{identifier}.json")
                with open(critical_steps_filepath, 'w', encoding='utf-8') as f:
                    json.dump(self.vuln_info.critical_steps, f, indent=2, ensure_ascii=False)
                self.logger.info(f"  [VulnAnalysisAgent] Critical steps cached to: {critical_steps_filepath}")

            self.logger.info(f"  [VulnAnalysisAgent] Vulnerability analysis cached to: {cache_filepath}")

        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to store cache: {e}", exc_info=True)


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

        # Before all, Try to load from cache first.
        if self.load_from_cache():
            self.logger.info("  [VulnAnalysisAgent] Loaded vulnerability analysis from cache. Skipping analysis steps.")
            return self.vuln_info
        
        # Substep1: Extract basic vulnerability information (if sanitizer report is available)
        # TODO: raw_vuln_location could be used for cross checking.
        if len(sanitizer_report) > 0:
            self.logger.info(f"  [VulnAnalysisAgent] Extracting basic vulnerability information from report...")
            self.logger.info(f"  [VulnAnalysisAgent] Sanitizer report: {len(sanitizer_report)} chars.")
            self._extract_sanitizer_report(project_name, actual_repo_path, sanitizer_report)
            
            # Transform raw call trace to structured format for PathExplorationAgent
            if len(self.vuln_info.raw_call_trace) > 0:
                 self.vuln_info.call_trace = self._transform_raw_call_trace(self.vuln_info.raw_call_trace)
            
            self.logger.info(f"  [VulnAnalysisAgent] Extraction complete!")
        
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

        # Substep4: Identify critical function call steps for vulnerability triggering.
        # if not self.config.disable_root_cause_analysis:  # Only run if root cause analysis is enabled
        #     self.logger.info("  [VulnAnalysisAgent] Identifying critical function call steps...")
        #     self._identify_critical_steps()
        # else:
        #     self.logger.info("  [VulnAnalysisAgent] Critical step identification is skipped (requires root cause analysis).")

        # Store results to cache for future use
        self.store_to_cache()

        return self.vuln_info

    def _extract_sanitizer_report(self, project_name, actual_repo_path, sanitizer_report):
        # Extract vulnerability information from sanitizer report using LLM with tools
        # LLM: Using new LLMInterface with automatic agent loop
        try:
            # Use LLMInterface for automatic tool calling and conversation management
            assert hasattr(self.drill_agent, 'basic_llm') and self.drill_agent.basic_llm is not None, "DrillAgent.basic_llm (LLMInterface) is not available!"
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

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.error(f"  [VulnAnalysisAgent] LLM agent loop failed: {error_msg}")
                raise RuntimeError(f"Failed to extract sanitizer report: {error_msg}")

            response = result['final_response']
            self.logger.info(f"  [VulnAnalysisAgent] LLM completed in {result['iterations']} iteration(s)")
            self.logger.info(f"  [VulnAnalysisAgent] Stop reason: {result['stop_reason']}")
            self.logger.info(f"  [VulnAnalysisAgent] LLM Response: {response[:300]}...")

            # Extract JSON from response (handle multiple formats)
            # Try to extract JSON from markdown code block
            extracted_info = None
            if '```' in response:
                parts = response.split('```')
                for i, part in enumerate(parts):
                    # Skip the first part (before first ```) and try every other part
                    if i > 0 and i % 2 == 1:
                        # Remove language identifier if present
                        lines = part.strip().split('\n')
                        if lines and lines[0].strip().lower() in ['json', '']:
                            json_str = '\n'.join(lines[1:]) if lines[0].strip() else part.strip()
                        else:
                            json_str = part.strip()

                        try:
                            extracted_info = json.loads(json_str)
                            if extracted_info:
                                break
                        except:
                            continue

            # Try to find JSON object in response
            if not extracted_info:
                # Find first { and last }
                start_idx = response.find('{')
                end_idx = response.rfind('}')
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    try:
                        extracted_info = json.loads(response[start_idx:end_idx+1])
                    except:
                        pass

            # Try parsing entire response as JSON
            if not extracted_info:
                try:
                    extracted_info = json.loads(response.strip())
                except:
                    pass

            # If still no JSON, raise error to use fallback
            if not extracted_info:
                raise ValueError("Could not extract JSON from LLM response")

            # Store extracted information
            self.vuln_info.vuln_type = extracted_info.get('vuln_type', '')
            self.vuln_info.crash_function = extracted_info.get('crash_function', '')
            self.vuln_info.crash_location = extracted_info.get('crash_location', '')
            self.vuln_info.entry_function = extracted_info.get('entry_function', '')
            self.vuln_info.entry_location = extracted_info.get('entry_location', '')
            self.vuln_info.raw_call_trace = extracted_info.get('call_trace', '')

            self.logger.info(f"    ✓ Extracted vulnerability information:")
            self.logger.info(f"      Type: {self.vuln_info.vuln_type}")
            self.logger.info(f"      Crash: {self.vuln_info.crash_function} @ {self.vuln_info.crash_location}")
            self.logger.info(f"      Entry: {self.vuln_info.entry_function} @ {self.vuln_info.entry_location}")

        except Exception as e:
            self.logger.error(f"    Failed to extract sanitizer report: {e}", exc_info=True)
            # Return empty values on failure

    def _transform_raw_call_trace(self, raw_call_trace: str) -> List[Dict[str, Any]]:
        # Transform raw call trace string to structured format using LLM. Also check and adjust the line numbers if needed.
        # Returns: List of structured call trace entries with validated file paths, from entry_function to crash_function.

        def extract_json_from_response(response: str) -> dict:
            # Try markdown code block first
            if '```' in response:
                for i, part in enumerate(response.split('```')):
                    if i > 0 and i % 2 == 1:
                        lines = part.strip().split('\n')
                        json_str = '\n'.join(lines[1:]) if lines and lines[0].strip().lower() in ['json', ''] else part.strip()
                        try:
                            data = json.loads(json_str)
                            if data: return data
                        except: continue
            # Try finding JSON object
            if '{' in response and '}' in response:
                start, end = response.find('{'), response.rfind('}')
                if start != -1 and end > start:
                    try: return json.loads(response[start:end+1])
                    except: pass
            # Try parsing entire response
            try: return json.loads(response.strip())
            except: return None

        try:
            repo_path = self.config.target_repo_path
            entry_function, crash_function = self.vuln_info.entry_function, self.vuln_info.crash_function

            # Substep 1: Transform raw call trace to structured format
            self.logger.info("  [VulnAnalysisAgent] Using LLMInterface to transform raw call trace...")
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

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.error(f"  [VulnAnalysisAgent] LLM agent loop failed: {error_msg}")
                raise RuntimeError(f"Failed to transform call trace: {error_msg}")

            response = result['final_response']
            self.logger.info(f"  [VulnAnalysisAgent] LLM completed in {result['iterations']} iteration(s)")
            self.logger.info(f"  [VulnAnalysisAgent] Stop reason: {result['stop_reason']}")
            self.logger.info(f"  [VulnAnalysisAgent] LLM Response: {response[:300]}...")

            parsed_data = extract_json_from_response(response)
            if not parsed_data or 'call_trace' not in parsed_data:
                raise ValueError("Could not extract call trace from LLM response")

            # Substep 2: Validate file paths and filter out invalid/external frames
            validated_trace = []
            for entry in parsed_data['call_trace']:
                if entry.get('is_external', False) or not entry.get('file_path'):
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
                    self.logger.warning(f"      ✗ File not found for frame #{entry.get('sequence_num')}: {abs_path}")
            self.logger.info(f"Validated file paths in call trace: {len(validated_trace)} valid frames (from {len(parsed_data['call_trace'])} total)")

            # Print trace before line number adjustment (for debug)
            validated_tmp_trace = '\n'.join(f"#{e.get('sequence_num', 'N/A')}: {e.get('function_name', 'N/A')} @ {e.get('file_path', 'N/A')}:{e.get('line_number', 'N/A')}" for e in validated_trace)
            print(f"Vulnerable call trace before line number adjustment:\n{validated_tmp_trace}\n")

            # Substep 3: Refine line numbers using LLM with tools (frame-by-frame approach)
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
                        self.logger.info(f"  Processing frame #{seq_num} ({func_name}): Innermost frame, keeping original line number")
                        refined_frames.append(current_frame)
                        continue

                    # Get callee frame (next frame in the sorted list, which has smaller sequence_num)
                    callee_frame = sorted_trace[idx + 1]
                    callee_func_name = callee_frame.get('function_name', '')
                    self.logger.info(f"  Processing frame #{seq_num} ({func_name}) -> callee: {callee_func_name}")
                    current_frame_json = json.dumps(current_frame, indent=2)

                    # Invoke low-cost LLM (faster) to refine the line number of each stack frame
                    result = self.drill_agent.low_cost_llm.run_agent_loop(
                        task=VAA_call_trace_linenum_refine_prompt.format(
                            project_name=self.config.project_name,
                            actual_repo_path=repo_path,
                            current_frame_json=current_frame_json,
                            callee_function_name=callee_func_name
                        ),
                        tools=self.enhanced_tools, # Allow the usage of ast-grep
                        system_prompt=VAA_system_prompt,
                        max_iterations=3,
                        temperature=0.1,
                        max_tokens=4096,
                        continuation_prompt="Please continue verifying the line number using the code browsing tools and provide the final JSON output."
                    )

                    if result['success']:
                        refined_frame = extract_json_from_response(result['final_response'])
                        if refined_frame and 'line_number' in refined_frame and refined_frame.get('line_number', 0) > 0:
                            old_linenum = current_frame['line_number']
                            # Merge refined data back to current frame
                            current_frame.update(refined_frame)
                            new_linenum = current_frame['line_number']
                            original = current_frame.get('is_original_linenum', True)
                            verified = current_frame.get('is_verified', False)
                            self.logger.info   (f"        ✓ Frame #{seq_num}: Linenum refined from {old_linenum} to {new_linenum} (original: {original}, verified: {verified})")
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

            # Print trace after line number adjustment (for debug)
            print(f"Vulnerable call trace after line number adjustment:")
            for e in validated_trace:
                print(f"#{e.get('sequence_num', 'N/A')}: {e.get('function_name', 'N/A')} @ {e.get('file_path', 'N/A')}:{e.get('line_number', 'N/A')}")
            print("")

            # Substep 4: Trim trace from crash_function to entry_function
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
                self.logger.info(f"      Successfully trimmed from entry '{entry_function}' to crash '{crash_function}'!")

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

            
            self.logger.info(f"    ✓ Transformed call trace: {len(trimmed_trace)} frames (from {len(validated_trace)} valid, {len(parsed_data['call_trace'])} total)")
            return trimmed_trace

        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to transform call trace: {e}", exc_info=True)
            return []

    def _refine_harness_command(self, project_name, actual_repo_path, raw_harness_command):
        # Refine harness command to use actual paths using LLM with tools
        # LLM: Using new LLMInterface with automatic agent loop
        try:
            # Prepare the prompt
            user_prompt = VAA_harness_refine_prompt.format(
                project_name=project_name,
                actual_repo_path=actual_repo_path,
                harness_command=raw_harness_command if raw_harness_command else "Not provided"
            )

            # Use LLMInterface for automatic tool calling and conversation management
            self.logger.info("  [VulnAnalysisAgent] Using LLMInterface to refine harness command...")

            result = self.drill_agent.basic_llm.run_agent_loop(
                task=user_prompt,
                tools=self.basic_tools,
                system_prompt=VAA_system_prompt,
                max_iterations=3,  # Allow up to 3 rounds of tool usage
                temperature=0.2,
                max_tokens=4096,
                continuation_prompt="Please continue exploring the repository and provide the final JSON output with the refined harness command."
            )

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.error(f"  [VulnAnalysisAgent] LLM agent loop failed: {error_msg}")
                raise RuntimeError(f"Failed to refine harness command: {error_msg}")

            response = result['final_response']
            self.logger.info(f"  [VulnAnalysisAgent] LLM completed in {result['iterations']} iteration(s)")
            self.logger.info(f"  [VulnAnalysisAgent] Stop reason: {result['stop_reason']}")
            self.logger.info(f"  [VulnAnalysisAgent] LLM Final Response: {response[:300]}...")

            # Extract JSON from response
            # Try to extract JSON from markdown code block
            refined_info = None
            if '```' in response:
                parts = response.split('```')
                for i, part in enumerate(parts):
                    if i > 0 and i % 2 == 1:
                        lines = part.strip().split('\n')
                        if lines and lines[0].strip().lower() in ['json', '']:
                            json_str = '\n'.join(lines[1:]) if lines[0].strip() else part.strip()
                        else:
                            json_str = part.strip()

                        try:
                            refined_info = json.loads(json_str)
                            if refined_info:
                                break
                        except:
                            continue

            # Try to find JSON object in response
            if not refined_info:
                start_idx = response.find('{')
                end_idx = response.rfind('}')
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    try:
                        refined_info = json.loads(response[start_idx:end_idx+1])
                    except:
                        pass

            # Try parsing entire response as JSON
            if not refined_info:
                try:
                    refined_info = json.loads(response.strip())
                except:
                    pass

            # If still no JSON, raise error
            if not refined_info:
                raise ValueError("Could not extract JSON from LLM response")

            # Store refined information
            self.vuln_info.binary_path = refined_info.get('binary_path', '')
            self.vuln_info.refined_harness_command = refined_info.get('refined_harness_command', '')

            self.logger.info(f"    ✓ Refined harness information:")
            self.logger.info(f"      Binary: {self.vuln_info.binary_path}")
            self.logger.info(f"      Command: {self.vuln_info.refined_harness_command}")

        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to refine harness command: {e}", exc_info=True)
            self.logger.error(f"  [VulnAnalysisAgent] Fallback to use raw harness command.")
            # Fallback: use original harness command
            self.vuln_info.refined_harness_command = raw_harness_command if raw_harness_command else ""
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
                refined_call_trace=self.vuln_info.get_refined_call_trace_as_string()
            )

            # Use LLMInterface for automatic tool calling and conversation management
            self.logger.info("    Using LLMInterface for root cause analysis...")

            # Run more powerful reasoning LLM than basic LLMs. 
            result = self.drill_agent.reasoning_llm.run_agent_loop(
                task=user_prompt,
                tools=self.enhanced_tools,  # Allow usage of enhanced code browsing tools for code exploration
                system_prompt=VAA_system_prompt,
                max_iterations=20,  # Allow up to 20 rounds of deep analysis
                temperature=0.3,
                max_tokens=40960, # Modern LLMs can handle larger contexts.
                continuation_prompt="Please continue your root cause analysis based on the code you examined."
            )

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.error(f"    LLM agent loop failed: {error_msg}")
                raise RuntimeError(f"Failed to perform root cause analysis: {error_msg}")

            # Store the root cause analysis
            self.vuln_info.root_cause = result['final_response']
            self.logger.info(f"    ✓ Root cause analysis complete in {result['iterations']} iteration(s)")
            self.logger.info(f"    Stop reason: {result['stop_reason']}")
            self.logger.info(f"    Analysis: {self.vuln_info.root_cause[:200]}...")

        except Exception as e:
            self.logger.error(f"    Failed to perform root cause analysis: {e}", exc_info=True)
            self.vuln_info.root_cause = f"Root cause analysis failed: {e}"

    # TODO: This part is too simple for now, improve this identification in the future if needed (LHY).
    def _identify_critical_steps(self):
        # Identify critical function call steps for vulnerability triggering.
        # LLM uses tools to read code and identify which frames are critical vs non-critical.
        # Results are stored in a JSON file for later use.
        try:
            # Skip if no call trace is available
            if not self.vuln_info.call_trace or len(self.vuln_info.call_trace) == 0:
                self.logger.warning("  [VulnAnalysisAgent] No refined call trace available. Skipping critical step identification.")
                return

            # Prepare the prompt
            initial_prompt = VAA_critical_step_identification_prompt.format(
                project_name=self.config.project_name,
                actual_repo_path=self.config.target_repo_path,
                vuln_type=self.vuln_info.vuln_type,
                root_cause=self.vuln_info.root_cause if self.vuln_info.root_cause else "Not available",
                refined_call_trace=self.vuln_info.get_refined_call_trace_as_string()
            )

            # Use LLMInterface for automatic tool calling and conversation management
            self.logger.info("    Using LLMInterface to identify critical steps...")
            result = self.drill_agent.basic_llm.run_agent_loop(
                task=initial_prompt,
                tools=self.enhanced_tools,
                system_prompt=VAA_system_prompt,
                max_iterations=10,  # To be adjusted...
                temperature=0.2,
                max_tokens=8192,
                continuation_prompt="Please continue examining the remaining frames and provide the final JSON output with critical and non-critical frames."
            )

            if not result['success']:
                error_msg = result.get('error', 'Unknown error')
                self.logger.error(f"    LLM agent loop failed: {error_msg}")
                raise RuntimeError(f"Failed to identify critical steps: {error_msg}")

            response = result['final_response']
            self.logger.info(f"    ✓ Critical step identification complete in {result['iterations']} iteration(s)")
            self.logger.info(f"    Stop reason: {result['stop_reason']}")
            self.logger.info(f"    LLM Response: {response[:300]}...")
            # Extract JSON from response
            critical_steps_data = None
            if '```' in response:
                parts = response.split('```')
                for i, part in enumerate(parts):
                    if i > 0 and i % 2 == 1:
                        lines = part.strip().split('\n')
                        if lines and lines[0].strip().lower() in ['json', '']:
                            json_str = '\n'.join(lines[1:]) if lines[0].strip() else part.strip()
                        else:
                            json_str = part.strip()
                        try:
                            critical_steps_data = json.loads(json_str)
                            if critical_steps_data:
                                break
                        except:
                            continue
            # Try to find JSON object in response
            if not critical_steps_data:
                start_idx = response.find('{')
                end_idx = response.rfind('}')
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    try:
                        critical_steps_data = json.loads(response[start_idx:end_idx+1])
                    except:
                        pass
            # Try parsing entire response as JSON
            if not critical_steps_data:
                try:
                    critical_steps_data = json.loads(response.strip())
                except:
                    pass
            # If still no JSON, raise error
            if not critical_steps_data:
                raise ValueError("Could not extract JSON from LLM response")

            # Store critical steps data in vuln_info
            self.vuln_info.critical_steps = critical_steps_data

            # Log summary
            num_critical = len(critical_steps_data.get('critical_frames', []))
            num_non_critical = len(critical_steps_data.get('non_critical_frames', []))
            total_frames = len(self.vuln_info.call_trace)
            self.logger.info(f"    ✓ Critical step identification complete:")
            self.logger.info(f"      Critical frames: {num_critical}/{total_frames}")
            self.logger.info(f"      Non-critical frames: {num_non_critical}/{total_frames}")

        except Exception as e:
            self.logger.error(f"    Failed to identify critical steps: {e}", exc_info=True)

@dataclass
class VulnInfo:
    """Container for vulnerability analysis information"""
    # vuln details
    # crash_location should be a relative path after the repo_name
    crash_location: str = ""  # Refined vulnerability crash location (file:line)
    crash_function: str = ""  # Function in which the crash occurs (i.e., the caller of the sink point)
    entry_location: str = ""  # Entry location (file:line)
    entry_function: str = ""  # Entry function leading to the vulnerability (usually the main function of the project)
    raw_call_trace: str = ""  # Call trace leading to the vulnerability (now we only consider CVEs with crash call traces)
    # Structured call trace: List of {sequence_num, function_name, file_path(relative), line_number, is_external}
    call_trace: List[Dict[str, Any]] = field(default_factory=list)
    # harness details
    refined_harness_command: str = ""  # Refined harness command
    binary_path: str = ""  # Relative path to the target binary
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
            'raw_call_trace': self.raw_call_trace,
            'call_trace': self.call_trace,
            'refined_harness_command': self.refined_harness_command,
            'binary_path': self.binary_path,
            'vuln_type': self.vuln_type,
            'root_cause': self.root_cause,
            'critical_steps': self.critical_steps
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnInfo':
        """Create VulnInfo instance from dictionary"""
        return cls(
            crash_location=data.get('crash_location', ''),
            crash_function=data.get('crash_function', ''),
            entry_location=data.get('entry_location', ''),
            entry_function=data.get('entry_function', ''),
            raw_call_trace=data.get('raw_call_trace', ''),
            call_trace=data.get('call_trace', []),
            refined_harness_command=data.get('refined_harness_command', ''),
            binary_path=data.get('binary_path', ''),
            vuln_type=data.get('vuln_type', ''),
            root_cause=data.get('root_cause', ''),
            critical_steps=data.get('critical_steps', {}),
        )

    def format_output(self, skip_rca_result=False) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY ANALYSIS RESULTS")
        lines.append("=" * 80)
        # Section 1: Vulnerability Details
        lines.append("[VULNERABILITY DETAILS]")
        lines.append(f"  Vuln Type:              {self.vuln_type if self.vuln_type else 'N/A'}")
        lines.append(f"  Crash Location:    {self.crash_location if self.crash_location else 'N/A'}")
        lines.append(f"  Crash Function:    {self.crash_function if self.crash_function else 'N/A'}")
        lines.append(f"  Entry Location:    {self.entry_location if self.entry_location else 'N/A'}")
        lines.append(f"  Entry Function:    {self.entry_function if self.entry_function else 'N/A'}")
        # Section 2: Harness Information
        lines.append("\n[HARNESS INFORMATION]")
        lines.append(f"  Binary Path:       {self.binary_path if self.binary_path else 'N/A'}")
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
        # Section 3: Call Trace
        lines.append("\n[CALL TRACE]")
        if self.call_trace and len(self.call_trace) > 0:
            lines.append("  (Refined Call Trace):")
            for entry in self.call_trace:
                seq_num = entry.get('sequence_num', 'N/A')
                func_name = entry.get('function_name', 'N/A')
                file_path = entry.get('file_path', 'N/A')
                line_number = entry.get('line_number', 'N/A')
                lines.append(f"  #{seq_num}: {func_name} @ {file_path}:{line_number}")
        elif self.raw_call_trace:
            lines.append("  (Raw Call Trace):")
            trace_lines = self.raw_call_trace.split('\n')
            for trace_line in trace_lines:
                if trace_line.strip():
                    lines.append(f"  {trace_line}")
        else:
            lines.append("  N/A")
        # Section 4: Root Cause Analysis
        if self.root_cause and not skip_rca_result:
            lines.append("\n[ROOT CAUSE ANALYSIS]")
            # Handle multi-line root cause descriptions
            root_cause_lines = self.root_cause.split('\n') # all lines
            # first 20 lines for simplicity (update: should not limit here, full details needed)
            # root_cause_lines = root_cause_lines[:20] #
            # root_cause_lines.append("...") if len(self.root_cause.split('\n')) > 20 else None #
            for rc_line in root_cause_lines:
                if rc_line.strip():
                    lines.append(f"  {rc_line}")
        # Section 5: Critical Steps (if available)
        # if self.critical_steps and len(self.critical_steps) > 0:
        #     lines.append("\n[CRITICAL STEPS]")
        #     for idx, step in enumerate(self.critical_steps, 1):
        #         lines.append(f"  {idx}. {step}")
        lines.append("=" * 80)
        # print('\n'.join(lines))
        return '\n'.join(lines)

    def get_full_root_cause(self) -> str:
        # Get the full root cause analysis text
        return self.root_cause if self.root_cause else "N/A"

    def get_refined_call_trace_as_string(self) -> str:
        # Get the refined call trace as a formatted string
        if not self.call_trace or len(self.call_trace) == 0:
            return self.raw_call_trace if self.raw_call_trace else "N/A"
        lines = []
        for entry in self.call_trace:
            seq_num = entry.get('sequence_num', 'N/A')
            func_name = entry.get('function_name', 'N/A')
            file_path = entry.get('file_path', 'N/A')
            line_number = entry.get('line_number', 'N/A')
            lines.append(f"  #{seq_num}: {func_name} @ {file_path}:{line_number}")
        return '\n'.join(lines)

