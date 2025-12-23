import os
import json
import logging
from typing import Dict, Any, List, TYPE_CHECKING
from dataclasses import dataclass, field
from drillagent.prompts.VulnAnalysisAgent_prompt import (
    VAA_system_prompt,
    VAA_sanitizer_extraction_prompt,
    VAA_harness_refine_prompt,
    VAA_root_cause_analysis_prompt,
    VAA_call_trace_transform_prompt,
    VAA_call_trace_linenum_refine_prompt
)

if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent
    from drillagent.config import AgentConfig
    from drillagent.models import LLM
    from drillagent.utils.tools import AgentTool

class VulnAnalysisAgent:
    # Analyzes vulnerabilities using LLM with code exploration tools

    def __init__(self, drill_agent: 'DrillAgent'):
        self.drill_agent: 'DrillAgent' = drill_agent
        self.config: 'AgentConfig' = drill_agent.config
        self.logger: logging.Logger = drill_agent.logger
        self.tools: List['AgentTool'] = drill_agent.agent_tools

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

            self.logger.info(f"  [VulnAnalysisAgent] Vulnerability analysis cached to: {cache_filepath}")

        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to store cache: {e}", exc_info=True)


    def run(self) -> 'VulnInfo':
        # Run vulnerability analysis with a VulnInfo object returned.
        self.logger.info("  [VulnAnalysisAgent] Starting vulnerability analysis...")

        # Check if basic_llm (LLMInterface) is available
        if not (hasattr(self.drill_agent, 'basic_llm') and self.drill_agent.basic_llm) or not self.tools:
            self.logger.warning("  [VulnAnalysisAgent] LLMInterface or tools not available! Return with nothing.")
            return self.vuln_info
        
        # The analysis is based on the following basic information.
        project_name     = self.config.project_name
        actual_repo_path = self.config.target_repo_path
        sanitizer_report = self.config.sanitizer_report
        # raw_vuln_location    = self.config.vuln_location    # won't use
        raw_harness_command  = self.config.harness_command
        self.logger.info(f"  [VulnAnalysisAgent] Actual repo path: {len(actual_repo_path)}.")

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
        
        # Substep2: Refine harness command
        # TODO: raw_harness_command could be used for cross checking.
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

    def _extract_sanitizer_report(self, project_name, actual_repo_path, sanitizer_report):
        # Extract vulnerability information from sanitizer report using LLM with tools
        # LLM: Using new LLMInterface with automatic agent loop
        try:
            # Prepare the prompt
            prompt = VAA_sanitizer_extraction_prompt.format(
                project_name=project_name,
                actual_repo_path=actual_repo_path,
                sanitizer_report=sanitizer_report
            )

            # Use LLMInterface for automatic tool calling and conversation management
            assert hasattr(self.drill_agent, 'basic_llm') and self.drill_agent.basic_llm is not None, "DrillAgent.basic_llm (LLMInterface) is not available!"
            self.logger.info("  [VulnAnalysisAgent] Using LLMInterface to extract sanitizer report...")

            result = self.drill_agent.basic_llm.run_agent_loop(
                task=prompt,
                tools=self.tools,
                system_prompt=VAA_system_prompt,
                max_iterations=5,  # Allow up to 5 rounds of tool usage
                temperature=0.1,  # Low temperature for precise extraction
                max_tokens=4096,
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
            self.vuln_info.refined_vuln_location = extracted_info.get('refined_vuln_location', '')
            self.vuln_info.entry_function = extracted_info.get('entry_function', '')
            self.vuln_info.entry_location = extracted_info.get('entry_location', '')
            self.vuln_info.raw_call_trace = extracted_info.get('call_trace', '')

            self.logger.info(f"    ✓ Extracted vulnerability information:")
            self.logger.info(f"      Type: {self.vuln_info.vuln_type}")
            self.logger.info(f"      Crash: {self.vuln_info.crash_function} @ {self.vuln_info.refined_vuln_location}")
            self.logger.info(f"      Entry: {self.vuln_info.entry_function} @ {self.vuln_info.entry_location}")

        except Exception as e:
            self.logger.error(f"    Failed to extract sanitizer report: {e}", exc_info=True)
            # Return empty values on failure

    def _transform_raw_call_trace(self, raw_call_trace: str) -> List[Dict[str, Any]]:
        # Transform raw call trace string to structured format using LLM. Also check and adjust the line numbers if needed.
        # Returns: List of structured call trace entries with validated file paths, from entry_function to crash_function.

        try:
            structured_trace = []
            # Firstly, do the basic raw_call_trace formatting using LLM. Here we focus on file path validation.
            prompt = VAA_call_trace_transform_prompt.format(
                project_name=self.config.project_name,
                actual_repo_path=self.config.target_repo_path,
                raw_call_trace=raw_call_trace
            )
            # Call LLM to transform the call trace
            self.logger.info("  [VulnAnalysisAgent] Using LLMInterface to transform raw call trace...")
            response = self.drill_agent.basic_llm.generate(
                prompt=prompt,
                system_prompt=VAA_system_prompt,
                temperature=0.1,  # Low temperature for precise extraction
                max_tokens=4096
            )
            self.logger.info(f"  [VulnAnalysisAgent] LLM Response: {response[:300]}...")

            # Extract JSON from response
            parsed_data = None
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
                            parsed_data = json.loads(json_str)
                            if parsed_data:
                                break
                        except:
                            continue
            # Try to find JSON object in response
            if not parsed_data:
                start_idx = response.find('{')
                end_idx = response.rfind('}')
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    try:
                        parsed_data = json.loads(response[start_idx:end_idx+1])
                    except:
                        pass
            # Try parsing entire response as JSON
            if not parsed_data:
                try:
                    parsed_data = json.loads(response.strip())
                except:
                    pass
            if not parsed_data or 'call_trace' not in parsed_data:
                raise ValueError("Could not extract call trace from LLM response")

            # Validate and filter call trace entries
            validated_trace = []
            repo_path = self.config.target_repo_path
            entry_function = self.vuln_info.entry_function
            crash_function = self.vuln_info.crash_function
            # Get the structured call trace
            structured_trace = parsed_data['call_trace']
            for entry in structured_trace:
                # Skip external library frames
                if entry.get('is_external', False):
                    self.logger.debug(f"      Skipping external frame: {entry.get('file_path', 'unknown')}")
                    continue

                file_path = entry.get('file_path', '')
                if not file_path:
                    self.logger.debug(f"      Skipping frame with empty file path")
                    continue

                # Construct absolute path for validation
                if os.path.isabs(file_path):
                    # If it's still an absolute path, try to make it relative
                    abs_path = file_path
                    # Try to extract relative path
                    if repo_path in file_path:
                        file_path = os.path.relpath(file_path, repo_path)
                        abs_path = os.path.join(repo_path, file_path)
                else:
                    abs_path = os.path.join(repo_path, file_path)

                # Check if file exists
                if os.path.exists(abs_path):
                    # Update entry with validated relative path
                    entry['file_path'] = file_path
                    validated_trace.append(entry)
                    # self.logger.debug(f"      ✓ Validated frame #{entry.get('sequence_num')}: {entry.get('function_name')} @ {file_path}:{entry.get('line_number')}")
                else:
                    self.logger.warning(f"      ✗ File not found for frame #{entry.get('sequence_num')}: {abs_path}")

            print(f"Vulnerable call trace before line number adjustment:")
            validated_tmp_trace = ""
            for entry in validated_trace:
                seq_num = entry.get('sequence_num', 'N/A')
                func_name = entry.get('function_name', 'N/A')
                file_path = entry.get('file_path', 'N/A')
                line_number = entry.get('line_number', 'N/A')
                validated_tmp_trace += f"#{seq_num}: {func_name} @ {file_path}:{line_number}\n"
                # print(f"#{seq_num}: {func_name} @ {file_path}:{line_number}")
            print(validated_tmp_trace)

            # Secondly, we further refine the call trace focusing on the line number adjustment.
            self.logger.info("  [VulnAnalysisAgent] Refining call trace line numbers...")
            try:
                linenum_prompt = VAA_call_trace_linenum_refine_prompt.format(
                    project_name=self.config.project_name,
                    actual_repo_path=self.config.target_repo_path,
                    current_call_trace=validated_tmp_trace
                )

                # Use LLMInterface with agent loop to refine line numbers
                self.logger.info("  [VulnAnalysisAgent] Using LLMInterface to refine line numbers...")
                result = self.drill_agent.basic_llm.run_agent_loop(
                    task=linenum_prompt,
                    tools=self.tools,
                    system_prompt=VAA_system_prompt,
                    max_iterations=10,  # Allow up to 10 rounds for checking files
                    temperature=0.1,
                    max_tokens=8192,
                    continuation_prompt="Please continue verifying line numbers using read_file and provide the final JSON output."
                )

                if not result['success']:
                    error_msg = result.get('error', 'Unknown error')
                    self.logger.warning(f"  [VulnAnalysisAgent] Line number refinement failed: {error_msg}, using original trace")
                else:
                    response = result['final_response']
                    self.logger.info(f"  [VulnAnalysisAgent] Line number refinement completed in {result['iterations']} iteration(s)")
                    # Extract JSON from response
                    refined_data = None
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
                                    refined_data = json.loads(json_str)
                                    if refined_data:
                                        break
                                except:
                                    continue
                    # Try to find JSON object in response
                    if not refined_data:
                        start_idx = response.find('{')
                        end_idx = response.rfind('}')
                        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                            try:
                                refined_data = json.loads(response[start_idx:end_idx+1])
                            except:
                                pass
                    # Try parsing entire response as JSON
                    if not refined_data:
                        try:
                            refined_data = json.loads(response.strip())
                        except:
                            pass

                    if refined_data and 'call_trace' in refined_data:
                        validated_trace = refined_data['call_trace']
                        self.logger.info(f"    ✓ Line numbers refined successfully")
                    else:
                        self.logger.warning(f"  [VulnAnalysisAgent] Could not extract refined trace from response, using original")
            except Exception as e:
                self.logger.error(f"  [VulnAnalysisAgent] Failed to refine line numbers: {e}", exc_info=True)
                self.logger.warning(f"  [VulnAnalysisAgent] Using original line numbers")

            print(f"Vulnerable call trace after line number adjustment:")
            for entry in validated_trace:
                seq_num = entry.get('sequence_num', 'N/A')
                func_name = entry.get('function_name', 'N/A')
                file_path = entry.get('file_path', 'N/A')
                line_number = entry.get('line_number', 'N/A')
                print(f"#{seq_num}: {func_name} @ {file_path}:{line_number}")
            print("")

            # Trim the call trace: from entry_function to crash_function
            trimmed_trace = validated_trace
            if validated_trace and entry_function and crash_function:
                # Find indices of entry and crash functions
                entry_idx = None
                crash_idx = None
                # Sanitizer traces are ordered from innermost (#0 = crash) to outermost (entry)
                for i, frame in enumerate(validated_trace):
                    func_name = frame.get('function_name', '')
                    if crash_idx is None and func_name == crash_function:
                        crash_idx = i
                    if func_name == entry_function:
                        entry_idx = i

                # Slice the trace if both functions found
                if crash_idx is not None and entry_idx is not None:
                    if crash_idx <= entry_idx:
                        trimmed_trace = validated_trace[crash_idx:entry_idx+1]
                        self.logger.debug(f"      Trimmed trace from frame #{crash_idx} ({crash_function}) to frame #{entry_idx} ({entry_function})")
                    else:
                        self.logger.warning(f"      Unexpected: crash_idx ({crash_idx}) > entry_idx ({entry_idx}), keeping full trace")
                elif crash_idx is not None:
                    trimmed_trace = validated_trace[crash_idx:]
                    self.logger.debug(f"      Entry function '{entry_function}' not found, keeping from crash function onwards")
                elif entry_idx is not None:
                    trimmed_trace = validated_trace[:entry_idx+1]
                    self.logger.debug(f"      Crash function '{crash_function}' not found, keeping up to entry function")
                else:
                    self.logger.warning(f"      Neither entry '{entry_function}' nor crash '{crash_function}' found in trace, keeping full trace")
            elif not entry_function or not crash_function:
                self.logger.debug("      No entry/crash function specified, keeping full trace")

            self.logger.info(f"    ✓ Transformed call trace: {len(trimmed_trace)} frames (from {len(validated_trace)} valid, {len(structured_trace)} total)")
            if entry_function and crash_function:
                self.logger.info(f"      Trimmed from entry '{entry_function}' to crash '{crash_function}'!")

            return trimmed_trace

        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed to transform call trace: {e}", exc_info=True)
            # Return empty list on failure
            return []

    def _refine_harness_command(self, project_name, actual_repo_path, raw_harness_command):
        # Refine harness command to use actual paths using LLM with tools
        # LLM: Using new LLMInterface with automatic agent loop
        try:
            # Prepare the prompt
            prompt = VAA_harness_refine_prompt.format(
                project_name=project_name,
                actual_repo_path=actual_repo_path,
                harness_command=raw_harness_command if raw_harness_command else "Not provided"
            )

            # Use LLMInterface for automatic tool calling and conversation management
            self.logger.info("  [VulnAnalysisAgent] Using LLMInterface to refine harness command...")

            result = self.drill_agent.basic_llm.run_agent_loop(
                task=prompt,
                tools=self.tools,
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
            initial_prompt = VAA_root_cause_analysis_prompt.format(
                project_name=self.config.project_name,
                actual_repo_path=self.config.target_repo_path,
                vuln_type=self.vuln_info.vuln_type,
                crash_location=self.vuln_info.refined_vuln_location,
                crash_function=self.vuln_info.crash_function,
                entry_location=self.vuln_info.entry_location,
                entry_function=self.vuln_info.entry_function,
                refined_harness_command=self.vuln_info.refined_harness_command,
                refined_call_trace=self.vuln_info.get_refined_call_trace_as_string()
            )

            # Use LLMInterface for automatic tool calling and conversation management
            self.logger.info("    Using LLMInterface for root cause analysis...")

            result = self.drill_agent.basic_llm.run_agent_loop(
                task=initial_prompt,
                tools=self.tools,
                system_prompt=VAA_system_prompt,
                max_iterations=20,  # Allow up to 20 rounds of deep analysis
                temperature=0.3,
                max_tokens=16384, # Modern LLMs can handle larger contexts.
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

@dataclass
class VulnInfo:
    """Container for vulnerability analysis information"""
    # vuln details
    # refined_vuln_location should be a relative path after the repo_name
    refined_vuln_location: str = ""  # Refined vulnerability crash location (file:line)
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
    # advanced analysis results (optional now)
    critical_branches: List[str] = field(default_factory=list)  # This can be used for the exploration phase later #TBD

    def to_dict(self) -> Dict[str, Any]:
        """Convert VulnInfo to dictionary"""
        return {
            'refined_vuln_location': self.refined_vuln_location,
            'crash_function': self.crash_function,
            'entry_location': self.entry_location,
            'entry_function': self.entry_function,
            'raw_call_trace': self.raw_call_trace,
            'call_trace': self.call_trace,
            'refined_harness_command': self.refined_harness_command,
            'binary_path': self.binary_path,
            'vuln_type': self.vuln_type,
            'root_cause': self.root_cause,
            'critical_branches': self.critical_branches
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VulnInfo':
        """Create VulnInfo instance from dictionary"""
        return cls(
            refined_vuln_location=data.get('refined_vuln_location', ''),
            crash_function=data.get('crash_function', ''),
            entry_location=data.get('entry_location', ''),
            entry_function=data.get('entry_function', ''),
            raw_call_trace=data.get('raw_call_trace', ''),
            call_trace=data.get('call_trace', []),
            refined_harness_command=data.get('refined_harness_command', ''),
            binary_path=data.get('binary_path', ''),
            vuln_type=data.get('vuln_type', ''),
            root_cause=data.get('root_cause', ''),
            critical_branches=data.get('critical_branches', [])
        )

    def format_output(self) -> str:
        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY ANALYSIS RESULTS")
        lines.append("=" * 80)
        # Section 1: Vulnerability Details
        lines.append("[VULNERABILITY DETAILS]")
        lines.append(f"  Type:              {self.vuln_type if self.vuln_type else 'N/A'}")
        lines.append(f"  Crash Location:    {self.refined_vuln_location if self.refined_vuln_location else 'N/A'}")
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
        if self.root_cause:
            lines.append("\n[ROOT CAUSE ANALYSIS]")
            # Handle multi-line root cause descriptions
            root_cause_lines = self.root_cause.split('\n')
            for rc_line in root_cause_lines:
                if rc_line.strip():
                    lines.append(f"  {rc_line}")
        # Section 5: Critical Branches (if available)
        # if self.critical_branches and len(self.critical_branches) > 0:
        #     lines.append("\n[CRITICAL BRANCHES]")
        #     for idx, branch in enumerate(self.critical_branches, 1):
        #         lines.append(f"  {idx}. {branch}")

        lines.append("=" * 80)
        # print('\n'.join(lines))
        return '\n'.join(lines)

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

