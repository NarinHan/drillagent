import json
import logging
from typing import Dict, Any, List, TYPE_CHECKING
from drillagent.prompts.VulnAnalysisAgent_prompt import (
    VAA_system_prompt,
    VAA_sanitizer_extraction_prompt,
    VAA_harness_refine_prompt,
    VAA_root_cause_analysis_prompt
)

if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent
    from drillagent.config import AgentConfig
    from drillagent.models import LLM
    from drillagent.utils.tools import AgentTool

class VulnAnalysisAgent:
    """Analyzes vulnerabilities using LLM with code exploration tools"""

    def __init__(self, drill_agent: 'DrillAgent'):
        self.drill_agent: 'DrillAgent' = drill_agent
        self.config: 'AgentConfig' = drill_agent.config
        self.logger: logging.Logger = drill_agent.logger
        self.llm: 'LLM' = drill_agent.llm
        self.tools: List['AgentTool'] = drill_agent.agent_tools

        # Vulnerability information container!!!!!
        self.vuln_info = VulnInfo()

    def run(self) -> Dict[str, Any]:
        # Run vulnerability analysis
        self.logger.info("  [VulnAnalysisAgent] Starting vulnerability analysis...")
        
        if not self.llm or not self.tools:
            self.logger.warning("  [VulnAnalysisAgent] LLM or tools not available! Return with nothing.")
            return self._generate_results()
        
        # The analysis is based on the following basic information.
        project_name     = self.config.project_name
        actual_repo_path = self.config.target_repo_path
        sanitizer_report = self.config.sanitizer_report
        # vuln_location    = self.config.vuln_location    # won't use
        harness_command  = self.config.harness_command
        self.logger.info(f"  [VulnAnalysisAgent] Actual repo path: {len(actual_repo_path)}.")
        
        # Substep1: Extract basic vulnerability information
        if len(sanitizer_report) > 0:
            self.logger.info(f"  [VulnAnalysisAgent] Extracting basic vulnerability information...")
            self.logger.info(f"  [VulnAnalysisAgent] Sanitizer report: {len(sanitizer_report)} chars.")
            self._extract_sanitizer_report(project_name, actual_repo_path, sanitizer_report)
            # 
        
        # Substep2: Refine harness command
        self.logger.info("  [VulnAnalysisAgent] Refining harness command...")
        self._refine_harness_command(project_name, actual_repo_path, harness_command)
        # 

        # Substep3: Perform root cause analysis
        # self.logger.info("  [VulnAnalysisAgent] Performing root cause analysis...")
        # self._root_cause_analysis()
        # LHY: Currently we skip this step to save cost and time.
        
        return self._generate_results()

    def store_to_cache(self, cache_dir: str):
        pass

    def _extract_sanitizer_report(self, project_name, actual_repo_path, sanitizer_report):
        """Extract vulnerability information from sanitizer report using LLM with tools"""
        try:
            # Prepare the prompt
            prompt = VAA_sanitizer_extraction_prompt.format(
                project_name=project_name,
                actual_repo_path=actual_repo_path,
                sanitizer_report=sanitizer_report
            )

            # Call LLM with tools - no tools needed for simple extraction
            self.logger.info("    Calling LLM to extract sanitizer report information...")

            # First try without tools - simple extraction
            response = self.llm.generate(
                prompt=prompt,
                system_prompt=VAA_system_prompt,
                temperature=0.1,  # Low temperature for precise extraction
                max_tokens=4096
            )

            # Check if we need tools (if response doesn't contain JSON)
            has_json = '{' in response and '}' in response

            if not has_json:
                # Retry with tools if first attempt failed
                response, tool_calls = self.llm.generate_with_tools(
                    prompt=prompt,
                    tools=self.tools,
                    system_prompt=VAA_system_prompt,
                    temperature=0.1,
                    max_tokens=4096
                )
            else:
                tool_calls = None

            # Execute any tool calls if needed
            if tool_calls and len(tool_calls) > 0:
                self.logger.info(f"    Executing {len(tool_calls)} tool calls...")
                for tool_call in tool_calls:
                    tool_name = tool_call.get('name')
                    tool_args = tool_call.get('arguments', {})
                    self.logger.debug(f"      {tool_name}({json.dumps(tool_args)})")

                    for tool in self.tools:
                        if tool.name() == tool_name:
                            try:
                                result = tool.execute(**tool_args)
                                self.logger.debug(f"      Result: {str(result)[:200]}")
                            except Exception as e:
                                self.logger.error(f"      Tool error: {e}")
                            break

                # Get final response after tool execution
                follow_up_prompt = f"""Based on the file verification results above, now extract the vulnerability information from the sanitizer report.

Provide your response in the following JSON format ONLY:
{{
    "vuln_type": "the vulnerability type",
    "crash_function": "innermost function IN REPOSITORY CODE (not libc)",
    "refined_vuln_location": "relative/path/file.c:line_number",
    "entry_function": "main or other entry function",
    "call_trace": "full stack trace starting with #0..."
}}"""

                response, _ = self.llm.generate_with_tools(
                    prompt=follow_up_prompt,
                    tools=self.tools,
                    system_prompt=VAA_system_prompt,
                    temperature=0.1,
                    max_tokens=2048
                )

            # Parse JSON response
            self.logger.info(f"    LLM Response: {response[:300]}...")

            # Extract JSON from response (handle multiple formats)
            extracted_info = None

            # Try to extract JSON from markdown code block
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
            self.vuln_info.call_trace = extracted_info.get('call_trace', '')

            self.logger.info(f"    ✓ Extracted vulnerability information:")
            self.logger.info(f"      Type: {self.vuln_info.vuln_type}")
            self.logger.info(f"      Crash: {self.vuln_info.crash_function} @ {self.vuln_info.refined_vuln_location}")
            self.logger.info(f"      Entry: {self.vuln_info.entry_function}")

        except Exception as e:
            self.logger.error(f"    Failed to extract sanitizer report: {e}", exc_info=True)
            # Fallback to basic extraction
            self.vuln_info.vuln_type = self._extract_vuln_type_basic(sanitizer_report)
            self.vuln_info.call_trace = self._extract_call_trace_basic(sanitizer_report)
            crash_info = self._extract_crash_info_basic(sanitizer_report)
            if crash_info:
                self.vuln_info.crash_function = crash_info.get('function', '')
                self.vuln_info.refined_vuln_location = crash_info.get('location', '')
            if 'main' in self.vuln_info.call_trace.lower():
                self.vuln_info.entry_function = 'main'

    def _refine_harness_command(self, project_name, actual_repo_path, harness_command):
        """Refine harness command to use actual paths using LLM with tools"""
        try:
            # Prepare the prompt
            prompt = VAA_harness_refine_prompt.format(
                project_name=project_name,
                actual_repo_path=actual_repo_path,
                harness_command=harness_command if harness_command else "Not provided"
            )

            # Call LLM with tools - allow multiple rounds for exploration
            self.logger.info("    Calling LLM to refine harness command...")
            max_rounds = 3
            current_prompt = prompt

            for round_num in range(max_rounds):
                self.logger.info(f"      [Round {round_num + 1}/{max_rounds}]")

                response, tool_calls = self.llm.generate_with_tools(
                    prompt=current_prompt,
                    tools=self.tools,
                    system_prompt=VAA_system_prompt,
                    temperature=0.2,
                    max_tokens=4096
                )

                # If no tool calls, LLM is done
                if not tool_calls:
                    self.logger.info(f"      LLM finished refining harness command")
                    break

                # Execute tool calls
                self.logger.info(f"      Executing {len(tool_calls)} tool calls...")
                tool_results = []
                for tool_call in tool_calls:
                    tool_name = tool_call.get('name')
                    tool_args = tool_call.get('arguments', {})
                    self.logger.debug(f"        {tool_name}({json.dumps(tool_args)})")

                    for tool in self.tools:
                        if tool.name() == tool_name:
                            try:
                                result = tool.execute(**tool_args)
                                tool_results.append(result)
                                self.logger.debug(f"        Result: {str(result)[:200]}")
                            except Exception as e:
                                self.logger.error(f"        Tool error: {e}")
                            break

                # Prepare next round prompt
                current_prompt = f"""Previous tool results:
{json.dumps(tool_results, indent=2)[:1500]}

Now provide the final refined harness information in JSON format:
{{
    "binary_path": "absolute/path/to/binary",
    "refined_harness_command": "concrete executable command"
}}"""

            # Parse JSON response
            self.logger.info(f"    LLM Response: {response[:300]}...")

            # Extract JSON from response
            refined_info = None

            # Try to extract JSON from markdown code block
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
            self.logger.error(f"    Failed to refine harness command: {e}", exc_info=True)
            # Fallback: use original harness command
            self.vuln_info.refined_harness_command = harness_command if harness_command else ""
            # Try to extract binary path from original command
            if harness_command:
                parts = harness_command.split()
                if parts:
                    self.vuln_info.binary_path = parts[0]

    def _root_cause_analysis(self):
        """Perform root cause analysis using LLM with tools"""
        try:
            # Prepare the prompt
            prompt = VAA_root_cause_analysis_prompt.format(
                project_name=self.config.project_name,
                vuln_type=self.vuln_info.vuln_type,
                refined_vuln_location=self.vuln_info.refined_vuln_location,
                crash_function=self.vuln_info.crash_function,
                entry_function=self.vuln_info.entry_function,
                sanitizer_report=self.config.sanitizer_report[:2000]  # Truncate for brevity
            )

            # Call LLM with tools - allow multiple rounds for deep analysis
            self.logger.info("    Calling LLM for root cause analysis...")
            max_rounds = 5
            current_prompt = prompt
            all_responses = []

            for round_num in range(max_rounds):
                self.logger.info(f"      [Round {round_num + 1}/{max_rounds}]")

                response, tool_calls = self.llm.generate_with_tools(
                    prompt=current_prompt,
                    tools=self.tools,
                    system_prompt=VAA_system_prompt,
                    temperature=0.3,
                    max_tokens=4096
                )

                self.logger.info(f"      LLM Response: {response[:200]}...")
                all_responses.append(response)

                # If no tool calls, LLM is done with analysis
                if not tool_calls:
                    self.logger.info(f"      LLM finished root cause analysis")
                    self.vuln_info.root_cause = response
                    break

                # Execute tool calls
                self.logger.info(f"      Executing {len(tool_calls)} tool calls...")
                tool_results = []
                for tool_call in tool_calls:
                    tool_name = tool_call.get('name')
                    tool_args = tool_call.get('arguments', {})
                    self.logger.debug(f"        {tool_name}({json.dumps(tool_args)})")

                    for tool in self.tools:
                        if tool.name() == tool_name:
                            try:
                                result = tool.execute(**tool_args)
                                tool_results.append(result)
                                # Show preview of result
                                if result.get('success') and 'content' in result:
                                    lines = result['content'].split('\n')[:5]
                                    self.logger.debug(f"        Result preview: {chr(10).join(lines)}")
                            except Exception as e:
                                self.logger.error(f"        Tool error: {e}")
                            break

                # Prepare next round prompt
                current_prompt = f"""Based on the code you examined, continue your root cause analysis.

Tool results:
{json.dumps(tool_results, indent=2)[:3000]}

Provide your complete root cause analysis explanation."""

            # Use last response as root cause if not set
            if not self.vuln_info.root_cause and all_responses:
                self.vuln_info.root_cause = all_responses[-1]

            self.logger.info(f"    ✓ Root cause analysis complete")
            self.logger.info(f"      Analysis: {self.vuln_info.root_cause[:200]}...")

        except Exception as e:
            self.logger.error(f"    Failed to perform root cause analysis: {e}", exc_info=True)
            self.vuln_info.root_cause = f"Root cause analysis failed: {e}"

    def _extract_call_trace_basic(self, report: str) -> str:
        """Fallback: Extract stack trace lines from sanitizer report"""
        lines = []
        for line in report.split('\n'):
            stripped = line.strip()
            if stripped and stripped[0] == '#' and len(stripped) > 1:
                # Check if next char is a digit
                if stripped[1].isdigit():
                    lines.append(stripped)
        return '\n'.join(lines)

    def _extract_vuln_type_basic(self, report: str) -> str:
        """Fallback: Extract vulnerability type from sanitizer report"""
        report_lower = report.lower()
        types = {
            'heap-use-after-free': 'heap-use-after-free',
            'heap-buffer-overflow': 'heap-buffer-overflow',
            'stack-buffer-overflow': 'stack-buffer-overflow',
            'use-after-return': 'use-after-return',
            'double-free': 'double-free',
        }
        for pattern, vtype in types.items():
            if pattern in report_lower:
                return vtype
        return "Unknown"

    def _extract_crash_info_basic(self, report: str) -> Dict[str, str]:
        """Fallback: Extract crash function and location from #0 frame"""
        for line in report.split('\n'):
            stripped = line.strip()
            # Look for #0 line
            if not (stripped.startswith('#0') and ' in ' in stripped):
                continue

            # Extract function name (after " in " and before next space)
            in_pos = stripped.find(' in ')
            if in_pos == -1:
                continue

            after_in = stripped[in_pos + 4:]  # Skip " in "
            parts = after_in.split()
            if not parts:
                continue

            function = parts[0]

            # Look for file path (contains :line_number)
            for part in parts[1:]:
                if ':' in part:
                    # Split by : to get file and line number
                    file_parts = part.split(':')
                    if len(file_parts) >= 2:
                        file_path = file_parts[0]
                        line_num = file_parts[1]

                        # Get relative path by finding common project directories
                        path_parts = file_path.split('/')
                        for i, p in enumerate(path_parts):
                            if p in ['src', 'lib', 'include', 'core', 'mrbgems', 'test']:
                                rel_path = '/'.join(path_parts[i:])
                                return {'function': function, 'location': f"{rel_path}:{line_num}"}

                        # Fallback: last 2 parts
                        if len(path_parts) >= 2:
                            rel_path = '/'.join(path_parts[-2:])
                        else:
                            rel_path = path_parts[-1] if path_parts else file_path

                        return {'function': function, 'location': f"{rel_path}:{line_num}"}

        return {}

    def _generate_results(self) -> Dict[str, Any]:
        # Generate final results
        return self.vuln_info.to_dict()


class VulnInfo:
    # Container for vulnerability analysis information
    def __init__(self):        
        # vuln details
        # refined_vuln_location should be a relative path after the repo_name
        self.refined_vuln_location: str = ""  # Refined vulnerability crash location after analysis
        self.entry_function:        str = ""  # Entry function leading to the vulnerability (usually the main function of the project)
        self.crash_function:        str = ""  # Function in which the crash occurs (i.e., the caller of the sink point)
        self.call_trace:            str = ""  # Call trace leading to the vulnerability (now we only consider CVEs with crash call traces)
        # harness details
        self.refined_harness_command: str = ""  # Refined harness command #TBD
        self.binary_path:             str = ""  # Path to the binary to be analyzed #TBD
        # vuln semantics
        self.vuln_type:  str = ""  # Type of vulnerability (e.g., buffer overflow, use-after-free)
        self.root_cause: str = ""  # Root cause analysis result
        # advanced analysis results (optional now)
        self.critical_branches: List[str] = []  # This can be used for the exploration phase later #TBD

    def to_dict(self) -> Dict[str, Any]:
        """Convert VulnInfo to dictionary"""
        return {
            'refined_vuln_location': self.refined_vuln_location,
            'entry_function': self.entry_function,
            'crash_function': self.crash_function,
            'call_trace': self.call_trace,
            'refined_harness_command': self.refined_harness_command,
            'binary_path': self.binary_path,
            'vuln_type': self.vuln_type,
            'root_cause': self.root_cause,
            'critical_branches': self.critical_branches
        }

