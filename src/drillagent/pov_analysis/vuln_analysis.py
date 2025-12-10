import json
import logging
from typing import Dict, Any, List, TYPE_CHECKING
from dataclasses import dataclass, field
from drillagent.prompts.VulnAnalysisAgent_prompt import (
    VAA_system_prompt,
    VAA_sanitizer_extraction_prompt,
    VAA_sanitizer_followup_prompt,
    VAA_harness_refine_prompt,
    VAA_harness_followup_prompt,
    VAA_root_cause_analysis_prompt
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
        self.llm: 'LLM' = drill_agent.llm
        self.tools: List['AgentTool'] = drill_agent.agent_tools

        # Vulnerability information container!!!!!
        self.vuln_info = VulnInfo()

    def run(self) -> 'VulnInfo':
        # Run vulnerability analysis
        self.logger.info("  [VulnAnalysisAgent] Starting vulnerability analysis...")

        if not self.llm or not self.tools:
            self.logger.warning("  [VulnAnalysisAgent] LLM or tools not available! Return with nothing.")
            return self.vuln_info
        
        # The analysis is based on the following basic information.
        project_name     = self.config.project_name
        actual_repo_path = self.config.target_repo_path
        sanitizer_report = self.config.sanitizer_report
        # raw_vuln_location    = self.config.vuln_location    # won't use
        raw_harness_command  = self.config.harness_command
        self.logger.info(f"  [VulnAnalysisAgent] Actual repo path: {len(actual_repo_path)}.")
        
        # Substep1: Extract basic vulnerability information (if sanitizer report is available)
        # TODO: call_trace structure should be easier to use. And raw_vuln_location could be used for cross checking.
        if len(sanitizer_report) > 0:
            self.logger.info(f"  [VulnAnalysisAgent] Extracting basic vulnerability information...")
            self.logger.info(f"  [VulnAnalysisAgent] Sanitizer report: {len(sanitizer_report)} chars.")
            self._extract_sanitizer_report(project_name, actual_repo_path, sanitizer_report)
            # TODO: Need to transform raw call trace to structured format, for the following PathExplorationAgent.
            if len(self.vuln_info.raw_call_trace) > 0:
                 self.vuln_info.call_trace = self.transform_raw_call_trace(self.vuln_info.raw_call_trace)
            # 
        
        # Substep2: Refine harness command
        # TODO: raw_harness_command could be used for cross checking.
        if raw_harness_command and len(raw_harness_command) > 0:
            self.logger.info(f"  [VulnAnalysisAgent] Refining harness command...")
            self.logger.info(f"  [VulnAnalysisAgent] Raw harness command: {raw_harness_command}")
            self._refine_harness_command(project_name, actual_repo_path, raw_harness_command)
            # 

        # Substep3: Perform root cause analysis
        # self.logger.info("  [VulnAnalysisAgent] Performing root cause analysis...")
        # self._root_cause_analysis()
        # LHY: Currently we skip this step to save cost and time.

        return self.vuln_info

    def store_to_cache(self, cache_dir: str):
        pass

    def _extract_sanitizer_report(self, project_name, actual_repo_path, sanitizer_report):
        # Extract vulnerability information from sanitizer report using LLM with tools
        try:
            # Prepare the prompt
            prompt = VAA_sanitizer_extraction_prompt.format(
                project_name=project_name,
                actual_repo_path=actual_repo_path,
                sanitizer_report=sanitizer_report
            )

            # First try without tools - simple extraction
            self.logger.info("  [VulnAnalysisAgent] Calling LLM to extract sanitizer report information...")
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
                self.logger.info(f"  [VulnAnalysisAgent] Executing {len(tool_calls)} tool calls...")
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
                response, _ = self.llm.generate_with_tools(
                    prompt=VAA_sanitizer_followup_prompt,
                    tools=self.tools,
                    system_prompt=VAA_system_prompt,
                    temperature=0.1,
                    max_tokens=2048
                )

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

    def _refine_harness_command(self, project_name, actual_repo_path, raw_harness_command):
        # Refine harness command to use actual paths using LLM with tools
        try:
            # Prepare the prompt
            prompt = VAA_harness_refine_prompt.format(
                project_name=project_name,
                actual_repo_path=actual_repo_path,
                harness_command=raw_harness_command if raw_harness_command else "Not provided"
            )

            # Call LLM with tools - allow multiple rounds for exploration
            self.logger.info("  [VulnAnalysisAgent] Calling LLM to refine harness command...")
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
                # print(f"Round {round_num+1} Response: {response[:300]}...") # debug

                # If no tool calls, LLM is done
                if not tool_calls:
                    self.logger.info(f"  [VulnAnalysisAgent] Found no more tool calls. LLM finished refining harness command")
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
                # print(f"Round {round_num+1} Tool Results: {tool_results}") # debug
                current_prompt = VAA_harness_followup_prompt.format(
                    project_name=project_name,
                    actual_repo_path=actual_repo_path,
                    harness_command=raw_harness_command,
                    tool_results=json.dumps(tool_results, indent=2)[:1500]
                )

            self.logger.info(f"  [VulnAnalysisAgent] LLM Final Response (after {round_num + 1} rounds): {response[:300]}...")

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
        """Perform root cause analysis using LLM with tools"""
        try:
            # Prepare the prompt
            prompt = VAA_root_cause_analysis_prompt.format(
                project_name=self.config.project_name,
                vuln_type=self.vuln_info.vuln_type,
                refined_vuln_location=self.vuln_info.refined_vuln_location,
                crash_function=self.vuln_info.crash_function,
                entry_location=self.vuln_info.entry_location,
                entry_function=self.vuln_info.entry_function,
                sanitizer_report=self.config.sanitizer_report[:2000]  # Truncate for brevity
            )

            # Call LLM with tools - allow multiple rounds for deep analysis
            self.logger.info("    Calling LLM for root cause analysis...")
            max_rounds = 10
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

    def transform_raw_call_trace(self, raw_call_trace: str) -> List[Any]:
        # Transform raw call trace string to structured format
        structured_trace = []


@dataclass
class VulnInfo:
    """Container for vulnerability analysis information"""
    # vuln details
    # refined_vuln_location should be a relative path after the repo_name
    refined_vuln_location: str = ""  # Refined vulnerability crash location (file:line)
    crash_function: str = ""  # Function in which the crash occurs (i.e., the caller of the sink point)
    entry_location: str = ""  # Entry location (file:line)
    entry_function: str = ""  # Entry function leading to the vulnerability (usually the main function of the project)
    raw_call_trace: str = ""
    call_trace: List[Any] = field(default_factory=list)  # Call trace leading to the vulnerability (now we only consider CVEs with crash call traces)
    # harness details
    refined_harness_command: str = ""  # Refined harness command #TBD
    binary_path: str = ""  # Path to the binary to be analyzed #TBD
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
            'refined_harness_command': self.refined_harness_command,
            'binary_path': self.binary_path,
            'vuln_type': self.vuln_type,
            'root_cause': self.root_cause,
            'critical_branches': self.critical_branches
        }

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
        if self.raw_call_trace:
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
        print('\n'.join(lines))
        return '\n'.join(lines)
