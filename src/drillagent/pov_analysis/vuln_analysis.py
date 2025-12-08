import re
import json
from typing import Dict, Any, List

class VulnAnalysisAgent:
    """Analyzes vulnerabilities using LLM with code exploration tools"""
    
    def __init__(self, drill_agent):
        self.drill_agent = drill_agent
        self.config = drill_agent.config
        self.logger = drill_agent.logger
        self.llm = drill_agent.llm
        self.tools = drill_agent.agent_tools

        # output fields
        # refined_vuln_location should be a relative path starting with repo_name
        self.refined_vuln_location: str = ""  # Refined vulnerability location after analysis
        self.refined_harness_command: str = ""  # Refined harness command #TBD
        self.binary_path: str = ""  # Path to the binary to be analyzed #TBD
        self.call_trace: str = ""  # Call trace leading to the vulnerability (now we only consider CVEs with crash call traces)
        # vuln details
        self.entry_function: str = ""  # Entry function leading to the vulnerability (usually the main function of the project)
        self.crash_function: str = ""  # Function in which the crash occurs (i.e., the caller of the sink point)
        self.vuln_type: str = ""  # Type of vulnerability (e.g., buffer overflow, use-after-free)
        self.root_cause: str = ""  # Root cause analysis result
        # advanced analysis results (optional now)
        self.critical_branches: List[str] = []  # This can be used for the exploration phase later #TBD

    def run(self) -> Dict[str, Any]:
        # Run vulnerability analysis
        self.logger.info("  [VulnAnalysisAgent] Starting vulnerability analysis...")
        
        if not self.llm or not self.tools:
            self.logger.warning("  [VulnAnalysisAgent] LLM or tools not available")
            return self._generate_results()
        
        sanitizer_report = self.config.sanitizer_report or ""
        if not sanitizer_report:
            self.logger.warning("  [VulnAnalysisAgent] No sanitizer report provided!")
            return self._generate_results()
        self.logger.info(f"  [VulnAnalysisAgent] Sanitizer report: {len(sanitizer_report)} chars")
        
        # Extract info from sanitizer report
        self.call_trace = self._extract_call_trace(sanitizer_report)
        self.vuln_type = self._extract_vuln_type(sanitizer_report)
        crash_info = self._extract_crash_info(sanitizer_report)
        
        if crash_info:
            self.crash_function = crash_info.get('function', '')
            self.refined_vuln_location = crash_info.get('location', '')
            if 'main' in self.call_trace.lower():
                self.entry_function = 'main'
        
        self.logger.info(f"  [VulnAnalysisAgent] Extracted: {self.vuln_type} @ {self.refined_vuln_location}")
        
        # Simple LLM prompt for root cause analysis
        system_prompt = """You are a security researcher. Analyze the sanitizer report and source code to explain the vulnerability's root cause.

When using tools, use RELATIVE paths (e.g., src/vm.c NOT /absolute/path/src/vm.c)."""

        analysis_prompt = f"""Below is a sanitizer report for a vulnerability:

{sanitizer_report}

The crash occurs at: {self.refined_vuln_location} in function {self.crash_function}

Examine the source code and explain:
1. What causes this {self.vuln_type} vulnerability?
2. Why does the memory become invalid?
3. What is the root cause?

Use read_file to examine {self.refined_vuln_location.split(':')[0]} around line {self.refined_vuln_location.split(':')[1] if ':' in self.refined_vuln_location else '0'}, then provide your analysis."""

        try:
            # Multi-round analysis - LLM explores until it understands
            max_rounds = 5
            current_prompt = analysis_prompt
            all_responses = []
            
            for round_num in range(max_rounds):
                self.logger.info(f"\n{'='*60}")
                self.logger.info(f"  [Round {round_num + 1}/{max_rounds}] Calling LLM...")
                self.logger.info(f"{'='*60}\n")
                
                response, tool_calls = self.llm.generate_with_tools(
                    prompt=current_prompt,
                    tools=self.tools,
                    system_prompt=system_prompt,
                    temperature=0.3,
                    max_tokens=4096
                )
                
                self.logger.info(f"[LLM Response]: {response}\n")
                all_responses.append(response)
                
                # If no tool calls, LLM is done with analysis
                if not tool_calls:
                    self.logger.info(f"[Round {round_num + 1}] LLM finished - no more tools needed")
                    self.root_cause = response
                    break
                
                # Execute tools
                self.logger.info(f"[Executing {len(tool_calls)} tools...]")
                tool_results = []
                
                for tool_call in tool_calls:
                    tool_name = tool_call.get('name')
                    tool_args = tool_call.get('arguments', {})
                    
                    self.logger.info(f"  {tool_name}({json.dumps(tool_args)})")
                    
                    for tool in self.tools:
                        if tool.name() == tool_name:
                            try:
                                result = tool.execute(**tool_args)
                                tool_results.append(result)
                                
                                # Show preview
                                if result.get('success') and 'content' in result:
                                    lines = result['content'].split('\n')[:10]
                                    self.logger.info(f"  Result: {chr(10).join(lines)}\n")
                                elif result.get('success') and 'matches' in result:
                                    matches = result['matches']
                                    self.logger.info(f"  Found {len(matches)} matches")
                                    for m in matches[:3]:
                                        if isinstance(m, dict):
                                            self.logger.info(f"    {m.get('file')}:{m.get('line')}")
                                        else:
                                            self.logger.info(f"    {m}")
                            except Exception as e:
                                self.logger.error(f"  Error: {e}")
                            break
                
                # Prepare next round prompt - KEEP sanitizer report context!
                tool_results_summary = []
                for tr in tool_results:
                    if tr.get('success'):
                        if 'content' in tr:
                            tool_results_summary.append(f"read_file: Got {len(tr['content'].split(chr(10)))} lines of code")
                        elif 'matches' in tr:
                            tool_results_summary.append(f"grep_code: Found {len(tr.get('matches', []))} matches")
                        else:
                            tool_results_summary.append(f"Tool returned: {str(tr)[:100]}")
                
                current_prompt = f"""SANITIZER REPORT (for context):
```
{sanitizer_report[:1000]}... (truncated)
```

Previous tools called: {', '.join(tool_results_summary)}

Tool results:
{json.dumps(tool_results, indent=2)[:2000]}

Based on the code you examined and the sanitizer report above, provide your root cause analysis.

Explain what causes the {self.vuln_type} at {self.refined_vuln_location} in {self.crash_function}."""

            # Use last response as root cause
            if not self.root_cause and all_responses:
                self.root_cause = all_responses[-1]
            
            # Log final analysis
            if self.root_cause:
                self.logger.info(f"\n{'='*60}")
                self.logger.info("[ROOT CAUSE ANALYSIS]")
                self.logger.info(f"{'='*60}")
                self.logger.info(self.root_cause)
                self.logger.info(f"{'='*60}\n")
            
            self.logger.info("  [VulnAnalysisAgent] ✓ Complete")
            self.logger.info(f"    Type: {self.vuln_type}")
            self.logger.info(f"    Crash: {self.crash_function}")
            self.logger.info(f"    Entry: {self.entry_function}")
            self.logger.debug(f"    Call Trace: {self.call_trace}")   
            
        except Exception as e:
            self.logger.error(f"  [VulnAnalysisAgent] Failed: {e}", exc_info=True)
            self.root_cause = f"Analysis failed: {e}"
        
        return self._generate_results()

    def _extract_call_trace(self, report: str) -> str:
        """Extract stack trace lines from sanitizer report"""
        lines = []
        for line in report.split('\n'):
            if re.match(r'^\s*#\d+', line.strip()):
                lines.append(line.strip())
        return '\n'.join(lines)
    
    def _extract_vuln_type(self, report: str) -> str:
        """Extract vulnerability type from sanitizer report"""
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
    
    def _extract_crash_info(self, report: str) -> Dict[str, str]:
        """Extract crash function and location from #0 frame"""
        for line in report.split('\n'):
            # Match: #0 0xADDR in function_name /path/file.c:line:col
            match = re.search(r'#0.*?in\s+(\S+)\s+(.+?):(\d+)', line)
            if match:
                function = match.group(1)
                file_path = match.group(2)
                line_num = match.group(3)
                
                # Get relative path: /home/fuzz/proj/src/vm.c -> src/vm.c
                parts = file_path.split('/')
                # Find common project paths (src, lib, include, etc.)
                for i, part in enumerate(parts):
                    if part in ['src', 'lib', 'include', 'core', 'mrbgems']:
                        rel_path = '/'.join(parts[i:])
                        return {'function': function, 'location': f"{rel_path}:{line_num}"}
                
                # Fallback: last 2 parts
                rel_path = '/'.join(parts[-2:]) if len(parts) >= 2 else parts[-1]
                return {'function': function, 'location': f"{rel_path}:{line_num}"}
        
        return {}
    
    def _generate_results(self) -> Dict[str, Any]:
        """Generate final results"""
        return {
            'refined_vuln_location': self.refined_vuln_location,
            'refined_harness_command': "",
            'binary_path': "",
            'call_trace': self.call_trace,
            'entry_function': self.entry_function,
            'crash_function': self.crash_function,
            'vuln_type': self.vuln_type,
            'root_cause': self.root_cause,
            'critical_branches': self.critical_branches
        }
