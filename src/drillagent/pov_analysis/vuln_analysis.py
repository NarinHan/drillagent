from drillagent.drill_agent import DrillAgent
from typing import Dict, Any, List

class VulnAnalysisAgent:
    # Responsible for analyzing the basic information and root cause of vulnerabilities
    def __init__(self, drill_agent:DrillAgent):
        self.drill_agent = drill_agent
        self.config = drill_agent.config
        self.logger = drill_agent.logger

        # output fields
        self.refined_vuln_location: str = ""  # Refined vulnerability location after analysis
        self.refined_harness_command: str = ""  # Refined harness command
        self.binary_path: str = ""  # Path to the binary to be analyzed
        self.call_trace: str = ""  # Call trace leading to the vulnerability
        # vuln details
        self.entry_function: str = ""  # Entry function leading to the vulnerability (usually the main function of the project)
        self.crash_function: str = ""  # Function in which the crash occurs (i.e., the caller of the sink point)
        self.vuln_type: str = ""  # Type of vulnerability (e.g., buffer overflow, use-after-free)
        self.root_cause: str = ""  # Root cause analysis result
        # advanced analysis results (optional now)
        self.critical_branches: List[str] = []  # This can be used for the exploration phase later




