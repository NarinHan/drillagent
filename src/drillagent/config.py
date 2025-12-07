#!/usr/bin/env python3
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

@dataclass
class AgentConfig:
    # Input configuration for DrillAgent (for a single CVE task)

    # 
    # PoV task information
    # 
    project_name: Optional[str] = None                    
    cve_id: Optional[str] = None            # CVE identifier, if applicable
    lang: Optional[str] = None              # Programming language of the project

    target_repo_path: str = ""              # Path to the target source repository (with .git/)
    vuln_location: str = ""                 # Location of the vulnerability in the source code (file:line)
    base_commit: str = ""                   # Necessary to checkout the correct commit.
    build_sh: Optional[str] = None          # If not provided, reasoning by ourselves.
    harness_command: Optional[str] = None   # If not provided, reasoning by ourselves.
    sanitizer_report: Optional[str] = None  # If not provided (no call trace), we have to conduct control/data flow analysis.

    # 
    # LLM configuration
    # 
    model_provider: str = "openai"  # claude or openai
    model_name: str = "gpt-4o-2024-05-13"
    api_key: Optional[str] = None

    # 
    # Ablation options
    # 
    # By default, we will conduct all the inplemented analyses.
    disable_program_instrumentation: bool    = False
    disable_vuln_root_cause_analysis: bool   = False
    disable_project_structure_analysis: bool = False
    disable_coverage_feedback: bool          = False
    disable_crash_trigger_analysis: bool     = False
    disable_advanced_agent_tools: bool       = False # To be discussed
    disable_in_context_rl: bool              = False # To be discussed
    # Instrumentation options are not needed (LHY: The instrumentation choice should be fixed by us.)

    #
    # Analysis options
    #
    max_iterations: int = 10
    timeout: int = 1200  # in seconds # 20mins

    # Instrumentation options
    enable_coverage: bool = False   # Enable coverage instrumentation
    enable_distance: bool = False   # Enable distance calculation for guided fuzzing
    enable_sanitizer: bool = False  # Enable memory sanitizer

    # 
    # Output options
    # 
    work_dir: str = "./workspace"
    output_dir: str = "./output"
    verbose: bool = False
    # TODO: logging level?

    # Used to process the parameters right after initialization
    def __post_init__(self):
        # Check necessary fields
        if not self.target_repo_path:
            raise ValueError("target_repo_path is required")
        # if not self.vuln_location:
        #     raise ValueError("vuln_location is required")
        # if not self.base_commit:
        #     raise ValueError("base_commit is required")

        # Validate and normalize paths
        self.target_repo_path = str(Path(self.target_repo_path).resolve())
        self.output_dir = str(Path(self.output_dir).resolve())
        self.work_dir = str(Path(self.work_dir).resolve())


