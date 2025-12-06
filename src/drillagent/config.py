#!/usr/bin/env python3
"""
Configuration Module for DrillAgent
"""

from pathlib import Path
from typing import Optional
from dataclasses import dataclass


@dataclass
class AgentConfig:
    # Input configuration for DrillAgent (for a single CVE task)

    # 
    # PoV task information
    # 
    target_repo_path: str                   # Path to the target source repository (with .git/)
    project_name: Optional[str] = None                    
    cve_id: Optional[str] = None            # CVE identifier, if applicable
    lang: Optional[str] = None              # Programming language of the project

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

    # Instrumentation options (LHY: The instrumentation choice should be fixed by us.)

    #
    # Analysis options
    # 
    max_iterations: int = 10
    timeout: int = 1200  # in seconds # 20mins

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
        self.output_dir = str(Path(self.output_dir).resolve())
        self.work_dir = str(Path(self.work_dir).resolve())


