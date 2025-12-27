#!/usr/bin/env python3
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

@dataclass
class AgentConfig:
    # Input configuration for DrillAgent (for a single CVE task)
    # This dataclass should be benchmark-agnostic.

    # 
    # PoV task information
    # 
    project_name: Optional[str] = None
    cve_id: Optional[str] = None            # CVE identifier, if applicable
    lang: Optional[str] = None              # Programming language of the project

    target_repo_path: str = ""              # Actual path to the target source repository (with .git/) (should exactly exist in your local machine)
    vuln_location: str = ""                 # Location of the vulnerability in the source code (file:line)
    base_commit: str = ""                   # Necessary to checkout the correct commit.
    build_sh: Optional[str] = None          # If not provided, reasoning by ourselves.
    harness_command: Optional[str] = None   # If not provided, reasoning by ourselves.
    sanitizer_report: Optional[str] = None  # If not provided (no call trace), we have to conduct control/data flow analysis.

    # 
    # LLM configuration
    # 
    # General-purpose LLM model (may have latent reasoning capabilities).
    model_provider: str = "openai"  # claude or openai
    model_name: str = "gpt-5.1-2025-11-13"
    api_key: Optional[str] = None
    # TODO: Provide more specific model configurations.
    reasoning_model : tuple = ("", "")
    low_cost_model  : tuple = ("", "") # (provider, model name)

    # 
    # Ablation options
    # 
    # By default, we will conduct all the inplemented analyses.
    disable_program_instrumentation: bool    = False
    disable_vulnerability_analysis: bool     = False
    disable_project_structure_analysis: bool = False
    # TODO: Some options are too redundant and should be removed.
    disable_path_exploration: bool           = False
    disable_pov_generation: bool             = False
    disable_coverage_feedback: bool          = False
    disable_crash_trigger_analysis: bool     = False
    disable_advanced_agent_tools: bool       = False # To be discussed
    disable_in_context_rl: bool              = False # To be discussed
    # More fine-grained ablation options can be added here.
    disable_root_cause_analysis: bool        = False
    # Instrumentation options are not needed (LHY: The instrumentation choice should be fixed by us.)

    #
    # Analysis options
    #
    max_iterations: int = 10
    timeout: int = 1200  # in seconds # 20mins

    # 
    # Output options
    # 
    work_dir: str = "./workspace" # Including: Intermidiate results in each round and cache dir.
    output_dir: str = "./output"  # Including: Final PoV inputs and analysis logs.
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

    def print_config(self):
        print("=" * 80)
        print("Agent Configuration")
        print("=" * 80)

        print("[PoV Task Information]")
        print(f"  Project Name:       {self.project_name}")
        print(f"  CVE ID:             {self.cve_id}")
        # print(f"  Language:           {self.lang}")
        print(f"  Target Repo Path:   {self.target_repo_path}")
        print(f"  Vuln Locatio   (raw):    {self.vuln_location}")
        print(f"  Harness Command(raw):    {self.harness_command}")
        print(f"  Base Commit:        {self.base_commit}")
        # print(f"  Build Script:       {self.build_sh}")
        # print(f"  Sanitizer Report:   {self.sanitizer_report}")

        # print("\n[LLM Configuration]")
        # print(f"  Model Provider:     {self.model_provider}")
        # print(f"  Model Name:         {self.model_name}")

        print("\n[Ablation Options]")
        print(f"  Disable Program Instrumentation:       {self.disable_program_instrumentation}")
        print(f"  Disable Vulnerability Analysis:        {self.disable_vulnerability_analysis}")
        # print(f"  Disable Project Structure Analysis:    {self.disable_project_structure_analysis}")
        # print(f"  Disable Coverage Feedback:             {self.disable_coverage_feedback}")
        # print(f"  Disable Crash Trigger Analysis:        {self.disable_crash_trigger_analysis}")
        # print(f"  Disable Advanced Agent Tools:          {self.disable_advanced_agent_tools}")
        # print(f"  Disable In-Context RL:                 {self.disable_in_context_rl}")

        print("\n[Analysis Options]")
        print(f"  Max Iterations:     {self.max_iterations} rounds")
        print(f"  Timeout:            {self.timeout} seconds")

        # print("\n[Output Options]")
        # print(f"  Work Directory:     {self.work_dir}")
        # print(f"  Output Directory:   {self.output_dir}")
        # print(f"  Verbose:            {self.verbose}")

        print("=" * 80)
