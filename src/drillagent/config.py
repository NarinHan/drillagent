#!/usr/bin/env python3
"""
Configuration Module for DrillAgent
"""

from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class AgentConfig:
    """Configuration for DrillAgent"""
    # Target information
    target_repo: str
    target_binary: Optional[str] = None
    cve_id: Optional[str] = None

    # LLM configuration
    model_provider: str = "claude"  # claude, openai, google
    model_name: str = "claude-sonnet-4"
    api_key: Optional[str] = None

    # Instrumentation options
    enable_coverage: bool = True
    enable_distance: bool = True
    enable_sanitizer: bool = True

    # Analysis options
    max_iterations: int = 100
    timeout: int = 3600  # seconds

    # Output options
    output_dir: str = "./output"
    verbose: bool = False

    # Paths
    work_dir: str = "./workspace"

    def __post_init__(self):
        """Validate and normalize paths"""
        self.output_dir = str(Path(self.output_dir).resolve())
        self.work_dir = str(Path(self.work_dir).resolve())


@dataclass
class AnalysisState:
    """Track the state of vulnerability analysis"""
    phase: str = "initialized"  # initialized, instrumented, analyzing, mutating, completed
    coverage_data: Optional[Dict] = None
    vulnerability_info: Optional[Dict] = None
    crash_inputs: List[str] = field(default_factory=list)
    pov_candidates: List[Dict] = field(default_factory=list)
    iteration: int = 0
    errors: List[str] = field(default_factory=list)
