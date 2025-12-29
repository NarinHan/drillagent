#!/usr/bin/env python3
import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from drillagent.config import AgentConfig
from drillagent.models import LLM, LLMInterface
from drillagent.instrumentation import CoverageInstrumentAgent
from drillagent.pov_analysis.vuln_analysis import VulnAnalysisAgent, VulnInfo
from drillagent.pov_analysis.path_exploration import PathExplorationAgent
from drillagent.utils.utils import *

class DrillAgent:
    # Core orchestration class of DrillAgent
    # Note that:
    # 1. This DrillAgent only runs for a single CVE task at a time. Benchmark's batch task scheduling should be placed at the caller layer.
    # 2. Only the essential elements for basic PoV generation are included in DrillAgent; all other information should be maintained at the caller layer.

    # This dataclass should be benchmark-agnostic.

    def __init__(self, config: AgentConfig):
        # The only init parameter is the AgentConfig dataclass instance.
        self.config = config       # Include all the PoV task information and configuration options.
        self.phase = "initialized" # initialized, analyzing, instrumented, exploring, completed
        self.skip_instrumentation        = config.disable_program_instrumentation
        self.skip_vulnerability_analysis = config.disable_vulnerability_analysis
        self.skip_path_exploration       = config.disable_path_exploration 
        self.skip_crash_triggering       = config.disable_crash_triggering

        self.project_name = config.project_name
        self.cve_id       = config.cve_id
        self.work_dir   = self.config.work_dir
        self.output_dir = self.config.output_dir
        self.iteration = 0 ##
        self.errors = []

        # LLM interfaces (We use different LLMs for different sub-tasks to optimize cost and performance)
        self.llm: LLM = None # Old LLM interface, kept for backward compatibility.
        self.basic_llm: LLMInterface     = None
        self.reasoning_llm: LLMInterface = None
        self.low_cost_llm:  LLMInterface = None

        # Intermediate analysis results
        self.vulnerability_info: VulnInfo = VulnInfo() # For vulnerability analysis results (e.g., call trace, root cause)
        self.project_info       = None # For project-level analysis results # TBD
        # Path exploration results
        self.pov_candidates     = []
        self.coverage_data      = None
        # Final analysis results
        self.crash_inputs = []         # Real PoV inputs that trigger the vulnerability

        # # Initialize logger and components
        self.logger = self._setup_logger()
        self._init_components()

        self.logger.info(f"DrillAgent initialized for target: {config.target_repo_path}")
        self.logger.info(f"Skip vulnerability analysis: {self.skip_vulnerability_analysis}")
        self.logger.info(f"Skip instrumentation:  {self.skip_instrumentation}")
        self.logger.info(f"Skip path exploration: {self.skip_path_exploration}")
        self.logger.info(f"Skip crash trigger analysis: {self.skip_crash_triggering}")

    def _setup_logger(self) -> logging.Logger:
        # Setup logging for DrillAgent
        # Determine log directory and filename
        if self.output_dir == str(Path("./output").resolve()):
            # User didn't set custom output_dir, use DrillAgent/logs
            current_file = Path(__file__).resolve()
            project_root = current_file.parent.parent.parent  # Go up to DrillAgent root
            log_dir = project_root / "logs"
        else:
            # User set custom output_dir, use it
            log_dir = Path(self.output_dir)
        
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate log filename with repo name and CVE ID
        repo_name = Path(self.config.target_repo_path).name if self.config.target_repo_path else "unknown"
        cve_id = self.config.cve_id.lower() if self.config.cve_id else "no-cve"
        log_filename = f"drillagent_{repo_name}_{cve_id}.log"
        log_path = log_dir / log_filename
        
        # Clean the log file if it already exists
        if log_path.exists():
            log_path.unlink()
        
        # Also ensure output_dir exists for other files
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Configure root logger to INFO to avoid debug spam from third-party libs
        logging.basicConfig(
            level=logging.INFO,  # Always INFO for root logger
            format='[%(asctime)s] %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(str(log_path), mode='w')  # Use 'w' mode to overwrite
            ]
        )
        
        # Get DrillAgent logger and set its level based on verbose flag
        logger = logging.getLogger("DrillAgent")
        if self.config.verbose:
            logger.setLevel(logging.DEBUG)
        
        # Suppress debug logs from noisy third-party libraries
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("anthropic").setLevel(logging.WARNING)
        logging.getLogger("openai").setLevel(logging.WARNING)
        
        return logger

    def _init_components(self):
        # Initialize all required components (mainly LLM interfaces and tools)
        self.logger.info("Initializing components...")

        # Initialize old LLM interface (backward compatibility)
        try:
            self.logger.info(f"Initializing {self.config.model_provider} LLM (legacy)...")
            self.llm = LLM(
                provider=self.config.model_provider,
                model_name=self.config.model_name,
                api_key=self.config.api_key
            )
            self.logger.info(f"✓ Legacy LLM initialized: {self.llm.provider}/{self.llm.model_name}")
        except Exception as e:
            self.logger.error(f"Failed to initialize legacy LLM: {e}")
            self.llm = None

        # Initialize agent tools for LLM
        from drillagent.utils.tools import ReadFileTool, GrepTool, FindFileTool, ListDirTool, TreeTool
        try:
            self.agent_tools = [
                ReadFileTool(self.config.target_repo_path),
                GrepTool(self.config.target_repo_path),
                FindFileTool(self.config.target_repo_path),
                ListDirTool(self.config.target_repo_path),
                TreeTool(self.config.target_repo_path)
            ]
            self.logger.info(f"✓ Agent tools initialized: {len(self.agent_tools)} tools available")
        except Exception as e:
            self.logger.error(f"Failed to initialize agent tools: {e}")
            self.agent_tools = []

        # Initialize new LLMInterface instances
        # We use different models for different sub-tasks to optimize cost and performance
        try:
            # 1. Basic LLM - uses config's default model for general tasks
            self.logger.info(f"Initializing basic LLM interface...")
            self.basic_llm = LLMInterface(
                provider=self.config.model_provider,
                model_name=self.config.model_name,
                api_key=self.config.api_key,
                logger=self.logger
            )
            self.logger.info(f"✓ Basic LLM initialized: {self.basic_llm.provider}/{self.basic_llm.model_name}")

            # 2. Reasoning LLM - uses reasoning_model if configured, otherwise same as basic
            if self.config.reasoning_model and self.config.reasoning_model[0]:
                reasoning_provider, reasoning_model = self.config.reasoning_model
                self.logger.info(f"Initializing reasoning LLM interface ({reasoning_provider}/{reasoning_model})...")
                self.reasoning_llm = LLMInterface(
                    provider=reasoning_provider,
                    model_name=reasoning_model,
                    api_key=self.config.api_key,
                    logger=self.logger
                )
                self.logger.info(f"✓ Reasoning LLM initialized: {self.reasoning_llm.provider}/{self.reasoning_llm.model_name}")
            else:
                # Use same as basic_llm if not configured
                self.reasoning_llm = self.basic_llm
                self.logger.info(f"✓ Reasoning LLM using basic LLM configuration")

            # 3. Low-cost LLM - uses low_cost_model if configured, otherwise use cheaper default
            if self.config.low_cost_model and self.config.low_cost_model[0]:
                low_cost_provider, low_cost_model = self.config.low_cost_model
                self.logger.info(f"Initializing low-cost LLM interface ({low_cost_provider}/{low_cost_model})...")
                self.low_cost_llm = LLMInterface(
                    provider=low_cost_provider,
                    model_name=low_cost_model,
                    api_key=self.config.api_key,
                    logger=self.logger
                )
                self.logger.info(f"✓ Low-cost LLM initialized: {self.low_cost_llm.provider}/{self.low_cost_llm.model_name}")
            else:
                # Default to cheaper models if not configured
                if self.config.model_provider == "openai":
                    low_cost_model = "gpt-4o-mini"
                else:  # claude
                    low_cost_model = "claude-3-5-haiku-20241022"

                self.logger.info(f"Initializing low-cost LLM with default cheaper model ({low_cost_model})...")
                self.low_cost_llm = LLMInterface(
                    provider=self.config.model_provider,
                    model_name=low_cost_model,
                    api_key=self.config.api_key,
                    logger=self.logger
                )
                self.logger.info(f"✓ Low-cost LLM initialized: {self.low_cost_llm.provider}/{self.low_cost_llm.model_name}")
        except Exception as e:
            self.logger.error(f"Failed to initialize LLMInterface instances: {e}")
            # Fallback: keep them as None
            self.basic_llm = None
            self.reasoning_llm = None
            self.low_cost_llm = None

        self.logger.info("All components initialized")

    def run(self) -> Dict[str, Any]:
        # Main orchestration workflow
        # Returns: Dict containing analysis results and generated PoVs
        print("")
        self.logger.info("=" * 60)
        self.logger.info("Starting DrillAgent workflow")
        self.logger.info("=" * 60)

        # Checkout the base commit for the target repository is provided!
        assert len(self.config.base_commit) == 40, "Base commit should be a valid 40-char git SHA1 hash."

        try:
            # Phase 1: Vulnerability Analysis
            if not self.skip_vulnerability_analysis:
                self._phase_vulnerability_analysis()

            # Phase 2: Code Instrumentation
            if not self.skip_instrumentation:
                self._phase_instrumentation()

            # Phase 3: Path Exploration with the coverage feedback
            if not self.skip_path_exploration:
                self._phase_path_exploration()

            # Phase 4: PoV Generation and Verification
            if not self.skip_crash_triggering:
                self._phase_crash_triggering()

            # Mark as completed
            self.phase = "completed"
            return self._generate_report()

        except Exception as e:
            self.logger.error(f"Fatal error in DrillAgent workflow: {e}", exc_info=True)
            self.errors.append(str(e))
            return self._generate_report()

    def _phase_vulnerability_analysis(self):
        """Phase 1: Analyze vulnerability using LLM"""
        self.logger.info("[Phase 1] Vulnerability Analysis")
        self.phase = "analyzing"

        # Use VulnAnalysisAgent for structured vulnerability analysis
        try:
            vuln_agent = VulnAnalysisAgent(self)
            self.logger.info("Initialized VulnAnalysisAgent!")

            # Run the analysis 
            # Store the returned VulnInfo object into DrillAgent's field directly!
            self.vulnerability_info = vuln_agent.run()

            # Print the formatted vulnerability analysis results
            vuln_info_str = self.vulnerability_info.format_output()
            print(vuln_info_str)
            self.logger.info("✓ Vulnerability analysis completed")

        except Exception as e:
            self.logger.error(f"  Failed to analyze vulnerability: {e}", exc_info=True)
            self.errors.append(f"Vulnerability analysis failed: {e}")
            # Keep the VulnInfo instance but mark it with error in root_cause field
            self.vulnerability_info.root_cause = f"Analysis failed: {e}"

    def _phase_instrumentation(self):
        """Phase 2: Instrument the target binary with coverage and sanitizers"""
        self.logger.info("[Phase 2] Code Instrumentation")
        self.phase = "instrumentation"

        target_repo_path = self.config.target_repo_path
        binary_relative_path = self.vulnerability_info.binary_path

        # Substep 1: check if llvm-cov instrumented binary already exists
        existing_binary = check_llvmcov_binary_exists(
            actual_repo_path=target_repo_path,
            binary_relative_path=binary_relative_path
        )
        if existing_binary:
            matched_commit = compare_gitrepo_commit(
                actual_repo_path=target_repo_path,
                base_commit=self.config.base_commit
            )
            if matched_commit:
                tmp_path_str = f"{target_repo_path}/{binary_relative_path}"
                self.logger.info(f"✓ Found existing coverage-instrumented binary at {tmp_path_str}, built from commit {self.config.base_commit}")
                self.logger.info(f"    Binary relative path: {binary_relative_path}")
                self.logger.info(f"✓ Skipping instrumentation phase...")
                return
            else:
                self.logger.info("Existing qualified coverage-instrumented binary found, but built from a different commit. Proceeding with instrumentation")
        else:
            self.logger.info("No existing qualified coverage-instrumented binary found. Proceeding with instrumentation")
        
        # Before compiling, clean repository and checkout target commit.
        self.logger.info("Cleaning repository...")
        clean_gitrepo(target_repo_path)
        self.logger.info("✓ Cleaning finished!")

        self.logger.info(f"Checking out base commit: {self.config.base_commit}")
        checkout_gitrepo_commit(target_repo_path, self.config.base_commit)
        self.logger.info("✓ Checked out Base commit!")

        # Substep 2: Build source code with memory sanitizer instrumentation (TODO)
        self.logger.info("To be developed: Implement memory sanitizer instrumentation.")

        # Substep 3: Build source code with coverage instrumentation
        self.logger.info("  - Building with coverage instrumentation...")
        coverage_agent = CoverageInstrumentAgent(self, target_repo_path, binary_relative_path)
        result = coverage_agent.run()
        if result['success']:
            self.logger.info(f"✓ \"{self.project_name}\" coverage instrumentation completed.")
            self.logger.info(f"    Binary relative path: {result.get('instrumented_binary')}")
        else:
            self.logger.error(f"    Failed coverage instrumentation: {result.get('error')}")
            self.errors.append(f"Coverage instrumentation failed: {result.get('error')}")
            # exit(1) # Cannot proceed without coverage-instrumented binary

        # # Run distance calculation if enabled
        # self.logger.info("  - Running distance calculation...")
        # # Load the YAML config file into a dictionary
        # with open(self.aflgo_config_path, 'r') as f: # LHY: self.aflgo_config_path is not used anymore.
        #     config_dict = yaml.safe_load(f)
        # # Initialize DistanceAgent
        # instrumentation_agent = DistanceAgent(
        #     config=config_dict,
        #     llm=self.llm,
        #     logger=self.logger
        # )
        # # Execute the full instrumentation workflow
        # result = instrumentation_agent.run()
        # if result['success']:
        #     self.logger.info(f"    ✓ Distance calculation completed: {result.get('instrumented_binary')}")
        # else:
        #     self.logger.error(f"    Failed to instrument binary: {result.get('error')}")
        #     self.errors.append(f"Distance calculation failed: {result.get('error')}")

        self.logger.info("✓ Instrumentation phase completed")

    def _phase_path_exploration(self):
        """Phase 3: Coverage-guided path exploration"""
        self.logger.info("[Phase 3] Path Exploration")
        self.phase = "exploring"

        max_iterations = self.config.max_iterations

        # Utilize PathExplorationAgent to reach the vulnerable function
        try:
            path_agent = PathExplorationAgent(self)
            self.logger.info("Initialized PathExplorationAgent!")

            # Run the path exploration process
            path_agent.run()

            # Extract exploration results
            self.pov_candidates = path_agent.history_pov_candidates

            # TODO: Print the formatted exploration results

        except Exception as e:
            self.logger.error(f"  Failed to run path exploration: {e}", exc_info=True)
            self.errors.append(f"Path exploration failed: {e}")

        self.logger.info("✓ Path exploration completed")
        self.logger.info(f"  - Total PoV candidates generated: {len(self.pov_candidates)}")

    def _phase_crash_triggering(self):
        """Phase 4: Generate and verify PoV test cases"""
        self.logger.info("[Phase 4] Crash Triggering and PoV Validation")
        self.phase = "triggering"

        # Step 1: Analyze the vulnerability from a pwner perspective.

        # Step 2: Generate PoVs based on the analysis results, (the only goal is to trigger the crash).

        # Step 3: Actually verify PoVs by executing them with sanitizers.

        # Step 4: Generate summary report

        self.logger.info("✓ Crash triggering analysis completed")
        # successful_povs = sum(1 for c in self.pov_candidates if c.get('status') == 'generated')
        # self.logger.info(f"\n  ✓ PoV generation completed: {successful_povs}/{len(self.pov_candidates)} successful")

    def _generate_report(self) -> Dict[str, Any]:
        """Generate final analysis report"""
        report = {
            "target_repo_path": self.config.target_repo_path,
            "cve_id": self.config.cve_id,
            "final_phase": self.phase,
            "iterations": self.iteration,
            "crashes_found": len(self.crash_inputs),
            "povs_generated": len(self.pov_candidates),
            "errors": self.errors,
            "vulnerability_info": self.vulnerability_info.to_dict(),
            "pov_candidates": self.pov_candidates,
        }

        self.logger.info("\n" + "=" * 60)
        self.logger.info("DrillAgent Analysis Report")
        self.logger.info("=" * 60)
        self.logger.info(f"Target: {report['target_repo_path']}")
        self.logger.info(f"CVE ID: {report['cve_id']}")
        self.logger.info(f"Final Phase: {report['final_phase']}")
        self.logger.info(f"Iterations: {report['iterations']}")
        self.logger.info(f"Crashes Found: {report['crashes_found']}")
        self.logger.info(f"PoVs Generated: {report['povs_generated']}")

        if report['errors']:
            self.logger.warning(f"Errors: {len(report['errors'])}")
            for error in report['errors']:
                self.logger.warning(f"  - {error}")

        self.logger.info("=" * 60)

        return report


@dataclass
class AnalysisState:
    # LHY: Not use it currently, but kept for reference.
    # Track the state of vulnerability analysis
    phase: str = "initialized"  # initialized, instrumented, analyzing, exploring, completed
    crash_inputs: List[str] = field(default_factory=list)
    pov_candidates: List[Dict] = field(default_factory=list)
    iteration: int = 0


