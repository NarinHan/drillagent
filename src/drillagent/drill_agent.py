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
from drillagent.pov_analysis.crash_triggering import CrashTriggerAgent
from drillagent.utils.utils import *
from drillagent.utils.tools import ReadFileTool, GrepTool, FindFileTool, ListDirTool, TreeTool, FuncLineCovTool
from drillagent.utils.logging import init_llm_history_log, log_phase_separator, setup_drillagent_logger

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
        self.skip_code_instrumentation        = config.disable_program_instrumentation
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
        # LLM agent tools
        self.agent_tools: List[Any] = []
        self.agent_cov_tools: List[Any] = []

        # Sub-agents: These can be used for inter-communication.
        self.vuln_agent: VulnAnalysisAgent           = None
        self.coverage_agent: CoverageInstrumentAgent = None
        self.path_agent: PathExplorationAgent        = None
        self.crash_agent: CrashTriggerAgent          = None


        # Intermediate analysis results
        self.vulnerability_info: VulnInfo = VulnInfo() # For vulnerability analysis results (e.g., call trace, root cause)
        self.project_info       = None # For project-level analysis results # TBD

        # Final analysis results
        self.crash_inputs = [] # Real PoV inputs that trigger the vulnerability

        ## Initialize logger and components
        self.logger = setup_drillagent_logger(
            output_dir=self.output_dir,
            target_repo_path=self.config.target_repo_path,
            cve_id=self.config.cve_id,
            verbose=self.config.verbose
        )

        # Initialize LLM history log (clear any previous content)
        try:
            init_llm_history_log(self.output_dir)
            self.logger.info(f"LLM history log initialized at {self.output_dir}/llm_history.json")
        except Exception as e:
            self.logger.warning(f"Failed to initialize LLM history log: {e}")

        self._init_components()

        self.logger.info(f"DrillAgent initialized for target: {config.target_repo_path}")
        self.logger.info(f"Skip vulnerability analysis: {self.skip_vulnerability_analysis}")
        self.logger.info(f"Skip instrumentation:  {self.skip_code_instrumentation}")
        self.logger.info(f"Skip path exploration: {self.skip_path_exploration}")
        self.logger.info(f"Skip crash trigger analysis: {self.skip_crash_triggering}")

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
        try:
            self.agent_tools = [
                ReadFileTool(self.config.target_repo_path),
                GrepTool(self.config.target_repo_path),
                FindFileTool(self.config.target_repo_path),
                ListDirTool(self.config.target_repo_path),
                TreeTool(self.config.target_repo_path)
            ]
            self.logger.info(f"✓ Agent tools initialized: {len(self.agent_tools)} tools available")
            # Note: agent_cov_tools will be initialized after vulnerability analysis
            # when binary_path becomes available
        except Exception as e:
            self.logger.error(f"Failed to initialize agent tools: {e}")

        # Initialize new LLMInterface instances
        # We use different models for different sub-tasks to optimize cost and performance
        try:
            # 1. Basic LLM - uses config's default model for general tasks
            self.logger.info(f"Initializing basic LLM interface...")
            self.basic_llm = LLMInterface(
                provider=self.config.model_provider,
                model_name=self.config.model_name,
                api_key=self.config.api_key,
                logger=self.logger,
                output_dir=self.output_dir
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
                    logger=self.logger,
                    output_dir=self.output_dir
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
                    logger=self.logger,
                    output_dir=self.output_dir
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
                    logger=self.logger,
                    output_dir=self.output_dir
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
            if not self.skip_code_instrumentation:
                self._phase_code_instrumentation()

            # Initialize coverage analysis tools now that we have binary_path
            try:
                binary_abs_path = os.path.join(
                    self.config.target_repo_path,
                    self.vulnerability_info.binary_path # obtained from two phases ago
                )
                self.agent_cov_tools = [
                    FuncLineCovTool(self.config.target_repo_path, binary_abs_path)
                ]
                self.logger.info(f"✓ Coverage agent tools initialized: {len(self.agent_cov_tools)} tools available")
            except Exception as e:
                self.logger.warning(f"Failed to initialize coverage agent tools: {e}")
                self.agent_cov_tools = []  # Keep empty list to avoid errors

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
        print("\n")
        self.logger.info("[Phase 1] Vulnerability Analysis")
        self.phase = "analyzing"

        # Log phase separator
        try:
            log_phase_separator(self.output_dir, "VulnerabilityAnalysis")
        except Exception as e:
            self.logger.warning(f"Failed to log phase separator: {e}")

        # Use VulnAnalysisAgent for structured vulnerability analysis
        try:
            self.vuln_agent = VulnAnalysisAgent(self)
            self.logger.info("Initialized VulnAnalysisAgent!")

            # Run the analysis 
            # Store the returned VulnInfo object into DrillAgent's field directly!
            self.vulnerability_info = self.vuln_agent.run()

            # Print the formatted vulnerability analysis results
            vuln_info_str = self.vulnerability_info.format_output()
            print(vuln_info_str)
            self.logger.info("✓ Vulnerability analysis completed")

        except Exception as e:
            self.logger.error(f"  Failed to analyze vulnerability: {e}", exc_info=True)
            self.errors.append(f"Vulnerability analysis failed: {e}")
            # Keep the VulnInfo instance but mark it with error in root_cause field
            self.vulnerability_info.root_cause = f"Analysis failed: {e}"

    def _phase_code_instrumentation(self):
        """Phase 2: Instrument the target binary with coverage and sanitizers"""
        print("\n")
        self.logger.info("[Phase 2] Code Instrumentation")
        self.phase = "instrumentation"

        # Log phase separator
        try:
            log_phase_separator(self.output_dir, "CodeInstrumentation")
        except Exception as e:
            self.logger.warning(f"Failed to log phase separator: {e}")

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
        self.coverage_agent = CoverageInstrumentAgent(self, target_repo_path, binary_relative_path)
        result = self.coverage_agent.run()
        if result['success']:
            self.logger.info(f"✓ \"{self.project_name}\" coverage instrumentation completed.")
            self.logger.info(f"    Binary relative path: {result.get('instrumented_binary')}")
        else:
            self.logger.error(f"    Failed coverage instrumentation: {result.get('error')}")
            self.errors.append(f"Coverage instrumentation failed: {result.get('error')}")
            # exit(1) # Cannot proceed without coverage-instrumented binary

        self.logger.info("✓ Instrumentation phase completed")

    def _phase_path_exploration(self):
        """Phase 3: Coverage-guided path exploration"""
        print("\n")
        self.logger.info("[Phase 3] Path Exploration")
        self.phase = "exploring"

        # Log phase separator
        try:
            log_phase_separator(self.output_dir, "PathExploration")
        except Exception as e:
            self.logger.warning(f"Failed to log phase separator: {e}")

        # Utilize PathExplorationAgent to reach the vulnerable function
        try:
            self.path_agent = PathExplorationAgent(self)
            self.logger.info("Initialized PathExplorationAgent!")

            # Run the path exploration process
            self.path_agent.run()

            # Print the formatted exploration results
            self.logger.info(f"Generated {len(self.path_agent.history_testcases)} test cases in total during path exploration.")
            self.logger.info(f"  - {len(self.path_agent.vfunc_reached_testcases)} reached the vulnerable function.")
            self.logger.info(60 * "-")

        except Exception as e:
            self.logger.error(f"  Failed to run path exploration: {e}", exc_info=True)
            self.errors.append(f"Path exploration failed: {e}")

        self.logger.info("✓ Path exploration completed")

    def _phase_crash_triggering(self):
        """Phase 4: Generate and verify PoV test cases"""
        print("\n")
        self.logger.info("[Phase 4] Crash Triggering and PoV Validation")
        self.phase = "triggering"

        # Log phase separator
        try:
            log_phase_separator(self.output_dir, "CrashTrigger")
        except Exception as e:
            self.logger.warning(f"Failed to log phase separator: {e}")

        # Utilize CrashTriggerAgent to generate and validate final PoV
        try:
            self.crash_agent = CrashTriggerAgent(self)
            self.logger.info("Initialized CrashTriggerAgent!")

            # Run the crash triggering process
            self.crash_agent.run()

            # Extract final PoV result
            final_pov = self.crash_agent.final_pov
            if final_pov:
                self.logger.info(f"  ✓ Final PoV successfully generated and validated!")
                self.logger.info(f"  - PoV path: {final_pov['saved_pov_path']}")
                # self.logger.info(f"  - Found at iteration: {final_pov['iteration']}")
                self.crash_inputs.append(final_pov['saved_pov_path'])
            else:
                self.logger.warning(f"  ✗ No valid PoV generated after {self.crash_agent.current_trigger_iteration} iterations")
                self.errors.append("Crash triggering failed: No valid PoV found")

        except Exception as e:
            self.logger.error(f"  Failed to run crash triggering: {e}", exc_info=True)
            self.errors.append(f"Crash triggering failed: {e}")

        self.logger.info("✓ Crash triggering analysis completed")

    def _generate_report(self) -> Dict[str, Any]:
        """Generate final analysis report"""
        report = {
            "target_repo_path": self.config.target_repo_path,
            "cve_id": self.config.cve_id,
            "final_phase": self.phase,
            "crashes_found": len(self.crash_inputs),
            "errors": self.errors,
            "vulnerability_info": self.vulnerability_info.to_dict(),
        }

        self.logger.info("\n" + "=" * 60)
        self.logger.info("DrillAgent Analysis Report")
        self.logger.info("=" * 60)
        self.logger.info(f"Target: {report['target_repo_path']}")
        self.logger.info(f"CVE ID: {report['cve_id']}")
        self.logger.info(f"Final Phase: {report['final_phase']}")
        self.logger.info(f"Crashes Found: {report['crashes_found']}")

        if report['errors']:
            self.logger.warning(f"Errors: {len(report['errors'])}")
            for error in report['errors']:
                self.logger.warning(f"  - {error}")

        self.logger.info("=" * 60)

        return report


# # Not use it currently, but kept for reference.
# @dataclass
# class AnalysisState:
#     # Track the state of vulnerability analysis
#     phase: str = "initialized"  # initialized, instrumented, analyzing, exploring, completed
#     crash_inputs: List[str] = field(default_factory=list)
#     pov_candidates: List[Dict] = field(default_factory=list)
#     iteration: int = 0

