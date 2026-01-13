#!/usr/bin/env python3
import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from drillagent.config import AgentConfig
from drillagent.models import LLMInterface
from drillagent.instrumentation import CoverageInstrumentAgent, SanitizerInstrumentAgent
from drillagent.pov_analysis.vuln_analysis import VulnAnalysisAgent, VulnInfo
from drillagent.pov_analysis.path_exploration import PathExplorationAgent
from drillagent.pov_analysis.crash_triggering import CrashTriggerAgent
from drillagent.utils.utils import *
from drillagent.tools.basic_tools import *
from drillagent.tools.cov_query_tools import FuncLineCovTool
from drillagent.tools.ast_grep_tools import AstGrepFunctionSearchTool
from drillagent.utils.logging import init_llm_history_log, log_phase_separator, setup_drillagent_logger
from drillagent.utils.log_converter import convert_llm_history_to_text

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
        self.basic_llm: LLMInterface     = None
        self.reasoning_llm: LLMInterface = None
        self.low_cost_llm:  LLMInterface = None
        # LLM agent tools
        self.basic_tools: List[Any] = []
        self.cov_tools:   List[Any] = []
        self.ast_grep_tools:  List[Any] = []
        self.clangd_tools:    List[Any] = []

        # Sub-agents: These can be used for inter-communication.
        self.vuln_agent: VulnAnalysisAgent             = None
        self.sanitizer_agent: SanitizerInstrumentAgent = None
        self.coverage_agent: CoverageInstrumentAgent   = None
        self.path_agent: PathExplorationAgent          = None
        self.crash_agent: CrashTriggerAgent            = None


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
        self.logger.info("Initializing components...")

        # Initialize basic agent tools for LLM
        try:
            self.basic_tools = [
                ReadFileTool(self.config.target_repo_path),
                WriteFileTool(self.config.target_repo_path),
                GrepTool(self.config.target_repo_path),
                FindFileTool(self.config.target_repo_path),
                ListDirTool(self.config.target_repo_path),
                TreeTool(self.config.target_repo_path)
            ]
            self.logger.info(f"✓ Agent basic tools initialized: {len(self.basic_tools)} tools available")
            # Note: cov_tools will be initialized after vulnerability analysis when binary_path becomes available.
        except Exception as e:
            self.logger.error(f"Failed to initialize agent basic tools: {e}")

        # Init ast-grep tools for LLM
        try:
            self.ast_grep_tools = [
                AstGrepFunctionSearchTool(self.config.target_repo_path)
            ]
            self.logger.info(f"✓ ast-grep tools initialized: {len(self.ast_grep_tools)} tools available")
        except Exception as e:
            self.logger.error(f"Failed to initialize ast-grep tools: {e}")

        # Initialize new LLMInterface instances
        # We use different models for different sub-tasks to optimize cost and performance
        try:
            # 1. Basic LLM - uses config's default model for general tasks
            self.logger.info(f"Initializing basic LLM interface...")
            self.basic_llm = LLMInterface(
                provider=self.config.model_provider,
                model_name=self.config.basic_model,
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
                    low_cost_model = "gpt-5-mini-2025-08-07"
                else:  # claude
                    low_cost_model = "claude-haiku-4-5-20251001"
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
        # print("")
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
                res = self._phase_code_instrumentation()
                if not res:
                    self.logger.error("Instrumentation phase failed, cannot proceed further.")
                    return self._generate_report()

            # Initialize coverage analysis tools now that we have binary_path
            try:
                binary_abs_path = os.path.join(
                    self.config.target_repo_path,
                    self.vulnerability_info.binary_path # obtained from two phases ago
                )
                self.cov_tools = [
                    FuncLineCovTool(self.config.target_repo_path, binary_abs_path)
                ]
                self.logger.info(f"✓ Coverage agent tools initialized: {len(self.cov_tools)} tools available")
            except Exception as e:
                self.logger.warning(f"Failed to initialize coverage agent tools: {e}")
                self.cov_tools = []  # Keep empty list to avoid errors

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

        # Fixed: Before analyzing, we should make sure the target repository is at the base commit!!
        target_repo_path = self.config.target_repo_path
        matched_commit = compare_gitrepo_commit(
            actual_repo_path=target_repo_path,
            base_commit=self.config.base_commit
        )
        if not matched_commit:
            clean_gitrepo(target_repo_path)
            self.logger.info("✓ Cleaned target repository!")
            checkout_gitrepo_commit(target_repo_path, self.config.base_commit)
            self.logger.info(f"✓ Checked out Base commit: {self.config.base_commit}")

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

    def _phase_code_instrumentation(self) -> bool:
        """Phase 2: Instrument the target binary with coverage and sanitizers"""
        print("\n")
        self.logger.info("[Phase 2] Code Instrumentation")
        self.phase = "instrumentation"

        # Log phase separator
        try:
            log_phase_separator(self.output_dir, "CodeInstrumentation")
        except Exception as e:
            self.logger.warning(f"Failed to log phase separator: {e}")

        def _clean_and_checkout(repo_path: str):
            # Before compiling, clean repository and checkout target commit.
            self.logger.info("Cleaning repository...")
            clean_gitrepo(repo_path)
            self.logger.info("✓ Cleaning finished!")

            self.logger.info(f"Checking out base commit: {self.config.base_commit}")
            checkout_gitrepo_commit(repo_path, self.config.base_commit)
            self.logger.info("✓ Checked out Base commit!")

        target_repo_path   = self.config.target_repo_path
        saninstr_repo_path = self.config.saninstr_repo_path
        binary_relative_path = self.vulnerability_info.binary_path

        # Substep 1: check if instrumented binary already exists (currently two types, llvm-cov and sanitizer)
        if check_saninstr_binary_exists(saninstr_repo_path, binary_relative_path) \
              and compare_gitrepo_commit(saninstr_repo_path, self.config.base_commit):
            self.logger.info(f"✓ Found qualified sanitizer-instrumented binary, built from commit {self.config.base_commit}")
            self.logger.info(f"    Binary path: {saninstr_repo_path}/{binary_relative_path}")
            found_san_bin = True
        else:
            self.logger.info("No existing qualified sanitizer-instrumented binary found.")
            found_san_bin = False
            _clean_and_checkout(saninstr_repo_path)
        
        print("")
        if check_llvmcov_binary_exists(target_repo_path, binary_relative_path) \
              and compare_gitrepo_commit(target_repo_path, self.config.base_commit):
            self.logger.info(f"✓ Found qualified coverage-instrumented binary, built from commit {self.config.base_commit}")
            self.logger.info(f"    Binary path: {target_repo_path}/{binary_relative_path}")
            found_cov_bin = True
        else:
            self.logger.info("No existing qualified coverage-instrumented binary found.")
            found_cov_bin = False
            _clean_and_checkout(target_repo_path)
        
        if found_cov_bin and found_san_bin:
            self.logger.info(f"✓ All satisfied. Skipping instrumentation phase...")
            return True

        # Substep 2: Build source code with memory sanitizer instrumentation
        print("")
        if not found_san_bin:
            self.logger.info("Building with memory sanitizer instrumentation...")
            self.sanitizer_agent = SanitizerInstrumentAgent(self, saninstr_repo_path, binary_relative_path)
            result_san = self.sanitizer_agent.run()
            if result_san['success']:
                self.logger.info(f"✓ \"{self.project_name}\" sanitizer instrumentation completed.")
                self.logger.info(f"    Binary path: {saninstr_repo_path}/{result_san.get('instrumented_binary')}")
            else:
                self.logger.error(f"    Failed sanitizer instrumentation: {result_san.get('error')}")
                self.errors.append(f"Sanitizer instrumentation failed: {result_san.get('error')}")
                exit(1) # For debug
                return False

        # Substep 3: Build source code with coverage instrumentation
        print("")
        if not found_cov_bin:
            self.logger.info("Building with coverage instrumentation...")
            self.coverage_agent = CoverageInstrumentAgent(self, target_repo_path, binary_relative_path)
            result = self.coverage_agent.run()
            if result['success']:
                self.logger.info(f"✓ \"{self.project_name}\" coverage instrumentation completed.")
                self.logger.info(f"    Binary path: {target_repo_path}/{result.get('instrumented_binary')}")
            else:
                self.logger.error(f"    Failed coverage instrumentation: {result.get('error')}")
                self.errors.append(f"Coverage instrumentation failed: {result.get('error')}")
                exit(2) # For debug
                return False

        self.logger.info("✓ Instrumentation phase completed")
        return True

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

        # Convert LLM history JSON to text format for easier review
        try:
            self.logger.info("\nConverting LLM history to text format...")
            convert_llm_history_to_text(self.output_dir)
            self.logger.info(f"✓ LLM history text log saved to {self.output_dir}/llm_history.txt")
        except Exception as e:
            self.logger.warning(f"Failed to convert LLM history to text: {e}")

        return report


# # Not use it currently, but kept for reference.
# @dataclass
# class AnalysisState:
#     # Track the state of vulnerability analysis
#     phase: str = "initialized"  # initialized, instrumented, analyzing, exploring, completed
#     crash_inputs: List[str] = field(default_factory=list)
#     pov_candidates: List[Dict] = field(default_factory=list)
#     iteration: int = 0

