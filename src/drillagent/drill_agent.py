#!/usr/bin/env python3
import os
import re
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Tuple
from dataclasses import dataclass, field

from drillagent.config import AgentConfig
from drillagent.models import LLMInterface
from drillagent.instrumentation import CoverageInstrumentAgent, SanitizerInstrumentAgent
from drillagent.pov_analysis.vuln_analysis import VulnAnalysisAgent, VulnInfo
from drillagent.pov_analysis.path_exploration import PathExplorationAgent
from drillagent.pov_analysis.crash_triggering import CrashTriggerAgent
from drillagent.utils.utils import *
from drillagent.tools.basic_tools import *
from drillagent.tools.cov_query_tools import FunctionCovTool
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
        self.cache_dir = os.path.join(self.config.work_dir, "cache_drillagent")
        self.errors = []

        # LLM interfaces (We use different LLMs for different sub-tasks to optimize cost and performance)
        self.basic_llm: LLMInterface     = None
        self.reasoning_llm: LLMInterface = None
        self.low_cost_llm:  LLMInterface = None
        # LLM agent tools
        self.basic_tools: List[Any] = []     # Include BashTool, ReadFileTool, WriteFileTool, etc.
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
        self.gt_crash_type = get_sanitizer_crash_type(self.config.sanitizer_report) if self.config.sanitizer_report else "" # Expected crash answer

        # Initialize logger and components
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

        # Prepare token usage tracking
        self.overall_token_usage = {
            "VAA" : TokenUsage(),
            # "InstrAgent" : TokenUsage(), # skipped for now
            "PEA" : TokenUsage(),
            "CTA" : TokenUsage()
        }

        self.logger.info(f"DrillAgent initialized for target: {config.target_repo_path}")
        self.logger.info(f"Skip vulnerability analysis: {self.skip_vulnerability_analysis}")
        self.logger.info(f"Skip code instrumentation:  {self.skip_code_instrumentation}")
        self.logger.info(f"Skip path exploration: {self.skip_path_exploration}")
        self.logger.info(f"Skip crash trigger analysis: {self.skip_crash_triggering}")

    def _init_components(self):
        self.logger.info("Initializing components...")

        # Initialize basic agent tools for LLM
        try:
            self.basic_tools = [
                ReadFileTool(self.config.target_repo_path),
                WriteFileTool(self.config.target_repo_path),
                BashTool(self.config.target_repo_path),
                FinishTool()
            ]
            self.logger.info(f"✓ Agent basic tools initialized: {len(self.basic_tools)} tools available")
        except Exception as e:
            self.logger.error(f"Failed to initialize agent basic tools: {e}")

        # Init ast-grep tools for LLM
        try:
            self.ast_grep_tools = [
                AstGrepFunctionSearchTool(self.config.target_repo_path)
            ]
            self.logger.info(f"✓ ast-grep tools initialized: {len(self.ast_grep_tools)} tools available")
            for tool in self.ast_grep_tools: print("  "+tool.name()) # debug
        except Exception as e:
            self.logger.error(f"Failed to initialize ast-grep tools: {e}")

        # Initialize coverage query tools for LLM
        try:
            self.cov_tools = [
                FunctionCovTool(self.config.target_repo_path)
            ]
            self.logger.info(f"✓ Coverage query tools initialized: {len(self.cov_tools)} tools available")
            for tool in self.cov_tools: print("  "+tool.name()) # debug
        except Exception as e:
            self.logger.warning(f"Failed to initialize coverage query tools: {e}")

        # Initialize new LLMInterface instances
        # We use different models for different sub-tasks to optimize cost and performance
        self.logger.info(f"Initializing LLM interface...")
        try:
            # 1. Basic LLM - uses config's default model for general tasks
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
                self.logger.info(f"✓ Reasoning LLM initialized: re-using basic LLM configuration")

            # 3. Low-cost LLM - uses low_cost_model if configured, otherwise use cheaper default
            if self.config.low_cost_model and self.config.low_cost_model[0]:
                low_cost_provider, low_cost_model = self.config.low_cost_model
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

        # Initialize time overhead tracking
        time_overhead = {
            "phase_vulnerability_analysis": 0.0,
            "phase_code_instrumentation": 0.0,
            "phase_path_exploration": 0.0,
            "phase_crash_triggering": 0.0
        }

        # Checkout the base commit for the target repository is provided!
        if len(self.config.base_commit) != 40:
            self.logger.error("Invalid base commit hash provided, cannot proceed.")
            self._save_time_overhead(time_overhead)
            return self.generate_report()

        try:
            # Phase 1: Vulnerability Analysis
            if not self.skip_vulnerability_analysis:
                start_time = time.time()
                self._phase_vulnerability_analysis()
                time_overhead["phase_vulnerability_analysis"] = time.time() - start_time
                self._log_phase_token_usage("VAA", "Vulnerability Analysis")

            # Phase 2: Code Instrumentation
            if not self.skip_code_instrumentation:
                start_time = time.time()
                res = self._phase_code_instrumentation()
                time_overhead["phase_code_instrumentation"] = time.time() - start_time
                if not res:
                    self.logger.error("Instrumentation phase failed, cannot proceed further.")
                    self._save_time_overhead(time_overhead)
                    self._save_tokens_overhead()
                    return self.generate_report()

            # Phase 3: Path Exploration with the coverage feedback
            if not self.skip_path_exploration:
                start_time = time.time()
                self._phase_path_exploration()
                time_overhead["phase_path_exploration"] = time.time() - start_time
                self._log_phase_token_usage("PEA", "Path Exploration")

            # Phase 4: PoV Generation and Verification
            if not self.skip_crash_triggering:
                start_time = time.time()
                self._phase_crash_triggering()
                time_overhead["phase_crash_triggering"] = time.time() - start_time
                self._log_phase_token_usage("CTA", "Crash Triggering")

            # Mark as completed
            self.phase = "completed"
            self._save_time_overhead(time_overhead)
            self._save_tokens_overhead()
            return self.generate_report()

        except Exception as e:
            self.logger.error(f"Fatal error in DrillAgent workflow: {e}", exc_info=True)
            self.errors.append(str(e))
            self._save_time_overhead(time_overhead)
            self._save_tokens_overhead()
            return self.generate_report()

    def _save_time_overhead(self, time_overhead: Dict[str, float]) -> None:
        """Save time overhead for each phase to a JSON file."""
        time_overhead_path = os.path.join(self.output_dir, "time_overhead.json")
        try:
            with open(time_overhead_path, 'w') as f:
                json.dump(time_overhead, f, indent=2)
            self.logger.info(f"Time overhead saved to {time_overhead_path}")
        except Exception as e:
            self.logger.warning(f"Failed to save time overhead: {e}")

    def _save_tokens_overhead(self) -> None:
        """Save token usage for each phase to a JSON file."""
        tokens_overhead_path = os.path.join(self.output_dir, "tokens_overhead.json")
        try:
            tokens_overhead = {}
            for phase_name, usage in self.overall_token_usage.items():
                tokens_overhead[phase_name] = {
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "total_tokens": usage.total_tokens,
                    "cost_input_usd": usage.cost_input_usd,
                    "cost_output_usd": usage.cost_output_usd,
                    "cost_total_usd": usage.cost_total_usd
                }
            with open(tokens_overhead_path, 'w') as f:
                json.dump(tokens_overhead, f, indent=2)
            self.logger.info(f"Token usage saved to {tokens_overhead_path}")
        except Exception as e:
            self.logger.warning(f"Failed to save tokens overhead: {e}")

    def _log_phase_token_usage(self, phase_key: str, phase_label: str) -> None:
        usage = self.overall_token_usage.get(phase_key)
        if not usage:
            return
        self.logger.info(
            f"[{phase_label}] Tokens used: input={usage.input_tokens}, "
            f"output={usage.output_tokens}, total={usage.total_tokens}, "
            f"cost=${usage.cost_total_usd:.6f}"
        )

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
            clean_gitrepo(repo_path)
            self.logger.info("✓ Cleaning finished!")

            # self.logger.info(f"  Checking out base commit: {self.config.base_commit}")
            checkout_gitrepo_commit(repo_path, self.config.base_commit)
            self.logger.info(f"✓ Checked out base commit: {self.config.base_commit}!")

        # Prepare related paths
        target_repo_path    = self.config.target_repo_path
        saninstr_repo_path  = self.config.saninstr_repo_path
        bin_rel_path        = self.vulnerability_info.binary_path  
        actual_bin_rel_path = self.vulnerability_info.actual_binary_path
        if len(actual_bin_rel_path) > 0: # We have reliable actual binary path from previous cache!
            binary_relative_path = actual_bin_rel_path
        else:
            binary_relative_path = bin_rel_path

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
                self.logger.info(f"\"{self.project_name}\" sanitizer instrumentation completed.")
                # self.logger.info(f"    Binary path: {saninstr_repo_path}/{result_san.get('instrumented_binary')}")
            else:
                self.logger.error(f"    Failed sanitizer instrumentation: {result_san.get('error')}")
                self.errors.append(f"Sanitizer instrumentation failed: {result_san.get('error')}")
                exit(1) # For debug
                return False
            
            # After the compilation, verify if the sanitizer-instrumented actual binary is qualified.
            self._update_actual_binary_path(saninstr_repo_path)
            actual_bin_rel_path = self.vulnerability_info.actual_binary_path # Update local variable
            if check_saninstr_binary_exists(saninstr_repo_path, actual_bin_rel_path):
                self.logger.info(f"Created qualified sanitizer-instrumented binary! \n{33*' '}{saninstr_repo_path}/{actual_bin_rel_path}")
            else:
                self.logger.error(f"  Failed to create qualified sanitizer-instrumented binary at expected path: \n{saninstr_repo_path}/{actual_bin_rel_path}")
                self.errors.append(f"Sanitizer instrumentation failed: Qualified binary not found after build.")
                exit(1) # For debug
                return False

        # Substep 3: Build source code with coverage instrumentation
        print("")
        if not found_cov_bin:
            self.logger.info("Building with coverage instrumentation...")
            self.coverage_agent = CoverageInstrumentAgent(self, target_repo_path, binary_relative_path)
            result = self.coverage_agent.run()
            if result['success']:
                self.logger.info(f"\"{self.project_name}\" coverage instrumentation completed.")
                # self.logger.info(f"    Binary path: {target_repo_path}/{result.get('instrumented_binary')}")
            else:
                self.logger.error(f"    Failed coverage instrumentation: {result.get('error')}")
                self.errors.append(f"Coverage instrumentation failed: {result.get('error')}")
                exit(2) # For debug
                return False
            
            # After the compilation, verify if the coverage-instrumented binary is qualified.
            self._update_actual_binary_path(target_repo_path)
            actual_bin_rel_path = self.vulnerability_info.actual_binary_path # Update local variable
            if check_llvmcov_binary_exists(target_repo_path, actual_bin_rel_path):
                self.logger.info(f"Created qualified coverage-instrumented binary! \n{33*' '}{target_repo_path}/{actual_bin_rel_path}")
            else:
                self.logger.error(f"  Failed to create qualified coverage-instrumented binary at expected path: \n{target_repo_path}/{actual_bin_rel_path}")
                self.errors.append(f"Coverage instrumentation failed: Qualified binary not found after build.")
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
            final_pov     = self.crash_agent.final_pov
            variants_povs = self.crash_agent.variants_povs
            if final_pov:
                self.logger.info(f"✓ Final PoV successfully generated and validated!")
                self.logger.info(f"  - PoV path: {final_pov['saved_pov_path']}")
                self.crash_inputs.append(final_pov['saved_pov_path'])
            elif len(variants_povs) > 0:
                self.logger.info(f"✓ No final PoV, but found {len(variants_povs)} variant PoVs that can trigger crashes.")
                for idx, pov in enumerate(variants_povs):
                    self.logger.info(f"    - Variant PoV {idx+1} path: {pov['saved_pov_path']}")
                    self.crash_inputs.append(pov['saved_pov_path'])
            else:
                self.logger.warning(f"✗ No valid PoV generated after {self.crash_agent.current_trigger_iteration} iterations")
                self.errors.append("Crash triggering failed: No valid PoV found")

        except Exception as e:
            self.logger.error(f"  Failed to run crash triggering: {e}", exc_info=True)
            self.errors.append(f"Crash triggering failed: {e}")

        self.logger.info("✓ Crash triggering analysis completed")

    def _update_actual_binary_path(self, target_repo_path: str) -> None:
        # IMPORTANT: This should only be called AFTER basic vuln analysis and the compilation.
        if len(self.vulnerability_info.actual_binary_path) == 0: # Examine if we already have the reliable actual binary path from cache.
            program_abs_path = os.path.join(target_repo_path, self.vulnerability_info.binary_path)
            if is_text_file(program_abs_path): # Examine if the "binary_path" is actually a text script file.
                self.logger.info(f"Detected that binary_path points to a text script file. Attempting to find the real binary...")
                # # Inner logic will finish the cache update and setting.
                actual_bin_path = self.vuln_agent.find_actual_binary_path(target_repo_path, entry_program_path=program_abs_path)
                self.vulnerability_info.actual_binary_path = actual_bin_path
            else:
                self.vulnerability_info.actual_binary_path = self.vulnerability_info.binary_path # necessary
            self.logger.info(f"✓ Entry program and actual binary path: \n{36*' '+self.vulnerability_info.binary_path} \n{36*' '+self.vulnerability_info.actual_binary_path}")
        else:
            pass # do nothing

    def validate_pov(self, command: str) -> Tuple[str, bool]:
        """
        Validate a PoV by running it with the sanitizer-instrumented binary to see if any crash occurs.
        This method can be called by both PathExplorationAgent and CrashTriggerAgent.

        Args:
            command: The harness command with instantiated PoV path (using llvm-cov repo path).

        Returns:
            A tuple of (crash_type, is_valid):
                - crash_type: The type of sanitizer crash detected (e.g., "heap-buffer-overflow"), or empty string if none.
                - is_valid: True if PoV triggers a sanitizer error, False otherwise.
        """
        if command is None or command.strip() == "":
            self.logger.error("  [DrillAgent] No harness command provided for PoV validation.")
            return "", False

        # Replace llvm-cov repo path with sanitizer-instr repo path
        llvm_cov_repo = self.config.target_repo_path
        saninstr_repo = self.config.saninstr_repo_path
        if llvm_cov_repo in command:
            command = command.replace(llvm_cov_repo, saninstr_repo)
        else:
            raise RuntimeError("Cannot map llvm-cov repo path to sanitizer-instr repo path in command.")

        # Set ASAN options
        env = os.environ.copy()
        env['ASAN_OPTIONS'] = 'use_sigaltstack=0:hard_rss_limit_mb=12000'
        # Handle existing ASAN_OPTIONS in command
        if "ASAN_OPTIONS=" in command:
            prefix = env['ASAN_OPTIONS'].rstrip(':')
            if 'ASAN_OPTIONS="' in command:
                command = re.sub(
                    r'ASAN_OPTIONS="([^"]*)"',
                    r'ASAN_OPTIONS="' + prefix + r':\1"',
                    command,
                    count=1
                )
            else:
                command = re.sub(
                    r'ASAN_OPTIONS=([^\s]+)',
                    r'ASAN_OPTIONS=' + prefix + r':\1',
                    command,
                    count=1
                )

        # Execute the test case, and check for sanitizer crash.
        self.logger.info(f"  [DrillAgent] PoV validation command: {command}")
        exit_code, exec_output = execute_command(command, env)
        if detect_sanitizer_triggered(exec_output):
            self.logger.info(f"  [DrillAgent] PoV validation successful: Sanitizer error detected! Exit code: {exit_code}")
            print(exec_output)
            # Crash successfully triggered! Triage the crash type further.
            cur_crash_type = get_sanitizer_crash_type(exec_output)
            return cur_crash_type, True
        else:
            self.logger.info(f"  [DrillAgent] PoV validation: No sanitizer error detected. Exit code: {exit_code}")

        return "", False

    def generate_report(self) -> Dict[str, Any]:
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


@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cost_input_usd: float = 0.0
    cost_output_usd: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def cost_total_usd(self) -> float:
        return self.cost_input_usd + self.cost_output_usd

    def add(self, input_tokens: int = 0, output_tokens: int = 0) -> None:
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens

    def add_cost(self, cost_input_usd: float = 0.0, cost_output_usd: float = 0.0) -> None:
        self.cost_input_usd += cost_input_usd
        self.cost_output_usd += cost_output_usd

# # Not use it currently, but kept for reference.
# @dataclass
# class AnalysisState:
#     # Track the state of vulnerability analysis
#     phase: str = "initialized"  # initialized, instrumented, analyzing, exploring, completed
#     crash_inputs: List[str] = field(default_factory=list)
#     pov_candidates: List[Dict] = field(default_factory=list)
