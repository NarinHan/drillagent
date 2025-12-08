#!/usr/bin/env python3
import os
import sys
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List
from dataclasses import dataclass, field

from drillagent.config import AgentConfig 
from drillagent.models import LLM
from drillagent.instrumentation import ConfigGeneratorAgent, InstrumentationAgent, CoverageInstrumentAgent


class DrillAgent:
    # Core orchestration class of DrillAgent
    # Note that:
    # 1. This DrillAgent only runs for a single CVE task at a time. Benchmark's batch task scheduling should be placed at the caller layer.
    # 2. Only the essential elements for basic PoV generation are included in DrillAgent; all other information should be maintained at the caller layer.

    def __init__(self, config: AgentConfig):
        # The only init parameter is the AgentConfig dataclass instance.
        self.config = config
        self.phase = "initialized" # TODO: initialized, instrumented, analyzing, mutating, completed
        self.skip_instrumentation     = config.disable_program_instrumentation
        self.skip_vulnerability_analysis = config.disable_vulnerability_analysis # Currently we only consider these two skip options.
        self.iteration = 0
        self.errors = []

        # Intermediate analysis results
        self.vulnerability_info = None # For vulnerability analysis results (e.g., root cause)
        self.project_info       = None # For project-level analysis results
        self.pov_candidates     = []
        self.coverage_data      = None
        self.closest_pov_candidate = None
        
        # Instrumentation results
        self.aflgo_config_path  = None # Path to AFLGo configuration file
        self.instrumented_binary = None

        # Final analysis results
        self.crash_inputs = []         # Real PoV inputs that trigger the vulnerability

        # # Initialize logger and components (TODO: implement these)
        self.logger = self._setup_logger()
        self._init_components()

        self.logger.info(f"DrillAgent initialized for target: {config.target_repo_path}")
        self.logger.info(f"Skip instrumentation: {self.skip_instrumentation}")
        self.logger.info(f"Skip vulnerability analysis: {self.skip_vulnerability_analysis}")

    def _setup_logger(self) -> logging.Logger:
        # Setup logging for DrillAgent
        # Ensure output directory exists
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Configure root logger to INFO to avoid debug spam from third-party libs
        logging.basicConfig(
            level=logging.INFO,  # Always INFO for root logger
            format='[%(asctime)s] %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(f"{self.config.output_dir}/drillagent.log")
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
        # Initialize all required components
        self.logger.info("Initializing components...")

        # Initialize LLM interface
        try:
            self.logger.info(f"Initializing {self.config.model_provider} LLM...")
            self.llm = LLM(
                provider=self.config.model_provider,
                model_name=self.config.model_name,
                api_key=self.config.api_key
            )
            self.logger.info(f"✓ LLM initialized: {self.llm.provider}/{self.llm.model_name}")
        except Exception as e:
            self.logger.error(f"Failed to initialize LLM: {e}")
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

        # Initialize coverage instrumentation agent
        if self.config.enable_coverage:
            self.logger.info("Initializing CoverageInstrumentAgent...")
            self.coverage_instrument = CoverageInstrumentAgent
            self.logger.info("✓ CoverageInstrumentAgent class loaded")
        else:
            self.coverage_instrument = None
        
        # Distance calculator using ConfigGeneratorAgent
        if self.config.enable_distance:
            self.logger.info("Initializing ConfigGeneratorAgent for distance calculation...")
            # Get project root to locate SEC-bench data
            project_root = Path(__file__).resolve().parent.parent.parent
            secbench_dir = project_root / 'datasets' / 'sec-bench'
            
            self.config_generator = ConfigGeneratorAgent(
                llm_provider=self.config.model_provider,
                llm_model=self.config.model_name,
                api_key=self.config.api_key,
                secbench_dir=secbench_dir
            )
            self.logger.info("✓ ConfigGeneratorAgent initialized")
        else:
            self.config_generator = None
        
        # Memory sanitizer (TODO)
        self.memory_sanitizer = None

        # TODO: Initialize PoV analysis components
        # self.root_cause_analyzer = RootCauseAnalyzer(self.llm)
        # self.path_explorer = PathExplorer(self.llm)
        # self.input_mutator = InputMutator(self.llm)
        self.root_cause_analyzer = None
        self.path_explorer = None
        self.input_mutator = None

        self.logger.info("Components initialized")

    def _checkout_base_commit(self):
        # Checkout the target repository to the specified base commit
        self.logger.info(f"Checking out base commit: {self.config.base_commit}")

        # Verify target repo path exists
        if not os.path.exists(self.config.target_repo_path):
            error_msg = f"Target repository path does not exist: {self.config.target_repo_path}"
            self.logger.error(error_msg)
            raise FileNotFoundError(error_msg)

        # Verify it's a git repository
        git_dir = os.path.join(self.config.target_repo_path, '.git')
        if not os.path.exists(git_dir):
            error_msg = f"Target path is not a git repository: {self.config.target_repo_path}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)

        try:
            # Run git checkout command
            result = subprocess.run(
                ['git', 'checkout', self.config.base_commit],
                cwd=self.config.target_repo_path,
                capture_output=True,
                text=True,
                check=True
            )

            self.logger.info(f"✓ Successfully checked out commit: {self.config.base_commit[:12]}...")
            if result.stdout:
                self.logger.debug(f"Git output: {result.stdout.strip()}")

        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to checkout commit {self.config.base_commit}: {e.stderr}"
            self.logger.error(error_msg)
            self.errors.append(error_msg)
            raise RuntimeError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error during git checkout: {str(e)}"
            self.logger.error(error_msg)
            self.errors.append(error_msg)
            raise

    def run(self) -> Dict[str, Any]:
        """
        Main orchestration workflow
        Returns:
            Dictionary containing analysis results and generated PoVs
        """
        self.logger.info("=" * 60)
        self.logger.info("Starting DrillAgent workflow")
        self.logger.info("=" * 60)

        # Checkout the base commit for the target repository
        assert len(self.config.base_commit) == 40, "Base commit should be a valid 40-char git SHA1 hash."
        self._checkout_base_commit()

        try:
            # Phase 1: Code Instrumentation
            if not self.skip_instrumentation:
                self._phase_instrumentation()

            # Phase 2: Vulnerability Analysis
            if not self.skip_vulnerability_analysis:
                self._phase_vulnerability_analysis()

            # Phase 3: Path Exploration and Input Mutation
            self._phase_exploration()

            # Phase 4: PoV Generation and Verification
            self._phase_pov_generation()

            # Mark as completed
            self.phase = "completed"

            return self._generate_report()

        except Exception as e:
            self.logger.error(f"Fatal error in DrillAgent workflow: {e}", exc_info=True)
            self.errors.append(str(e))
            return self._generate_report()

    def _phase_instrumentation(self):
        """Phase 1: Instrument the target binary with coverage and sanitizers"""
        self.logger.info("\n[Phase 1] Code Instrumentation")
        self.phase = "instrumentation"

        # TODO: Implement instrumentation logic
        # Step 1: Build with coverage instrumentation
        if self.config.enable_coverage and self.coverage_instrument:
            self.logger.info("  - Applying coverage instrumentation (llvm-cov)...")
            try:
                # Instantiate and run coverage agent - pass self (DrillAgent instance)
                coverage_agent = self.coverage_instrument(self)
                
                result = coverage_agent.run()
                
                if result['success']:
                    self.logger.info(f"    ✓ Coverage instrumentation completed")
                    self.logger.info(f"      Binary: {result.get('instrumented_binary')}")
                    # Store the coverage-instrumented binary path
                    self.coverage_binary = result.get('instrumented_binary')
                else:
                    self.logger.error(f"    Failed coverage instrumentation: {result.get('error')}")
                    self.errors.append(f"Coverage instrumentation failed: {result.get('error')}")
            except Exception as e:
                self.logger.error(f"    Coverage instrumentation error: {e}")
                self.errors.append(f"Coverage instrumentation error: {e}")

        # Step 2: Calculate distance file for guided fuzzing
        if self.config.enable_distance and self.config_generator:
            self.logger.info("  - Generating AFLGo configuration...")
            try:
                # Get project root for paths
                project_root = Path(__file__).resolve().parent.parent.parent
                
                # Determine CVE instance path
                if self.config.cve_id:
                    # Try to find CVE instance from SEC-bench data
                    instance_path = project_root / 'datasets' / 'sec-bench' / 'CVE-instances' / f"{self.config.cve_id}.json"
                    
                    if instance_path.exists():
                        # Generate config for AFLGo instrumentation
                        output_dir = Path(self.config.output_dir) / 'configs'
                        output_path = output_dir / f"{self.config.cve_id}.yaml"
                        
                        self.logger.info(f"    Generating config from: {instance_path.name}")
                        config_yaml = self.config_generator.generate_config(instance_path, output_path)
                        
                        # Store config path for later use
                        self.aflgo_config_path = str(output_path)
                        self.logger.info(f"    ✓ AFLGo config generated: {output_path}")
                        
                        # Run AFLGo instrumentation using InstrumentationAgent
                        self.logger.info("  - Running AFLGo instrumentation...")
                        
                        # Load the YAML config file into a dictionary
                        import yaml
                        with open(output_path, 'r') as f:
                            config_dict = yaml.safe_load(f)
                        
                        instrumentation_agent = InstrumentationAgent(
                            config=config_dict,
                            llm=self.llm,
                            logger=self.logger
                        )
                        
                        # Execute the full instrumentation workflow
                        result = instrumentation_agent.run()
                        
                        if result['success']:
                            self.logger.info(f"    ✓ AFLGo instrumentation completed: {result.get('instrumented_binary')}")
                            self.instrumented_binary = result.get('instrumented_binary')
                        else:
                            self.logger.error(f"    Failed to instrument binary: {result.get('error')}")
                            self.errors.append(f"Instrumentation failed: {result.get('error')}")
                    else:
                        self.logger.warning(f"    CVE instance not found: {instance_path}")
                        self.logger.info("    Skipping config generation")
                else:
                    self.logger.warning("    No CVE ID provided, skipping config generation")
            except Exception as e:
                self.logger.error(f"    Failed to generate AFLGo config: {e}")
                self.errors.append(f"Config generation failed: {e}")

        # Step 3: Build with memory sanitizer
        if self.config.enable_sanitizer:
            self.logger.info("  - Applying memory sanitizer...")
            # sanitized_binary = self.memory_sanitizer.instrument(self.config.target_repo)
            self.logger.info("    TODO: Implement memory sanitizer")

        self.logger.info("  ✓ Instrumentation phase completed")

    def _phase_vulnerability_analysis(self):
        """Phase 2: Analyze vulnerability using LLM"""
        self.logger.info("\n[Phase 2] Vulnerability Analysis")
        self.phase = "analyzing"

        # Check if vulnerability analysis is disabled
        if self.config.disable_vulnerability_analysis:
            self.logger.info("  - Vulnerability analysis disabled by config")
            return

        # Use VulnAnalysisAgent for structured vulnerability analysis
        try:
            from drillagent.pov_analysis.vuln_analysis import VulnAnalysisAgent
            
            self.logger.info("  - Initializing VulnAnalysisAgent...")
            vuln_agent = VulnAnalysisAgent(self)
            
            # Run the analysis
            analysis_results = vuln_agent.run()
            
            # Store the structured analysis results
            self.vulnerability_info = {
                "refined_vuln_location": analysis_results.get('refined_vuln_location', ''),
                "refined_harness_command": analysis_results.get('refined_harness_command', ''),
                "binary_path": analysis_results.get('binary_path', ''),
                "call_trace": analysis_results.get('call_trace', ''),
                "entry_function": analysis_results.get('entry_function', ''),
                "crash_function": analysis_results.get('crash_function', ''),
                "vuln_type": analysis_results.get('vuln_type', ''),
                "root_cause": analysis_results.get('root_cause', ''),
                "critical_branches": analysis_results.get('critical_branches', [])
            }
            
            self.logger.info("  ✓ Vulnerability analysis completed")
            self.logger.info(f"    - Vulnerability Type: {self.vulnerability_info['vuln_type']}")
            self.logger.info(f"    - Crash Function: {self.vulnerability_info['crash_function']}")
            self.logger.info(f"    - Entry Function: {self.vulnerability_info['entry_function']}")
            self.logger.info(f"    - Vuln Location: {self.vulnerability_info['refined_vuln_location']}")
            
        except Exception as e:
            self.logger.error(f"  Failed to analyze vulnerability: {e}", exc_info=True)
            self.errors.append(f"Vulnerability analysis failed: {e}")
            self.vulnerability_info = {"error": str(e)}

    def _phase_exploration(self):
        """Phase 3: Coverage-guided path exploration and input mutation"""
        self.logger.info("\n[Phase 3] Path Exploration and Input Mutation")
        self.phase = "mutating"

        max_iterations = self.config.max_iterations

        for iteration in range(max_iterations):
            self.iteration = iteration
            self.logger.info(f"\n  Iteration {iteration + 1}/{max_iterations}")

            # Step 1: Use LLM to explore execution paths toward vulnerability
            if self.llm and not self.config.disable_coverage_feedback:
                self.logger.info("    - Exploring paths with LLM guidance...")

                # Prepare context for path exploration
                exploration_prompt = f"""Based on the vulnerability analysis, suggest execution paths that could trigger the vulnerability.

Vulnerability Info: {self.vulnerability_info.get('llm_analysis', 'Not available')[:500] if self.vulnerability_info else 'Not analyzed'}

Harness Command: {self.config.harness_command or 'Not specified'}

Please suggest:
1. Input patterns that might trigger the vulnerable path
2. Specific program states or conditions needed
3. Potential input mutations to explore

Format your response as structured suggestions."""

                try:
                    path_suggestions = self.llm.generate(
                        prompt=exploration_prompt,
                        system_prompt="You are an expert in program analysis and vulnerability exploitation.",
                        temperature=0.8,  # Higher temperature for creative exploration
                        max_tokens=2048
                    )

                    self.logger.info(f"    ✓ Path exploration suggestions generated ({len(path_suggestions)} chars)")

                except Exception as e:
                    self.logger.warning(f"    Path exploration failed: {e}")
                    path_suggestions = None
            else:
                self.logger.info("    - Path exploration skipped (LLM unavailable or disabled)")
                path_suggestions = None

            # Step 2: Generate mutated inputs based on exploration
            if self.llm and not self.config.disable_crash_trigger_analysis:
                self.logger.info("    - Generating input mutations...")

                mutation_prompt = f"""Generate test inputs to trigger the vulnerability.

Path Suggestions: {path_suggestions[:500] if path_suggestions else 'None'}

Harness Command: {self.config.harness_command or 'Please infer from project structure'}

Generate concrete test inputs that could trigger the vulnerability.
Consider edge cases, boundary conditions, and malformed inputs."""

                try:
                    mutated_inputs_suggestion = self.llm.generate(
                        prompt=mutation_prompt,
                        system_prompt="You are an expert in fuzzing and test case generation.",
                        temperature=0.9,  # Higher temperature for diverse mutations
                        max_tokens=2048
                    )

                    self.logger.info(f"    ✓ Input mutations generated ({len(mutated_inputs_suggestion)} chars)")

                    # Store the generated inputs as PoV candidates
                    self.pov_candidates.append({
                        "iteration": iteration,
                        "path_suggestions": path_suggestions,
                        "input_mutations": mutated_inputs_suggestion,
                        "timestamp": self.iteration
                    })

                except Exception as e:
                    self.logger.warning(f"    Input mutation failed: {e}")

            # TODO: Step 3: Actually execute the inputs with harness and collect coverage
            # This requires implementing the harness execution and coverage collection
            # For now, we just simulate the exploration process

            # Step 4: Check early termination conditions
            if len(self.pov_candidates) >= 5:
                self.logger.info(f"    - Generated {len(self.pov_candidates)} PoV candidates, moving to next phase")
                break

        self.logger.info("  ✓ Exploration and mutation completed")
        self.logger.info(f"  - Total PoV candidates generated: {len(self.pov_candidates)}")

    def _phase_pov_generation(self):
        """Phase 4: Generate and verify PoV test cases"""
        self.logger.info("\n[Phase 4] PoV Generation and Verification")

        # Step 1: Convert PoV candidates to concrete test cases
        self.logger.info("  - Refining PoV candidates into concrete test cases...")

        if self.llm and len(self.pov_candidates) > 0:
            self.logger.info(f"  - Processing {len(self.pov_candidates)} PoV candidates...")

            for idx, candidate in enumerate(self.pov_candidates):
                self.logger.info(f"    - Processing candidate {idx + 1}/{len(self.pov_candidates)}...")

                # Use LLM to generate concrete PoV code/script
                pov_generation_prompt = f"""Generate a concrete proof-of-vulnerability (PoV) test case based on the following:

Input Mutations: {candidate.get('input_mutations', 'N/A')[:500]}

Path Suggestions: {candidate.get('path_suggestions', 'N/A')[:300]}

Harness Command: {self.config.harness_command or 'To be determined'}

CVE ID: {self.config.cve_id or 'N/A'}

Please generate:
1. A concrete test input file or command-line arguments
2. Steps to execute the test
3. Expected crash behavior or sanitizer output

Format your response as a complete, executable test case."""

                try:
                    pov_code = self.llm.generate(
                        prompt=pov_generation_prompt,
                        system_prompt="You are an expert in writing PoV test cases for vulnerabilities.",
                        temperature=0.5,  # Lower temperature for more deterministic output
                        max_tokens=3072
                    )

                    # Update candidate with generated PoV
                    candidate['pov_code'] = pov_code
                    candidate['status'] = 'generated'

                    self.logger.info(f"      ✓ PoV generated ({len(pov_code)} chars)")

                except Exception as e:
                    self.logger.warning(f"      Failed to generate PoV: {e}")
                    candidate['status'] = 'failed'
                    candidate['error'] = str(e)

        # Step 2: Save PoV candidates to output directory
        self.logger.info("  - Saving PoV test cases...")
        import json
        from pathlib import Path

        try:
            output_path = Path(self.config.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Save PoV candidates as JSON
            pov_output_file = output_path / "pov_candidates.json"
            with open(pov_output_file, 'w', encoding='utf-8') as f:
                json.dump(self.pov_candidates, f, indent=2)

            self.logger.info(f"    ✓ Saved PoV candidates to {pov_output_file}")

            # Save individual PoV scripts
            for idx, candidate in enumerate(self.pov_candidates):
                if candidate.get('status') == 'generated':
                    pov_script_file = output_path / f"pov_{idx + 1}.txt"
                    with open(pov_script_file, 'w', encoding='utf-8') as f:
                        f.write(candidate.get('pov_code', ''))
                    self.logger.info(f"    ✓ Saved PoV script to {pov_script_file}")

        except Exception as e:
            self.logger.error(f"    Failed to save PoVs: {e}")
            self.errors.append(f"Failed to save PoVs: {e}")

        # TODO: Step 3: Actually verify PoVs by executing them with harness
        # This requires:
        # - Implementing harness execution logic
        # - Detecting crashes from sanitizer output
        # - Validating that the crash matches the expected vulnerability
        self.logger.info("  - PoV verification (TODO: implement harness execution)")
        self.logger.info("    For now, PoVs are generated but not automatically verified")

        # Step 4: Generate summary report
        successful_povs = sum(1 for c in self.pov_candidates if c.get('status') == 'generated')
        self.logger.info(f"\n  ✓ PoV generation completed: {successful_povs}/{len(self.pov_candidates)} successful")

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
            "vulnerability_info": self.vulnerability_info,
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
    phase: str = "initialized"  # initialized, instrumented, analyzing, mutating, completed
    crash_inputs: List[str] = field(default_factory=list)
    pov_candidates: List[Dict] = field(default_factory=list)
    iteration: int = 0


