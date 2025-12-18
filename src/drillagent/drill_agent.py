#!/usr/bin/env python3
import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from drillagent.config import AgentConfig
from drillagent.models import LLM
from drillagent.instrumentation import DistanceAgent, CoverageInstrumentAgent
from drillagent.task_loader.sec_bench import RawSecbTaskLoader, SecbTask
from drillagent.pov_analysis.vuln_analysis import VulnAnalysisAgent, VulnInfo
from drillagent.pov_analysis.path_exploration import PathExplorationAgent
from drillagent.utils.utils import check_coverage_binary_exists, check_repo_at_commit

class DrillAgent:
    # Core orchestration class of DrillAgent
    # Note that:
    # 1. This DrillAgent only runs for a single CVE task at a time. Benchmark's batch task scheduling should be placed at the caller layer.
    # 2. Only the essential elements for basic PoV generation are included in DrillAgent; all other information should be maintained at the caller layer.

    # This dataclass should be benchmark-agnostic.

    def __init__(self, config: AgentConfig):
        # The only init parameter is the AgentConfig dataclass instance.
        self.config = config       # Include all the PoV task information and configuration options.
        self.phase = "initialized" # TODO: initialized, instrumented, analyzing, exploring, completed
        self.skip_instrumentation     = config.disable_program_instrumentation
        self.skip_vulnerability_analysis = config.disable_vulnerability_analysis 
        self.skip_crash_trigger_analysis = config.disable_crash_trigger_analysis
        self.skip_path_exploration = config.disable_path_exploration
        self.skip_pov_generation = config.disable_pov_generation

        self.work_dir   = self.config.work_dir
        self.output_dir = self.config.output_dir
        self.iteration = 0
        self.errors = []

        # LLM interface
        self.llm: LLM = None
        self.reasoning_llm: LLM = None
        self.low_cost_llm:  LLM = None

        # Intermediate analysis results
        self.vulnerability_info: VulnInfo = VulnInfo() # For vulnerability analysis results (e.g., call trace, root cause)
        self.project_info       = None # For project-level analysis results # TBD
        # Path exploration results
        self.pov_candidates     = []
        self.coverage_data      = None
        self.closest_pov_candidate = None
        
        # Instrumentation results
        self.task_loader: RawSecbTaskLoader = None  # Dataset task loader (general interface)
        self.secb_task: SecbTask = None  # SEC-bench task data (dataset-specific)
        self.instrumented_binary = None

        # Final analysis results
        self.crash_inputs = []         # Real PoV inputs that trigger the vulnerability

        # # Initialize logger and components (TODO: implement these)
        self.logger = self._setup_logger()
        self._init_components()
        self._init_task_loader()  # Load task data early for fail-fast behavior

        self.logger.info(f"DrillAgent initialized for target: {config.target_repo_path}")
        self.logger.info(f"Skip instrumentation: {self.skip_instrumentation}")
        self.logger.info(f"Skip vulnerability analysis: {self.skip_vulnerability_analysis}")
        self.logger.info(f"Skip crash trigger analysis: {self.skip_crash_trigger_analysis}")

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
        # Initialize all required components
        self.logger.info("Initializing components...")

        # Initialize LLM interface
        try:
            self.logger.info(f"Initializing {self.config.model_provider} LLM...")
            self.logger.info(f"Config model_name: '{self.config.model_name}'")
            
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

        self.logger.info("Components initialized")

    def _init_task_loader(self):
        """Initialize dataset-specific task loader and load task data.
        
        This method loads task data early for fail-fast behavior.
        Currently only SEC-bench dataset is supported.
        
        Future: Support multiple datasets by checking config.dataset_type
        and instantiating the appropriate loader (SecbTaskLoader, PrimevulTaskLoader, etc.)
        """
        self.logger.info("Initializing task loader...")
        
        try:
            # Get project root for dataset paths
            project_root = Path(__file__).resolve().parent.parent.parent
            instances_dir = project_root / 'datasets' / 'sec-bench' / 'CVE-instances'
            
            # Build instance_id from project_name and cve_id
            instance_id = f"{self.config.project_name}.{self.config.cve_id.lower()}"
            
            # Initialize task loader
            self.task_loader = RawSecbTaskLoader(
                dataset_path=str(instances_dir),
                instance_ids=[instance_id]
            )
            self.task_loader.load_cve_tasks()
            
            # Load the specific task
            self.secb_task = self.task_loader.get_task(instance_id)
            
            if not self.secb_task:
                raise ValueError(f"Task {instance_id} not found in CVE-instances")
            
            self.logger.info(f"✓ Task loaded: {instance_id}")
            self.logger.info(f"  - project: {self.secb_task.project_name}")
            self.logger.info(f"  - binary_name: {self.secb_task.binary_name}")
            self.logger.info(f"  - binary_path: {self.secb_task.binary_path}")
            self.logger.info(f"  - vuln_location: {self.secb_task.vuln_location}")
            
        except Exception as e:
            self.logger.error(f"Failed to load task: {e}")
            raise ValueError(f"Task loading failed: {e}")

    def _clean_repository(self):
        # Clean build artifacts and git repository state
        self.logger.info("Cleaning repository...")

        # Clean build artifacts (make clean or equivalent)
        self.logger.info("Cleaning build artifacts...")
        clean_result = subprocess.run(
            ['make', 'clean'],
            cwd=self.config.target_repo_path,
            capture_output=True,
            text=True,
            timeout=60
        )
        if clean_result.returncode == 0:
            self.logger.info("✓ Build artifacts cleaned")
        else:
            self.logger.warning(f"make clean failed or not available (this is OK if no Makefile exists)")
        
        # Reset git repository state - discard all local changes
        self.logger.info("Resetting git repository state...")
        subprocess.run(
            ['git', 'reset', '--hard', 'HEAD'],
            cwd=self.config.target_repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        self.logger.info("✓ Git repository reset to HEAD")
        
        # Clean untracked files and directories
        self.logger.info("Cleaning untracked files...")
        subprocess.run(
            ['git', 'clean', '-fdx'],
            cwd=self.config.target_repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        self.logger.info("✓ Untracked files cleaned")

    def _checkout_base_commit(self):
        # Checkout the target repository to the specified base commit
        self.logger.info(f"Checking out base commit: {self.config.base_commit}")

        # Checkout the target commit
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
        
        # Update git submodules
        self.logger.info("Updating git submodules...")
        result = subprocess.run(
            ['git', 'submodule', 'update', '--init', '--recursive'],
            cwd=self.config.target_repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        self.logger.info("✓ Successfully updated git submodules")
        if result.stdout:
            self.logger.debug(f"Submodule output: {result.stdout.strip()}")

    def run(self) -> Dict[str, Any]:
        """
        Main orchestration workflow
        Returns:
            Dictionary containing analysis results and generated PoVs
        """
        print("")
        self.logger.info("=" * 60)
        self.logger.info("Starting DrillAgent workflow")
        self.logger.info("=" * 60)

        # Checkout the base commit for the target repository
        assert len(self.config.base_commit) == 40, "Base commit should be a valid 40-char git SHA1 hash."

        try:
            # Check if we can reuse existing coverage binary (check commit first to save time)
            if check_repo_at_commit(Path(self.config.target_repo_path), self.config.base_commit, self.logger):
                existing_binary = check_coverage_binary_exists(
                    target_repo_path=Path(self.config.target_repo_path),
                    secb_task=self.secb_task,
                    logger=self.logger
                )
                if existing_binary:
                    self.logger.info(f"✓ Reusing existing coverage binary: {existing_binary}")
                    self.coverage_binary = existing_binary
                    self.config.enable_coverage = False
            
            # Phase 1: Code Instrumentation
            if not self.skip_instrumentation:
                self._phase_instrumentation()

            # Phase 2: Vulnerability Analysis
            if not self.skip_vulnerability_analysis:
                self._phase_vulnerability_analysis()

            # Phase 3: Path Exploration with the coverage feedback
            if not self.skip_path_exploration:
                self._phase_path_exploration()

            # Phase 4: PoV Generation and Verification
            if not self.skip_pov_generation:
                self._phase_crash_triggering()

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

        # Step 1: Run AFLGo instrumentation if enabled
        if self.config.enable_distance:
            self.logger.info("  - Running AFLGo instrumentation...")
            
            # Runtime config only - task data comes from secb_task
            config_dict = {
                'repos_dir': 'repos',
                'log_level': 'INFO',
                'log_file': f'aflgo_{self.secb_task.project_name}.log'
            }
            
            distance_agent = DistanceAgent(
                config=config_dict,
                secb_task=self.secb_task,
                llm=self.llm,
                logger=self.logger
            )
            
            # Execute the full instrumentation workflow
            result = distance_agent.run()
            if result['success']:
                self.logger.info(f"    ✓ AFLGo instrumentation completed: {result.get('instrumented_binary')}")
                self.instrumented_binary = result.get('instrumented_binary')
            else:
                self.logger.error(f"    Failed to instrument binary: {result.get('error')}")
                self.errors.append(f"AFLGo instrumentation failed: {result.get('error')}")
        else:
            self.logger.info("  - AFLGo instrumentation disabled (enable_distance=False)")

        # Step 2: Build with coverage instrumentation
        if self.config.enable_coverage:
            self.logger.info("  - Building with coverage instrumentation...")
            coverage_agent = CoverageInstrumentAgent(self)
            
            # Clean and checkout before instrumentation
            self._clean_repository()
            self._checkout_base_commit()

            # Run coverage instrumentation
            result = coverage_agent.run()
                
            if result['success']:
                self.logger.info(f"    ✓ Coverage instrumentation completed")
                self.logger.info(f"      Binary: {result.get('instrumented_binary')}")
                self.coverage_binary = result.get('instrumented_binary')
            else:
                self.logger.error(f"    Failed coverage instrumentation: {result.get('error')}")
                self.errors.append(f"Coverage instrumentation failed: {result.get('error')}")

        # Step 3: Apply memory sanitizer if enabled
        if self.config.enable_sanitizer:
            self.logger.info("  - Applying memory sanitizer...")
            # sanitized_binary = self.memory_sanitizer.instrument(self.config.target_repo)
            self.logger.info("    TODO: Implement memory sanitizer")

        self.logger.info("  ✓ Instrumentation phase completed")

    def _phase_vulnerability_analysis(self):
        """Phase 2: Analyze vulnerability using LLM"""
        self.logger.info("\n[Phase 2] Vulnerability Analysis")
        self.phase = "analyzing"

        # Use VulnAnalysisAgent for structured vulnerability analysis
        try:
            vuln_agent = VulnAnalysisAgent(self)
            self.logger.info("  - Initialized VulnAnalysisAgent!")

            # Run the analysis - returns VulnInfo instance directly
            self.vulnerability_info = vuln_agent.run()

            # Print the formatted vulnerability analysis results
            vuln_info_str = self.vulnerability_info.format_output()
            print(vuln_info_str)
            self.logger.info("  ✓ Vulnerability analysis completed")

        except Exception as e:
            self.logger.error(f"  Failed to analyze vulnerability: {e}", exc_info=True)
            self.errors.append(f"Vulnerability analysis failed: {e}")
            # Keep the VulnInfo instance but mark it with error in root_cause field
            self.vulnerability_info.root_cause = f"Analysis failed: {e}"

    def _phase_path_exploration(self):
        """Phase 3: Coverage-guided path exploration"""
        self.logger.info("\n[Phase 3] Path Exploration")
        self.phase = "exploring"

        max_iterations = self.config.max_iterations

        # Utilize PathExplorationAgent to reach the vulnerable function
        try:
            path_agent = PathExplorationAgent(self)
            self.logger.info("  - Initialized PathExplorationAgent!")

            # Run the path exploration process
            path_agent.run()

            # Extract exploration results
            self.pov_candidates = path_agent.history_pov_candidates
            self.closest_pov_candidate = path_agent.best_pov_candidate

            # TODO: Print the formatted exploration results

        except Exception as e:
            self.logger.error(f"  Failed to run path exploration: {e}", exc_info=True)
            self.errors.append(f"Path exploration failed: {e}")

        self.logger.info("  ✓ Path exploration completed")
        self.logger.info(f"  - Total PoV candidates generated: {len(self.pov_candidates)}")

    def _phase_crash_triggering(self):
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
        try:
            output_path = Path(self.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Save PoV candidates as JSON
            # pov_output_file = output_path / "pov_candidates.json"
            # with open(pov_output_file, 'w', encoding='utf-8') as f:
            #     json.dump(self.pov_candidates, f, indent=2)

            # self.logger.info(f"    ✓ Saved PoV candidates to {pov_output_file}")

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


