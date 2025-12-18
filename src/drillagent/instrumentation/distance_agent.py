"""
Instrumentation Agent for DrillAgent

This agent handles AFLGo instrumentation for directed fuzzing, including:
- Repository setup
- Target extraction from sanitizer reports  
- Build instrumentation (CG/CFG generation)
- Distance calculation
- Final instrumented binary generation
"""

import os
import subprocess
import shutil
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from drillagent.instrumentation.base_agent import BaseAgent, AgentState
from drillagent.models.llm import LLM
from drillagent.prompts.DistanceAgent_prompt import (
    DA_system_prompt,
    DA_extract_target_prompt,
    DA_identify_paragraph_prompt,
    DA_build_prompt,
    DA_distance_generation_prompt
)

if TYPE_CHECKING:
    from drillagent.task_loader.sec_bench import SecbTask


class DistanceAgent(BaseAgent):
    """AFLGo-based distance agent for directed fuzzing
    
    This agent inherits from BaseAgent and specializes in:
    - Setting up target repositories
    - Extracting vulnerability targets from sanitizer reports
    - Building projects with AFLGo instrumentation
    - Calculating distances for directed fuzzing
    - Producing instrumented binaries ready for fuzzing
    """
    
    # AFLGo-specific system prompt
    AFLGO_SYSTEM_PROMPT = DA_system_prompt
    
    def __init__(self, config: Dict, secb_task: "SecbTask" = None, llm: Optional[LLM] = None, logger=None):
        """Initialize DistanceAgent
        
        Args:
            config: Configuration dictionary containing:
                - aflgo_dir, repos_dir, temps_dir: Directory paths
                - llm_model, openai_api_key: LLM configuration
                - output_dir: Output directory for artifacts
            secb_task: SecbTask instance with task-specific data:
                - repo: Git repository URL
                - base_commit: Commit to instrument
                - instance_id: CVE identifier
                - sanitizer_report: Sanitizer report content
                - build_sh: Build commands
                - binary_name, binary_path: Binary information
            llm: LLM instance (will create if not provided)
            logger: Logger instance (will create if not provided)
        """
        self.config = config
        self.secb_task = secb_task
        
        # Setup environment first
        self.setup_environment()
        
        # Initialize LLM if not provided
        if llm is None:
            llm_model = config.get('llm_model', 'gpt-4-turbo')
            llm_api_key = config.get('openai_api_key') or os.getenv('OPENAI_API_KEY')
            llm = LLM(provider="openai", model_name=llm_model, api_key=llm_api_key)
        
        # Initialize BaseAgent with AFLGo-specific system prompt
        # BaseAgent will handle log file creation using config
        super().__init__(
            llm=llm,
            system_prompt=self.AFLGO_SYSTEM_PROMPT,
            initial_phase="setup",
            max_attempts=10,
            logger=logger,
            config=config
        )
        
        # Store environment variables for reset between attempts
        self.original_env = {
            'CC': os.environ.get('CC', ''),
            'CXX': os.environ.get('CXX', ''),
            'CFLAGS': '',
            'CXXFLAGS': '',
            'LDFLAGS': os.environ.get('LDFLAGS', '')
        }
        
        self.logger.info(f"Initialized DistanceAgent for {self.repo_name}")
    
    def setup_environment(self):
        """Setup directory structure and environment variables for AFLGo"""
        # Determine base directory (cs562 level)
        # DrillAgent and aflgo are siblings under cs562
        if 'aflgo_dir' in self.config:
            # Use configured directory
            ray_base = Path(self.config['aflgo_dir']).parent
        else:
            # Auto-detect: we're in DrillAgent/src/drillagent/instrumentation/instrumentation_agent.py
            # Go up to DrillAgent root, then up one more to cs562 where aflgo is a sibling
            script_dir = Path(__file__).resolve().parent  # .../DrillAgent/src/drillagent/instrumentation
            drillagent_root = script_dir.parent.parent.parent  # .../DrillAgent
            ray_base = drillagent_root.parent  # .../cs562 (where both DrillAgent and aflgo live)
        
        # Base paths - aflgo is at cs562/aflgo (sibling to DrillAgent)
        self.aflgo_dir = Path(self.config.get('aflgo_dir', ray_base / 'aflgo')).resolve()
        # repos and temps are relative to DrillAgent by default, or use config paths
        default_repos = ray_base / 'DrillAgent' / 'repos'
        default_temps = ray_base / 'DrillAgent' / 'fuzzing' / 'temps'
        self.repos_dir = Path(self.config.get('repos_dir', default_repos)).resolve()
        self.temps_dir = Path(self.config.get('temps_dir', default_temps)).resolve()
        
        # Repository info - prefer secb_task, fallback to config
        self.repo_url = self.secb_task.repo if self.secb_task else self.config.get('repo_url', '')
        self.repo_name = self.secb_task.project_name if self.secb_task else Path(self.repo_url).stem.replace('.git', '')
        
        # Subject and temp directories
        self.subject_dir = self.repos_dir / self.repo_name
        
        # Create temp directory name
        temp_name = f"temp_{self.repo_name}"
        cve_id = self.secb_task.instance_id if self.secb_task else self.config.get('cve_id')
        if cve_id:
            cve_suffix = cve_id.replace('CVE-', '').replace('-', '_')
            temp_name += f"_{cve_suffix}"
        self.temp_dir = self.temps_dir / temp_name
        
        # Create directories
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        
        # Set AFLGo environment variables
        os.environ['AFLGO'] = str(self.aflgo_dir)
        os.environ['SUBJECT'] = str(self.subject_dir)
        os.environ['TMP_DIR'] = str(self.temp_dir)
        os.environ['CC'] = str(self.aflgo_dir / 'instrument' / 'aflgo-clang')
        os.environ['CXX'] = str(self.aflgo_dir / 'instrument' / 'aflgo-clang++')
        os.environ['LDFLAGS'] = '-lpthread'
        os.environ['LIB_FUZZING_ENGINE'] = ''
    
    def run(self, **kwargs) -> Dict:
        """Main instrumentation workflow
        
        Returns:
            Dictionary containing:
                - success: bool
                - instrumented_binary: Path to instrumented binary
                - distance_file: Path to distance.cfg.txt
                - targets_file: Path to BBtargets.txt
                - errors: List of errors encountered
        """
        self.logger.info("="*60)
        self.logger.info("Starting AFLGo Instrumentation")
        self.logger.info("="*60)
        
        results = {
            'success': False,
            'instrumented_binary': None,
            'distance_file': None,
            'targets_file': None,
            'errors': []
        }
        
        try:
            # Phase 1: Target Extraction
            if not self.phase_extract_targets():
                results['errors'] = self.state.errors
                return results
            
            results['targets_file'] = str(self.temp_dir / 'BBtargets.txt')
            
            # Phase 2: CG/CFG Generation (First Build)
            if not self.phase_build_with_llm(phase_num=1):
                results['errors'] = self.state.errors
                return results
            
            # Phase 3: Distance Calculation
            if not self.phase_generate_distance():
                results['errors'] = self.state.errors
                return results
            
            results['distance_file'] = str(self.temp_dir / 'distance.cfg.txt')
            
            # Phase 4: Final Instrumented Build
            if not self.phase_build_with_llm(phase_num=2):
                results['errors'] = self.state.errors
                return results
            
            # Find and record instrumented binary
            binary_path = self.find_instrumented_binary()
            if binary_path:
                results['instrumented_binary'] = str(binary_path)
                results['success'] = True
                
                # Copy artifacts to output directory
                self.copy_instrumented_artifacts()
            else:
                results['errors'].append("Instrumented binary not found")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Fatal error: {e}", exc_info=True)
            results['errors'].append(str(e))
            return results
    
    def log_llm_reasoning(self, prefix: str, reasoning: str):
        """Log LLM reasoning with color"""
        BLUE = '\033[94m'
        RESET = '\033[0m'
        self.logger.info(f"{prefix} {BLUE}{reasoning}{RESET}")
    
    def run_command(self, cmd: str, cwd: Optional[Path] = None) -> Tuple[int, str, str]:
        """Run a shell command and return results"""
        GREEN = '\033[92m'
        RESET = '\033[0m'
        self.logger.info(f"{GREEN}Running: {cmd}{RESET}")
        if cwd:
            self.logger.info(f"  CWD: {cwd}")
        
        result = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Log command output for debugging
        if result.returncode != 0:
            self.logger.error(f"Command failed with exit code {result.returncode}")
            if result.stderr:
                stderr_preview = result.stderr[-500:] if len(result.stderr) > 500 else result.stderr
                self.logger.error(f"stderr: {stderr_preview}")
        
        return result.returncode, result.stdout, result.stderr
    
    def ask_llm(self, question: str, context: Optional[Dict] = None) -> Dict:
        """Ask LLM with context and parse JSON response
        
        Args:
            question: Question to ask
            context: Additional context dictionary
            
        Returns:
            Parsed JSON response from LLM
        """
        # Build prompt with context
        prompt_parts = [question]
        
        if context:
            prompt_parts.append("\n\nContext:")
            prompt_parts.append(json.dumps(context, indent=2))
        
        # Add current state
        prompt_parts.append(f"\n\nCurrent Phase: {self.state.phase}")
        prompt_parts.append(f"Attempts: {self.state.attempts}/{self.state.max_attempts}")
        
        if self.state.observations:
            prompt_parts.append("\n\nObservations:")
            for obs in self.state.observations[-5:]:
                prompt_parts.append(f"- {obs}")
        
        prompt = "\n".join(prompt_parts)
        
        # Query LLM using BaseAgent's query_llm method
        response = self.query_llm(prompt, temperature=0.7, max_tokens=4096)
        
        # Parse JSON response
        response_clean = response.strip()
        if response_clean.startswith('```'):
            lines = response_clean.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            response_clean = '\n'.join(lines).strip()
        
        try:
            parsed = json.loads(response_clean)
            return parsed
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse LLM response as JSON: {e}")
            return {
                'reasoning': response if response else '',
                'action': 'continue',
                'confidence': 0.5
            }
    
    # AFLGo-specific phase methods
    
    def _extract_targets_from_sanitizer_report(self) -> Optional[List[str]]:
        """Extract targets from sanitizer report using LLM guidance"""
        report_content = self.secb_task.sanitizer_report if self.secb_task else self.config.get('sanitizer_report')
        if not report_content:
            self.logger.warning("No sanitizer_report available")
            return None
        
        self.logger.info(f"Using sanitizer report from config (length: {len(report_content)} chars)")
        
        parse_question = DA_extract_target_prompt.format(
            repo_name=self.repo_name,
            report_content=report_content[:1500]
        )
        
        parse_response = self.ask_llm(parse_question)
        self.log_llm_reasoning("LLM parsing:", parse_response.get('reasoning', ''))
        
        target = parse_response.get('target', '') or (parse_response.get('targets', [''])[0] if parse_response.get('targets') else '')
        
        if not target:
            self.logger.info("LLM didn't provide target, trying regex fallback")
            for line in report_content.split('\n'):
                if '#0 ' in line or '#1 ' in line:
                    match = re.search(r'#\d+\s+0x[0-9a-f]+\s+in\s+\S+\s+(/[^\s:]+):(\d+)(?::\d+)?', line)
                    if match:
                        file_path = match.group(1)
                        line_num = match.group(2)
                        repo_pattern = rf'/{re.escape(self.repo_name)}[^/]*/(.*)'
                        repo_match = re.search(repo_pattern, file_path)
                        if repo_match:
                            rel_path = repo_match.group(1)
                            target = f"{rel_path}:{line_num}"
                            break
        
        if not target:
            return None
        
        try:
            file_path, line_str = target.rsplit(':', 1)
            base_line = int(line_str)
        except (ValueError, AttributeError):
            self.logger.error(f"Failed to parse target: {target}")
            return None
        
        # Checkout to vulnerable version before reading source
        commit_id = self.secb_task.base_commit if self.secb_task else self.config.get('commit_id')
        if commit_id:
            self.logger.info(f"Checking out vulnerable version: {commit_id}")
            self.run_command(f"git checkout {commit_id}", self.subject_dir)
            self.run_command("git submodule update --init --recursive", self.subject_dir)
        
        # Read source file
        source_file_path = self.subject_dir / file_path
        
        if not source_file_path.exists():
            self.logger.info(f"Direct path not found: {source_file_path}, searching repository...")
            file_name = Path(file_path).name
            find_cmd = f"find {self.subject_dir} -name '{file_name}' -type f"
            code, stdout, stderr = self.run_command(find_cmd)
            
            if code == 0 and stdout.strip():
                candidates = [Path(p.strip()) for p in stdout.strip().split('\n') if p.strip()]
                path_parts = Path(file_path).parts
                best_match = None
                
                for candidate in candidates:
                    candidate_parts = candidate.parts
                    if len(candidate_parts) >= len(path_parts):
                        if all(candidate_parts[-(len(path_parts)-i)] == path_parts[-(len(path_parts)-i)] 
                               for i in range(len(path_parts))):
                            best_match = candidate
                            break
                
                if best_match:
                    source_file_path = best_match
                    file_path = str(source_file_path.relative_to(self.subject_dir))
                    self.logger.info(f"Updated target path to: {file_path}")
                elif candidates:
                    source_file_path = candidates[0]
                    file_path = str(source_file_path.relative_to(self.subject_dir))
        
        if not source_file_path.exists():
            self.logger.warning(f"Source file not found: {source_file_path}")
            lines_before = self.config.get('target_lines_before', 4)
            lines_after = self.config.get('target_lines_after', 3)
            start_line = max(1, base_line - lines_before)
            end_line = base_line + lines_after
            extended_targets = [f"{file_path}:{line}" for line in range(start_line, end_line + 1)]
            return extended_targets
        
        # Read source code around target line
        try:
            with open(source_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()
            
            context_start = max(0, base_line - 11)
            context_end = min(len(all_lines), base_line + 10)
            context_lines = all_lines[context_start:context_end]
            
            context_with_numbers = []
            for i, line in enumerate(context_lines):
                line_num = context_start + i + 1
                marker = " <-- BUG HERE" if line_num == base_line else ""
                context_with_numbers.append(f"{line_num:4d}: {line.rstrip()}{marker}")
            
            context_text = "\n".join(context_with_numbers)
        except Exception as e:
            self.logger.warning(f"Error reading source file: {e}")
            start_line = max(1, base_line - 4)
            end_line = base_line + 3
            extended_targets = [f"{file_path}:{line}" for line in range(start_line, end_line + 1)]
            return extended_targets
        
        # Ask LLM for paragraph range
        paragraph_question = DA_identify_paragraph_prompt.format(
            file_path=file_path,
            base_line=base_line,
            context_text=context_text
        )
        
        paragraph_response = self.ask_llm(paragraph_question)
        self.log_llm_reasoning("LLM paragraph analysis:", paragraph_response.get('reasoning', ''))
        
        try:
            start_line = int(paragraph_response.get('start_line', base_line - 2))
            end_line = int(paragraph_response.get('end_line', base_line + 2))
            
            # Validation
            if start_line < 1:
                start_line = 1
            if end_line < start_line:
                end_line = start_line + 4
            if end_line - start_line > 15:
                end_line = start_line + 9
            if end_line - start_line < 1:
                end_line = start_line + 4
            if base_line < start_line or base_line > end_line:
                start_line = base_line - 2
                end_line = base_line + 2
        except (ValueError, TypeError) as e:
            self.logger.warning(f"Failed to parse line range: {e}")
            start_line = max(1, base_line - 2)
            end_line = base_line + 2
        
        extended_targets = [f"{file_path}:{line}" for line in range(start_line, end_line + 1)]
        self.logger.info(f"LLM identified paragraph: {file_path}:{start_line} to {file_path}:{end_line}")
        
        return extended_targets
    
    def phase_extract_targets(self) -> bool:
        """Phase 1: Extract targets from sanitizer reports"""
        self.logger.info("=== Phase 1: Target Extraction ===")
        self.state.phase = 'targets'
        
        targets_file = self.temp_dir / 'BBtargets.txt'
        
        # Manual targets have highest priority
        if self.config.get('targets'):
            targets = self.config['targets']
            self.logger.info(f"Using {len(targets)} manual targets from config")
            
            # Ensure minimum of 6 targets
            MIN_TARGETS = 6
            if len(targets) < MIN_TARGETS:
                last_target = targets[-1]
                match = re.match(r'(.+):(\d+)$', last_target)
                if match:
                    file_path = match.group(1)
                    last_line = int(match.group(2))
                    needed = MIN_TARGETS - len(targets)
                    for i in range(1, needed + 1):
                        targets.append(f"{file_path}:{last_line + i}")
            
            with open(targets_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
            return True
        
        # Extract from sanitizer report
        cve_id = self.secb_task.instance_id if self.secb_task else self.config.get('cve_id')
        if cve_id:
            sanitizer_targets = self._extract_targets_from_sanitizer_report()
            
            if sanitizer_targets:
                MIN_TARGETS = 6
                if len(sanitizer_targets) < MIN_TARGETS:
                    last_target = sanitizer_targets[-1]
                    match = re.match(r'(.+):(\d+)$', last_target)
                    if match:
                        file_path = match.group(1)
                        last_line = int(match.group(2))
                        needed = MIN_TARGETS - len(sanitizer_targets)
                        for i in range(1, needed + 1):
                            sanitizer_targets.append(f"{file_path}:{last_line + i}")
                
                with open(targets_file, 'w') as f:
                    for target in sanitizer_targets:
                        f.write(f"{target}\n")
                return True
            else:
                self.state.record_error("No targets extracted from sanitizer report", context="targets")
                return False
        
        self.state.record_error("No CVE ID provided for sanitizer report extraction", context="targets")
        return False
    
    def phase_build_with_llm(self, phase_num: int = 1) -> bool:
        """Phase 2/4: Build with LLM guidance
        
        Uses BaseAgent's diagnose_and_fix_build_error for error recovery.
        """
        phase_name = "CG/CFG Generation" if phase_num == 1 else "Distance Instrumentation"
        self.logger.info(f"=== Phase {phase_num + 1}: {phase_name} ===")
        
        targets_file = self.temp_dir / 'BBtargets.txt'
        distance_file = self.temp_dir / 'distance.cfg.txt'
        
        # Get build commands from secb_task or config
        build_commands_str = self.secb_task.build_sh if self.secb_task else self.config.get('build_config', {}).get('build_commands', '')
        current_build_script = build_commands_str  # Track current build script for error recovery
        
        max_build_attempts = 5
        for attempt in range(max_build_attempts):
            self.logger.info(f"Build attempt {attempt + 1}/{max_build_attempts}")
            self.state.attempts = attempt + 1
            
            # Reset and setup environment for this attempt
            self._setup_build_environment(phase_num, targets_file, distance_file)
            
            # First attempt: try config commands directly
            if attempt == 0 and build_commands_str:
                commands = [cmd.strip() for cmd in build_commands_str.split('\n') 
                           if cmd.strip() and not cmd.strip().startswith('#')]
                
                if commands:
                    success, stdout, stderr = self._execute_commands(commands)
                    if success:
                        validation_success = self._validate_build_phase(phase_num)
                        if validation_success:
                            self.logger.info("Build successful with config commands!")
                            return True
                    else:
                        # Use BaseAgent's diagnose_and_fix_build_error for recovery
                        self.logger.info("Analyzing build error with LLM...")
                        cve_id = self.secb_task.instance_id if self.secb_task else self.config.get('cve_id', 'N/A')
                        fixed_script = self.diagnose_and_fix_build_error(
                            error=stderr,
                            output=stdout,
                            build_commands=current_build_script,
                            project_name=self.repo_name,
                            context=f"Phase: {phase_name}, CVE: {cve_id}",
                            system_prompt=self.AFLGO_SYSTEM_PROMPT,
                            fallback_fixes=self._aflgo_fallback_fixes
                        )
                        if fixed_script:
                            current_build_script = fixed_script
                        continue
            
            # Subsequent attempts: use LLM for build guidance
            question = self._build_llm_question(phase_name, attempt, build_commands_str)
            
            response = self.ask_llm(question)
            self.log_llm_reasoning("LLM reasoning:", response.get('reasoning', ''))
            
            success, stdout, stderr = self._execute_build(response)
            
            if success:
                validation_success = self._validate_build_phase(phase_num)
                if validation_success:
                    self.logger.info("Build successful and validated!")
                    return True
            else:
                # Use BaseAgent's diagnose_and_fix_build_error for recovery
                if attempt < max_build_attempts - 1:
                    self.logger.info("Analyzing build error with LLM...")
                    # Get current commands from response for error context
                    commands = response.get('commands', [])
                    script_content = self._prepare_build_script(commands) if commands else current_build_script
                    
                    cve_id = self.secb_task.instance_id if self.secb_task else self.config.get('cve_id', 'N/A')
                    fixed_script = self.diagnose_and_fix_build_error(
                        error=stderr,
                        output=stdout,
                        build_commands=script_content,
                        project_name=self.repo_name,
                        context=f"Phase: {phase_name}, CVE: {cve_id}",
                        system_prompt=self.AFLGO_SYSTEM_PROMPT,
                        fallback_fixes=self._aflgo_fallback_fixes
                    )
                    if fixed_script:
                        current_build_script = fixed_script
        
        self.state.record_error(f"Build failed after {max_build_attempts} attempts", context=f"build_{phase_num}")
        return False
    
    def _setup_build_environment(self, phase_num: int, targets_file: Path, distance_file: Path):
        """Setup environment variables for build phase"""
        # Reset environment
        for key in ['CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS']:
            if self.original_env[key]:
                os.environ[key] = self.original_env[key]
            elif key in os.environ:
                del os.environ[key]
        
        # Set compiler flags based on phase
        if phase_num == 1:
            additional = f"-targets={targets_file} -outdir={self.temp_dir} -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
            os.environ['CFLAGS'] = f"{additional} -g"
            os.environ['CXXFLAGS'] = f"{additional} -g"
        else:
            os.environ['CFLAGS'] = f"-distance={distance_file.resolve()}"
            os.environ['CXXFLAGS'] = f"-distance={distance_file.resolve()}"
        
        # Custom cflags from config (runtime configuration, not task data)
        custom_cflags = self.config.get('cflags', '')
        if custom_cflags:
            os.environ['CFLAGS'] = f"{custom_cflags} {os.environ['CFLAGS']}"
            os.environ['CXXFLAGS'] = f"{custom_cflags} {os.environ['CXXFLAGS']}"
    
    def _validate_build_phase(self, phase_num: int) -> bool:
        """Validate build artifacts for the given phase"""
        if phase_num == 1:
            return self._validate_cg_cfg_artifacts()
        else:
            return self._validate_instrumented_binary()
    
    def _build_llm_question(self, phase_name: str, attempt: int, build_commands_str: str) -> str:
        """Build the LLM question for build guidance"""
        has_cmake = (self.subject_dir / 'CMakeLists.txt').exists()
        has_configure_ac = (self.subject_dir / 'configure.ac').exists()
        has_configure = (self.subject_dir / 'configure').exists()
        has_makefile = (self.subject_dir / 'Makefile').exists()
        has_autogen = (self.subject_dir / 'autogen.sh').exists()
        
        build_script_section = ""
        if build_commands_str:
            build_script_section = f"Reference build script:\n```bash\n{build_commands_str}\n```"
        
        question = DA_build_prompt.format(
            phase_name=phase_name,
            attempt=attempt + 1,
            cc=os.environ.get('CC'),
            cxx=os.environ.get('CXX'),
            cflags=os.environ.get('CFLAGS'),
            cxxflags=os.environ.get('CXXFLAGS'),
            has_cmake=has_cmake,
            has_configure_ac=has_configure_ac,
            has_configure=has_configure,
            has_makefile=has_makefile,
            has_autogen=has_autogen,
            build_script_section=build_script_section
        )
        
        if attempt > 0:
            recent_errors = self.state.errors[-min(3, len(self.state.errors)):]
            repeated = self.state.get_repeated_errors(2)
            question += "\n\n=== BUILD FAILURE ANALYSIS ==="
            if repeated:
                question += "\n\nREPEATED ERRORS:"
                for sig, count in repeated[:5]:
                    question += f"\n  [{count}x] {sig[:300]}"
            question += "\n\nRECENT ERRORS:"
            for i, err in enumerate(recent_errors, 1):
                question += f"\n\nAttempt {attempt - len(recent_errors) + i + 1}:\n{err[:2000]}"
        
        return question
    
    def _aflgo_fallback_fixes(self, error: str, build_commands: str) -> Optional[str]:
        """AFLGo-specific fallback fixes for common build errors
        
        Args:
            error: Build error message
            build_commands: Current build commands
            
        Returns:
            Fixed build commands if a fix is found, None otherwise
        """
        # Handle common AFLGo-specific errors
        error_lower = error.lower()
        
        # LTO/gold linker issues
        if 'plugin-opt' in error_lower or 'gold' in error_lower:
            self.logger.info("Attempting fix: LTO/gold linker issue")
            # Remove -flto and gold linker flags
            fixed = build_commands.replace('-flto', '')
            fixed = fixed.replace('-fuse-ld=gold', '')
            fixed = re.sub(r'-Wl,-plugin-opt[^\s]*', '', fixed)
            return fixed
        
        # Missing pthread
        if 'pthread' in error_lower and 'undefined reference' in error_lower:
            self.logger.info("Attempting fix: pthread linking issue")
            if '-lpthread' not in build_commands:
                return build_commands + '\nexport LDFLAGS="$LDFLAGS -lpthread"'
        
        return None
    
    def _execute_build(self, llm_response: Dict) -> Tuple[bool, str, str]:
        """Execute build based on LLM guidance
        
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            commands = llm_response.get('commands', [])
            if not commands:
                reasoning = llm_response.get('reasoning', '')
                if reasoning:
                    commands = self._extract_commands_from_reasoning(reasoning)
            
            if not commands:
                self.state.record_error("LLM provided no commands", context="build")
                return False, "", "LLM provided no commands"
            
            return self._execute_commands(commands)
        except Exception as e:
            error_msg = f"Exception in _execute_build: {str(e)}"
            self.state.record_error(error_msg, context="build")
            return False, "", error_msg
    
    def _extract_commands_from_reasoning(self, reasoning: str) -> List[str]:
        """Extract commands from LLM reasoning"""
        commands = []
        for pattern in [r'`([^`]+)`', r'"([^"]+)"', r"'([^']+)'"]:
            for match in re.finditer(pattern, reasoning):
                cmd = match.group(1).strip()
                if any(kw in cmd.lower() for kw in ['cmake', 'make', 'configure', 'autoreconf']):
                    commands.append(cmd)
        
        if not commands:
            build_commands = self.secb_task.build_sh if self.secb_task else self.config.get('build_config', {}).get('build_commands', '')
            if build_commands:
                commands = [cmd.strip() for cmd in build_commands.split('\n') if cmd.strip() and not cmd.strip().startswith('#')]
        return commands
    
    def _validate_cg_cfg_artifacts(self) -> bool:
        """Validate CG/CFG bytecode files exist"""
        find_cmd = f"find {self.subject_dir} -name '*.0.0.*.bc' -type f"
        code, stdout, stderr = self.run_command(find_cmd)
        bc_files = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        
        if not bc_files:
            self.state.record_error("No LLVM bytecode (.bc) files found", context="validation")
            return False
        
        self.logger.info(f"Found {len(bc_files)} bytecode files")
        return True
    
    def _validate_instrumented_binary(self) -> bool:
        """Validate instrumented binary exists"""
        binary_path = self.find_instrumented_binary()
        if not binary_path:
            self.state.record_error("Instrumented binary not found", context="validation")
            return False
        
        self.logger.info(f"Found instrumented binary: {binary_path}")
        return True
    
    def _execute_commands(self, commands: List[str]) -> Tuple[bool, str, str]:
        """Execute commands in single shell session using BaseAgent's run_build
        
        Returns:
            Tuple of (success, stdout, stderr)
        """
        if not commands:
            return True, "", ""
        
        # Safety checks for AFLGo-specific paths
        dangerous_patterns = [
            (r'\brm\s+.*aflgo/(instrument|distance)', 'removing AFLGo files'),
            (r'\bmv\s+.*aflgo/(instrument|distance)', 'moving AFLGo files'),
            (r'\bmake\s+.*install.*aflgo/', 'reinstalling AFLGo'),
        ]
        
        for cmd in commands:
            cmd = cmd.strip()
            if not cmd:
                continue
            
            for pattern, description in dangerous_patterns:
                if re.search(pattern, cmd.lower()):
                    error_msg = f"BLOCKED: {description}: {cmd}"
                    self.logger.error(error_msg)
                    self.state.record_error(error_msg, context="safety")
                    return False, "", error_msg
        
        # Build script content
        script_content = self._prepare_build_script(commands)
        
        GREEN = '\033[92m'
        RESET = '\033[0m'
        self.logger.info(f"{GREEN}Executing build commands:{RESET}")
        for i, cmd in enumerate(commands):
            if cmd.strip():
                self.logger.info(f"{GREEN}  [{i+1}] {cmd.strip()}{RESET}")
        
        # Use BaseAgent's run_build method
        success, stdout, stderr = self.run_build(
            build_commands=script_content,
            cwd=self.subject_dir,
            timeout=1200  # 20 minutes for AFLGo builds
        )
        
        if not success:
            error_context = f"Commands failed\nOutput:\n{stdout}\nError:\n{stderr}"
            self.state.record_error(error_context, context=f"phase_{self.state.phase}")
        
        return success, stdout, stderr
    
    def _prepare_build_script(self, commands: List[str]) -> str:
        """Prepare build script from command list
        
        Args:
            commands: List of commands to execute
            
        Returns:
            Shell script content
        """
        script_lines = ['#!/bin/bash', 'set -e', '']
        
        for i, cmd in enumerate(commands):
            cmd = cmd.strip()
            if not cmd:
                continue
            cmd = cmd.replace('$(nproc)', str(os.cpu_count()))
            if cmd.startswith('mkdir') and '-p' not in cmd:
                cmd = re.sub(r'^mkdir\s+', 'mkdir -p ', cmd)
            script_lines.append(f'# Command {i+1}')
            script_lines.append(cmd)
            script_lines.append('')
        
        return '\n'.join(script_lines)
    
    def phase_generate_distance(self) -> bool:
        """Phase 3: Generate distance file"""
        self.logger.info("=== Phase 3: Distance Generation ===")
        self.state.phase = 'distance'
        
        distance_cfg = self.temp_dir / 'distance.cfg.txt'
        if distance_cfg.exists():
            distance_cfg.unlink()
        
        # Clean files
        bbnames = self.temp_dir / 'BBnames.txt'
        bbcalls = self.temp_dir / 'BBcalls.txt'
        bbtargets = self.temp_dir / 'BBtargets.txt'
        
        if bbtargets.exists():
            self.run_command(f"sed 's|^.*/||' {bbtargets} > {self.temp_dir}/BBtargets2.txt && mv {self.temp_dir}/BBtargets2.txt {bbtargets}")
        
        if bbnames.exists():
            self.run_command(f"cat {bbnames} | grep -v '^$' | rev | cut -d: -f2- | rev | sort | uniq > {self.temp_dir}/BBnames2.txt && mv {self.temp_dir}/BBnames2.txt {bbnames}")
        
        if bbcalls.exists():
            self.run_command(f"cat {bbcalls} | grep -Ev '^[^,]*$|^([^,]*,){{2,}}[^,]*$' | sort | uniq > {self.temp_dir}/BBcalls2.txt && mv {self.temp_dir}/BBcalls2.txt {bbcalls}")
        
        # Get binary path and binary name from secb_task or config
        # binary_path: directory to search for .bc files (e.g., $SUBJECT, $SUBJECT/build)
        # binary_name: fuzzer binary name used to filter .bc files (e.g., jq, njs)
        binary_path = self.secb_task.binary_path if self.secb_task and self.secb_task.binary_path else self.config.get('build_config', {}).get('binary_path', '$SUBJECT')
        binary_name = self.secb_task.binary_name if self.secb_task and self.secb_task.binary_name else self.config.get('binary_name', self.repo_name)
        
        # Resolve binary_path (replace $SUBJECT with actual path)
        binary_path = binary_path.replace('$SUBJECT', str(self.subject_dir))
        binary_path_resolved = Path(binary_path).resolve()
        
        self.logger.info(f"Binary path: {binary_path_resolved}")
        self.logger.info(f"Binary name (fuzzer): {binary_name}")
        
        # Run gen_distance_fast.py with binary_path and binary_name
        # Format: gen_distance_fast.py <binary_path> <temp_dir> <fuzzer_name>
        # Examples: gen_distance_fast.py $SUBJECT $TMP_DIR jq
        #           gen_distance_fast.py $SUBJECT/build $TMP_DIR njs
        gen_distance_script = self.aflgo_dir / 'distance' / 'gen_distance_fast.py'
        cmd = f"python3 {gen_distance_script} {binary_path_resolved} {self.temp_dir} {binary_name}"
        
        code, stdout, stderr = self.run_command(cmd)
        
        if code == 0 and distance_cfg.exists() and distance_cfg.stat().st_size > 0:
            self.logger.info("✓ Distance file generated successfully")
            return True
        else:
            self.logger.error(f"Distance generation failed with exit code {code}")
            if stderr:
                self.logger.error(f"Error output: {stderr[:500]}")
        
        # Fallback to LLM if direct approach failed
        self.logger.info("Falling back to LLM for distance generation")
        
        question = DA_distance_generation_prompt.format(
            error=stderr[:500] if stderr else 'Unknown error',
            subject_dir=self.subject_dir,
            temp_dir=self.temp_dir,
            binary_name=binary_name,
            binary_path=binary_path_resolved,
            aflgo_dir=self.aflgo_dir
        )
        
        response = self.ask_llm(question)
        self.log_llm_reasoning("LLM reasoning:", response.get('reasoning', ''))
        
        commands = response.get('commands', [])
        if commands:
            cmd = commands[0]
            code, stdout, stderr = self.run_command(cmd)
            
            if code == 0 and distance_cfg.exists() and distance_cfg.stat().st_size > 0:
                self.logger.info("✓ Distance generated with LLM guidance")
                return True
            else:
                self.logger.error(f"LLM suggestion also failed: {stderr[:300]}")
        
        self.state.record_error("Distance generation failed even with LLM guidance", context="distance")
        return False
    
    def find_instrumented_binary(self) -> Optional[Path]:
        """Find instrumented binary"""
        binary_name = self.secb_task.binary_name if self.secb_task and self.secb_task.binary_name else self.config.get('binary_name', self.repo_name)
        
        search_paths = [
            self.subject_dir / binary_name,
            self.subject_dir / 'build' / binary_name,
            self.subject_dir / 'build' / 'bin' / binary_name,
            self.subject_dir / 'bin' / binary_name,
            self.subject_dir / 'src' / binary_name,
        ]
        
        for path in search_paths:
            if path.exists() and path.is_file():
                return path
        
        # Search recursively
        found = list(self.subject_dir.glob(f"**/{binary_name}"))
        if found:
            executables = [f for f in found if f.is_file() and os.access(f, os.X_OK)]
            if executables:
                return executables[0]
        
        return None
    
    def copy_instrumented_artifacts(self) -> bool:
        """Copy artifacts to output directory"""
        try:
            output_name = f"instrumented_{self.repo_name}"
            cve_id = self.secb_task.instance_id if self.secb_task else self.config.get('cve_id')
            if cve_id:
                cve_suffix = cve_id.replace('CVE-', '').replace('-', '_')
                output_name += f"_{cve_suffix}"
            
            script_dir = Path(__file__).resolve().parent
            drillagent_root = script_dir.parent.parent
            drillagent_default_output_dir = drillagent_root / 'instrumented'
            
            output_dir = Path(self.config.get('output_dir', drillagent_default_output_dir)) / output_name
            output_dir.mkdir(parents=True, exist_ok=True)
            
            self.logger.info(f"Copying artifacts to: {output_dir}")
            
            distance_file = self.temp_dir / 'distance.cfg.txt'
            if distance_file.exists():
                shutil.copy2(distance_file, output_dir / 'distance.cfg.txt')
                self.logger.info("  ✓ Copied distance.cfg.txt")
            
            bbtargets_file = self.temp_dir / 'BBtargets.txt'
            if bbtargets_file.exists():
                shutil.copy2(bbtargets_file, output_dir / 'BBtargets.txt')
                self.logger.info("  ✓ Copied BBtargets.txt")
            
            binary_path = self.find_instrumented_binary()
            if binary_path:
                binary_name = self.secb_task.binary_name if self.secb_task and self.secb_task.binary_name else self.config.get('binary_name', self.repo_name)
                dest_binary = output_dir / binary_name
                shutil.copy2(binary_path, dest_binary)
                dest_binary.chmod(binary_path.stat().st_mode)
                self.logger.info(f"  ✓ Copied instrumented binary: {binary_name}")
            else:
                return False
            
            self.logger.info(f"\n✓ Artifacts copied to: {output_dir}")
            return True
        except Exception as e:
            self.logger.error(f"Error copying artifacts: {e}")
            return False
