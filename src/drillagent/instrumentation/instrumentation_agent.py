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
import sys
import subprocess
import shutil
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from drillagent.instrumentation.base_agent import BaseAgent, AgentState
from drillagent.models.llm import LLM


class InstrumentationAgent(BaseAgent):
    """AFLGo-based instrumentation agent for directed fuzzing
    
    This agent inherits from BaseAgent and specializes in:
    - Setting up target repositories
    - Extracting vulnerability targets from sanitizer reports
    - Building projects with AFLGo instrumentation
    - Calculating distances for directed fuzzing
    - Producing instrumented binaries ready for fuzzing
    """
    
    # AFLGo-specific system prompt
    AFLGO_SYSTEM_PROMPT = """You are an expert systems engineer and security researcher specializing in 
directed fuzzing with AFLGo. Your task is to instrument programs for directed fuzzing following this workflow:

**Phase 1: Repository Setup**
- Clone or update the git repository from GITHUB_URL
- The repository goes to: $REPOS_DIR/<repo_name> (configurable via repos_dir in config)

**Phase 2: Target Extraction**
- Extract targets from SEC-bench sanitizer reports (CVE-sanitizer_reports directory)
- Find the LAST (deepest) target in the stack trace (#0, the actual bug location)
- Extend to include surrounding lines (default: 4 lines before, 3 lines after)
- COMMIT_ID refers to the vulnerable version (before patch)
- Save to BBtargets.txt in format: <file>:<line>

**Phase 3: CG/CFG Generation (First Build)**
- Set AFLGo compilers: CC=$AFLGO/instrument/aflgo-clang, CXX=$AFLGO/instrument/aflgo-clang++
- Set instrumentation flags: -targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps
- Checkout to vulnerable version: git checkout $COMMIT_ID (already vulnerable version)
- Build using the BUILD_SCRIPT from config file
- This generates BBnames.txt and BBcalls.txt

**Phase 4: Distance Calculation**
- Clean BBnames.txt: cat BBnames.txt | grep -v "^$"| rev | cut -d: -f2- | rev | sort | uniq
- Clean BBcalls.txt: cat BBcalls.txt | grep -Ev "^[^,]*$|^([^,]*,){2,}[^,]*$"| sort | uniq
- Run: $AFLGO/distance/gen_distance_fast.py $SUBJECT $TMP_DIR <binary_name>
- This generates distance.cfg.txt

**Phase 5: Final Instrumented Build**
- Set distance flag: -distance=$TMP_DIR/distance.cfg.txt (replace CG/CFG flags)
- Rebuild the project using the BUILD_SCRIPT from config file
- Final instrumented binary is ready for fuzzing

**CRITICAL CONSTRAINTS - DO NOT VIOLATE:**
1. NEVER modify, rebuild, or reinstall AFLGo itself
2. NEVER change AFLGo compiler paths (aflgo-clang, aflgo-clang++)
3. NEVER suggest installing different versions of AFLGo
4. NEVER modify files in $AFLGO directory (configurable via aflgo_dir in config)
5. ONLY modify the TARGET PROJECT being instrumented (libredwg, jq, etc.)
6. You can modify build scripts, Makefiles, configure.ac in the TARGET PROJECT
7. You can change environment variables (CFLAGS, CXXFLAGS, CPPFLAGS, etc.)
8. You can patch source files in the TARGET PROJECT if needed
9. AFLGo toolchain is WORKING and TESTED - trust it completely
10. All fixes must be in the TARGET PROJECT'S build configuration

**CRITICAL: Always respond in valid JSON format:**
{
  "reasoning": "Your detailed analysis and thought process",
  "commands": ["exact shell command 1", "exact shell command 2", ...],
  "action": "cmake|autotools|make|continue",
  "confidence": 0.9
}

For build questions:
- Analyze the build system type (cmake/autotools/make)
- Provide EXACT shell commands to execute
- For CMake: ["mkdir -p build", "cd build", "cmake ..", "make -j$(nproc)"]
- For autotools: ["autoreconf -i", "./configure", "make -j$(nproc)"]
- For make: ["make clean || true", "make -j$(nproc)"]
- Account for the environment variables (CC, CXX, CFLAGS, etc.) already being set
- If build fails, analyze the error and suggest different commands
- SOLUTIONS MUST TARGET THE PROJECT, NOT AFLGO:
  * ✓ Modify project's Makefile.am or configure.ac
  * ✓ Change CFLAGS/CXXFLAGS/CPPFLAGS environment variables
  * ✓ Add/modify configure arguments (--disable-shared, --enable-static, etc.)
  * ✓ Patch project source files if needed
  * ✗ NEVER modify aflgo-clang or aflgo-clang++ compilers
  * ✗ NEVER reinstall or rebuild AFLGo
  * ✗ NEVER change AFLGo instrumentation scripts

Handle errors by analyzing messages and providing alternative commands in your response.
"""
    
    def __init__(self, config: Dict, llm: Optional[LLM] = None, logger=None):
        """Initialize InstrumentationAgent
        
        Args:
            config: Configuration dictionary containing:
                - repo_url: Git repository URL
                - commit_id: Commit to instrument
                - cve_id: CVE identifier (optional)
                - sanitizer_report: Sanitizer report content (optional)
                - build_config: Build configuration
                - aflgo_dir, repos_dir, temps_dir: Directory paths
            llm: LLM instance (will create if not provided)
            logger: Logger instance (will create if not provided)
        """
        self.config = config
        
        # Setup environment first
        self.setup_environment()
        
        # Initialize LLM if not provided
        if llm is None:
            llm_model = config.get('llm_model', 'gpt-4-turbo')
            llm_api_key = config.get('openai_api_key') or os.getenv('OPENAI_API_KEY')
            llm = LLM(provider="openai", model_name=llm_model, api_key=llm_api_key)
        
        # Prepare log file path from config
        log_file = None
        if config.get('log_file'):
            # Find DrillAgent root for logs directory
            script_dir = Path(__file__).resolve().parent
            drillagent_root = script_dir.parent.parent.parent
            logs_dir = drillagent_root / 'logs'
            logs_dir.mkdir(exist_ok=True)
            log_file = str(logs_dir / config['log_file'])
        elif config.get('cve_id'):
            # Auto-generate log file name with CVE number
            script_dir = Path(__file__).resolve().parent
            drillagent_root = script_dir.parent.parent.parent
            logs_dir = drillagent_root / 'logs'
            logs_dir.mkdir(exist_ok=True)
            cve_suffix = config['cve_id'].replace('CVE-', '').replace('-', '_')
            log_file = str(logs_dir / f'instrumentation_{cve_suffix}.log')
        
        # Initialize BaseAgent with AFLGo-specific system prompt
        super().__init__(
            llm=llm,
            system_prompt=self.AFLGO_SYSTEM_PROMPT,
            initial_phase="setup",
            max_attempts=10,
            logger=logger,
            log_file=log_file
        )
        
        # Store environment variables for reset between attempts
        self.original_env = {
            'CC': os.environ.get('CC', ''),
            'CXX': os.environ.get('CXX', ''),
            'CFLAGS': '',
            'CXXFLAGS': '',
            'LDFLAGS': os.environ.get('LDFLAGS', '')
        }
        
        self.logger.info(f"Initialized InstrumentationAgent for {self.repo_name}")
    
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
        
        # Repository info
        self.repo_url = self.config['repo_url']
        self.repo_name = Path(self.repo_url).stem.replace('.git', '')
        
        # Subject and temp directories
        self.subject_dir = self.repos_dir / self.repo_name
        
        # Create temp directory name
        temp_name = f"temp_{self.repo_name}"
        if self.config.get('cve_id'):
            cve_suffix = self.config['cve_id'].replace('CVE-', '').replace('-', '_')
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
            # Phase 1: Repository Setup
            if not self.phase_setup_repository():
                results['errors'] = self.state.errors
                return results
            
            # Phase 2: Target Extraction
            if not self.phase_extract_targets():
                results['errors'] = self.state.errors
                return results
            
            results['targets_file'] = str(self.temp_dir / 'BBtargets.txt')
            
            # Phase 3: CG/CFG Generation (First Build)
            if not self.phase_build_with_llm(phase_num=1):
                results['errors'] = self.state.errors
                return results
            
            # Phase 4: Distance Calculation
            if not self.phase_generate_distance():
                results['errors'] = self.state.errors
                return results
            
            results['distance_file'] = str(self.temp_dir / 'distance.cfg.txt')
            
            # Phase 5: Final Instrumented Build
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
    
    def phase_setup_repository(self) -> bool:
        """Phase 1: Clone/update repository"""
        self.logger.info("=== Phase 1: Repository Setup ===")
        self.state.phase = 'setup'
        
        # Remove existing repository if it exists
        if self.subject_dir.exists():
            self.logger.info(f"Removing existing repository: {self.subject_dir}")
            shutil.rmtree(self.subject_dir)
        
        # Clone fresh repository
        self.logger.info(f"Cloning repository: {self.repo_url}")
        code, stdout, stderr = self.run_command(
            f"git clone {self.repo_url} {self.subject_dir}"
        )
        if code != 0:
            error_msg = f"git clone failed: {stderr}"
            self.logger.error(error_msg)
            self.state.record_error(error_msg, context="setup")
            return False
        
        # Initialize and update git submodules
        self.logger.info("Initializing git submodules...")
        code, stdout, stderr = self.run_command(
            "git submodule update --init --recursive",
            self.subject_dir
        )
        # Don't fail if there are no submodules
        if code != 0 and "No submodule mapping found" not in stderr:
            self.logger.warning(f"Submodule initialization warning: {stderr}")
        
        self.state.observations.append("Repository setup complete")
        return True
    
    def _extract_targets_from_sanitizer_report(self) -> Optional[List[str]]:
        """Extract targets from sanitizer report using LLM guidance"""
        report_content = self.config.get('sanitizer_report')
        if not report_content:
            self.logger.warning("No sanitizer_report field in config")
            return None
        
        self.logger.info(f"Using sanitizer report from config (length: {len(report_content)} chars)")
        
        parse_question = f"""I need to extract the LAST (deepest) vulnerability target location from this sanitizer report.

Repository name: {self.repo_name}
Report content (first 1500 chars):
{report_content[:1500]}

IMPORTANT: I need ONLY the LAST target in the stack trace (typically #0, the actual bug location).

Extract format: <relative_path>:<line_number>
For example: src/md4c.c:5985

Respond in JSON:
{{
  "reasoning": "your analysis identifying the last/deepest bug location",
  "target": "src/file.c:123"
}}"""
        
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
        if self.config.get('commit_id'):
            commit_id = self.config['commit_id']
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
        paragraph_question = f"""Identify the complete code paragraph containing a bug.

**Bug Location:** {file_path}:{base_line}

**Source Code:**
```c
{context_text}
```

**Task:** Identify a 5-line paragraph containing line {base_line}.

Respond in JSON:
{{
  "reasoning": "explain your range choice",
  "start_line": <number>,
  "end_line": <number>
}}"""
        
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
        """Phase 2: Extract targets from sanitizer reports"""
        self.logger.info("=== Phase 2: Target Extraction ===")
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
        if self.config.get('cve_id'):
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
        """Phase 3/5: Build with LLM guidance"""
        phase_name = "CG/CFG Generation" if phase_num == 1 else "Distance Instrumentation"
        self.logger.info(f"=== Phase {phase_num + 2}: {phase_name} ===")
        
        targets_file = self.temp_dir / 'BBtargets.txt'
        distance_file = self.temp_dir / 'distance.cfg.txt'
        
        build_commands_str = self.config.get('build_config', {}).get('build_commands', '')
        
        max_build_attempts = 5
        for attempt in range(max_build_attempts):
            self.logger.info(f"Build attempt {attempt + 1}/{max_build_attempts}")
            
            # Reset environment
            for key in ['CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS']:
                if self.original_env[key]:
                    os.environ[key] = self.original_env[key]
                elif key in os.environ:
                    del os.environ[key]
            
            # Set compiler flags
            if phase_num == 1:
                additional = f"-targets={targets_file} -outdir={self.temp_dir} -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
                os.environ['CFLAGS'] = f"{additional} -g"
                os.environ['CXXFLAGS'] = f"{additional} -g"
            else:
                os.environ['CFLAGS'] = f"-distance={distance_file.resolve()}"
                os.environ['CXXFLAGS'] = f"-distance={distance_file.resolve()}"
            
            custom_cflags = self.config.get('build_config', {}).get('cflags', '')
            if custom_cflags:
                os.environ['CFLAGS'] = f"{custom_cflags} {os.environ['CFLAGS']}"
                os.environ['CXXFLAGS'] = f"{custom_cflags} {os.environ['CXXFLAGS']}"
            
            # Try config commands first
            if attempt == 0 and build_commands_str:
                commands = [cmd.strip() for cmd in build_commands_str.split('\n') 
                           if cmd.strip() and not cmd.strip().startswith('#')]
                
                if commands:
                    success = self._execute_commands(commands)
                    if success:
                        validation_success = self._validate_cg_cfg_artifacts() if phase_num == 1 else self._validate_instrumented_binary()
                        if validation_success:
                            self.logger.info("Build successful with config commands!")
                            return True
            
            # Use LLM
            has_cmake = (self.subject_dir / 'CMakeLists.txt').exists()
            has_configure_ac = (self.subject_dir / 'configure.ac').exists()
            has_configure = (self.subject_dir / 'configure').exists()
            has_makefile = (self.subject_dir / 'Makefile').exists()
            has_autogen = (self.subject_dir / 'autogen.sh').exists()
            
            question = f"""Build project for AFLGo instrumentation.
Phase: {phase_name}
Attempt: {attempt + 1}

Environment:
- CC: {os.environ.get('CC')}
- CXX: {os.environ.get('CXX')}
- CFLAGS: {os.environ.get('CFLAGS')}
- CXXFLAGS: {os.environ.get('CXXFLAGS')}

Project structure:
- CMakeLists.txt: {has_cmake}
- configure.ac: {has_configure_ac}
- configure: {has_configure}
- Makefile: {has_makefile}
- autogen.sh: {has_autogen}"""
            
            if build_commands_str:
                question += f"\n\nReference build script:\n```bash\n{build_commands_str}\n```"
            
            question += """

Provide exact shell commands. Respond in JSON:
{{
  "reasoning": "your analysis",
  "commands": ["command1", "command2"]
}}"""
            
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
            
            response = self.ask_llm(question)
            self.log_llm_reasoning("LLM reasoning:", response.get('reasoning', ''))
            
            success = self._execute_build(response)
            
            if success:
                validation_success = self._validate_cg_cfg_artifacts() if phase_num == 1 else self._validate_instrumented_binary()
                if validation_success:
                    self.logger.info("Build successful and validated!")
                    return True
        
        self.state.record_error(f"Build failed after {max_build_attempts} attempts", context=f"build_{phase_num}")
        return False
    
    def _execute_build(self, llm_response: Dict) -> bool:
        """Execute build based on LLM guidance"""
        try:
            commands = llm_response.get('commands', [])
            if not commands:
                reasoning = llm_response.get('reasoning', '')
                if reasoning:
                    commands = self._extract_commands_from_reasoning(reasoning)
            
            if not commands:
                self.state.record_error("LLM provided no commands", context="build")
                return False
            
            return self._execute_commands(commands)
        except Exception as e:
            self.state.record_error(f"Exception in _execute_build: {str(e)}", context="build")
            return False
    
    def _extract_commands_from_reasoning(self, reasoning: str) -> List[str]:
        """Extract commands from LLM reasoning"""
        commands = []
        for pattern in [r'`([^`]+)`', r'"([^"]+)"', r"'([^']+)'"]:
            for match in re.finditer(pattern, reasoning):
                cmd = match.group(1).strip()
                if any(kw in cmd.lower() for kw in ['cmake', 'make', 'configure', 'autoreconf']):
                    commands.append(cmd)
        
        if not commands:
            build_commands = self.config.get('build_config', {}).get('build_commands', '')
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
    
    def _execute_commands(self, commands: List[str]) -> bool:
        """Execute commands in single shell session"""
        if not commands:
            return True
        
        # Safety checks
        aflgo_protected_paths = [str(self.aflgo_dir), 'aflgo-clang', 'aflgo/instrument']
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
                    return False
        
        # Build script
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
        
        script_content = '\n'.join(script_lines)
        
        GREEN = '\033[92m'
        RESET = '\033[0m'
        self.logger.info(f"{GREEN}Executing build commands:{RESET}")
        for i, cmd in enumerate(commands):
            if cmd.strip():
                self.logger.info(f"{GREEN}  [{i+1}] {cmd.strip()}{RESET}")
        
        # Execute with streaming output
        process = subprocess.Popen(
            script_content,
            shell=True,
            cwd=self.subject_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            executable='/bin/bash',
            bufsize=1
        )
        
        output_lines = []
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            output_lines.append(line)
        
        process.wait()
        result_stdout = ''.join(output_lines)
        
        if process.returncode != 0:
            error_context = f"Commands failed\nExit code: {process.returncode}\nOutput:\n{result_stdout}"
            self.state.record_error(error_context, context=f"phase_{self.state.phase}")
            return False
        
        return True
    
    def phase_generate_distance(self) -> bool:
        """Phase 4: Generate distance file"""
        self.logger.info("=== Phase 4: Distance Generation ===")
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
        
        # Get binary path and binary name from config
        # binary_path: directory to search for .bc files (e.g., $SUBJECT, $SUBJECT/build)
        # binary_name: fuzzer binary name used to filter .bc files (e.g., jq, njs)
        binary_path = self.config.get('build_config', {}).get('binary_path', '$SUBJECT')
        binary_name = self.config.get('binary_name', self.repo_name)
        
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
        
        question = f"""Distance generation FAILED with this error:
{stderr[:500] if stderr else 'Unknown error'}

**Configuration:**
- Subject directory: {self.subject_dir}
- Temp directory: {self.temp_dir}
- Binary name: {binary_name}
- Binary path tried: {binary_path_resolved}

**Command format:**
python3 $AFLGO/distance/gen_distance_fast.py <binary_path> <temp_dir> <fuzzer_name>

**Examples that work:**
- python3 gen_distance_fast.py $SUBJECT $TMP_DIR jq
- python3 gen_distance_fast.py $SUBJECT/build $TMP_DIR njs

**Your task:** Provide ONE command that will work. Do NOT use 'find' or other diagnostic commands.

Respond in JSON:
{{
  "reasoning": "why this binary_path and fuzzer_name will work",
  "commands": ["python3 {self.aflgo_dir}/distance/gen_distance_fast.py <correct_path> {self.temp_dir} {binary_name}"]
}}"""
        
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
        binary_name = self.config.get('binary_name', self.repo_name)
        
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
            if self.config.get('cve_id'):
                cve_suffix = self.config['cve_id'].replace('CVE-', '').replace('-', '_')
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
                binary_name = self.config.get('binary_name', self.repo_name)
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
