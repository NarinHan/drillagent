#!/usr/bin/env python3
"""
LLM-Driven AFLGo Automation Agent

This agent uses an LLM to intelligently handle AFLGo instrumentation,
making decisions about build systems, debugging failures, and adapting
to project-specific requirements.

Usage:
    ./aflgo_llm_agent.py --config config.yaml
    ./aflgo_llm_agent.py --repo-url <url> --commit-id <id>
"""

import os
import sys
import subprocess
import argparse
import yaml
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import re

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("Warning: openai package not installed. Install with: pip install openai")
    print("Falling back to rule-based logic.")

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels"""
    
    # ANSI color codes
    RED = '\033[91m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    
    COLORS = {
        'ERROR': RED,
        'WARNING': YELLOW,
        'INFO': RESET,
        'DEBUG': RESET,
    }
    
    def format(self, record):
        # Color errors in red
        if record.levelname == 'ERROR':
            record.levelname = f"{self.RED}{record.levelname}{self.RESET}"
            record.msg = f"{self.RED}{record.msg}{self.RESET}"
        elif record.levelname == 'WARNING':
            record.levelname = f"{self.YELLOW}{record.levelname}{self.RESET}"
        
        return super().format(record)


@dataclass
class AgentState:
    """Current state of the agent's work with memory"""
    phase: str  # 'setup', 'targets', 'build1', 'distance', 'build2', 'complete'
    attempts: int = 0
    max_attempts: int = 3
    errors: List[str] = None
    observations: List[str] = None
    actions_taken: List[str] = None
    error_patterns: Dict[str, int] = None  # Track recurring error patterns
    attempted_solutions: List[Dict] = None  # Track what solutions were tried
    diagnostics: Dict[str, any] = None  # Store diagnostic insights
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.observations is None:
            self.observations = []
        if self.actions_taken is None:
            self.actions_taken = []
        if self.error_patterns is None:
            self.error_patterns = {}
        if self.attempted_solutions is None:
            self.attempted_solutions = []
        if self.diagnostics is None:
            self.diagnostics = {}
    
    def record_error(self, error: str, context: str = ""):
        """Record an error and detect patterns"""
        self.errors.append(error)
        
        # Extract error signatures for pattern detection
        signatures = self._extract_error_signatures(error)
        for sig in signatures:
            self.error_patterns[sig] = self.error_patterns.get(sig, 0) + 1
    
    def _extract_error_signatures(self, error: str) -> List[str]:
        """Extract characteristic error patterns - keep it simple and generic"""
        # Extract key error indicators from the full error text
        # Don't hardcode specific patterns - let LLM reason about them
        signatures = []
        
        if not error:
            return []
        
        # Get all meaningful error lines (skip "Command:" line)
        lines = [line.strip() for line in error.split('\n') if line.strip()]
        error_lines = [line for line in lines if not line.startswith('Command:')]
        
        if error_lines:
            # Use first actual error line as signature (truncated to avoid huge keys)
            first_error = error_lines[0][:150]
            signatures.append(first_error)
            
            # Also capture specific compiler/linker error patterns
            # Look through ALL lines, not just first 10
            for line in error_lines:
                # Capture LLVM/clang option errors (CRITICAL for AFLGo issues)
                if 'option parsing' in line.lower() or 'may only occur' in line.lower():
                    signatures.append(line[:200])
                # Capture make target errors
                elif line.startswith('make[') and '***' in line:
                    signatures.append(line[:200])
                # Capture make general errors  
                elif line.startswith('make:') and '***' in line:
                    signatures.append(line[:200])
                # Capture missing file errors
                elif 'not found' in line.lower() or 'no such file' in line.lower():
                    signatures.append(line[:200])
                # Capture undefined reference errors
                elif 'undefined reference' in line.lower():
                    signatures.append(line[:200])
        
        return signatures
    
    def record_solution_attempt(self, solution_type: str, details: Dict, success: bool):
        """Record a solution that was attempted"""
        self.attempted_solutions.append({
            'type': solution_type,
            'details': details,
            'success': success,
            'attempt_number': self.attempts
        })
    
    def get_repeated_errors(self, threshold: int = 2) -> List[Tuple[str, int]]:
        """Get errors that have occurred multiple times"""
        return [(sig, count) for sig, count in self.error_patterns.items() 
                if count >= threshold]
    
    def diagnose_issue(self) -> Dict[str, any]:
        """Analyze accumulated errors and provide diagnostic insights"""
        diagnosis = {
            'repeated_errors': self.get_repeated_errors(2),
            'total_attempts': self.attempts,
            'unique_errors': len(self.error_patterns)
        }
        return diagnosis


class LLMInterface:
    """Interface to LLM for decision making"""
    
    def __init__(self, model: str = "gpt-5.1", api_key: Optional[str] = None):
        self.model = model
        
        # Load .env file if available
        if DOTENV_AVAILABLE:
            # Try to load from /home/ray/cs562/.env first
            env_path = Path.home() / 'cs562' / '.env'
            if env_path.exists():
                load_dotenv(env_path)
            else:
                # Try current directory
                load_dotenv()
        
        # Get API key: explicit > env var
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.use_openai = OPENAI_AVAILABLE and self.api_key
        
        if self.use_openai:
            # Use new OpenAI client API (>= 1.0.0)
            self.client = openai.OpenAI(api_key=self.api_key)
            print(f"Using OpenAI model: {self.model}")
        else:
            self.client = None
            if not OPENAI_AVAILABLE:
                print("OpenAI package not available")
            elif not self.api_key:
                print("No OpenAI API key found. Set OPENAI_API_KEY or use .env file")
            print("Using rule-based fallback logic")
        
    def query(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """
        Query the LLM with a prompt.
        """
        if not self.use_openai:
            raise RuntimeError("OpenAI API is required but not available")
        
        result = self._query_openai(prompt, system_prompt)
        if not result or len(result.strip()) == 0:
            print(f"⚠️  OpenAI returned empty result. Prompt length: {len(prompt)}")
        return result
    
    def _query_openai(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Query OpenAI API using new client-based API (>= 1.0.0)"""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.7,
            max_completion_tokens=2048,  # Increased from 1024 to allow longer responses
        )
        
        content = response.choices[0].message.content
        finish_reason = response.choices[0].finish_reason
        
        # Log if content is empty or None
        if not content:
            print(f"⚠️  OpenAI returned empty content!")
            print(f"Finish reason: {finish_reason}")
            print(f"Full response object: {response}")
            return ""
        
        # Warn if truncated
        if finish_reason == 'length':
            print(f"⚠️  Response was truncated due to length limit. Consider increasing max_completion_tokens.")
        
        return content


class AFLGoLLMAgent:
    """LLM-driven AFLGo instrumentation agent"""
    
    SYSTEM_PROMPT = """You are an expert systems engineer and security researcher specializing in 
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
    
    def __init__(self, config: Dict):
        self.config = config
        
        # Setup environment first so temp_dir is available for logging
        self.setup_environment()
        self.setup_logging()
        
        # Initialize LLM with configured model
        llm_model = config.get('llm_model', 'gpt-5.1')
        llm_api_key = config.get('openai_api_key') or os.getenv('OPENAI_API_KEY')
        self.llm = LLMInterface(model=llm_model, api_key=llm_api_key)
        
        self.state = AgentState(phase='setup')
        
        # Store environment variables AFTER setup to preserve AFLGo compilers
        # We'll reset CFLAGS/CXXFLAGS between attempts, but keep CC/CXX
        self.original_env = {
            'CC': os.environ.get('CC', ''),
            'CXX': os.environ.get('CXX', ''),
            'CFLAGS': '',  # Start fresh for each phase
            'CXXFLAGS': '',  # Start fresh for each phase
            'LDFLAGS': os.environ.get('LDFLAGS', '')
        }
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('log_level', 'INFO')
        
        # Store log file in the temp directory for this specific run
        # Each CVE/repo combination gets its own log file
        log_filename = f"aflgo_{self.repo_name}.log"
        if self.config.get('cve_id'):
            cve_suffix = self.config['cve_id'].replace('CVE-', '').replace('-', '_')
            log_filename = f"aflgo_{self.repo_name}_{cve_suffix}.log"
        
        log_file = self.temp_dir / log_filename
        
        # Store log file path for later use
        self.log_file = log_file
        
        # Remove old log file if it exists
        if log_file.exists():
            log_file.unlink()
        
        # Create console handler with color formatter
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColoredFormatter('[%(asctime)s] %(levelname)s: %(message)s'))
        
        # Create file handler with plain formatter (no colors in file)
        file_handler = logging.FileHandler(str(log_file))
        file_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s'))
        
        logging.basicConfig(
            level=getattr(logging, log_level),
            handlers=[console_handler, file_handler]
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_environment(self):
        """Setup directory structure and environment variables"""
        # Get the script directory (DrillAgent/src/instrumentation)
        script_dir = Path(__file__).resolve().parent
        # CS562 base directory is 3 levels up from DrillAgent/src/instrumentation
        ray_base = script_dir.parent.parent.parent
        
        # Base paths - use absolute paths with resolve()
        self.aflgo_dir = Path(self.config.get('aflgo_dir', ray_base / 'aflgo')).resolve()
        self.repos_dir = Path(self.config.get('repos_dir', ray_base / 'repos')).resolve()
        self.temps_dir = Path(self.config.get('temps_dir', ray_base / 'fuzzing' / 'temps')).resolve()
        
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
        
        # Environment variables
        os.environ['AFLGO'] = str(self.aflgo_dir)
        os.environ['SUBJECT'] = str(self.subject_dir)
        os.environ['TMP_DIR'] = str(self.temp_dir)
        os.environ['CC'] = str(self.aflgo_dir / 'instrument' / 'aflgo-clang')
        os.environ['CXX'] = str(self.aflgo_dir / 'instrument' / 'aflgo-clang++')
        os.environ['LDFLAGS'] = '-lpthread'
        os.environ['LIB_FUZZING_ENGINE'] = ''  # Set empty to avoid unbound variable errors
        
    def log_llm_reasoning(self, prefix: str, reasoning: str):
        """Log LLM reasoning in blue color"""
        BLUE = '\033[94m'
        RESET = '\033[0m'
        self.logger.info(f"{prefix} {BLUE}{reasoning}{RESET}")
    
    def run_command(self, cmd: str, cwd: Optional[Path] = None) -> Tuple[int, str, str]:
        """Run a command and return exit code, stdout, stderr"""
        # ANSI color codes: green text
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
        """
        Ask the LLM for guidance and get structured response
        
        Returns:
            Dict with keys: reasoning, action, command, parameters, confidence
        """
        # Build prompt with context
        prompt_parts = [question]
        
        if context:
            prompt_parts.append("\n\nContext:")
            prompt_parts.append(json.dumps(context, indent=2))
        
        # Add current state
        prompt_parts.append(f"\n\nCurrent Phase: {self.state.phase}")
        prompt_parts.append(f"Attempts: {self.state.attempts}/{self.state.max_attempts}")
        
        # Don't add errors here - the calling code (build phase, distance phase) 
        # already formats them properly with analysis context
        
        if self.state.observations:
            prompt_parts.append("\n\nObservations:")
            for obs in self.state.observations[-5:]:
                prompt_parts.append(f"- {obs}")
        
        prompt = "\n".join(prompt_parts)
        
        # Query LLM
        response = self.llm.query(prompt, self.SYSTEM_PROMPT)
        
        # Log raw response for debugging
        if not response or len(response.strip()) == 0:
            self.logger.error(f"🚨 LLM returned empty or whitespace-only response!")
            self.logger.error(f"Prompt length: {len(prompt)} chars")
            self.logger.error(f"Prompt preview: {prompt[:500]}...")
        
        # Strip markdown code blocks if present (LLM often wraps JSON in ```json...```)
        response_clean = response.strip()
        if response_clean.startswith('```'):
            # Remove opening ```json or ``` and closing ```
            lines = response_clean.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]  # Remove first line
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]  # Remove last line
            response_clean = '\n'.join(lines).strip()
        
        # Parse response (expecting JSON)
        try:
            parsed = json.loads(response_clean)
            return parsed
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse LLM response as JSON: {e}")
            self.logger.warning(f"Raw response (first 500 chars): {response[:500]}")
            # Fallback to simple structure - use the response as reasoning
            if response and len(response.strip()) > 0:
                return {
                    'reasoning': response,
                    'action': 'continue',
                    'confidence': 0.5
                }
            else:
                return {
                    'reasoning': '',
                    'action': 'continue',
                    'confidence': 0.5
                }
    
    def phase_setup_repository(self) -> bool:
        """Phase 1: Clone/update repository"""
        self.logger.info("=== Phase 1: Repository Setup ===")
        self.state.phase = 'setup'
        
        # Remove existing repository if it exists
        if self.subject_dir.exists():
            self.logger.info(f"Removing existing repository: {self.subject_dir}")
            import shutil
            shutil.rmtree(self.subject_dir)
        
        # Clone fresh repository
        self.logger.info(f"Cloning repository: {self.repo_url}")
        code, stdout, stderr = self.run_command(
            f"git clone {self.repo_url} {self.subject_dir}"
        )
        if code != 0:
            error_msg = f"git clone failed: {stderr}"
            self.logger.error(error_msg)
            self.state.errors.append(error_msg)
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
        """Extract targets from sanitizer report using LLM guidance
        
        Strategy: Use only the LAST point in the stack trace where the bug is triggered,
        then use LLM to read the source code and identify the whole paragraph (roughly 5 lines)
        containing that line for better instrumentation coverage.
        """
        # Get sanitizer report content directly from config
        report_content = self.config.get('sanitizer_report')
        if not report_content:
            self.logger.warning("No sanitizer_report field in config")
            return None
        
        self.logger.info(f"Using sanitizer report from config (length: {len(report_content)} chars)")
        
        parse_question = f"""I need to extract the LAST (deepest) vulnerability target location from this sanitizer report.

Repository name: {self.repo_name}
Report content (first 1500 chars):
{report_content[:1500]}

Sanitizer reports contain stack traces with file paths and line numbers like:
  #0 0x... in function_name /path/to/repo-version/src/file.c:123:45
  #1 0x... in other_function /path/to/repo-version/src/other.c:456:78

IMPORTANT: I need ONLY the LAST target in the stack trace (typically #0, the actual bug location).
The paths may contain version suffixes like "md4c-release-0.4.7" but I need just the relative path after the repo name.

Extract format: <relative_path>:<line_number>
For example: src/md4c.c:5985

Please identify the LAST (deepest) target location where the bug is actually triggered.
Respond in JSON:
{{
  "reasoning": "your analysis identifying the last/deepest bug location",
  "target": "src/file.c:123"
}}"""
        
        parse_response = self.ask_llm(parse_question)
        self.log_llm_reasoning("LLM parsing:", parse_response.get('reasoning', ''))
        
        # Accept both 'target' (singular) and 'targets' (plural)
        target = parse_response.get('target', '') or (parse_response.get('targets', [''])[0] if parse_response.get('targets') else '')
        
        # Fallback: try regex parsing if LLM didn't provide target
        if not target:
            self.logger.info("LLM didn't provide target, trying regex fallback")
            # Look for first line in stack trace (usually #0)
            for line in report_content.split('\n'):
                if '#0 ' in line or '#1 ' in line:
                    # Extract file:line pattern
                    match = re.search(r'#\d+\s+0x[0-9a-f]+\s+in\s+\S+\s+(/[^\s:]+):(\d+)(?::\d+)?', line)
                    if match:
                        file_path = match.group(1)
                        line_num = match.group(2)
                        
                        # Extract relative path - handle repo name with version suffixes
                        repo_pattern = rf'/{re.escape(self.repo_name)}[^/]*/(.*)'
                        repo_match = re.search(repo_pattern, file_path)
                        if repo_match:
                            rel_path = repo_match.group(1)
                            target = f"{rel_path}:{line_num}"
                            break
        
        if not target:
            return None
        
        # Parse the target to extract file and line number
        try:
            file_path, line_str = target.rsplit(':', 1)
            base_line = int(line_str)
        except (ValueError, AttributeError):
            self.logger.error(f"Failed to parse target: {target}")
            return None
        
        # IMPORTANT: Checkout to vulnerable version BEFORE reading source files
        # The source file may not exist on the current commit
        if self.config.get('commit_id'):
            commit_id = self.config['commit_id']
            self.logger.info(f"Checking out vulnerable version: {commit_id}")
            self.run_command(f"git checkout {commit_id}", self.subject_dir)
            # Update submodules to match the checked-out commit
            self.logger.info("Updating submodules for vulnerable version...")
            self.run_command("git submodule update --init --recursive", self.subject_dir)
        
        # Read the source file to get context around the target line
        source_file_path = self.subject_dir / file_path
        
        # If the direct path doesn't exist, try to find the file in the repository
        if not source_file_path.exists():
            self.logger.info(f"Direct path not found: {source_file_path}, searching repository...")
            
            # Extract just the filename to search for
            file_name = Path(file_path).name
            
            # Search for the file in the repository
            find_cmd = f"find {self.subject_dir} -name '{file_name}' -type f"
            code, stdout, stderr = self.run_command(find_cmd)
            
            if code == 0 and stdout.strip():
                candidates = [Path(p.strip()) for p in stdout.strip().split('\n') if p.strip()]
                
                # Filter candidates to find the one that matches the suffix path
                # For example, if file_path is "media_tools/mpeg2_ps.c", 
                # prefer "src/media_tools/mpeg2_ps.c" over other matches
                path_parts = Path(file_path).parts
                best_match = None
                
                for candidate in candidates:
                    candidate_parts = candidate.parts
                    # Check if the candidate ends with the same path structure
                    if len(candidate_parts) >= len(path_parts):
                        if all(candidate_parts[-(len(path_parts)-i)] == path_parts[-(len(path_parts)-i)] 
                               for i in range(len(path_parts))):
                            best_match = candidate
                            break
                
                if best_match:
                    source_file_path = best_match
                    # Update file_path to the correct relative path for BBtargets.txt
                    file_path = str(source_file_path.relative_to(self.subject_dir))
                    self.logger.info(f"Found file at: {source_file_path}")
                    self.logger.info(f"Updated target path to: {file_path}")
                elif candidates:
                    # Just use the first candidate if no perfect match
                    source_file_path = candidates[0]
                    file_path = str(source_file_path.relative_to(self.subject_dir))
                    self.logger.info(f"Using first match: {source_file_path}")
                    self.logger.info(f"Updated target path to: {file_path}")
        
        if not source_file_path.exists():
            self.logger.warning(f"Source file not found: {source_file_path}")
            # Fallback to fixed range
            lines_before = self.config.get('target_lines_before', 4)
            lines_after = self.config.get('target_lines_after', 3)
            start_line = max(1, base_line - lines_before)
            end_line = base_line + lines_after
            extended_targets = [f"{file_path}:{line}" for line in range(start_line, end_line + 1)]
            self.logger.info(f"Using fallback range: {file_path}:{start_line} to {file_path}:{end_line}")
            return extended_targets
        
        # Read source code around the target line (get extra context for LLM)
        try:
            with open(source_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()
            
            # Get context: 10 lines before and after for LLM to analyze
            context_start = max(0, base_line - 11)  # -11 because line numbers are 1-indexed
            context_end = min(len(all_lines), base_line + 10)
            context_lines = all_lines[context_start:context_end]
            
            # Create numbered context for LLM
            context_with_numbers = []
            for i, line in enumerate(context_lines):
                line_num = context_start + i + 1
                marker = " <-- BUG HERE" if line_num == base_line else ""
                context_with_numbers.append(f"{line_num:4d}: {line.rstrip()}{marker}")
            
            context_text = "\n".join(context_with_numbers)
        except Exception as e:
            self.logger.warning(f"Error reading source file: {e}")
            # Fallback to fixed range
            start_line = max(1, base_line - 4)
            end_line = base_line + 3
            extended_targets = [f"{file_path}:{line}" for line in range(start_line, end_line + 1)]
            return extended_targets
        
        # Ask LLM to identify the logical paragraph/block containing the bug
        paragraph_question = f"""I need to identify the complete code paragraph or logical block containing a bug.

**Bug Location:** {file_path}:{base_line}

**Source Code Context:**
```c
{context_text}
```

**Task:**
Analyze the code and identify the complete logical paragraph or code block that contains line {base_line}.
A "paragraph" here means a cohesive block of code, such as:
- A complete if/else block
- A complete for/while loop body
- A function call with its setup
- A logical group of related statements

The paragraph should:
1. Include roughly 5 lines total (can be 3-8 lines depending on context)
2. Be self-contained and meaningful for fuzzing instrumentation
3. Include line {base_line} (the bug location)
4. Not be too broad (avoid entire functions) or too narrow (single line)

Respond in JSON format:
{{
  "reasoning": "explain why you chose this range",
  "start_line": <number>,
  "end_line": <number>
}}

Example: If the bug is in a for-loop at line 100, you might include lines 99-103 to cover the loop header and a few iterations."""
        
        paragraph_response = self.ask_llm(paragraph_question)
        self.log_llm_reasoning("LLM paragraph analysis:", paragraph_response.get('reasoning', ''))
        
        # Extract line range from LLM response
        try:
            start_line = int(paragraph_response.get('start_line', base_line - 2))
            end_line = int(paragraph_response.get('end_line', base_line + 2))
            
            # Validation: ensure the range is reasonable
            if start_line < 1:
                start_line = 1
            if end_line < start_line:
                end_line = start_line + 4
            if end_line - start_line > 15:  # Cap at 15 lines max
                self.logger.warning(f"LLM suggested range too large ({end_line - start_line + 1} lines), capping at 10 lines")
                end_line = start_line + 9
            if end_line - start_line < 1:  # Minimum 2 lines
                end_line = start_line + 4
                
            # Ensure base_line is included
            if base_line < start_line or base_line > end_line:
                self.logger.warning(f"LLM range doesn't include bug line {base_line}, adjusting...")
                start_line = base_line - 2
                end_line = base_line + 2
                
        except (ValueError, TypeError) as e:
            self.logger.warning(f"Failed to parse LLM response for line range: {e}, using default")
            start_line = max(1, base_line - 2)
            end_line = base_line + 2
        
        # Generate extended target list
        extended_targets = [f"{file_path}:{line}" for line in range(start_line, end_line + 1)]
        
        self.logger.info(f"Using last bug trigger point: {target}")
        self.logger.info(f"LLM identified paragraph: {file_path}:{start_line} to {file_path}:{end_line} ({len(extended_targets)} lines)")
        
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
            
            # Ensure minimum of 6 targets by expanding range if needed
            MIN_TARGETS = 6
            if len(targets) < MIN_TARGETS:
                self.logger.info(f"Manual targets ({len(targets)}) less than minimum {MIN_TARGETS}, expanding...")
                
                # Parse the last target to get file and line
                last_target = targets[-1]
                match = re.match(r'(.+):(\d+)$', last_target)
                if match:
                    file_path = match.group(1)
                    last_line = int(match.group(2))
                    
                    # Add more lines after the last line to reach minimum
                    needed = MIN_TARGETS - len(targets)
                    for i in range(1, needed + 1):
                        targets.append(f"{file_path}:{last_line + i}")
                    
                    self.logger.info(f"Expanded to {len(targets)} targets: {file_path}:{last_line} to {file_path}:{last_line + needed}")
            
            with open(targets_file, 'w') as f:
                for target in targets:
                    f.write(f"{target}\n")
            self.logger.info(f"Using {len(targets)} manual targets")
            return True
        
        # Extract from sanitizer report (LLM-driven)
        if self.config.get('cve_id'):
            self.logger.info(f"Extracting targets from sanitizer report for CVE {self.config['cve_id']}")
            sanitizer_targets = self._extract_targets_from_sanitizer_report()
            
            if sanitizer_targets:
                self.log_llm_reasoning("Phase 2:", f"Successfully extracted {len(sanitizer_targets)} target lines from sanitizer report")
                
                # Ensure minimum of 6 targets by expanding range if needed
                MIN_TARGETS = 6
                if len(sanitizer_targets) < MIN_TARGETS:
                    self.logger.info(f"Found {len(sanitizer_targets)} targets, expanding to minimum of {MIN_TARGETS}")
                    
                    # Parse the last target to get file and line
                    last_target = sanitizer_targets[-1]
                    match = re.match(r'(.+):(\d+)$', last_target)
                    if match:
                        file_path = match.group(1)
                        last_line = int(match.group(2))
                        
                        # Add more lines after the last line to reach minimum
                        needed = MIN_TARGETS - len(sanitizer_targets)
                        for i in range(1, needed + 1):
                            sanitizer_targets.append(f"{file_path}:{last_line + i}")
                        
                        self.logger.info(f"Expanded to {len(sanitizer_targets)} targets: {file_path}:{last_line} to {file_path}:{last_line + needed}")
                
                self.logger.info(f"Writing {len(sanitizer_targets)} targets to BBtargets.txt")
                with open(targets_file, 'w') as f:
                    for target in sanitizer_targets:
                        f.write(f"{target}\n")
                
                # Note: git checkout is now done in _extract_targets_from_sanitizer_report()
                # before reading source files for LLM paragraph analysis
                
                return True
            else:
                error_msg = "No targets extracted from sanitizer report"
                self.logger.error(error_msg)
                self.state.errors.append(error_msg)
                return False
        
        error_msg = "No CVE ID provided for sanitizer report extraction"
        self.logger.error(error_msg)
        self.state.errors.append(error_msg)
        return False
    
    def phase_build_with_llm(self, phase_num: int = 1) -> bool:
        """Build using exact commands from config (phase 1 or 2)"""
        phase_name = "CG/CFG Generation" if phase_num == 1 else "Distance Instrumentation"
        self.logger.info(f"=== Phase {phase_num + 2}: {phase_name} ===")
        
        targets_file = self.temp_dir / 'BBtargets.txt'
        distance_file = self.temp_dir / 'distance.cfg.txt'
        
        # Get build commands from config
        build_commands_str = self.config.get('build_config', {}).get('build_commands', '')
        if not build_commands_str:
            error_msg = "No build_commands found in config"
            self.logger.error(error_msg)
            self.state.errors.append(error_msg)
            return False
        
        # Parse build commands from config (split by newlines, filter out comments and empty lines)
        build_commands = [cmd.strip() for cmd in build_commands_str.split('\n') 
                         if cmd.strip() and not cmd.strip().startswith('#')]
        
        if not build_commands:
            error_msg = "No valid build commands found in config after parsing"
            self.logger.error(error_msg)
            self.state.errors.append(error_msg)
            return False
        
        # For phase 1, ensure clean build to generate CFG files
        # The repository is already freshly cloned in Phase 1, so no need to clean
        # Just ensure we're building from scratch
        if phase_num == 1:
            self.logger.info("Building from fresh repository clone (Phase 1)")
        
        # Reset environment to original state
        for key in ['CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS']:
            if self.original_env[key]:
                os.environ[key] = self.original_env[key]
            elif key in os.environ:
                del os.environ[key]
        
        # Set compiler flags for this phase
        if phase_num == 1:
            additional = f"-targets={targets_file} -outdir={self.temp_dir} -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
            os.environ['CFLAGS'] = f"{additional} -g"
            os.environ['CXXFLAGS'] = f"{additional} -g"
        else:
            os.environ['CFLAGS'] = f"-distance={distance_file.resolve()}"
            os.environ['CXXFLAGS'] = f"-distance={distance_file.resolve()}"
        
        # Add custom flags from config
        custom_cflags = self.config.get('build_config', {}).get('cflags', '')
        if custom_cflags:
            os.environ['CFLAGS'] = f"{custom_cflags} {os.environ['CFLAGS']}"
            os.environ['CXXFLAGS'] = f"{custom_cflags} {os.environ['CXXFLAGS']}"
        
        # Log the build commands from config
        self.logger.info(f"Using build commands from config:")
        for i, cmd in enumerate(build_commands, 1):
            self.logger.info(f"  [{i}] {cmd}")
        
        # Execute build using exact commands from config
        success = self._execute_commands(build_commands)
        
        if not success:
            error_msg = f"{phase_name} build failed. Check the error messages above."
            self.logger.error(error_msg)
            self.state.errors.append(error_msg)
            return False
        
        # Validate that required artifacts were produced
        if phase_num == 1:
            # Phase 1: Check for LLVM bytecode files
            if not self._validate_cg_cfg_artifacts():
                error_msg = "Build succeeded but required .bc files not found"
                self.logger.error(error_msg)
                self.state.errors.append(error_msg)
                return False
        else:
            # Phase 2: Check for instrumented binary
            if not self._validate_instrumented_binary():
                error_msg = "Build succeeded but instrumented binary not found"
                self.logger.error(error_msg)
                self.state.errors.append(error_msg)
                return False
        
        self.logger.info("Build successful and artifacts validated!")
        return True
    
    def _extract_commands_from_reasoning(self, reasoning: str) -> List[str]:
        """Extract build commands from LLM's reasoning"""
        commands = []
        
        # Look for commands in backticks or quotes
        for pattern in [r'`([^`]+)`', r'"([^"]+)"', r"'([^']+)'"]:
            for match in re.finditer(pattern, reasoning):
                cmd = match.group(1).strip()
                if any(kw in cmd.lower() for kw in ['cmake', 'make', 'configure', 'autoreconf', 'gcc', 'clang']):
                    commands.append(cmd)
        
        # If no commands found, try to use build_commands from config
        if not commands:
            build_commands = self.config.get('build_config', {}).get('build_commands', '')
            if build_commands:
                self.logger.info("No commands extracted from reasoning, using build_commands from config")
                # Split build commands by newlines and clean up
                commands = [cmd.strip() for cmd in build_commands.split('\n') if cmd.strip() and not cmd.strip().startswith('#')]
        
        return commands
    
    def _validate_cg_cfg_artifacts(self) -> bool:
        """Validate that CG/CFG generation produced required bytecode files"""
        binary_name = self.config.get('binary_name', self.repo_name)
        
        # Search for .bc files
        find_cmd = f"find {self.subject_dir} -name '*.0.0.*.bc' -type f"
        code, stdout, stderr = self.run_command(find_cmd)
        bc_files = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
        
        if not bc_files:
            error_msg = f"""CG/CFG generation failed: No LLVM bytecode (.bc) files found.
            
This usually means:
1. The build system didn't use the AFLGo compilers (CC/CXX)
2. CFLAGS/CXXFLAGS were not properly passed to the compiler
3. The build system uses a different configuration method

Current environment:
- CC: {os.environ.get('CC')}
- CXX: {os.environ.get('CXX')}
- CFLAGS: {os.environ.get('CFLAGS')[:100]}...

Try:
- For autotools: Pass flags via --extra-cflags and --extra-ldflags to ./configure
- For CMake: Set CMAKE_C_FLAGS and CMAKE_CXX_FLAGS
- Check that the build actually compiles source files (not just linking pre-built objects)"""
            
            self.state.errors.append(error_msg)
            self.logger.error(error_msg)
            return False
        
        self.logger.info(f"Found {len(bc_files)} bytecode files:")
        for bc_file in bc_files[:5]:  # Show first 5
            self.logger.info(f"  - {bc_file}")
        if len(bc_files) > 5:
            self.logger.info(f"  ... and {len(bc_files) - 5} more")
        
        return True
    
    def _validate_instrumented_binary(self) -> bool:
        """Validate that final build produced instrumented binary"""
        binary_path = self.find_instrumented_binary()
        
        if not binary_path:
            binary_name = self.config.get('binary_name', self.repo_name)
            error_msg = f"""Instrumented binary '{binary_name}' not found after build.
            
Searched locations:
- {self.subject_dir / binary_name}
- {self.subject_dir / 'build' / binary_name}
- {self.subject_dir / 'build' / 'bin' / binary_name}
- {self.subject_dir / 'bin' / binary_name}
- {self.subject_dir / 'src' / binary_name}

The build may have succeeded but placed the binary in an unexpected location."""
            
            self.state.errors.append(error_msg)
            self.logger.error(error_msg)
            return False
        
        self.logger.info(f"Found instrumented binary: {binary_path}")
        return True
    
    def _execute_commands(self, commands: List[str]) -> bool:
        """Execute a list of commands in a single shell session to preserve variables"""
        if not commands:
            return True
        
        # SAFETY CHECKS: Validate all commands before execution
        aflgo_protected_paths = [
            str(self.aflgo_dir),
            'aflgo-clang',
            'aflgo/instrument',
            'aflgo/distance'
        ]
        
        for cmd in commands:
            cmd = cmd.strip()
            if not cmd:
                continue
            
            # SAFETY CHECK: Block system-wide package upgrades
            if re.search(r'\b(apt|apt-get|yum|dnf)\s+(upgrade|dist-upgrade|full-upgrade)', cmd.lower()):
                error_msg = f"🚫 BLOCKED: System package upgrade not allowed. Use 'apt install <package>' for specific packages: {cmd}"
                self.logger.error(error_msg)
                self.state.record_error(error_msg, context="safety_check")
                return False
            
            # Check if command tries to modify AFLGo implementation files
            dangerous_patterns = [
                (r'\brm\s+.*aflgo/(instrument|distance|afl-)', 'removing AFLGo implementation files'),
                (r'\bmv\s+.*aflgo/(instrument|distance|afl-)', 'moving AFLGo implementation files'),
                (r'\bcp\s+.*aflgo/(instrument|distance|afl-)', 'copying AFLGo implementation files'),
                (r'\b(sed|awk|perl)\s+.*aflgo/(instrument|distance|afl-)', 'modifying AFLGo implementation files'),
                (r'\bmake\s+.*install.*aflgo/(instrument|distance)', 'reinstalling AFLGo components'),
                (r'\bcmake\s+.*aflgo/(instrument|distance)', 'rebuilding AFLGo components'),
            ]
            
            for pattern, description in dangerous_patterns:
                if re.search(pattern, cmd.lower()):
                    error_msg = f"🚫 BLOCKED: Command would modify AFLGo toolchain ({description}): {cmd}"
                    self.logger.error(error_msg)
                    self.state.record_error(error_msg, context="safety_check")
                    return False
            
            # Additional check: commands should not write to aflgo_dir
            if any(protected in cmd for protected in aflgo_protected_paths):
                # Allow read-only operations
                readonly_ops = ['cat', 'ls', 'find', 'grep', 'echo', 'python', 'python3']
                is_readonly = any(cmd.strip().startswith(op) for op in readonly_ops)
                
                if not is_readonly:
                    self.logger.warning(f"⚠️  Command references AFLGo path but will be allowed: {cmd}")
        
        # Build a single shell script that combines all commands
        # Set error handling: exit on error, but track which command failed
        # Note: cwd is already set to self.subject_dir in Popen, so no cd needed
        script_lines = [
            '#!/bin/bash',
            'set -e',  # Exit on error
            ''
        ]
        
        # Process commands: expand variables and add to script
        for i, cmd in enumerate(commands):
            cmd = cmd.strip()
            if not cmd:
                continue
            
            # Expand variables
            cmd = cmd.replace('$(nproc)', str(os.cpu_count()))
            
            # Handle mkdir: make it idempotent
            if cmd.startswith('mkdir') and '-p' not in cmd:
                cmd = re.sub(r'^mkdir\s+', 'mkdir -p ', cmd)
            
            # Add command to script with error context
            script_lines.append(f'# Command {i+1}')
            script_lines.append(cmd)
            script_lines.append('')
        
        script_content = '\n'.join(script_lines)
        
        # Log the commands that will be executed
        GREEN = '\033[92m'
        RESET = '\033[0m'
        self.logger.info(f"{GREEN}Executing build commands:{RESET}")
        for i, cmd in enumerate(commands):
            cmd = cmd.strip()
            if cmd:
                self.logger.info(f"{GREEN}  [{i+1}] {cmd}{RESET}")
        
        # Execute the combined script with real-time output
        import sys
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
        
        # Stream output in real-time
        output_lines = []
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            output_lines.append(line)
        
        process.wait()
        result_stdout = ''.join(output_lines)
        result_stderr = ''  # Already merged into stdout
        
        # Create a result-like object for compatibility
        class Result:
            def __init__(self, returncode, stdout, stderr):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr
        
        result = Result(process.returncode, result_stdout, result_stderr)
        
        # Check result
        if result.returncode != 0:
            self.logger.error(f"Shell script failed with exit code {result.returncode}")
            
            if result.stderr:
                self.logger.error(f"Stderr:\n{result.stderr}")
            
            if result.stdout:
                self.logger.error(f"Stdout:\n{result.stdout}")
            
            # Build error context
            error_context = f"Combined shell script failed\nExit Code: {result.returncode}\n"
            if result.stderr:
                error_context += f"Stderr:\n{result.stderr}\n"
            if result.stdout:
                error_context += f"Stdout:\n{result.stdout}\n"
            
            self.state.record_error(error_context, context=f"phase_{self.state.phase}")
            return False
        
        # Log success output if present (truncate if too long)
        if result.stdout:
            output = result.stdout
            if len(output) > 2000:
                self.logger.info(f"Output (first 2000 chars):\n{output[:2000]}\n... (truncated)")
            else:
                self.logger.info(f"Output:\n{output}")
        
        return True
    
    def find_instrumented_binary(self) -> Optional[Path]:
        """Find the location of the instrumented binary after final build"""
        binary_name = self.config.get('binary_name', self.repo_name)
        
        # Common locations to search
        search_paths = [
            self.subject_dir / binary_name,
            self.subject_dir / 'build' / binary_name,
            self.subject_dir / 'build' / 'bin' / binary_name,
            self.subject_dir / 'bin' / binary_name,
            self.subject_dir / 'src' / binary_name,
        ]
        
        # Check known locations first
        for path in search_paths:
            if path.exists() and path.is_file():
                return path
        
        # Search recursively in build directory
        build_dir = self.subject_dir / 'build'
        if build_dir.exists():
            found = list(build_dir.glob(f"**/{binary_name}"))
            if found:
                # Filter for executable files
                executables = [f for f in found if f.is_file() and os.access(f, os.X_OK)]
                if executables:
                    return executables[0]
        
        # Search recursively in subject directory as last resort
        found = list(self.subject_dir.glob(f"**/{binary_name}"))
        if found:
            executables = [f for f in found if f.is_file() and os.access(f, os.X_OK)]
            if executables:
                return executables[0]
        
        return None
    
    def copy_instrumented_artifacts(self) -> bool:
        """Copy distance file and instrumented binary to a separate output directory"""
        try:
            # Create output directory name
            output_name = f"instrumented_{self.repo_name}"
            if self.config.get('cve_id'):
                cve_suffix = self.config['cve_id'].replace('CVE-', '').replace('-', '_')
                output_name += f"_{cve_suffix}"
            
            # Get the script directory (DrillAgent/src/instrumentation)
            script_dir = Path(__file__).resolve().parent
            # DrillAgent root is 2 levels up from src/instrumentation
            drillagent_root = script_dir.parent.parent
            drillagent_default_output_dir = drillagent_root / 'instrumented'

            output_dir = Path(self.config.get('output_dir', drillagent_default_output_dir)) / output_name
            output_dir.mkdir(parents=True, exist_ok=True)
            
            self.logger.info(f"Copying instrumented artifacts to: {output_dir}")
            
            # Copy distance file
            distance_file = self.temp_dir / 'distance.cfg.txt'
            if distance_file.exists():
                shutil.copy2(distance_file, output_dir / 'distance.cfg.txt')
                self.logger.info(f"  ✓ Copied distance.cfg.txt")
            else:
                self.logger.warning("  ✗ distance.cfg.txt not found")
            
            # Copy BBtargets.txt for reference
            bbtargets_file = self.temp_dir / 'BBtargets.txt'
            if bbtargets_file.exists():
                shutil.copy2(bbtargets_file, output_dir / 'BBtargets.txt')
                self.logger.info(f"  ✓ Copied BBtargets.txt")
            
            # Copy instrumented binary
            binary_path = self.find_instrumented_binary()
            if binary_path:
                binary_name = self.config.get('binary_name', self.repo_name)
                dest_binary = output_dir / binary_name
                shutil.copy2(binary_path, dest_binary)
                # Preserve executable permissions
                dest_binary.chmod(binary_path.stat().st_mode)
                
                size_mb = binary_path.stat().st_size / (1024 * 1024)
                self.logger.info(f"  ✓ Copied instrumented binary: {binary_name} ({size_mb:.2f} MB)")
            else:
                self.logger.warning("  ✗ Instrumented binary not found")
                return False
            
            self.logger.info(f"\n✓ All artifacts copied to: {output_dir}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error copying artifacts: {e}")
            return False
    
    def find_correct_bytecode_directory(self) -> Optional[Path]:
        """Find the bytecode directory that contains the target source files"""
        bbtargets = self.temp_dir / 'BBtargets.txt'
        if not bbtargets.exists():
            self.logger.warning("BBtargets.txt not found, cannot determine correct bytecode")
            return None
        
        # Extract unique source files from BBtargets.txt
        target_sources = set()
        with open(bbtargets, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    # Extract file path (e.g., "src/mat5.c" from "src/mat5.c:4915")
                    source_file = line.split(':')[0]
                    # Also try without directory prefix (e.g., "mat5.c")
                    basename = os.path.basename(source_file)
                    target_sources.add(source_file)
                    target_sources.add(basename)
        
        if not target_sources:
            self.logger.warning("No target sources found in BBtargets.txt")
            return None
        
        self.logger.info(f"Looking for bytecode containing: {list(target_sources)[:5]}")
        
        # Find all .bc files recursively
        bc_files = list(self.subject_dir.glob('**/*.0.0.*.bc'))
        if not bc_files:
            self.logger.warning("No *.0.0.*.bc files found")
            return None
        
        # For each .bc file directory, check if it has a BBnames.txt that contains our targets
        candidate_dirs = {}
        for bc_file in bc_files:
            bc_dir = bc_file.parent
            # The temp_dir should have BBnames.txt from this bc file
            # We need to check if the BBnames from this particular bc would contain our targets
            
            # Count how many target sources appear in BBnames.txt from temp_dir
            # (BBnames.txt is aggregated from all .bc files during build)
            # So we'll score each directory by checking the .bc filename relevance
            
            # Check if this .bc file is likely to contain the target code
            bc_name = bc_file.name
            score = 0
            
            # Prefer library files over test binaries
            if 'lib' in bc_name.lower():
                score += 10
            if 'a.out' in bc_name or 'conftest' in bc_name:
                score -= 20  # Deprioritize test binaries
            
            # Check file size (larger files more likely to contain library code)
            if bc_file.exists():
                size_mb = bc_file.stat().st_size / (1024 * 1024)
                score += min(size_mb, 10)  # Cap contribution at 10
            
            candidate_dirs[bc_dir] = score
            self.logger.debug(f"  {bc_file.name}: score={score}")
        
        if not candidate_dirs:
            return None
        
        # Return directory with highest score
        best_dir = max(candidate_dirs.items(), key=lambda x: x[1])[0]
        best_bc = list(best_dir.glob('*.0.0.*.bc'))[0]
        self.logger.info(f"Selected bytecode: {best_bc.name} (directory: {best_dir})")
        
        return best_dir
    
    def ensure_callgraphs_exist(self) -> bool:
        """Ensure callgraph.dot files exist for relevant .bc files (main binary + libraries with targets)"""
        dot_dir = self.temp_dir / 'dot-files'
        if not dot_dir.exists():
            self.logger.warning("dot-files directory doesn't exist, cannot generate callgraphs")
            return False
        
        # Find all .bc files
        all_bc_files = list(self.subject_dir.glob('**/*.0.0.*.bc'))
        if not all_bc_files:
            self.logger.warning("No .bc files found")
            return False
        
        self.logger.info(f"Found {len(all_bc_files)} bytecode files")
        
        # Filter to only relevant .bc files:
        # 1. Main binary (matches config binary_name or repo_name)
        # 2. Libraries (contains 'lib' in name)
        # 3. Exclude test binaries and utilities
        binary_name = self.config.get('binary_name', self.repo_name)
        
        relevant_bc_files = []
        for bc_file in all_bc_files:
            bc_name = bc_file.stem.replace('.0.0.preopt', '').replace('.0.0.postopt', '')
            
            # Skip obvious test files
            if any(skip in bc_name.lower() for skip in ['test', 'example', 'sample', 'demo', 'bench']):
                continue
            
            # Include main binary
            if bc_name == binary_name or bc_name.endswith(binary_name):
                relevant_bc_files.append(bc_file)
                self.logger.debug(f"  ✓ Including main binary: {bc_file.name}")
                continue
            
            # Include libraries
            if 'lib' in bc_name.lower():
                relevant_bc_files.append(bc_file)
                self.logger.debug(f"  ✓ Including library: {bc_file.name}")
                continue
            
            self.logger.debug(f"  ✗ Skipping: {bc_file.name}")
        
        if not relevant_bc_files:
            # Fallback: if we filtered everything, just use the first few
            self.logger.warning("No relevant .bc files after filtering, using first 5")
            relevant_bc_files = all_bc_files[:5]
        
        self.logger.info(f"Analyzing {len(relevant_bc_files)} relevant bytecode files (skipped {len(all_bc_files) - len(relevant_bc_files)} test/utility files)")
        
        # Check which ones have callgraphs
        missing_callgraphs = []
        for bc_file in relevant_bc_files:
            callgraph_file = dot_dir / f"{bc_file.name}.callgraph.dot"
            if not callgraph_file.exists():
                missing_callgraphs.append(bc_file)
        
        if not missing_callgraphs:
            self.logger.info("All relevant bytecode files have callgraphs")
            return True
        
        self.logger.info(f"Generating callgraphs for {len(missing_callgraphs)} bytecode files")
        
        # Generate missing callgraphs using opt
        for bc_file in missing_callgraphs:
            self.logger.info(f"Generating callgraph for {bc_file.name}")
            callgraph_file = dot_dir / f"{bc_file.name}.callgraph.dot"
            
            # Use opt to generate callgraph with explicit output prefix
            prefix = dot_dir / bc_file.name
            cmd = f"opt -dot-callgraph {bc_file} -callgraph-dot-filename-prefix {prefix} -o /dev/null"
            code, stdout, stderr = self.run_command(cmd, cwd=str(dot_dir))
            
            if code == 0 and callgraph_file.exists():
                self.logger.info(f"✓ Created {callgraph_file.name}")
            else:
                self.logger.warning(f"✗ Failed to create callgraph for {bc_file.name}")
        
        return True
    
    def phase_generate_distance(self) -> bool:
        """Generate distance file using binary_path and binary_name from config first, with LLM fallback"""
        self.logger.info("=== Phase 4: Distance Generation ===")
        self.state.phase = 'distance'
        
        # Clean up any previous distance generation state to force fresh run
        state_file = self.temp_dir / 'state-fast'
        dot_dir = self.temp_dir / 'dot-files'
        if state_file.exists():
            self.logger.info("Removing previous state-fast file to force fresh distance generation")
            state_file.unlink()
        if dot_dir.exists():
            self.logger.info("Removing previous dot-files directory to force fresh callgraph generation")
            shutil.rmtree(dot_dir)
            dot_dir.mkdir()
        
        # Clean up BB files
        bbnames = self.temp_dir / 'BBnames.txt'
        bbcalls = self.temp_dir / 'BBcalls.txt'
        bbtargets = self.temp_dir / 'BBtargets.txt'
        
        # Normalize BBtargets.txt: strip directory paths to match BBnames format
        # BBnames.txt typically has just "file.cpp:line", not "src/path/file.cpp:line"
        if bbtargets.exists():
            self.logger.info("Normalizing BBtargets.txt paths to match BBnames format")
            self.run_command(
                f"sed 's|^.*/||' {bbtargets} > {self.temp_dir}/BBtargets2.txt && "
                f"mv {self.temp_dir}/BBtargets2.txt {bbtargets}"
            )
        
        if bbnames.exists():
            self.run_command(
                f"cat {bbnames} | grep -v '^$' | rev | cut -d: -f2- | rev | "
                f"sort | uniq > {self.temp_dir}/BBnames2.txt && "
                f"mv {self.temp_dir}/BBnames2.txt {bbnames}"
            )
        
        if bbcalls.exists():
            self.run_command(
                f"cat {bbcalls} | grep -Ev '^[^,]*$|^([^,]*,){{2,}}[^,]*$' | "
                f"sort | uniq > {self.temp_dir}/BBcalls2.txt && "
                f"mv {self.temp_dir}/BBcalls2.txt {bbcalls}"
            )
        
        binary_name = self.config.get('binary_name', self.repo_name)
        binary_path = self.config.get('binary_path')
        
        # Helper function to run gen_distance_fast.py
        def try_generate_distance(bc_dir: Path, name: str, strategy_name: str) -> bool:
            """Try to generate distance with given parameters"""
            cmd = f"python3 {self.aflgo_dir / 'distance' / 'gen_distance_fast.py'} {bc_dir} {self.temp_dir} {name}"
            
            self.logger.info(f"Running ({strategy_name}): {cmd}")
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            output_lines = []
            for line in process.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                output_lines.append(line)
            
            code = process.wait()
            stdout = ''.join(output_lines)
            
            if code == 0:
                distance_file = self.temp_dir / 'distance.cfg.txt'
                if distance_file.exists() and distance_file.stat().st_size > 0:
                    self.logger.info(f"✓ Distance file generated successfully using {strategy_name}")
                    code, stdout, stderr = self.run_command(f"head -n5 {distance_file}")
                    self.logger.info(f"Distance values:\n{stdout}")
                    return True
                else:
                    self.logger.warning(f"{strategy_name}: Command succeeded but file was not created properly")
            else:
                self.logger.warning(f"{strategy_name}: Failed with exit code {code}")
            
            return False
        
        # Strategy 1: Use exact binary_path from config if provided
        if binary_path:
            self.logger.info(f"Strategy 1: Using exact binary_path from config: {binary_path}")
            
            # Convert to absolute path relative to subject_dir
            if not binary_path.startswith('/'):
                abs_binary_path = self.subject_dir / binary_path.lstrip('/')
            else:
                abs_binary_path = Path(binary_path)
            
            # The .bc file should be in the same directory as the binary
            bc_dir = abs_binary_path.parent
            
            # Check if .bc files exist in the binary directory
            bc_files = list(bc_dir.glob('*.0.0.*.bc'))
            
            if not bc_files:
                # Try common build subdirectories relative to binary location
                self.logger.warning(f"No .bc files in {bc_dir}, searching nearby directories...")
                search_dirs = [
                    bc_dir.parent,  # Parent directory
                    bc_dir.parent / 'CMakeFiles',  # CMake build artifacts
                    bc_dir / 'CMakeFiles',  # CMakeFiles in same dir
                ]
                
                for search_dir in search_dirs:
                    if search_dir.exists():
                        bc_files = list(search_dir.glob('**/*.0.0.*.bc'))
                        if bc_files:
                            bc_dir = bc_files[0].parent
                            self.logger.info(f"Found {len(bc_files)} .bc files in {bc_dir}")
                            break
            
            if bc_files:
                self.logger.info(f"Found {len(bc_files)} bytecode files in {bc_dir}")
                if try_generate_distance(bc_dir, binary_name, "binary_path from config"):
                    return True
            else:
                self.logger.warning(f"No .bc files found near binary_path: {abs_binary_path}")
        
        # Strategy 2: Fall back to LLM to find the correct binary
        self.logger.info("Strategy 2: Falling back to LLM to locate correct binary and .bc files")
        
        # Build context for LLM
        bc_files = list(self.subject_dir.glob('**/*.0.0.*.bc'))
        bc_context = ""
        if bc_files:
            bc_context = f"Found {len(bc_files)} .bc files:\n"
            for bc_file in bc_files[:10]:
                bc_context += f"  - {bc_file.relative_to(self.subject_dir)}\n"
            if len(bc_files) > 10:
                bc_context += f"  ... and {len(bc_files) - 10} more\n"
        else:
            bc_context = "No .bc files found in repository\n"
        
        question = f"""Distance generation failed with config binary_path and binary_name. Help find the correct binary and .bc directory.

**ENVIRONMENT:**
- Subject directory: {self.subject_dir}
- Temp directory: {self.temp_dir}
- Binary name from config: {binary_name}
- Binary path from config: {binary_path or 'not provided'}
- Distance script: {self.aflgo_dir / 'distance' / 'gen_distance_fast.py'}

**BYTECODE FILES:**
{bc_context}

**TASK:**
Find the correct .bc directory and binary name to run gen_distance_fast.py successfully.

**SCRIPT USAGE:**
  python3 gen_distance_fast.py <binaries-directory> <temp-directory> [binary-name]

**REQUIREMENTS:**
1. <binaries-directory> must contain *.0.0.*.bc files
2. The script does NOT search subdirectories - give exact directory path
3. [binary-name] can be omitted for auto-detect, or specify the actual binary name from .bc filename

Provide the exact command to run. Respond in JSON:
{{
  "reasoning": "explain which directory and binary to use",
  "commands": ["python3 /path/to/gen_distance_fast.py /path/to/bc/dir /path/to/temp binary_name"]
}}"""
        
        response = self.ask_llm(question)
        self.log_llm_reasoning("LLM reasoning:", response.get('reasoning', ''))
        
        commands = response.get('commands', [])
        if not commands:
            error_msg = "LLM failed to provide distance generation command"
            self.logger.error(error_msg)
            self.state.errors.append(error_msg)
            return False
        
        # Execute LLM's command
        cmd = commands[0] if len(commands) == 1 else " && ".join(commands)
        self.logger.info(f"Running LLM command: {cmd}")
        
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        output_lines = []
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            output_lines.append(line)
        
        code = process.wait()
        stdout = ''.join(output_lines)
        
        if code == 0:
            distance_file = self.temp_dir / 'distance.cfg.txt'
            if distance_file.exists() and distance_file.stat().st_size > 0:
                self.logger.info("✓ Distance file generated successfully using LLM guidance")
                code, stdout, stderr = self.run_command(f"head -n5 {distance_file}")
                self.logger.info(f"Distance values:\n{stdout}")
                return True
            else:
                error_msg = "LLM command succeeded but distance.cfg.txt was not created properly"
                self.logger.error(error_msg)
                self.state.errors.append(error_msg)
                return False
        else:
            error_msg = f"LLM distance generation command failed (exit code {code})"
            self.logger.error(error_msg)
            self.logger.error(f"Stdout:\n{stdout}")
            self.state.errors.append(error_msg)
            return False
    
    def run(self) -> bool:
        """Main execution loop with LLM-driven decision making"""
        try:
            self.logger.info("=" * 60)
            self.logger.info("AFLGo LLM-Driven Agent Starting")
            self.logger.info("=" * 60)
            
            # Phase 1: Setup repository
            if not self.phase_setup_repository():
                error_msg = "Phase 1 (Repository Setup) failed"
                self.logger.error(error_msg)
                self.state.errors.append(error_msg)
                return False
            
            # Phase 2: Extract targets
            if not self.phase_extract_targets():
                error_msg = "Phase 2 (Target Extraction) failed"
                self.logger.error(error_msg)
                self.state.errors.append(error_msg)
                return False
            
            # Phase 3: First build (CG/CFG)
            if not self.phase_build_with_llm(phase_num=1):
                error_msg = "Phase 3 (CG/CFG Generation Build) failed"
                self.logger.error(error_msg)
                self.state.errors.append(error_msg)
                return False
            
            # Phase 4: Generate distance
            if not self.phase_generate_distance():
                error_msg = "Phase 4 (Distance Generation) failed"
                self.logger.error(error_msg)
                self.state.errors.append(error_msg)
                return False
            
            # Phase 5: Second build (instrumentation)
            if not self.phase_build_with_llm(phase_num=2):
                error_msg = "Phase 5 (Final Instrumented Build) failed"
                self.logger.error(error_msg)
                self.state.errors.append(error_msg)
                return False
            
            self.logger.info("=" * 60)
            self.logger.info("AFLGo Instrumentation Complete!")
            self.logger.info("=" * 60)
            self.logger.info(f"Subject directory: {self.subject_dir}")
            self.logger.info(f"Temp directory: {self.temp_dir}")
            self.logger.info(f"Distance file: {self.temp_dir}/distance.cfg.txt")
            
            # Find and log binary location
            binary_path = self.find_instrumented_binary()
            if binary_path:
                self.logger.info(f"Instrumented binary: {binary_path}")
                # Log binary size and permissions for verification
                import stat
                size_mb = binary_path.stat().st_size / (1024 * 1024)
                perms = stat.filemode(binary_path.stat().st_mode)
                self.logger.info(f"  Size: {size_mb:.2f} MB, Permissions: {perms}")
            else:
                binary_name = self.config.get('binary_name', self.repo_name)
                self.logger.warning(f"Could not locate instrumented binary '{binary_name}'")
                self.logger.warning(f"  Search in {self.subject_dir} and subdirectories")
            
            self.logger.info(f"Log file: {self.log_file}")
            
            # Phase 6: Copy artifacts to output directory
            self.logger.info("\n=== Phase 6: Copying Artifacts ===")
            if self.copy_instrumented_artifacts():
                self.logger.info("✓ Artifacts copied successfully")
            else:
                self.logger.warning("⚠ Failed to copy some artifacts, but instrumentation was successful")
            
            self.state.phase = 'complete'
            return True
            
        except Exception as e:
            self.logger.error(f"Error during execution: {e}", exc_info=True)
            return False
        finally:
            # Log the final location of logs
            self.logger.info(f"\nAll logs have been saved to: {self.log_file}")


def load_config(config_file: Path) -> Dict:
    """Load configuration from YAML or JSON file"""
    with open(config_file) as f:
        if config_file.suffix in ['.yaml', '.yml']:
            return yaml.safe_load(f)
        elif config_file.suffix == '.json':
            return json.load(f)
        else:
            raise ValueError(f"Unsupported config file format: {config_file.suffix}")


def main():
    parser = argparse.ArgumentParser(
        description='LLM-Driven AFLGo Automation Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--config', type=Path, help='Path to YAML/JSON configuration file')
    parser.add_argument('--repo-url', help='Git repository URL')
    parser.add_argument('--commit-id', help='Commit ID to analyze')
    parser.add_argument('--cve-id', help='CVE identifier')
    parser.add_argument('--targets', nargs='+', help='Manual targets')
    parser.add_argument('--llm-model', default='gpt-5.1', help='OpenAI model to use (gpt-5.1, gpt-4, gpt-3.5-turbo, etc.)')
    parser.add_argument('--openai-api-key', help='OpenAI API key (or set OPENAI_API_KEY env var)')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    
    args = parser.parse_args()
    
    if args.config:
        config = load_config(args.config)
        # Override with command-line args if provided
        if args.llm_model:
            config['llm_model'] = args.llm_model
        if args.openai_api_key:
            config['openai_api_key'] = args.openai_api_key
    elif args.repo_url:
        config = {
            'repo_url': args.repo_url,
            'commit_id': args.commit_id,
            'cve_id': args.cve_id,
            'targets': args.targets,
            'log_level': args.log_level,
            'llm_model': args.llm_model,
            'openai_api_key': args.openai_api_key,
        }
    else:
        parser.print_help()
        return 1
    
    agent = AFLGoLLMAgent(config)
    success = agent.run()
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
