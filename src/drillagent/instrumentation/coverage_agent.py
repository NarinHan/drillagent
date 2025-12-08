#!/usr/bin/env python3
"""
Coverage Instrumentation Agent

This module provides the CoverageInstrumentAgent class for building target binaries
with LLVM source-based code coverage instrumentation enabled.

The agent:
- Loads existing build configuration from datasets/sec-bench/instrumentation_configs
- Injects LLVM coverage flags into the build commands
- Executes the build with coverage instrumentation
- Uses LLM assistance for error resolution if needed
"""

import os
import subprocess
import logging
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from drillagent.models.llm import LLM
from drillagent.instrumentation.base_agent import BaseAgent, AgentState


class CoverageInstrumentAgent(BaseAgent):
    """Coverage instrumentation agent using SEC-bench configs
    
    This agent loads build configurations from datasets/sec-bench/instrumentation_configs,
    injects LLVM coverage flags, and builds the instrumented binary.
    """
    
    SYSTEM_PROMPT = """You are an expert in LLVM compiler tooling and build systems.
Your task is to help with:
1. Replacing Docker paths with actual repository paths in build scripts
2. Diagnosing and fixing build errors when instrumenting C/C++ programs with LLVM coverage

**Coverage Instrumentation:**
LLVM coverage uses these flags:
- Compilation: -fprofile-instr-generate -fcoverage-mapping
- Linking: -fprofile-instr-generate

**Common issues:**
- -Werror blocking builds → suggest removing it
- Conflicting optimization flags → suggest compatible levels
- Missing dependencies → suggest installation commands

**Output format:**
When replacing paths or fixing build scripts, output ONLY the corrected script/commands.
No explanations, no markdown code blocks, just the raw script content."""

    def __init__(
        self,
        config: Dict[str, Any],
        llm: Optional[LLM] = None,
        logger: Optional[logging.Logger] = None
    ):
        """Initialize coverage instrumentation agent
        
        Args:
            config: Configuration dictionary with keys:
                - cve_id: CVE ID (e.g., "CVE-2022-43284")
                - project_name: Project name (e.g., "njs")
                - target_repo_path: Path to target repository
                - config_file: Optional path to instrumentation config file
                - output_dir: Directory for instrumented binary
            llm: LLM instance for intelligent build assistance
            logger: Logger instance
        """
        # Initialize parent BaseAgent
        # BaseAgent will handle log file creation using config
        super().__init__(
            llm=llm,
            system_prompt=self.SYSTEM_PROMPT,
            initial_phase='initialized',
            max_attempts=3,
            logger=logger,
            config=config
        )
        
        self.config = config
        self.cve_id = config.get('cve_id', '')
        self.project_name = config.get('project_name', '')
        self.target_repo = Path(config.get('target_repo_path', ''))
        self.output_dir = Path(config.get('output_dir', './output'))
        
        # Coverage flags
        self.coverage_flags = [
            '-fprofile-instr-generate',
            '-fcoverage-mapping'
        ]
        
        # Load instrumentation config
        self.instr_config = self._load_instrumentation_config(config.get('config_file'))
        
        # State tracking
        self.state = AgentState(phase='initialized', max_attempts=3)
        self.build_log = []
        self.instrumented_binary_path = None
        
        self.logger.info(f"CoverageInstrumentAgent initialized for {self.project_name} {self.cve_id}")

    def _load_instrumentation_config(self, config_file: Optional[str] = None) -> Dict[str, Any]:
        """Load instrumentation config from SEC-bench datasets
        
        Args:
            config_file: Optional path to config file. If not provided, constructs from CVE ID and project name
            
        Returns:
            Loaded configuration dictionary
        """
        if config_file and Path(config_file).exists():
            config_path = Path(config_file)
        else:
            # Construct path from project and CVE ID
            # Find project root
            current_file = Path(__file__).resolve()
            project_root = current_file.parent.parent.parent.parent
            
            # Construct config filename: project.cve-id.yaml (lowercase)
            config_filename = f"{self.project_name}.{self.cve_id.lower()}.yaml"
            config_path = project_root / 'datasets' / 'sec-bench' / 'instrumentation_configs' / config_filename
        
        if not config_path.exists():
            raise FileNotFoundError(f"Instrumentation config not found: {config_path}")
        
        self.logger.info(f"Loading instrumentation config from: {config_path.name}")
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        return config

    def run(self) -> Dict[str, Any]:
        """Execute coverage instrumentation workflow
        
        Returns:
            Dictionary with keys:
                - success: bool
                - instrumented_binary: path to instrumented binary
                - build_log: list of build outputs
                - error: error message if failed
        """
        self.logger.info("=" * 60)
        self.logger.info("Starting Coverage Instrumentation")
        self.logger.info("=" * 60)
        
        try:
            # Phase 1: Inject coverage flags into build commands
            self.state.phase = 'prepare_build'
            modified_commands = self._inject_coverage_flags()
            self.logger.info("Coverage flags injected into build commands")
            
            # Phase 2: Prepare build environment
            self.state.phase = 'prepare_environment'
            build_env = self._prepare_environment()
            self.logger.info("Build environment prepared")
            
            # Phase 3: Execute build with retries
            self.state.phase = 'build'
            success = self._execute_build_with_retries(build_env, modified_commands)
            
            if success:
                self.state.phase = 'complete'
                self.logger.info(f"✓ Coverage instrumentation successful")
                self.logger.info(f"  Instrumented binary: {self.instrumented_binary_path}")
                
                return {
                    'success': True,
                    'instrumented_binary': str(self.instrumented_binary_path),
                    'build_log': self.build_log,
                    'coverage_flags': self.coverage_flags
                }
            else:
                self.state.phase = 'failed'
                error_msg = f"Build failed after {self.state.attempts} attempts"
                self.logger.error(error_msg)
                
                return {
                    'success': False,
                    'error': error_msg,
                    'build_log': self.build_log,
                    'errors': self.state.errors
                }
                
        except Exception as e:
            self.logger.error(f"Coverage instrumentation failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'build_log': self.build_log
            }

    def _inject_coverage_flags(self) -> str:
        """Inject coverage flags into build commands from config
        
        Returns:
            Modified build commands with coverage flags
        """
        # Get original build commands
        build_commands = self.instr_config.get('build_config', {}).get('build_commands', '')
        
        if not build_commands:
            raise ValueError("No build commands found in instrumentation config")
        
        # Step 1: Remove Docker-specific commands that will fail locally
        import re
        build_commands = re.sub(
            r'\nmkdir\s+-p\s+/(?:src|out|testcase|work)\S*\s*',
            '\n',
            build_commands
        )
        
        # Step 2: Replace Docker paths with actual repo path using LLM
        build_commands = self._replace_docker_paths(build_commands)
        
        # Define coverage flags
        cov_flags = ' '.join(self.coverage_flags)
        
        # Initialize flags to empty if they might be used in expansions
        modified = f'''#!/bin/bash -eu
# Coverage instrumentation flags
COV_FLAGS="{cov_flags}"
CFLAGS="${{CFLAGS:-}}"
CXXFLAGS="${{CXXFLAGS:-}}"
LDFLAGS="${{LDFLAGS:-}}"

{build_commands}
'''
        
        # Replace patterns that modify CFLAGS/CXXFLAGS to append to COV_FLAGS instead
        # Handle: export CFLAGS="$CFLAGS -flag" -> export CFLAGS="$COV_FLAGS $CFLAGS -flag"
        import re
        modified = re.sub(
            r'export (C(?:XX)?FLAGS)="(\$\1\s+[^"]+)"',
            r'export \1="$COV_FLAGS \2"',
            modified
        )
        
        # Replace common compiler/flag patterns to include coverage flags
        # Use regex to avoid replacing ./configure in test conditions like [ -f ./configure ]
        
        # Pattern 1: Configure scripts with --cc-opt and --ld-opt (like njs)
        if '--cc-opt' in modified:
            # Only replace ./configure when it's executed (not in tests)
            modified = re.sub(
                r'(\n\s*)(\./configure\s)',
                r'\1CC=clang CFLAGS="$COV_FLAGS $CFLAGS" LDFLAGS="$COV_FLAGS $LDFLAGS" ./configure --cc=clang --cc-opt="$COV_FLAGS" --ld-opt="$COV_FLAGS" ',
                modified
            )
        # Pattern 2: Plain configure without special flags
        elif './configure' in modified and '--cc-opt' not in modified:
            # Only replace ./configure when it's executed (not in tests)
            modified = re.sub(
                r'(\n\s*)(\./configure)(\s|$)',
                r'\1CC=clang CXX=clang++ CFLAGS="$COV_FLAGS $CFLAGS" CXXFLAGS="$COV_FLAGS $CXXFLAGS" LDFLAGS="$COV_FLAGS $LDFLAGS" ./configure\3',
                modified
            )
        # Pattern 3: CMake builds
        elif 'cmake' in modified.lower():
            # Only replace cmake when it's a command (not in tests)
            modified = re.sub(
                r'(\n\s*)(cmake\s)',
                r'\1CC=clang CXX=clang++ cmake -DCMAKE_C_FLAGS="$COV_FLAGS $CFLAGS" -DCMAKE_CXX_FLAGS="$COV_FLAGS $CXXFLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COV_FLAGS $LDFLAGS" ',
                modified
            )
        # Pattern 4: Direct make without configure
        else:
            # Ensure CC/CXX and flags are exported before make
            if 'make' in modified and 'export CC' not in modified:
                # Insert exports before first make command
                modified = modified.replace(
                    'make',
                    'export CC=clang CXX=clang++ CFLAGS="$COV_FLAGS $CFLAGS" CXXFLAGS="$COV_FLAGS $CXXFLAGS" LDFLAGS="$COV_FLAGS $LDFLAGS"\nmake',
                    1  # Only replace first occurrence
                )
        
        self.logger.debug(f"Modified build commands:\n{modified[:500]}...")
        return modified

    def _replace_docker_paths(self, build_commands: str) -> str:
        """Replace Docker absolute paths with actual repository path
        
        Uses LLM to intelligently replace paths like /src/openexr with the actual
        target_repo path. Falls back to regex if LLM is not available.
        
        Args:
            build_commands: Original build commands potentially with Docker paths
            
        Returns:
            Build commands with Docker paths replaced
        """
        import re
        
        # Check if there are any Docker-like absolute paths to replace
        docker_path_pattern = r'/(?:src|out|work|testcase)/\S+'
        if not re.search(docker_path_pattern, build_commands):
            self.logger.debug("No Docker paths detected in build commands")
            return build_commands
        
        if self.llm:
            # Use LLM for intelligent path replacement
            self.logger.info("Using LLM to replace Docker paths with actual repository path")
            
            prompt = f"""Replace all Docker absolute paths in these build commands with the actual repository path.

**Docker paths to replace:**
- /src/{self.project_name} → {self.target_repo}
- /src/... → {self.target_repo}
- /out/... → {self.target_repo}
- /work/... → {self.target_repo}

**Original build commands:**
{build_commands}

**Instructions:**
1. Replace absolute Docker paths (like /src/openexr) with: {self.target_repo}
2. Keep all other parts of the commands unchanged
3. Preserve relative paths and current directory references (. or ./)
4. Output ONLY the corrected build commands, nothing else
5. Do NOT wrap in markdown code blocks
6. Do NOT add explanations
"""
            
            try:
                response = self.llm.generate(
                    prompt=prompt,
                    system_prompt=self.SYSTEM_PROMPT,
                    temperature=0.1,
                    max_tokens=2048
                )
                
                # Clean up response - remove any markdown code blocks
                response = response.strip()
                if response.startswith('```'):
                    lines = response.split('\n')
                    # Remove first and last line if they're code block markers
                    if lines[0].startswith('```'):
                        lines = lines[1:]
                    if lines and lines[-1].startswith('```'):
                        lines = lines[:-1]
                    response = '\n'.join(lines)
                
                self.logger.info(f"LLM replaced Docker paths (first 300 chars): {response[:300]}")
                return response
                
            except Exception as e:
                self.logger.warning(f"LLM path replacement failed: {e}. Falling back to regex.")
        
        # Fallback: Use regex-based replacement
        self.logger.info("Using regex to replace Docker paths")
        
        # Replace common Docker path patterns
        modified = build_commands
        
        # Pattern 1: /src/project_name → target_repo
        modified = re.sub(
            rf'/src/{re.escape(self.project_name)}(?=/|\s|$)',
            str(self.target_repo),
            modified
        )
        
        # Pattern 2: /src/... → target_repo (if project name not in path)
        modified = re.sub(
            r'/src(?=/|\s|$)',
            str(self.target_repo),
            modified
        )
        
        # Pattern 3: /out/... → target_repo
        modified = re.sub(
            r'/out(?=/|\s|$)',
            str(self.target_repo),
            modified
        )
        
        # Pattern 4: /work/... → target_repo
        modified = re.sub(
            r'/work(?=/|\s|$)',
            str(self.target_repo),
            modified
        )
        
        self.logger.debug(f"Regex replaced paths (first 300 chars): {modified[:300]}")
        return modified

    def _prepare_environment(self) -> Dict[str, str]:
        """Prepare environment variables for build
        
        Returns:
            Dictionary of environment variables
        """
        env = os.environ.copy()
        
        # Set compilers
        env['CC'] = 'clang'
        env['CXX'] = 'clang++'
        
        # Coverage flags will be set in the build script via COV_FLAGS
        # But also set them in environment as backup
        cov_flags_str = ' '.join(self.coverage_flags)
        env['COVERAGE_FLAGS'] = cov_flags_str
        
        return env

    def _execute_build_with_retries(self, env: Dict[str, str], build_commands: str) -> bool:
        """Execute build with intelligent retries using LLM
        
        Args:
            env: Environment variables for build
            build_commands: Modified build commands with coverage flags
            
        Returns:
            True if build succeeded, False otherwise
        """
        max_attempts = self.state.max_attempts
        
        for attempt in range(1, max_attempts + 1):
            self.state.attempts = attempt
            self.logger.info(f"Build attempt {attempt}/{max_attempts}")
            
            # Execute build
            success, output, error = self._run_build(env, build_commands)
            
            # Log the output
            self.build_log.append({
                'attempt': attempt,
                'success': success,
                'output': output,
                'error': error
            })
            
            if success:
                return True
            
            # Record error
            self.state.record_error(error, context=f"Build attempt {attempt}")
            
            # If we have more attempts and LLM is available, ask for help
            if attempt < max_attempts and self.llm:
                self.logger.info("Analyzing build error with LLM...")
                fixed_commands = self._diagnose_and_fix_build_error(
                    error, output, build_commands, attempt
                )
                if fixed_commands:
                    build_commands = fixed_commands
                    self.logger.info("Retrying with LLM-suggested fixes...")
                else:
                    self.logger.warning("LLM could not suggest a fix")
            else:
                self.logger.error(f"Build failed (attempt {attempt})")
        
        return False

    def _run_build(self, env: Dict[str, str], build_commands: str) -> tuple[bool, str, str]:
        """Execute the actual build command
        
        Args:
            env: Environment variables
            build_commands: Build script to execute
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            self.logger.info(f"Executing build in {self.target_repo}")
            self.logger.info(f"Build commands (first 500 chars): {build_commands[:500]}")
            
            # Execute build script
            result = subprocess.run(
                build_commands,
                shell=True,
                executable='/bin/bash',
                cwd=self.target_repo,
                env=env,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            success = result.returncode == 0
            
            # Log stdout (truncate if too long)
            if result.stdout:
                stdout_preview = result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout
                self.logger.info(f"Build stdout (last 2000 chars):\n{stdout_preview}")
            
            # Log stderr
            if result.stderr:
                stderr_preview = result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr
                self.logger.error(f"Build stderr (last 2000 chars):\n{stderr_preview}")
            
            if success:
                self.logger.info("✓ Build completed successfully")
                # Locate the instrumented binary
                self._locate_instrumented_binary()
            else:
                self.logger.error(f"✗ Build failed with exit code {result.returncode}")
            
            return success, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            error_msg = "Build command timed out after 10 minutes"
            self.logger.error(error_msg)
            return False, "", error_msg
        except Exception as e:
            error_msg = f"Build execution failed: {str(e)}"
            self.logger.error(error_msg)
            return False, "", error_msg

    def _locate_instrumented_binary(self) -> Optional[Path]:
        """Locate the instrumented binary after build using config
        
        Returns:
            Path to binary if found, None otherwise
        """
        binary_name = self.instr_config.get('binary_name', '')
        binary_path = self.instr_config.get('binary_path', '')
        
        if binary_path:
            # binary_path may be Docker path like "/src/njs/build/njs"
            # Try multiple path variations:
            # 1. Strip Docker prefix and use relative to repo root
            # 2. Use just the relative part after project name
            
            # Remove leading slash and common Docker prefixes
            rel_path = binary_path.lstrip('/')
            
            # Try stripping /src/ prefix
            if rel_path.startswith('src/'):
                rel_path = rel_path[4:]
            
            # If path contains project name, try using part after it
            parts = Path(rel_path).parts
            if self.project_name in parts:
                idx = parts.index(self.project_name)
                rel_path = str(Path(*parts[idx+1:])) if idx + 1 < len(parts) else rel_path
            
            full_path = self.target_repo / rel_path
            
            if full_path.exists() and os.access(full_path, os.X_OK):
                self.instrumented_binary_path = full_path
                self.logger.debug(f"Found binary at: {full_path}")
                return full_path
        
        # Fallback: search by binary name
        if binary_name:
            candidates = list(self.target_repo.rglob(binary_name))
            executables = [c for c in candidates if os.access(c, os.X_OK)]
            
            if executables:
                # Prefer binaries in build directories
                for exe in executables:
                    if 'build' in str(exe).lower():
                        self.instrumented_binary_path = exe
                        self.logger.debug(f"Found binary at: {exe}")
                        return exe
                
                self.instrumented_binary_path = executables[0]
                self.logger.debug(f"Found binary at: {executables[0]}")
                return executables[0]
        
        self.logger.debug(f"Could not locate binary: {binary_name}")
        return None

    def _diagnose_and_fix_build_error(
        self,
        error: str,
        output: str,
        build_commands: str,
        attempt: int
    ) -> Optional[str]:
        """Use LLM to diagnose build error and suggest fixes
        
        Args:
            error: Error output from build
            output: Standard output from build
            build_commands: Current build commands
            attempt: Current attempt number
            
        Returns:
            Updated build commands if fix found, None otherwise
        """
        if not self.llm:
            return None
        
        # Prepare diagnostic prompt - ask for complete fixed script
        prompt = f"""A build with LLVM coverage instrumentation failed. Fix the build script.

**Project:** {self.project_name}
**CVE:** {self.cve_id}

**Current Build Commands:**
{build_commands}

**Build Error:**
{error[-2000:]}

**Common issues and fixes:**
- Unbound variable (like LIB_FUZZING_ENGINE): Export it with empty value or remove references
- Missing headers: Add -include <header> to flags or remove problematic code
- -Werror blocking builds: Remove it from commands

**Instructions:**
1. Analyze the error and identify the fix needed
2. Output the COMPLETE CORRECTED build script
3. Do NOT use markdown code blocks (```bash)
4. Do NOT add explanations - just the fixed script
5. Keep all the original structure (#!/bin/bash, COV_FLAGS, etc.)

Output the fixed build script now:"""

        try:
            response = self.llm.generate(
                prompt=prompt,
                system_prompt=self.SYSTEM_PROMPT,
                temperature=0.2,
                max_tokens=2048
            )
            
            # Clean up response - remove markdown code blocks if present
            response = response.strip()
            if '```' in response:
                # Extract content between code blocks
                lines = response.split('\n')
                in_code_block = False
                cleaned_lines = []
                
                for line in lines:
                    if line.strip().startswith('```'):
                        in_code_block = not in_code_block
                        continue
                    if in_code_block or (not line.strip().startswith('```') and not in_code_block):
                        cleaned_lines.append(line)
                
                response = '\n'.join(cleaned_lines).strip()
            
            # Check if response looks like a valid script
            if response and (response.startswith('#!/bin/bash') or 'COV_FLAGS' in response):
                self.logger.info(f"LLM provided fixed build script (first 300 chars):\n{response[:300]}")
                return response
            else:
                self.logger.warning(f"LLM response doesn't look like a valid build script: {response[:200]}")
                
                # Try specific pattern-based fixes as fallback
                if 'LIB_FUZZING_ENGINE' in error:
                    self.logger.info("Applying fallback fix: Setting LIB_FUZZING_ENGINE=\"\"")
                    # Add export before the line that fails
                    modified = build_commands.replace(
                        'export CFLAGS=',
                        'export LIB_FUZZING_ENGINE=""\nexport CFLAGS='
                    )
                    if modified != build_commands:
                        return modified
                
                if '-Werror' in error or 'warnings being treated as errors' in error.lower():
                    self.logger.info("Applying fallback fix: Removing -Werror")
                    modified = build_commands.replace('-Werror', '').replace('-WARNINGS_AS_ERRORS', '')
                    if modified != build_commands:
                        return modified
                
                return None
            
        except Exception as e:
            self.logger.error(f"LLM diagnosis failed: {e}")
            return None

    def _format_error_history(self) -> str:
        """Format error history for LLM context"""
        if not self.state.errors:
            return "None"
        
        repeated = self.state.get_repeated_errors(threshold=1)
        if repeated:
            return "\n".join([f"- {sig[:100]}" for sig, count in repeated[:3]])
        return "None"


def main():
    """CLI entry point for testing coverage instrumentation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Coverage Instrumentation Agent')
    parser.add_argument('--cve-id', required=True, help='CVE ID (e.g., CVE-2022-43284)')
    parser.add_argument('--project', required=True, help='Project name (e.g., njs)')
    parser.add_argument('--repo-path', required=True, help='Path to target repository')
    parser.add_argument('--output-dir', default='./output', help='Output directory')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Create config
    config = {
        'cve_id': args.cve_id,
        'project_name': args.project,
        'target_repo_path': args.repo_path,
        'output_dir': args.output_dir
    }

    # Load YAML config to get commit_id
    current_file = Path(__file__).resolve()
    project_root = current_file.parent.parent.parent.parent
    config_filename = f"{args.project}.{args.cve_id.lower()}.yaml"
    config_path = project_root / 'datasets' / 'sec-bench' / 'instrumentation_configs' / config_filename
    
    if config_path.exists():
        with open(config_path, 'r') as f:
            yaml_config = yaml.safe_load(f)
            commit_id = yaml_config.get('commit_id')
            
            if commit_id:
                print(f"Checking out commit: {commit_id}")
                repo_path = Path(args.repo_path)
                if repo_path.exists():
                    try:
                        # Git checkout to the specified commit
                        subprocess.run(
                            ['git', 'checkout', commit_id],
                            cwd=repo_path,
                            check=True,
                            capture_output=True,
                            text=True
                        )
                        print(f"✓ Successfully checked out commit {commit_id}")
                        
                        # Initialize and update git submodules
                        subprocess.run(
                            ['git', 'submodule', 'update', '--init', '--recursive'],
                            cwd=repo_path,
                            check=True,
                            capture_output=True,
                            text=True
                        )
                        print(f"✓ Successfully initialized git submodules")
                    except subprocess.CalledProcessError as e:
                        print(f"Warning: Failed to checkout commit {commit_id}: {e.stderr}")
                else:
                    print(f"Warning: Repository path does not exist: {repo_path}")
    
    # Initialize LLM for intelligent build assistance if API key available
    llm = None
    try:
        from drillagent.models.llm import LLM
        from dotenv import load_dotenv
        
        # Load .env file from project root
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent.parent
        env_file = project_root / '.env'
        
        if env_file.exists():
            load_dotenv(env_file)
            print(f"Loaded environment from {env_file}")
        
        # Try to initialize LLM - will fail gracefully if no API key
        llm = LLM(provider="openai", model_name="gpt-4-turbo")
        print("✓ LLM initialized successfully")
    except (ValueError, Exception) as e:
        print(f"Note: LLM not available ({e}). Will use regex-based path replacement.")
    
    # Run agent - let BaseAgent create logger with file handler
    # Don't pass logger so BaseAgent can set up file logging automatically
    agent = CoverageInstrumentAgent(config=config, llm=llm)
    result = agent.run()
    
    # Print result
    print("\n" + "=" * 60)
    print("Coverage Instrumentation Result")
    print("=" * 60)
    print(f"Success: {result['success']}")
    if result['success']:
        print(f"Instrumented Binary: {result['instrumented_binary']}")
    else:
        print(f"Error: {result.get('error', 'Unknown error')}")
    print("=" * 60)
    
    return 0 if result['success'] else 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
