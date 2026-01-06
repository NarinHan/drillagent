"""
Coverage Instrumentation Agent

This module provides the CoverageInstrumentAgent class for building target binaries
with LLVM source-based code coverage instrumentation enabled.
"""

import os
import re
from pathlib import Path
from typing import Dict, Optional, Any, TYPE_CHECKING

from drillagent.instrumentation.base_instr_agent import BaseInstrAgent
from drillagent.utils.utils import *
from drillagent.prompts.InstrumentationAgent_prompt import (
    CIA_system_prompt,
    CIA_replace_docker_paths_prompt
)

if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent

class CoverageInstrumentAgent(BaseInstrAgent):
    # Coverage instrumentation agent based on llvm-cov

    def __init__(self, drill_agent: 'DrillAgent', target_repo_path: str, binary_relative_path: str):
        # Initialize base instrumentation agent first
        super().__init__(drill_agent)
        
        # Basic attributes
        self.target_repo = Path(target_repo_path)
        self.binary_path = binary_relative_path
        self.work_dir    = drill_agent.work_dir
        self.output_dir  = drill_agent.output_dir
        
        # Coverage flags
        self.coverage_flags = [
            '-fprofile-instr-generate',
            '-fcoverage-mapping'
        ]

        # Load instrumentation config first to get project_name and repo_url
        # self.instr_config = self._load_instrumentation_config()
        
        self.logger.info(f"CoverageInstrumentAgent initialized for {self.project_name} {self.drill_agent.cve_id}")
        self.logger.info(f"Target repository: {self.target_repo}")

    def run(self) -> Dict[str, Any]:
        """Execute coverage instrumentation workflow
        
        Returns:
            Dictionary with keys:
                - success: bool
                - instrumented_binary: absolute path to instrumented binary
                - build_log: list of build outputs
                - error: error message if failed
        """
        self.logger.info("=" * 60)
        self.logger.info("Starting Coverage Instrumentation")
        self.logger.info("=" * 60)
        
        try:
            # Get basic build commands
            basic_build_cmds = self.drill_agent.config.build_sh
            if not basic_build_cmds:
                raise ValueError("No build commands found in instrumentation config")
            
            # Step 1: Inject coverage flags into build commands
            # Current step: 'prepare_build'
            modified_commands = self._inject_coverage_flags(basic_build_cmds)
            self.logger.info("Coverage flags injected into build commands.")
            
            # Step 2: Prepare build environment
            # Current step: 'prepare_environment'
            build_env_vars = self._prepare_environment_vars()
            self.logger.info("Building environment prepared.")
            
            # Step 3: Execute build with retries using base class method
            # Current step: 'build'
            success, self.build_log = self.execute_build_with_retries( #BaseInstrAgent
                build_commands=modified_commands,
                cwd=self.target_repo,
                env=build_env_vars,
                context=f"Project name: {self.project_name}, Coverage instrumentation",
                system_prompt=CIA_system_prompt,
                fallback_fixes=self._coverage_fallback_fixes,
            )
            
            if success:
                # Step 4: Test coverage instrumentation
                # Current step: 'testing'
                self.logger.info("Testing Coverage Instrumentation...")
                
                # Verify the binary exists and has coverage symbols
                if check_llvmcov_binary_exists(
                    actual_repo_path=self.target_repo,
                    binary_relative_path=self.binary_path
                ):
                    self.logger.info(f"  Created qualified cov-instrumented binary!")
                    return {
                        'success': True,
                        'instrumented_binary': str(self.binary_path),
                        'build_log': self.build_log,
                        'coverage_flags': self.coverage_flags
                    }
                else:
                    # TODO: If we can not find the qualified binary according to the path from VulnAnalysis, we may need to search the repo more smartly.
                    error_msg = 'No __llvm_profile symbols found in binary'
                    self.logger.error(f"Coverage instrumentation test failed: {error_msg}")
                    return {
                        'success': False,
                        'error': error_msg,
                        'build_log': self.build_log
                    }

            else:
                error_msg = f"Build failed after {self.attempts} attempts"
                self.logger.error(error_msg)
                return {
                    'success': False,
                    'error': error_msg,
                    'build_log': self.build_log,
                    'errors': self.errors
                }
                
        except Exception as e:
            self.logger.error(f"Coverage instrumentation failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'build_log': self.build_log
            }

    def _inject_coverage_flags(self, build_commands: str) -> str:
        """Inject coverage flags into build commands from config
        
        Returns:
            Modified build commands with coverage flags
        """
        # Step 1: Remove Docker-specific commands that will fail locally
        build_commands = re.sub(
            r'\nmkdir\s+-p\s+/(?:src|out|testcase|work)\S*\s*',
            '\n',
            build_commands
        )
        
        # Step 2: Replace Docker paths with actual repo path using LLM
        build_commands = self._replace_docker_paths(build_commands)
        
        # Step 3: Remove sanitizer flags that conflict with coverage instrumentation
        build_commands = self._remove_sanitizer_flags(build_commands)
        
        # Define coverage flags
        cov_flags = ' '.join(self.coverage_flags)
        
        # Initialize flags to empty if they might be used in expansions
        # TODO: "#!/bin/bash -eu" will duplicate. 
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
        modified = re.sub(
            r'export (C(?:XX)?FLAGS)="(\$\1\s+[^"]+)"',
            r'export \1="$COV_FLAGS \2"',
            modified
        )
        
        # Replace common compiler/flag patterns to include coverage flags
        # Use regex to avoid replacing ./configure in test conditions like [ -f ./configure ]
        
        # TODO: These patterns still have a lot of issues.
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
        # Pattern 4: Rake/minirake builds
        elif re.search(r'(mini)?rake', modified.lower()):
            # For rake builds: insert exports before the first rake command
            # This handles all rake formats: ./rake, minirake, rake clean, rake all, etc.
            self.logger.debug("Detected Rake/minirake build, injecting coverage flags")

            # Find the first rake/minirake command and insert exports before it
            # Pattern matches: rake, minirake, ./rake, ./minirake (optionally followed by arguments like clean/all)
            rake_pattern = r'(\n\s*)((?:\./)?(?:mini)?rake(?:\s+\w+)?)'
            if re.search(rake_pattern, modified, re.IGNORECASE):
                modified = re.sub(
                    rake_pattern,
                    r'\1export CC=clang\n\1export CXX=clang++\n\1export CFLAGS="$COV_FLAGS $CFLAGS"\n\1export CXXFLAGS="$COV_FLAGS $CXXFLAGS"\n\1export LDFLAGS="$COV_FLAGS $LDFLAGS"\n\1\2',
                    modified,
                    count=1,  # Only insert before the first rake command
                    flags=re.IGNORECASE
                )
                self.logger.info("Injected coverage flags before rake command!!")
            else:
                self.logger.warning("Could not find rake command to inject coverage flags")

        # Pattern 5: Direct make without configure
        else:
            # Ensure CC/CXX and flags are exported before make
            if 'make' in modified and 'export CC' not in modified:
                # Insert exports before first make command
                modified = modified.replace(
                    'make',
                    'export CC=clang CXX=clang++ CFLAGS="$COV_FLAGS $CFLAGS" CXXFLAGS="$COV_FLAGS $CXXFLAGS" LDFLAGS="$COV_FLAGS $LDFLAGS"\nmake',
                    1  # Only replace first occurrence
                )
        
        # self.logger.debug(f"Modified build commands:\n{modified}")
        return modified

    def _replace_docker_paths(self, build_commands: str) -> str:
        # LLM: One-shot refinement.
        """Replace Docker absolute paths with actual repository path
        
        Uses LLM to intelligently replace paths like /src/openexr with the actual
        target_repo path. Falls back to regex if LLM is not available.
        
        Args:
            build_commands: Original build commands potentially with Docker paths
            
        Returns:
            Build commands with Docker paths replaced
        """
        # Check if there are any Docker-like patterns that need fixing
        docker_patterns = [
            r'\$\(dirname\s+["\']?\$0["\']?\)',  # $(dirname "$0")
            r'/(?:src|out|work|testcase)/',       # Absolute Docker paths
            r'\$(?:LIBHEIF_PATH|SRC|OUT|WORK)\b'  # Docker environment variables
        ]
        
        has_docker_patterns = any(re.search(pattern, build_commands) for pattern in docker_patterns)
        
        if not has_docker_patterns:
            self.logger.debug("No Docker patterns detected in build commands")
            return build_commands
        
        # Use LLM for intelligent path replacement
        self.logger.info("Using LLM to replace Docker paths with actual repository path")
        
        prompt = CIA_replace_docker_paths_prompt.format(
            target_repo=self.target_repo,
            project_name=self.project_name,
            build_commands=build_commands
        )
        
        try:
            # Use LLMInterface.generate() for simple text generation
            response = self.drill_agent.basic_llm.generate(
                prompt=prompt,
                system_prompt=CIA_system_prompt,
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
            
            self.logger.info(f"LLM replaced Docker paths:\n{response}")
            return response
            
        except Exception as e:
            self.logger.warning(f"LLM path replacement failed: {e}. Falling back to regex.")
        
        # Fallback: Use regex-based replacement. Replace common Docker path patterns.
        self.logger.info("Using regex to replace Docker paths")
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
        self.logger.debug(f"Regex replaced paths:\n{modified}")
        return modified

    def _remove_sanitizer_flags(self, build_commands: str) -> str:
        """Remove sanitizer flags that conflict with coverage instrumentation
        
        Sanitizer instrumentation (AddressSanitizer, UBSan, etc.) can conflict with
        coverage instrumentation, especially during configure's sanity checks where
        the test program needs to link against sanitizer runtime libraries.
        
        Args:
            build_commands: Build commands that may contain sanitizer flags
            
        Returns:
            Build commands with sanitizer flags removed
        """
        modified = build_commands
        removed_flags = []
        
        # Common sanitizer flags to remove
        sanitizer_patterns = [
            r'-fsanitize=\S+',           # Any -fsanitize flag
            r'-fno-sanitize-recover=\S+', # Sanitizer recovery flags
            r'-fsanitize-coverage=\S+',  # Sanitizer coverage flags (different from LLVM coverage)
        ]
        for pattern in sanitizer_patterns:
            matches = re.findall(pattern, modified)
            if matches:
                removed_flags.extend(matches)
                # Replace with a space to avoid concatenating words
                modified = re.sub(pattern, ' ', modified)
        
        # Clean up multiple consecutive spaces on the same line (but preserve newlines)
        # Only collapse spaces within lines, not across lines
        modified = re.sub(r'[ \t]+', ' ', modified)
        
        # Clean up spaces next to quotes that were left by removed flags
        # modified = re.sub(r'"\s+([^"\n])', r'" \1', modified)
        # modified = re.sub(r'([^"\n])\s+"', r'\1 "', modified)
        
        if removed_flags:
            self.logger.info(f"Removed conflicting sanitizer flags: {', '.join(set(removed_flags))}")
        else:
            self.logger.debug("No sanitizer flags found to remove")
        
        return modified

    def _prepare_environment_vars(self) -> Dict[str, str]:
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

    def _coverage_fallback_fixes(self, error: str, build_commands: str) -> Optional[str]:
        """Coverage-specific fallback fixes when LLM doesn't provide a valid fix
        
        Args:
            error: Build error message
            build_commands: Current build commands
            
        Returns:
            Fixed build commands or None
        """
        # Fix for unbound LIB_FUZZING_ENGINE variable
        if 'LIB_FUZZING_ENGINE' in error:
            self.logger.info("Applying fallback fix: Setting LIB_FUZZING_ENGINE=\"\"")
            modified = build_commands.replace(
                'export CFLAGS=',
                'export LIB_FUZZING_ENGINE=""\nexport CFLAGS='
            )
            if modified != build_commands:
                return modified
        
        # Fix for -Werror blocking builds
        if '-Werror' in error or 'warnings being treated as errors' in error.lower():
            self.logger.info("Applying fallback fix: Removing -Werror")
            modified = build_commands.replace('-Werror', '').replace('-WARNINGS_AS_ERRORS', '')
            if modified != build_commands:
                return modified
        
        return None

