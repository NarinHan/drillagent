"""
Sanitizer Instrumentation Agent

This module provides the SanitizerInstrumentAgent class for building target binaries
with ASAN/MSAN/UBSAN instrumentation enabled.
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

class SanitizerInstrumentAgent(BaseInstrAgent):
    """Sanitizer instrumentation agent based on ASAN, MSAN, UBSAN, etc."""

    def __init__(self, drill_agent: 'DrillAgent', saninstr_repo_path: str, binary_relative_path: str):
        # Initialize base instrumentation agent first
        super().__init__(drill_agent)

        # Basic attributes
        self.target_repo = Path(saninstr_repo_path)
        self.binary_path = binary_relative_path
        self.work_dir    = drill_agent.work_dir
        self.output_dir  = drill_agent.output_dir

        # Determine sanitizer type from report
        report = self.drill_agent.config.sanitizer_report
        if "AddressSanitizer" in report:
            self.sanitizer_type = "address"
        elif "UndefinedBehaviorSanitizer" in report:
            self.sanitizer_type = "undefined"
        elif "MemorySanitizer" in report:
            self.sanitizer_type = "memory"
        else:
            self.sanitizer_type = "address"  # Default to ASAN

        self.logger.info(f"SanitizerInstrumentAgent initialized for {self.project_name} {self.drill_agent.cve_id}")
        self.logger.info(f"Sanitizer type: {self.sanitizer_type}")
        self.logger.info(f"Target repository: {self.target_repo}")

    def run(self) -> Dict[str, Any]:
        """Execute sanitizer instrumentation workflow

        Returns:
            Dictionary with keys:
                - success: bool
                - instrumented_binary: absolute path to instrumented binary
                - build_log: list of build outputs
                - error: error message if failed
        """
        self.logger.info("=" * 60)
        self.logger.info(f"Starting Sanitizer Instrumentation ({self.sanitizer_type})")
        self.logger.info("=" * 60)

        try:
            # Get basic build commands
            basic_build_cmds = self.drill_agent.config.build_sh
            if not basic_build_cmds:
                raise ValueError("No build commands found in config")
            # Replace "set -eu" with "set -e" (don't be that strict)
            basic_build_cmds = re.sub(r'set\s+-eu', 'set -e', basic_build_cmds)

            # Step 1: Inject sanitizer flags into build commands
            if "-fsanitize=" not in basic_build_cmds:
                modified_commands = self._inject_sanitizer_flags(basic_build_cmds)
                self.logger.info(f"Sanitizer flags ({self.sanitizer_type}) injected into build commands.")
            else:
                modified_commands = basic_build_cmds
                self.logger.info(f"Sanitizer flags already present in build commands. Skipping injection.")

            # Step 2: Prepare build environment
            build_env_vars = os.environ.copy()
            self.logger.info("Build environment prepared.")

            # Special: switch ruby version for mruby builds
            # ASAN_OPTIONS=use_sigaltstack=0 bin/mruby -e 'puts "Hello from mruby with ASAN!"'
            if self.drill_agent.project_name.lower() == "mruby":
                if self.drill_agent.config.base_commit in [ #mruby.cve-2018-xxx
                    "fabc460880fbabd18369a7ef8715538c83ebffc9", "023070a6396233974785a8fd5735b9380a884f27",
                    "1dddc2f712f774b22a8f65432299cebb3b26361b", "cfd0c93d7d9dad13e6677beb7b7bd822a7572f8d",
                    "ff0a4f78674308b7643db1da9b9dc591f25c21d0", "55edae0226409de25e59922807cb09acb45731a2",
                ]:
                    res, msg = switch_ruby_version("2.7.8")
                    self.logger.info("Switch mruby to 2.7.8: " + msg)
                else:
                    res, msg = switch_ruby_version("3.0.6")
                    self.logger.info("Switch mruby to 3.0.6: " + msg)

            # Step 3: Execute build with retries using base class method
            success, self.build_log = self.execute_build_with_retries(
                build_commands=modified_commands,
                cwd=self.target_repo,
                env=build_env_vars,
                context=f"Project name: {self.project_name}, Sanitizer instrumentation ({self.sanitizer_type})",
                system_prompt=CIA_system_prompt,
                fallback_fixes=self._sanitizer_fallback_fixes,
            )

            if success:
                # Verify binary exists
                if check_saninstr_binary_exists(
                    actual_repo_path=self.target_repo,
                    binary_relative_path=self.binary_path
                ):
                    self.logger.info("  Created qualified sanitizer-instrumented binary!")
                    return {
                        'success': True,
                        'instrumented_binary': str(self.binary_path),
                        'build_log': self.build_log,
                        'sanitizer_type': self.sanitizer_type
                    }
                else:
                    error_msg = f"Binary not found at expected path: {self.binary_path}"
                    self.logger.error(error_msg)
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
            self.logger.error(f"Sanitizer instrumentation failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'build_log': self.build_log
            }

    def _inject_sanitizer_flags(self, build_commands: str) -> str:
        """Inject sanitizer flags into build commands

        Args:
            build_commands: Original build commands

        Returns:
            Modified build commands with sanitizer flags
        """
        # Remove Docker-specific commands
        build_commands = re.sub(
            r'\nmkdir\s+-p\s+/(?:src|out|testcase|work)\S*\s*',
            '\n',
            build_commands
        )

        # Replace Docker paths with actual repo path using LLM
        build_commands = self._replace_docker_paths(build_commands)

        # Define sanitizer flags
        san_flags = f"-g -O1 -fsanitize={self.sanitizer_type} -fno-omit-frame-pointer"

        # Initialize flags to empty if they might be used in expansions
        modified = f'''#!/bin/bash -eu
# Sanitizer instrumentation flags ({self.sanitizer_type})
SAN_FLAGS="{san_flags}"
CFLAGS="${{CFLAGS:-}}"
CXXFLAGS="${{CXXFLAGS:-}}"
LDFLAGS="${{LDFLAGS:-}}"

{build_commands}
'''

        # Replace patterns that modify CFLAGS/CXXFLAGS to append to SAN_FLAGS instead
        modified = re.sub(
            r'export (C(?:XX)?FLAGS)="(\$\1\s+[^"]+)"',
            r'export \1="$SAN_FLAGS \2"',
            modified
        )

        # Inject flags based on build system
        if 'configure' in modified:
            # Plain configure
            modified = re.sub(
                r'(\n\s*)(\./configure)(\s|$)',
                r'\nexport CFLAGS="${CFLAGS//-fno-use-cxa-atexit/}"\n\1CFLAGS="$SAN_FLAGS $CFLAGS" CXXFLAGS="$SAN_FLAGS $CXXFLAGS" LDFLAGS="$SAN_FLAGS $LDFLAGS" ./configure\3',
                modified
            )
        elif 'cmake' in modified.lower():
            # CMake builds
            modified = re.sub(
                r'(\n\s*)(cmake\s)',
                r'\1cmake -DCMAKE_C_FLAGS="$SAN_FLAGS $CFLAGS" -DCMAKE_CXX_FLAGS="$SAN_FLAGS $CXXFLAGS" -DCMAKE_EXE_LINKER_FLAGS="$SAN_FLAGS $LDFLAGS" ',
                modified
            )
        elif re.search(r'(mini)?rake', modified.lower()):
            # Rake/minirake builds
            rake_pattern = r'(\n\s*)((?:\./)?(?:mini)?rake(?:\s+\w+)?)'
            if re.search(rake_pattern, modified, re.IGNORECASE):
                modified = re.sub(
                    rake_pattern,
                    r'\1export CFLAGS="$SAN_FLAGS $CFLAGS"\n\1export CXXFLAGS="$SAN_FLAGS $CXXFLAGS"\n\1export LDFLAGS="$SAN_FLAGS $LDFLAGS"\n\1\2',
                    modified,
                    count=1,
                    flags=re.IGNORECASE
                )
        else:
            # Direct make without configure
            if 'make' in modified and 'export CC' not in modified:
                modified = modified.replace(
                    'make',
                    'export CFLAGS="$SAN_FLAGS $CFLAGS" CXXFLAGS="$SAN_FLAGS $CXXFLAGS" LDFLAGS="$SAN_FLAGS $LDFLAGS"\nmake',
                    1
                )

        return modified

    def _replace_docker_paths(self, build_commands: str) -> str:
        """Replace Docker absolute paths with actual repository path

        Uses LLM to intelligently replace paths. Falls back to regex if LLM is not available.
        """
        # Check if there are any Docker-like patterns that need fixing
        docker_patterns = [
            r'\$\(dirname\s+["\']?\$0["\']?\)',
            r'/(?:src|out|work|testcase)/',
            r'\$(?:LIBHEIF_PATH|SRC|OUT|WORK)\b'
        ]

        has_docker_patterns = any(re.search(pattern, build_commands) for pattern in docker_patterns)

        if not has_docker_patterns:
            return build_commands

        # Use LLM for intelligent path replacement
        self.logger.info("Using LLM to replace Docker paths with actual repository path")

        prompt = CIA_replace_docker_paths_prompt.format(
            target_repo=self.target_repo,
            project_name=self.project_name,
            build_commands=build_commands
        )

        try:
            response = self.drill_agent.basic_llm.generate(
                prompt=prompt,
                system_prompt=CIA_system_prompt,
                temperature=0.1,
                max_tokens=2048
            )

            # Clean up response - remove markdown code blocks
            response = response.strip()
            if response.startswith('```'):
                lines = response.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                if lines and lines[-1].startswith('```'):
                    lines = lines[:-1]
                response = '\n'.join(lines)

            return response

        except Exception as e:
            self.logger.warning(f"LLM path replacement failed: {e}. Falling back to regex.")

        # Fallback: Use regex-based replacement
        modified = build_commands
        modified = re.sub(rf'/src/{re.escape(self.project_name)}(?=/|\s|$)', str(self.target_repo), modified)
        modified = re.sub(r'/src(?=/|\s|$)', str(self.target_repo), modified)
        modified = re.sub(r'/out(?=/|\s|$)', str(self.target_repo), modified)
        modified = re.sub(r'/work(?=/|\s|$)', str(self.target_repo), modified)

    def _sanitizer_fallback_fixes(self, error: str, build_commands: str) -> Optional[str]:
        """Sanitizer-specific fallback fixes when LLM doesn't provide a valid fix

        Args:
            error: Build error message
            build_commands: Current build commands

        Returns:
            Fixed build commands or None
        """
        # Fix for -Werror blocking builds
        if '-Werror' in error or 'warnings being treated as errors' in error.lower():
            self.logger.info("Applying fallback fix: Removing -Werror")
            modified = build_commands.replace('-Werror', '').replace('-WARNINGS_AS_ERRORS', '')
            if modified != build_commands:
                return modified

        # Fix for unbound LIB_FUZZING_ENGINE variable
        if 'LIB_FUZZING_ENGINE' in error:
            self.logger.info("Applying fallback fix: Setting LIB_FUZZING_ENGINE=\"\"")
            modified = build_commands.replace(
                'export CFLAGS=',
                'export LIB_FUZZING_ENGINE=""\nexport CFLAGS='
            )
            if modified != build_commands:
                return modified

        return None