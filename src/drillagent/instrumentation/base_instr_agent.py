import os
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Tuple, Callable, Optional, TYPE_CHECKING

from drillagent.prompts.InstrumentationAgent_prompt import (
    BA_diagnose_build_error_prompt
)

if TYPE_CHECKING:
    from drillagent.drill_agent import DrillAgent

class BaseInstrAgent:
    def __init__(self, drill_agent: 'DrillAgent'):
        self.drill_agent = drill_agent
        # Basic properties
        self.project_name = drill_agent.config.project_name
        self.logger = drill_agent.logger

        # Instrumentation compiling parameters
        self.attempts = 0
        self.max_attempts = 3
        self.build_log = []
        self.errors: List[str] = []
        self.error_patterns: Dict[str, int] = {}  # Track recurring error patterns

    # ==================== Error Management Methods ====================
    def record_error(self, error: str):
        # Record an error and detect patterns
        self.errors.append(error)
        
        # Extract error signatures for pattern detection
        signatures = self._extract_error_signatures(error)
        for sig in signatures:
            self.error_patterns[sig] = self.error_patterns.get(sig, 0) + 1
    
    def _extract_error_signatures(self, error: str) -> List[str]:
        """Extract characteristic error patterns - keep it simple and generic
        
        This method identifies recurring error patterns without hardcoding
        specific error types, allowing the LLM to reason about them.
        
        Args:
            error: Error message to analyze
            
        Returns:
            List of error signatures extracted from the message
        """
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
                # Capture LLVM/clang option errors (CRITICAL for AFLGo instrumentation issues)
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

    def get_repeated_errors(self, threshold: int = 2) -> List[Tuple[str, int]]:
        """Get errors that have occurred multiple times

        Args:
            threshold: Minimum number of occurrences to consider an error repeated

        Returns:
            List of (error_signature, count) tuples for repeated errors
        """
        return [(sig, count) for sig, count in self.error_patterns.items()
                if count >= threshold]

    # ==================== Text Truncation Methods ====================
    def _truncate_middle(
        self,
        text: str,
        max_lines: int = 100,
        max_chars: int = 6000,
        head_ratio: float = 0.4
    ) -> str:
        """Truncate text by keeping head and tail, omitting middle

        For build errors, the head often contains the command and early warnings,
        while the tail contains the actual error messages and summary.

        Args:
            text: Text to truncate
            max_lines: Maximum number of lines to keep
            max_chars: Maximum number of characters (fallback limit)
            head_ratio: Ratio of lines to keep from head (default 0.4, so tail gets 0.6)

        Returns:
            Truncated text with middle omitted if necessary
        """
        if not text:
            return text

        lines = text.splitlines()

        # Check if truncation is needed
        if len(lines) <= max_lines and len(text) <= max_chars:
            return text

        # Calculate head/tail line counts
        head_lines_count = int(max_lines * head_ratio)
        tail_lines_count = max_lines - head_lines_count

        # Truncate by lines first
        if len(lines) > max_lines:
            head_lines = lines[:head_lines_count]
            tail_lines = lines[-tail_lines_count:]
            omitted_count = len(lines) - max_lines
            result = "\n".join(head_lines) + f"\n\n... [{omitted_count} lines omitted] ...\n\n" + "\n".join(tail_lines)
        else:
            result = text

        # Apply character limit as fallback (truncate middle of the result)
        if len(result) > max_chars:
            head_chars = int(max_chars * head_ratio)
            tail_chars = max_chars - head_chars - 50  # Reserve space for omission marker
            result = result[:head_chars] + "\n... [truncated] ...\n" + result[-tail_chars:]

        return result

    # ==================== Build Execution Methods ====================
    # These methods provide common build functionality for instrumentation agents
    def execute_build_with_retries(
        self,
        build_commands: str,
        cwd: Path,
        env: Optional[Dict[str, str]] = None,
        context: str = "",
        system_prompt: Optional[str] = None,
        fallback_fixes: Optional[Callable[[str, str], Optional[str]]] = None,
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """Execute build with intelligent retries using LLM for error recovery
        
        Args:
            build_commands: Build script to execute
            cwd: Working directory for the build
            env: Environment variables
            context: Additional context for LLM (e.g., CVE ID)
            system_prompt: Custom system prompt for LLM diagnosis
            fallback_fixes: Agent-specific fallback fix callback
            
        Returns:
            Tuple of (success, build_log)
            build_log is a list of dicts with keys: attempt, success, output, error
        """
        attempts = self.max_attempts
        build_log = []
        
        for attempt in range(1, attempts + 1):
            self.attempts = attempt
            self.logger.info(f"Build attempt {attempt}/{attempts}")
            
            # Execute building commands with coverage parameters
            success, output, error = self._run_build_commands(
                build_commands, cwd, env
            )
            
            # Log the output
            build_log.append({
                'attempt': attempt,
                'success': success,
                'output': output,
                'error': error
            })
            
            if success:
                return True, build_log
            
            # Record error
            self.record_error(error)
            
            # If we have more attempts and LLM is available, ask for help
            if attempt < attempts:
                self.logger.info("Analyzing build error with LLM...")
                fixed_commands = self._diagnose_and_fix_build_error(
                    error=error,
                    output=output,
                    build_commands=build_commands,
                    context=context,
                    system_prompt=system_prompt,
                    fallback_fixes=fallback_fixes
                )
                if fixed_commands:
                    build_commands = fixed_commands
                    self.logger.info("Retrying with LLM-suggested fixes...")
                else:
                    self.logger.warning("LLM could not suggest a fix")
            else:
                self.logger.error(f"Build failed (attempt {attempt})")
        
        return False, build_log

    def _run_build_commands(
        self,
        build_commands: str,
        cwd: Path,
        env: Optional[Dict[str, str]] = None,
        timeout: int = 600
    ) -> Tuple[bool, str, str]:
        """Execute build commands as a shell script
        
        Args:
            build_commands: Build script content to execute
            cwd: Working directory for the build
            env: Environment variables (uses os.environ if None)
            timeout: Timeout in seconds (default 10 minutes)
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            self.logger.info(f"Building source code in {cwd} ...")
            self.logger.debug(f"Executing build commands: \n{build_commands}")
            
            # Use provided env or copy current environment
            build_env = env if env is not None else os.environ.copy()
            
            # Execute build script
            result = subprocess.run(
                build_commands,
                shell=True,
                executable='/bin/bash',
                cwd=cwd,
                env=build_env,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            success = (result.returncode == 0)
            if success:
                self.logger.info("Build completed!")
            else:
                self.logger.error(f"✗ Build failed with exit code {result.returncode}")
                # Log output only when failed.
                # if result.stdout:
                #     self.logger.debug(f"Build stdout:\n{result.stdout}")
                if result.stderr:
                    log_level = logging.DEBUG if success else logging.ERROR
                    self.logger.log(log_level, f"Build stderr:\n{result.stderr}")

            return success, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            error_msg = f"Build command timed out after {timeout // 60} minutes"
            self.logger.error(error_msg)
            return False, "", error_msg
        except Exception as e:
            error_msg = f"Build execution failed: {str(e)}"
            self.logger.error(error_msg)
            return False, "", error_msg

    def _diagnose_and_fix_build_error(
        self,
        error: str,
        output: str,
        build_commands: str,
        context: str = "",
        system_prompt: Optional[str] = None,
        fallback_fixes: Optional[Callable[[str, str], Optional[str]]] = None
    ) -> Optional[str]:
        """Use LLM to diagnose build error and suggest fixes
        
        Args:
            error: Error output from build (stderr)
            output: Standard output from build (stdout)
            build_commands: Current build commands
            context: Additional context (e.g., CVE ID, build phase)
            system_prompt: Custom system prompt
            fallback_fixes: Optional callback for agent-specific fallback fixes
                           Signature: (error, build_commands) -> Optional[fixed_commands]
            
        Returns:
            Updated build commands if fix found, None otherwise
        """
        # Build the diagnostic prompt with truncated outputs
        # Use head-tail truncation to preserve both command context and final errors
        truncated_error = self._truncate_middle(error, max_lines=80, max_chars=4000, head_ratio=0.3)
        truncated_output = self._truncate_middle(output, max_lines=40, max_chars=2000, head_ratio=0.3)

        prompt = BA_diagnose_build_error_prompt.format(
            project_name=self.project_name,
            context=context,
            build_commands=build_commands,
            error=truncated_error,
            output=truncated_output
        )

        try:
            # Use LLMInterface.generate() for simple text generation
            response = self.drill_agent.basic_llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.1,
                max_tokens=2048
            )

            # Clean up response - remove markdown code blocks if present
            response = self._clean_llm_script_response(response)
            
            # Check if response looks like a valid script
            if response and (response.startswith('#!/bin/bash') or 
                           'make' in response.lower() or 
                           'cmake' in response.lower() or
                           'configure' in response.lower()):
                self.logger.info(f"LLM provided fixed build script")
                self.logger.debug(f"Fixed script:\n{response}")
                return response
            else:
                self.logger.warning(f"LLM response doesn't look like a valid build script")
                self.logger.debug(f"Response:\n{response}")
                
                # Try agent-specific fallback fixes
                if fallback_fixes:
                    fixed = fallback_fixes(error, build_commands)
                    if fixed:
                        return fixed
                
                return None
            
        except Exception as e:
            self.logger.error(f"LLM diagnosis failed: {e}")
            return None

    def _clean_llm_script_response(self, response: str) -> str:
        """Clean up LLM response by removing markdown code blocks
        
        Args:
            response: Raw LLM response
            
        Returns:
            Cleaned response with code blocks removed
        """
        response = response.strip()
        
        if '```' not in response:
            return response
        
        # Extract content between code blocks
        lines = response.split('\n')
        in_code_block = False
        cleaned_lines = []
        
        for line in lines:
            if line.strip().startswith('```'):
                in_code_block = not in_code_block
                continue
            if in_code_block:
                cleaned_lines.append(line)
        
        # If we found code block content, use it
        if cleaned_lines:
            return '\n'.join(cleaned_lines).strip()
        
        # Otherwise return original (minus any leading/trailing ```)
        if response.startswith('```'):
            lines = response.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            if lines and lines[-1].startswith('```'):
                lines = lines[:-1]
            return '\n'.join(lines).strip()
        
        return response
