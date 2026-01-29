import os
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

from .basic_tools import AgentTool

# New implementation of llvm-cov encapsulated tool (imitate BashTool) for function code coverage query.
# Usage: We should provide the following in the LLM prompt:
## 1. the cov-instrumented binary program path.
## 2. the round-dir containing profdata file.
class FunctionCovTool(AgentTool):
    """
    Tool for querying code coverage using llvm-cov and related commands.
    Follows BashTool pattern: LLM specifies command directly, with whitelist restrictions.
    """

    def __init__(self, code_repo_path: str):
        """
        Initialize FunctionCovTool.

        Args:
            code_repo_path: Absolute path to the repository root (used as default working directory)
        """
        self.code_repo_path = Path(code_repo_path).resolve()

        if not self.code_repo_path.exists():
            raise ValueError(f"Repository path does not exist: {code_repo_path}")
        if not self.code_repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {code_repo_path}")

        # Strictly limited whitelist for coverage-related commands
        self.allowed_commands = {
            'llvm-cov',      # Primary coverage tool
            'llvm-profdata', # Profile data inspection tool
            'cat',           # Read file contents
            'head',          # Read first N lines
            'tail',          # Read last N lines
            'grep',          # Search/filter output
            'wc',            # Count lines/words/bytes
            'strings',       # Extract printable strings
        }

        # Timeout for command execution (seconds)
        self.timeout = 30

        # Maximum output lines
        self.max_output_lines = 200

        # Maximum output characters (to control context size)
        self.max_output_chars = 15000

    def name(self) -> str:
        return "coverage_query"

    def description(self) -> str:
        cmd_list = ", ".join(sorted(self.allowed_commands))

        return (
            "Execute coverage-related commands to query code coverage information.\n"
            "This tool is specifically designed for llvm-cov operations.\n"
            "\n"
            "ALLOWED COMMANDS:\n"
            f"{cmd_list}\n"
            "\n"
            "LLVM-COV USAGE:\n"
            "The primary use case is querying function/line coverage with `llvm-cov show`.\n"
            "\n"
            "Command format:\n"
            "  llvm-cov show <binary> [source_file] -instr-profile=<profdata> [options]\n"
            "\n"
            "Common options:\n"
            "  --name=<func>           Show coverage for exact function name\n"
            "  --name-regex=<pattern>  Show coverage for functions matching regex\n"
            "  --show-line-counts      Show execution counts for each line\n"
            "  --show-regions          Show coverage regions\n"
            "\n"
            "EXAMPLE - Query coverage for a specific function with precisely specified name:\n"
            "  llvm-cov show /path/to/binary /path/to/source.c -instr-profile=/path/to/coverage.profdata --name-regex=^parse_input$\n"
            "\n"
            "EXAMPLE - Query coverage for all functions in a file:\n"
            "  llvm-cov show /path/to/binary /path/to/source.c -instr-profile=/path/to/coverage.profdata\n"
            "\n"
            "EXAMPLE - Pipe output for filtering:\n"
            "  llvm-cov show /path/to/binary -instr-profile=/path/to/coverage.profdata | grep 'function_name'\n"
            "\n"
            "OUTPUT FORMAT:\n"
            "llvm-cov show outputs source code with execution counts:\n"
            "  - Lines starting with a number show execution count\n"
            "  - Lines with '|' show the source code\n"
            "  - '0|' means the line was NOT executed (uncovered)\n"
            "  - 'N|' (N>0) means the line was executed N times\n"
            "\n"
            "LLVM-PROFDATA USAGE:\n"
            "Use `llvm-profdata show <profdata_file>` to inspect profdata metadata (e.g., validate the file, check function count).\n"
            "  Add --all-functions to list all recorded functions.\n"
            "\n"
            "OUTPUT LIMIT:\n"
            f"Output is limited to {self.max_output_lines} lines. Use filters (grep, head, tail) if needed.\n"
            "If the output is truncated due to length limit, use the read_file tool to read the truncated content directly.\n"
            "\n"
            "WORKING DIRECTORY:\n"
            "Commands execute in the specified `working_dir` (default: code repository root).\n"
            "`working_dir` can be relative (to repo root) or absolute path.\n"
        )

    def parameters_schema(self) -> Dict[str, Any]:
        pipe_commands = ", ".join(sorted(self.allowed_commands - {'llvm-cov'}))
        return {
            "command": {
                "type": "string",
                "description": (
                    "The coverage query command to execute. "
                    "MUST start with 'llvm-cov' or 'llvm-profdata' (e.g., 'llvm-cov show ...', 'llvm-profdata show ...'). "
                    f"You can pipe the output to text processing commands: {pipe_commands}. "
                    "Example: 'llvm-cov show /path/to/bin -instr-profile=cov.profdata | grep func_name'"
                ),
                "required": True
            },
            "working_dir": {
                "type": "string",
                "description": (
                    "Working directory for command execution. Can be either: "
                    "1) Relative path from code repository root (e.g., '.', 'src'), or "
                    "2) Absolute path (e.g., '/tmp', '/path/to/workspace'). "
                    "Default: '.' (code repository root)"
                ),
                "required": False
            }
        }

    # TODO: Sometimes multiple functions are matched.
    # Maybe we should first parse how many functions are matched, and then decide which to provide to LLM (?)
    def execute(self, command: str, working_dir: str = ".") -> Dict[str, Any]:
        """
        Execute a coverage-related command with whitelist validation.

        Args:
            command: The command to execute
            working_dir: Working directory (default: "." = repo root)

        Returns:
            Dict with execution results:
            - success: bool indicating if execution succeeded
            - stdout: Command standard output
            - stderr: Command standard error
            - exit_code: Command exit code
            - command: The executed command
            - working_dir: The actual working directory used
            - truncated: True if output was truncated
            - error/blocked_reason: Present if command was blocked
        """
        import shlex

        try:
            # Step 1: Resolve working directory
            if working_dir.startswith('/'):
                work_path = Path(working_dir)
            else:
                work_path = self.code_repo_path / working_dir

            work_path = work_path.resolve()

            # Validate working directory
            if not work_path.exists():
                return {
                    "success": False,
                    "error": f"Working directory does not exist: {working_dir}",
                    "command": command,
                    "blocked_reason": "invalid_working_dir"
                }

            if not work_path.is_dir():
                return {
                    "success": False,
                    "error": f"Working directory is not a directory: {working_dir}",
                    "command": command,
                    "blocked_reason": "invalid_working_dir"
                }

            # Step 2: Parse command to extract base command
            try:
                tokens = shlex.split(command)
            except ValueError as e:
                return {
                    "success": False,
                    "error": f"Failed to parse command: {str(e)}",
                    "command": command,
                    "blocked_reason": "parse_error"
                }

            if not tokens:
                return {
                    "success": False,
                    "error": "Empty command",
                    "command": command,
                    "blocked_reason": "empty_command"
                }

            # Extract base command (first token)
            base_command = tokens[0]

            # Step 3: Validate that command starts with an allowed primary command
            allowed_primary = {'llvm-cov', 'llvm-profdata'}
            if base_command not in allowed_primary:
                return {
                    "success": False,
                    "error": (
                        f"Command must start with one of {sorted(allowed_primary)}, got '{base_command}'. "
                        f"Example: llvm-cov show <binary> -instr-profile=<profdata> [| grep/head/tail ...]"
                    ),
                    "command": command,
                    "blocked_reason": "must_start_with_allowed_primary"
                }

            # Step 4: Execute command
            result = subprocess.run(
                command,
                shell=True,
                cwd=str(work_path),
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Step 5: Truncate output by line count and character count
            stdout = result.stdout
            stderr = result.stderr
            truncated = False

            # First, truncate by line count
            stdout_lines = stdout.split('\n')
            if len(stdout_lines) > self.max_output_lines:
                omitted_lines = len(stdout_lines) - self.max_output_lines
                stdout = '\n'.join(stdout_lines[:self.max_output_lines])
                stdout += f"\n\n... [OUTPUT TRUNCATED: showing first {self.max_output_lines} lines, {omitted_lines} lines omitted]"
                truncated = True

            stderr_lines = stderr.split('\n')
            if len(stderr_lines) > self.max_output_lines:
                omitted_lines = len(stderr_lines) - self.max_output_lines
                stderr = '\n'.join(stderr_lines[:self.max_output_lines])
                stderr += f"\n\n... [STDERR TRUNCATED: showing first {self.max_output_lines} lines, {omitted_lines} lines omitted]"
                truncated = True

            # Then, truncate by character count (to control context size)
            if len(stdout) > self.max_output_chars:
                # Truncate at line boundary
                truncated_stdout = stdout[:self.max_output_chars]
                last_newline = truncated_stdout.rfind('\n')
                if last_newline > self.max_output_chars * 0.8:
                    stdout = truncated_stdout[:last_newline]
                else:
                    stdout = truncated_stdout
                stdout += f"\n\n... [OUTPUT TRUNCATED: {len(result.stdout)} chars total, showing first {self.max_output_chars}]"
                truncated = True

            if len(stderr) > self.max_output_chars:
                truncated_stderr = stderr[:self.max_output_chars]
                last_newline = truncated_stderr.rfind('\n')
                if last_newline > self.max_output_chars * 0.8:
                    stderr = truncated_stderr[:last_newline]
                else:
                    stderr = truncated_stderr
                stderr += f"\n\n... [STDERR TRUNCATED: {len(result.stderr)} chars total, showing first {self.max_output_chars}]"
                truncated = True

            # Build response
            # success: indicates tool execution succeeded (not blocked, not timed out)
            # command_success: indicates the command itself returned exit_code 0
            response = {
                "success": True,
                "command_success": result.returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": result.returncode,
                "command": command,
                "working_dir": str(work_path.relative_to(self.code_repo_path)) if work_path.is_relative_to(self.code_repo_path) else str(work_path)
            }

            if truncated:
                response["truncated"] = True

            return response

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Command timed out after {self.timeout} seconds",
                "command": command,
                "blocked_reason": "timeout"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Execution failed: {str(e)}",
                "command": command,
                "blocked_reason": "execution_error"
            }



# 
# Legacy. 
# 
## TIP: gpt-5-mini seems don't know how to use this tool well.
class FuncLineCovTool(AgentTool):
    # When use this agent tool, we assume that there is already a *.profdata file.
    """
    Tool for retrieving detailed line-by-line coverage for a specific function.
    Uses llvm-cov show command to display execution counts and source code.
    """

    def __init__(self, repo_path: str, binary_abs_path: str, llvm_cov_path: str = "llvm-cov"):
        """
        Initialize FuncLineCovTool.

        Args:
            repo_path: Absolute path to the repository root
            binary_abs_path: Absolute path to the instrumented binary (FIXED for entire session)
            llvm_cov_path: Path to llvm-cov executable (default: "llvm-cov")
        """
        self.repo_path = Path(repo_path).resolve()
        self.binary_path = os.path.abspath(binary_abs_path)
        self.llvm_cov_path = llvm_cov_path

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {repo_path}")
        if not Path(self.binary_path).exists():
            raise ValueError(f"Binary file not found: {binary_abs_path}")

    def name(self) -> str:
        return "get_function_line_coverage" # abandoned

    def description(self) -> str:
        return (
            "Retrieve detailed line-by-line coverage information for a specific function. "
            "Shows execution counts for each line of code within the function. "
            "Use this when you need to understand which lines in a function were executed "
            "and how many times during test runs. "
            "Requires an instrumented binary and corresponding profdata coverage file. "
            "Output is limited to 200 lines. "
            "If the output is truncated due to length limit, use the read_file tool to read the truncated content directly."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "profdata_path": {
                "type": "string",
                "description": (
                    "Absolute path to the profdata coverage data file. "
                    "This file is generated by merging profraw files using llvm-profdata. "
                    "Example: '/path/to/coverage.profdata'"
                ),
                "required": True
            },
            "function_name": {
                "type": "string",
                "description": (
                    "Name of the function to retrieve coverage for. "
                    "Must exactly match the function name in the source code. "
                    "Examples: 'main', 'parse_input', 'calculate_sum'"
                ),
                "required": True
            },
            "source_file_path": {
                "type": "string",
                "description": (
                    "Path to the source file containing the function. "
                    "Can be absolute or relative to repository root. "
                    "If not specified, llvm-cov will search all files for the function. "
                    "Examples: 'src/parser.c', '/absolute/path/to/parser.c'"
                ),
                "required": False
            },
        }

    # Currently, it just run `llvm-cov` directly, without using LLVMCovUtils. 
    def execute(self, profdata_path: str, function_name: str,
                source_file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute llvm-cov show to retrieve function line coverage.

        Args:
            profdata_path: Path to profdata file
            function_name: Function name to analyze
            source_file_path: Optional path to source file (absolute or relative to repo)

        Returns:
            Dict containing:
            - success: bool indicating if execution succeeded
            - coverage_output: str with line-by-line coverage information
            - function_name: str the queried function name
            - source_file_path: str the resolved file path (if provided)
            - error: str error message if failed
        """
        print(f"[FuncLineCovTool] Coverage query for function '{function_name}' ") # DEBUG
        try:
            # Use the binary_path from initialization
            binary_path = self.binary_path
            profdata_path = os.path.abspath(profdata_path)

            # Handle source_file_path: if provided, resolve it
            resolved_file_path = None
            if source_file_path is not None:
                file_path_obj = Path(source_file_path)
                if file_path_obj.is_absolute():
                    resolved_file_path = file_path_obj
                else:
                    resolved_file_path = self.repo_path / source_file_path
                resolved_file_path = resolved_file_path.resolve()

            # Validate inputs
            if not Path(binary_path).exists():
                return {
                    "success": False,
                    "error": f"Binary file not found: {binary_path}",
                    "function_name": function_name,
                    "source_file_path": str(resolved_file_path) if resolved_file_path else None
                }

            if not Path(profdata_path).exists():
                return {
                    "success": False,
                    "error": f"Profdata file not found: {profdata_path}",
                    "function_name": function_name,
                    "source_file_path": str(resolved_file_path) if resolved_file_path else None
                }

            if resolved_file_path is not None and not resolved_file_path.exists():
                return {
                    "success": False,
                    "error": f"Source file not found: {resolved_file_path}",
                    "function_name": function_name,
                    "source_file_path": str(resolved_file_path)
                }

            # Construct llvm-cov show command
            # Format: llvm-cov show <binary> [<source_file>] -instr-profile=<profdata> --name=<function_name>
            cmd = [
                self.llvm_cov_path,
                'show',
                binary_path
            ]

            # Only add source file if provided
            if resolved_file_path is not None:
                cmd.append(str(resolved_file_path))

            cmd.extend([
                f'-instr-profile={profdata_path}',
                f'--name-regex=^{function_name}$'
            ])

            # Execute command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": f"llvm-cov command failed: {result.stderr}",
                    "function_name": function_name,
                    "source_file_path": str(resolved_file_path) if resolved_file_path else None
                }

            # Check if output is empty (function might not exist or not covered)
            output = result.stdout.strip()

            # Limit output to first N lines
            output_lines = output.split('\n')
            limit_line_num = 200
            if len(output_lines) > limit_line_num:
                omitted_lines = len(output_lines) - limit_line_num
                output = '\n'.join(output_lines[:limit_line_num])
                output += f'\n\n... [OUTPUT TRUNCATED: showing first {limit_line_num} lines, {omitted_lines} lines omitted]'

            if not output:
                # Is this happens a lot?
                file_info = f" in {resolved_file_path}" if resolved_file_path else ""
                return {
                    "success": False,
                    "error": (
                        f"No coverage data found for function '{function_name}'{file_info}. "
                        f"The function may not exist, or it was not executed during coverage collection."
                    ),
                    "function_name": function_name,
                    "source_file_path": str(resolved_file_path) if resolved_file_path else None
                }

            result_dict = {
                "success": True,
                "coverage_output": output,
                "function_name": function_name,
                "message": f"Successfully retrieved coverage for function '{function_name}'"
            }

            if resolved_file_path is not None:
                result_dict["source_file_path"] = str(resolved_file_path)

            return result_dict

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "llvm-cov command timed out (>30s)",
                "function_name": function_name,
                "source_file_path": source_file_path
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "function_name": function_name,
                "source_file_path": source_file_path
            }
