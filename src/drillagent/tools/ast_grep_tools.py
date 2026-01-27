"""
ast-grep based code search tools.

This module provides fast structural code search using ast-grep (alisa: sg).
Does not require compilation - works on source code directly.
Useful as a fallback when clangd is unavailable or for quick searches.

Tools:
- AstGrepFunctionSearchTool: Quick function definition search by name
- AstGrepPatternSearchTool: Advanced pattern-based structural search

Manager:
- AstGrepManager: Manages ast-grep CLI interactions
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import subprocess
import json

from .basic_tools import AgentTool


class AstGrepManager:
    """
    Manager for ast-grep CLI interactions.

    Responsibilities:
    - Execute ast-grep commands
    - Parse ast-grep output
    - Handle pattern compilation
    - Provide common search operations

    Unlike ClangdManager, this doesn't maintain a persistent process.
    Each operation is a fresh CLI invocation.
    """

    def __init__(self, repo_path: str, ast_grep_path: str = "ast-grep"):
        """
        Initialize AstGrepManager.

        Args:
            repo_path: Absolute path to the repository root
            ast_grep_path: Path to ast-grep executable (default: "ast-grep")

        Raises:
            ValueError: If repo_path is invalid
        """
        self.repo_path = Path(repo_path).resolve()
        self.ast_grep_path = ast_grep_path

        # Validate repo_path exists
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {repo_path}")

        # Validate ast-grep is installed
        if not self.is_available():
            raise RuntimeError(
                f"ast-grep executable '{ast_grep_path}' not found or not working. "
                f"Please install ast-grep: https://ast-grep.github.io/guide/introduction.html"
            )

    def search_pattern(self, pattern: str, path: Optional[str] = None,
                      language: str = "cpp", context_lines: int = 0) -> Dict[str, Any]:
        """
        Search for a code pattern using ast-grep.

        Args:
            pattern: ast-grep pattern (e.g., "void $FUNC($$$)")
            path: Optional path to search in (relative to repo)
            language: Language to use (c, cpp, etc.)
            context_lines: Number of context lines to include

        Returns:
            Dict containing:
            - success: bool
            - matches: List[Dict] with match information
            - error: str (if failed)
        """
        try:
            # Build ast-grep command
            cmd = [
                self.ast_grep_path,
                "run",
                "--pattern", pattern,
                "--lang", language,
                "--json"
            ]

            # Add context lines if requested
            if context_lines > 0:
                cmd.extend(["--context", str(context_lines)])

            # Determine search path
            search_path = self.repo_path
            search_is_file = False
            if path:
                search_path = self.repo_path / path
                if not search_path.exists():
                    return {
                        "success": False,
                        "matches": [],
                        "error": f"Search path does not exist: {path}"
                    }
                # Check if it's a file or directory
                if search_path.is_file():
                    search_is_file = True

            # Execute subprocess
            # If searching a specific file, add it to command; otherwise use cwd
            if search_is_file:
                cmd.append(str(search_path))
                result = subprocess.run(
                    cmd,
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                result = subprocess.run(
                    cmd,
                    cwd=search_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

            if result.returncode != 0 and result.returncode != 1:
                # Return code 1 means no matches found, which is valid
                return {
                    "success": False,
                    "matches": [],
                    "error": f"ast-grep failed: {result.stderr}"
                }

            # Parse JSON output
            if not result.stdout.strip():
                # No matches found
                return {
                    "success": True,
                    "matches": [],
                    "count": 0
                }

            matches_raw = json.loads(result.stdout)

            # Format matches
            matches = []
            for match in matches_raw:
                formatted_match = {
                    "file": match["file"],
                    "line": match["range"]["start"]["line"],
                    "column": match["range"]["start"]["column"],
                    "end_line": match["range"]["end"]["line"],
                    "end_column": match["range"]["end"]["column"],
                    "text": match["text"],
                    "lines": match.get("lines", match["text"])
                }

                # Include captured metavariables if any
                if "metaVariables" in match and match["metaVariables"].get("single"):
                    formatted_match["captures"] = {
                        name: var["text"]
                        for name, var in match["metaVariables"]["single"].items()
                    }

                matches.append(formatted_match)

            return {
                "success": True,
                "matches": matches,
                "count": len(matches)
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "matches": [],
                "error": "Search timed out after 30 seconds"
            }
        except json.JSONDecodeError as e:
            return {
                "success": False,
                "matches": [],
                "error": f"Failed to parse ast-grep output: {e}"
            }
        except Exception as e:
            return {
                "success": False,
                "matches": [],
                "error": f"Unexpected error: {e}"
            }

    def search_function(self, function_name: str, path: Optional[str] = None,
                       language: str = "cpp") -> Dict[str, Any]:
        """
        Search for function definitions by name.

        This is a convenience wrapper that constructs appropriate patterns
        for finding function definitions.

        Args:
            function_name: Name of the function to find
            path: Optional path to search in (relative to repo)
            language: Language (c or cpp)

        Returns:
            Dict containing:
            - success: bool
            - matches: List[Dict] with function definitions
            - error: str (if failed)
        """
        # Construct function definition pattern based on language
        if language in ["c", "cpp"]:
            # For C/C++, use TWO patterns to handle both pointer and non-pointer return types
            # Pattern 1: Functions returning non-pointers (e.g., int func(), static void func())
            # Pattern 2: Functions returning pointers (e.g., User *func(), static const char *func())
            # $$$MODS matches: storage specifiers (static), type qualifiers (const), type names
            patterns = [
                f"$$$MODS {function_name}($$$PARAMS) {{ $$$BODY }}",  # non-pointer returns
                f"$$$MODS *{function_name}($$$PARAMS) {{ $$$BODY }}", # pointer returns
            ]

            # Try both patterns and combine results
            all_matches = []
            for pattern in patterns:
                result = self.search_pattern(pattern, path, language, context_lines=0)
                if result["success"] and result.get("matches"):
                    all_matches.extend(result["matches"])

            # Remove duplicates based on line number (same function matched by both patterns)
            seen_lines = set()
            unique_matches = []
            for match in all_matches:
                line = match.get("line")
                if line not in seen_lines:
                    seen_lines.add(line)
                    unique_matches.append(match)

            result = {
                "success": True,
                "matches": unique_matches,
                "count": len(unique_matches)
            }

        elif language == "python":
            # Pattern that matches: def function_name(<params>)
            # Note: ast-grep handles the colon automatically for Python
            pattern = f"def {function_name}($$$)"
            result = self.search_pattern(pattern, path, language, context_lines=0)
        else:
            return {
                "success": False,
                "matches": [],
                "error": f"Unsupported language: {language}"
            }

        if not result["success"]:
            return result

        # Post-process to extract function signature and body
        for match in result.get("matches", []):
            # Extract function signature from the matched text
            text = match.get("text", "")
            lines = text.split("\n")

            # Find the first line with opening brace (C/C++) or colon (Python) to get signature
            signature_lines = []
            if language == "python":
                # For Python, signature ends at the colon
                for line in lines:
                    signature_lines.append(line)
                    if ":" in line:
                        break
            else:
                # For C/C++, signature ends at the opening brace
                for line in lines:
                    signature_lines.append(line)
                    if "{" in line:
                        break

            match["signature"] = "\n".join(signature_lines).strip()
            match["function_name"] = function_name

        return result

    def is_available(self) -> bool:
        """
        Check if ast-grep is available.

        Returns:
            True if ast-grep is installed and executable, False otherwise
        """
        try:
            result = subprocess.run(
                [self.ast_grep_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return False


class AstGrepFunctionSearchTool(AgentTool):
    """
    Fast function definition search using ast-grep.

    This tool provides quick syntax-based function search that doesn't
    require compilation or build configuration.

    Supported languages:
    - C: Full support for all function types (static, const, pointer returns, etc.)
    - C++: Limited support (ast-grep has known issues with C++ function pattern matching)
    - Python: Good support for basic function definitions

    For C code, the tool uses a dual-pattern approach to handle both
    pointer and non-pointer return types comprehensively.
    """

    def __init__(self, repo_path: str, ast_grep_path: str = "ast-grep"):
        """
        Initialize AstGrepFunctionSearchTool.

        Args:
            repo_path: Absolute path to the repository root
            ast_grep_path: Path to ast-grep executable
        """
        self.repo_path = Path(repo_path).resolve()
        self.ast_grep_path = ast_grep_path
        # Create AstGrepManager instance
        self.manager = AstGrepManager(str(self.repo_path), ast_grep_path)

    def name(self) -> str:
        return "ast_grep_search_function"

    def description(self) -> str:
        return (
            "Quickly search for function definitions by name using ast-grep. "
            "Supports C, C++, and Python. "
            "Fast syntax-based search that doesn't require compilation or compile_commands.json. "
            "Returns file paths, line numbers, and function signatures. "
            "Use this for quick exploration or when clangd-based tools are unavailable. "
            "Note: Less accurate than clangd for complex cases (macros, templates). "
            "Good for rapid initial exploration of unfamiliar codebases. "
            "Output is limited to 200 lines per function. "
            "If the output is truncated due to length limit, use the read_file tool to read the truncated content directly."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "function_name": {
                "type": "string",
                "description": "Name of the function to search for (e.g., 'main', 'parse_input')",
                "required": True
            },
            "search_path": {
                "type": "string",
                "description": (
                    "Optional: Path to search in (relative to repo root). "
                    "If not provided, searches entire repository. "
                    "Examples: 'src/', 'lib/parser.c'"
                ),
                "required": False
            },
            "language": {
                "type": "string",
                "description": "Programming language: 'c', 'cpp', or 'python'. Default: 'cpp'",
                "required": False
            }
        }

    def execute(self, function_name: str, search_path: Optional[str] = None,
                language: str = "cpp") -> Dict[str, Any]:
        """
        Execute function search.

        Args:
            function_name: Name of the function to find
            search_path: Optional path to narrow search
            language: Programming language (c, cpp, or python)

        Returns:
            Dict containing:
            - success: bool
            - summary: str (human-readable overview of matches, shows if results limited)
            - matches: List[Dict] with (max 3 results):
                - file: str (file path)
                - line: int (start line number)
                - column: int (start column)
                - signature: str (function signature)
                - source_snippet: str (formatted with line numbers, max N lines)
                - total_lines: int (actual function length)
            - count: int (number of matches returned, max 3)
            - total_found: int (total number of matches found)
            - function_name: str (the queried function name)
            - error: str (if failed)
        """
        # Use AstGrepManager.search_function()
        result = self.manager.search_function(function_name, search_path, language)

        if not result["success"]:
            return result

        # Limit to first 3 matches
        all_matches = result.get("matches", [])
        total_found = len(all_matches)
        matches_to_process = all_matches[:3]

        # Format results for LLM consumption
        formatted_matches = []
        summary_lines = []

        for idx, match in enumerate(matches_to_process, 1):
            # Format source snippet with line numbers
            source_text = match.get("text", "")
            source_lines = source_text.split("\n")
            start_line = match["line"]

            # Limit to first 200 lines for readability
            max_lines = 200
            truncated = len(source_lines) > max_lines
            display_lines = source_lines[:max_lines]

            # Add line numbers
            numbered_lines = []
            for i, line in enumerate(display_lines):
                line_num = start_line + i + 1 # Added this "+ 1". Seems good now.
                numbered_lines.append(f"{line_num:4d} | {line}")

            formatted_snippet = "\n".join(numbered_lines)
            if truncated:
                omitted_lines = len(source_lines) - max_lines
                formatted_snippet += f"\n\n... [OUTPUT TRUNCATED: showing first {max_lines} lines, {omitted_lines} lines omitted]"

            formatted_match = {
                "file": match["file"],
                "line": match["line"],
                "column": match["column"],
                "signature": match.get("signature", ""),
                "source_snippet": formatted_snippet,
                "total_lines": len(source_lines)
            }
            formatted_matches.append(formatted_match)

            # Build summary
            summary_lines.append(
                f"  [{idx}] {match['file']}:{match['line']} - {match.get('signature', '')}"
            )

        # Create human-readable summary
        summary = f"Found {total_found} definition(s) of '{function_name}'"
        if total_found > 3:
            summary += f" (showing first 3)"
        summary += ":\n" + "\n".join(summary_lines)

        # For debug
        # print(f"[AstGrepFunctionSearchTool] Search Summary:")
        # print(f"  Function Name:    {function_name}")
        # print(f"  Matched Results:  {len(formatted_matches)} / {total_found}")
        # print(f"  Code lines (1st): {len(formatted_matches[0]['source_snippet'].splitlines()) if formatted_matches else 0}\n")
        # if formatted_matches:
        #     print(formatted_matches[0]['source_snippet'])

        return {
            "success": True,
            "summary": summary,
            "matches": formatted_matches,
            "count": len(formatted_matches),
            "total_found": total_found,
            "function_name": function_name
        }


class AstGrepPatternSearchTool(AgentTool):
    """
    Advanced pattern-based code search using ast-grep.

    Supports structural pattern matching with wildcards for finding
    specific code constructs across the codebase.
    """

    def __init__(self, repo_path: str, ast_grep_path: str = "ast-grep"):
        """
        Initialize AstGrepPatternSearchTool.

        Args:
            repo_path: Absolute path to the repository root
            ast_grep_path: Path to ast-grep executable
        """
        self.repo_path = Path(repo_path).resolve()
        self.ast_grep_path = ast_grep_path
        # Create AstGrepManager instance
        self.manager = AstGrepManager(str(self.repo_path), ast_grep_path)

    def name(self) -> str:
        return "ast_grep_pattern_search"

    def description(self) -> str:
        return (
            "Search for code using structural patterns with ast-grep. "
            "Supports pattern matching with wildcards for finding specific code constructs. "
            "Pattern syntax: $VAR for single node wildcards, $$$ for multiple nodes. "
            "Useful for finding specific patterns like: all malloc calls, error handling patterns, "
            "specific function call patterns, etc. "
            "Examples: 'malloc($SIZE)' finds all malloc calls; "
            "'if ($COND) { $$$ }' finds all if statements; "
            "'return $VALUE;' finds all return statements. "
            "Output is limited to 200 lines per match. "
            "If the output is truncated due to length limit, use the read_file tool to read the truncated content directly."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "pattern": {
                "type": "string",
                "description": (
                    "ast-grep pattern to search for. "
                    "Use $VAR for single node wildcards (matches one AST node). "
                    "Use $$$ for multiple node wildcards (matches zero or more nodes). "
                    "Examples:\n"
                    "- 'malloc($SIZE)' - find malloc calls\n"
                    "- 'if ($COND) { $$$ }' - find if statements\n"
                    "- 'return $VALUE;' - find return statements\n"
                    "- '$FUNC($$$)' - find all function calls"
                ),
                "required": True
            },
            "language": {
                "type": "string",
                "description": "Programming language: 'c', 'cpp', etc. Default: 'cpp'",
                "required": False
            },
            "search_path": {
                "type": "string",
                "description": (
                    "Optional: Path to search in (relative to repo root). "
                    "If not provided, searches entire repository."
                ),
                "required": False
            },
            "context_lines": {
                "type": "integer",
                "description": "Number of context lines to show around matches. Default: 2",
                "required": False
            }
        }

    def execute(self, pattern: str, language: str = "cpp",
                search_path: Optional[str] = None,
                context_lines: int = 2) -> Dict[str, Any]:
        """
        Execute pattern search.

        Args:
            pattern: ast-grep pattern to search
            language: Programming language
            search_path: Optional path to narrow search
            context_lines: Number of context lines around matches

        Returns:
            Dict containing:
            - success: bool
            - matches: List[Dict] with 'file', 'line', 'column', 'matched_code', 'context'
            - count: int (number of matches)
            - pattern_used: str (the pattern that was searched)
            - error: str (if failed)
        """
        # Use AstGrepManager.search_pattern()
        result = self.manager.search_pattern(pattern, search_path, language, context_lines)

        if not result["success"]:
            return result

        # Format results with context
        formatted_matches = []
        max_results = 100  # Limit to prevent overwhelming output
        max_lines_per_match = 200  # Limit lines per match

        matches = result.get("matches", [])
        limited = len(matches) > max_results

        def truncate_to_lines(text: str, max_lines: int) -> str:
            """Truncate text to max_lines, showing omitted line count."""
            lines = text.split("\n")
            if len(lines) > max_lines:
                omitted = len(lines) - max_lines
                return "\n".join(lines[:max_lines]) + f"\n\n... [OUTPUT TRUNCATED: showing first {max_lines} lines, {omitted} lines omitted]"
            return text

        for match in matches[:max_results]:
            matched_code = match.get("text", "")
            context = match.get("lines", match.get("text", ""))

            # Truncate matched_code and context to max_lines_per_match
            matched_code = truncate_to_lines(matched_code, max_lines_per_match)
            context = truncate_to_lines(context, max_lines_per_match)

            formatted_match = {
                "file": match["file"],
                "line": match["line"],
                "column": match["column"],
                "matched_code": matched_code,
                "context": context
            }

            # Include captured variables if any
            if "captures" in match:
                formatted_match["captures"] = match["captures"]

            formatted_matches.append(formatted_match)

        result_dict = {
            "success": True,
            "matches": formatted_matches,
            "count": len(formatted_matches),
            "total_matches": len(matches),
            "pattern_used": pattern
        }

        # Add warning if results were limited
        if limited:
            result_dict["warning"] = f"Results limited to {max_results} out of {len(matches)} total matches"

        return result_dict
