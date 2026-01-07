"""
ast-grep based code search tools.

This module provides fast structural code search using ast-grep (sg).
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

    def __init__(self, repo_path: str, ast_grep_path: str = "sg"):
        """
        Initialize AstGrepManager.

        Args:
            repo_path: Absolute path to the repository root
            ast_grep_path: Path to ast-grep executable (default: "sg")

        Raises:
            ValueError: If repo_path is invalid
        """
        self.repo_path = Path(repo_path).resolve()
        self.ast_grep_path = ast_grep_path

        # TODO: Validate repo_path exists
        # TODO: Validate ast-grep is installed
        pass

    def search_pattern(self, pattern: str, path: Optional[str] = None,
                      language: str = "c", context_lines: int = 0) -> Dict[str, Any]:
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
        # TODO: Build ast-grep command
        # TODO: Execute subprocess
        # TODO: Parse JSON output
        # TODO: Return formatted results
        pass

    def search_function(self, function_name: str, path: Optional[str] = None,
                       language: str = "c") -> Dict[str, Any]:
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
        # TODO: Construct function definition pattern based on language
        # TODO: Call search_pattern()
        # TODO: Post-process to extract function signature and body
        # TODO: Return formatted results
        pass

    def is_available(self) -> bool:
        """
        Check if ast-grep (sg) is available.

        Returns:
            True if ast-grep is installed and executable, False otherwise
        """
        # TODO: Try running 'sg --version'
        # TODO: Return True if successful, False otherwise
        pass


class AstGrepFunctionSearchTool(AgentTool):
    """
    Fast function definition search using ast-grep.

    This tool provides quick syntax-based function search that doesn't
    require compilation or build configuration.
    """

    def __init__(self, repo_path: str, ast_grep_path: str = "sg"):
        """
        Initialize AstGrepFunctionSearchTool.

        Args:
            repo_path: Absolute path to the repository root
            ast_grep_path: Path to ast-grep executable
        """
        self.repo_path = Path(repo_path).resolve()
        self.ast_grep_path = ast_grep_path
        # TODO: Create or get AstGrepManager instance
        pass

    def name(self) -> str:
        return "ast_grep_search_function"

    def description(self) -> str:
        return (
            "Quickly search for C/C++ function definitions by name using ast-grep. "
            "Fast syntax-based search that doesn't require compilation or compile_commands.json. "
            "Returns file paths, line numbers, and function signatures. "
            "Use this for quick exploration or when clangd-based tools are unavailable. "
            "Note: Less accurate than clangd for complex cases (macros, templates). "
            "Good for rapid initial exploration of unfamiliar codebases."
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
                "description": "Programming language: 'c' or 'cpp'. Default: 'c'",
                "required": False
            }
        }

    def execute(self, function_name: str, search_path: Optional[str] = None,
                language: str = "c") -> Dict[str, Any]:
        """
        Execute function search.

        Args:
            function_name: Name of the function to find
            search_path: Optional path to narrow search
            language: Programming language (c or cpp)

        Returns:
            Dict containing:
            - success: bool
            - matches: List[Dict] with 'file', 'line', 'column', 'signature', 'source_snippet'
            - count: int (number of matches)
            - error: str (if failed)
        """
        # TODO: Use AstGrepManager.search_function()
        # TODO: Format results for LLM consumption
        # TODO: Include source snippets
        # TODO: Return formatted result
        pass


class AstGrepPatternSearchTool(AgentTool):
    """
    Advanced pattern-based code search using ast-grep.

    Supports structural pattern matching with wildcards for finding
    specific code constructs across the codebase.
    """

    def __init__(self, repo_path: str, ast_grep_path: str = "sg"):
        """
        Initialize AstGrepPatternSearchTool.

        Args:
            repo_path: Absolute path to the repository root
            ast_grep_path: Path to ast-grep executable
        """
        self.repo_path = Path(repo_path).resolve()
        self.ast_grep_path = ast_grep_path
        # TODO: Create or get AstGrepManager instance
        pass

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
            "'return $VALUE;' finds all return statements."
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
                "description": "Programming language: 'c', 'cpp', etc. Default: 'c'",
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

    def execute(self, pattern: str, language: str = "c",
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
        # TODO: Use AstGrepManager.search_pattern()
        # TODO: Format results with context
        # TODO: Limit number of results if too many (with warning)
        # TODO: Return formatted result
        pass
