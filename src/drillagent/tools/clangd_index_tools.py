"""
Clangd-based code indexing and analysis tools.

This module provides LSP-based code intelligence tools powered by clangd.
Requires compile_commands.json for accurate analysis.

Tools:
- FindFunctionDefTool: Find function definitions by name
- FindReferencesTool: Find all callers of a function
- GetCallHierarchyTool: Get functions called by a function (callees)
- GetHoverInfoTool: Get type and documentation info for symbols

Manager:
- ClangdManager: Singleton that manages clangd LSP server process
"""

from pathlib import Path
from typing import Dict, Any, List, Optional

from .basic_tools import AgentTool


class ClangdManager:
    """
    Singleton manager for clangd LSP server process.

    Responsibilities:
    - Start/stop clangd process
    - Handle LSP protocol communication (textDocument/*, callHierarchy/*)
    - Cache indexing state
    - Manage workspace configuration

    The manager is shared across all clangd-based tools to avoid
    starting multiple clangd processes.
    """

    _instance = None

    def __init__(self, repo_path: str, compile_commands_path: str, clangd_path: str = "clangd"):
        """
        Initialize ClangdManager.

        Args:
            repo_path: Absolute path to the repository root
            compile_commands_path: Path to compile_commands.json
            clangd_path: Path to clangd executable (default: "clangd")

        Raises:
            ValueError: If repo_path or compile_commands_path is invalid
        """
        self.repo_path = Path(repo_path).resolve()
        self.compile_commands_path = Path(compile_commands_path).resolve()
        self.clangd_path = clangd_path

        # TODO: Validate paths
        # TODO: Initialize LSP client/connection variables
        # TODO: Set up clangd process variables
        pass

    @classmethod
    def get_instance(cls, repo_path: str, compile_commands_path: str, clangd_path: str = "clangd"):
        """
        Get or create ClangdManager singleton instance.

        Args:
            repo_path: Absolute path to the repository root
            compile_commands_path: Path to compile_commands.json
            clangd_path: Path to clangd executable

        Returns:
            ClangdManager instance
        """
        # TODO: Implement singleton pattern
        # TODO: Handle re-initialization if paths change
        pass

    @classmethod
    def reset_instance(cls):
        """
        Reset singleton instance.
        Useful when switching to a different repository or commit.
        """
        # TODO: Stop existing instance if running
        # TODO: Clear _instance
        pass

    def start(self):
        """
        Start clangd LSP server process.

        Raises:
            RuntimeError: If clangd fails to start
        """
        # TODO: Start clangd subprocess with stdio communication
        # TODO: Send LSP initialize request
        # TODO: Wait for initialize response
        # TODO: Send initialized notification
        pass

    def stop(self):
        """
        Stop clangd LSP server process.
        """
        # TODO: Send LSP shutdown request
        # TODO: Send exit notification
        # TODO: Terminate process
        # TODO: Clean up resources
        pass

    def restart(self):
        """
        Restart clangd LSP server.

        Useful when switching git commits - forces re-indexing.
        """
        # TODO: Call stop()
        # TODO: Call start()
        pass

    def is_running(self) -> bool:
        """
        Check if clangd process is running.

        Returns:
            True if running, False otherwise
        """
        # TODO: Check process status
        pass

    def find_definition(self, file_path: str, line: int, column: int) -> Dict[str, Any]:
        """
        Find symbol definition using LSP textDocument/definition.

        Args:
            file_path: Relative or absolute path to source file
            line: Line number (1-based)
            column: Column number (1-based)

        Returns:
            Dict containing:
            - success: bool
            - locations: List[Dict] with 'uri', 'range' (LSP format)
            - error: str (if failed)
        """
        # TODO: Convert file_path to URI
        # TODO: Send textDocument/definition request
        # TODO: Parse response
        # TODO: Return formatted result
        pass

    def find_references(self, file_path: str, line: int, column: int,
                       include_declaration: bool = True) -> Dict[str, Any]:
        """
        Find all references to a symbol using LSP textDocument/references.

        Args:
            file_path: Relative or absolute path to source file
            line: Line number (1-based)
            column: Column number (1-based)
            include_declaration: Whether to include the declaration itself

        Returns:
            Dict containing:
            - success: bool
            - references: List[Dict] with 'uri', 'range' (LSP format)
            - error: str (if failed)
        """
        # TODO: Convert file_path to URI
        # TODO: Send textDocument/references request with includeDeclaration
        # TODO: Parse response
        # TODO: Return formatted result
        pass

    def prepare_call_hierarchy(self, file_path: str, line: int, column: int) -> Dict[str, Any]:
        """
        Prepare call hierarchy item using LSP textDocument/prepareCallHierarchy.

        This is the first step before querying incoming/outgoing calls.

        Args:
            file_path: Relative or absolute path to source file
            line: Line number (1-based)
            column: Column number (1-based)

        Returns:
            Dict containing:
            - success: bool
            - items: List[Dict] with call hierarchy items (LSP format)
            - error: str (if failed)
        """
        # TODO: Convert file_path to URI
        # TODO: Send textDocument/prepareCallHierarchy request
        # TODO: Parse response
        # TODO: Return formatted result
        pass

    def call_hierarchy_incoming(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get incoming calls (callers) using LSP callHierarchy/incomingCalls.

        Args:
            item: Call hierarchy item from prepareCallHierarchy

        Returns:
            Dict containing:
            - success: bool
            - calls: List[Dict] with incoming call info (LSP format)
            - error: str (if failed)
        """
        # TODO: Send callHierarchy/incomingCalls request
        # TODO: Parse response
        # TODO: Return formatted result
        pass

    def call_hierarchy_outgoing(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get outgoing calls (callees) using LSP callHierarchy/outgoingCalls.

        Args:
            item: Call hierarchy item from prepareCallHierarchy

        Returns:
            Dict containing:
            - success: bool
            - calls: List[Dict] with outgoing call info (LSP format)
            - error: str (if failed)
        """
        # TODO: Send callHierarchy/outgoingCalls request
        # TODO: Parse response
        # TODO: Return formatted result
        pass

    def hover(self, file_path: str, line: int, column: int) -> Dict[str, Any]:
        """
        Get hover information using LSP textDocument/hover.

        Args:
            file_path: Relative or absolute path to source file
            line: Line number (1-based)
            column: Column number (1-based)

        Returns:
            Dict containing:
            - success: bool
            - contents: str or List (hover markup content)
            - range: Dict (optional range for hover)
            - error: str (if failed)
        """
        # TODO: Convert file_path to URI
        # TODO: Send textDocument/hover request
        # TODO: Parse response (handle MarkupContent)
        # TODO: Return formatted result
        pass


class FindFunctionDefTool(AgentTool):
    """
    Find C/C++ function definition location and source code.

    This tool helps locate function definitions by name and returns
    the complete source code with file location information.
    """

    def __init__(self, repo_path: str, compile_commands_path: str, clangd_path: str = "clangd"):
        """
        Initialize FindFunctionDefTool.

        Args:
            repo_path: Absolute path to the repository root
            compile_commands_path: Path to compile_commands.json
            clangd_path: Path to clangd executable
        """
        self.repo_path = Path(repo_path).resolve()
        self.compile_commands_path = Path(compile_commands_path).resolve()
        self.clangd_path = clangd_path
        # TODO: Get or create ClangdManager instance
        pass

    def name(self) -> str:
        return "find_function_definition"

    def description(self) -> str:
        return (
            "Find the definition of a C/C++ function by name. "
            "Returns the file path, start/end line numbers, and complete function source code. "
            "Optionally provide a context file to disambiguate functions with the same name. "
            "Requires clangd LSP server and compile_commands.json for accurate results."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "function_name": {
                "type": "string",
                "description": "Name of the function to find (e.g., 'main', 'parse_input', 'calculate_sum')",
                "required": True
            },
            "context_file": {
                "type": "string",
                "description": (
                    "Optional: Path to file containing the function (relative to repo root). "
                    "Use this to disambiguate when multiple functions have the same name. "
                    "Example: 'src/parser.c'"
                ),
                "required": False
            }
        }

    def execute(self, function_name: str, context_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute function definition search.

        Args:
            function_name: Name of the function to find
            context_file: Optional file path to narrow search

        Returns:
            Dict containing:
            - success: bool
            - file_path: str (relative to repo, if found)
            - start_line: int (1-based, if found)
            - end_line: int (1-based, if found)
            - source_code: str (complete function source, if found)
            - error: str (if failed)
        """
        # TODO: If context_file provided, search within that file
        # TODO: Otherwise, search across entire repository (using workspace symbol search)
        # TODO: Use clangd to find symbol definition
        # TODO: Extract function source code from file
        # TODO: Return formatted result
        pass


class FindReferencesTool(AgentTool):
    """
    Find all references to a function (callers).

    Given a function's location, finds all places where it's called.
    """

    def __init__(self, repo_path: str, compile_commands_path: str, clangd_path: str = "clangd"):
        """
        Initialize FindReferencesTool.

        Args:
            repo_path: Absolute path to the repository root
            compile_commands_path: Path to compile_commands.json
            clangd_path: Path to clangd executable
        """
        self.repo_path = Path(repo_path).resolve()
        self.compile_commands_path = Path(compile_commands_path).resolve()
        self.clangd_path = clangd_path
        # TODO: Get or create ClangdManager instance
        pass

    def name(self) -> str:
        return "find_function_references"

    def description(self) -> str:
        return (
            "Find all locations where a function is called (callers/references). "
            "Returns a list of call sites with file paths, line numbers, and code snippets. "
            "Requires the exact location of the function definition. "
            "Use find_function_definition first to get the location if you only have the function name."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "file_path": {
                "type": "string",
                "description": "Path to file containing the function definition (relative to repo root)",
                "required": True
            },
            "line": {
                "type": "integer",
                "description": "Line number of the function definition (1-based)",
                "required": True
            },
            "column": {
                "type": "integer",
                "description": "Column number of the function name (1-based, default: 1)",
                "required": False
            }
        }

    def execute(self, file_path: str, line: int, column: int = 1) -> Dict[str, Any]:
        """
        Execute reference search.

        Args:
            file_path: Path to file containing the function (relative to repo)
            line: Line number of function definition
            column: Column number of function name

        Returns:
            Dict containing:
            - success: bool
            - references: List[Dict] with 'file', 'line', 'column', 'code_snippet'
            - count: int (number of references)
            - error: str (if failed)
        """
        # TODO: Use ClangdManager.find_references()
        # TODO: For each reference, extract code snippet from file
        # TODO: Format and return results
        pass


class GetCallHierarchyTool(AgentTool):
    """
    Get call hierarchy for a function (callees - functions it calls).

    Given a function's location, finds all functions called by it.
    """

    def __init__(self, repo_path: str, compile_commands_path: str, clangd_path: str = "clangd"):
        """
        Initialize GetCallHierarchyTool.

        Args:
            repo_path: Absolute path to the repository root
            compile_commands_path: Path to compile_commands.json
            clangd_path: Path to clangd executable
        """
        self.repo_path = Path(repo_path).resolve()
        self.compile_commands_path = Path(compile_commands_path).resolve()
        self.clangd_path = clangd_path
        # TODO: Get or create ClangdManager instance
        pass

    def name(self) -> str:
        return "get_call_hierarchy"

    def description(self) -> str:
        return (
            "Get all functions called by a specific function (callees/outgoing calls). "
            "Returns a list of called functions with their locations. "
            "Useful for understanding what a function does internally and its dependencies. "
            "Requires the exact location of the function definition."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "file_path": {
                "type": "string",
                "description": "Path to file containing the function definition (relative to repo root)",
                "required": True
            },
            "line": {
                "type": "integer",
                "description": "Line number of the function definition (1-based)",
                "required": True
            },
            "column": {
                "type": "integer",
                "description": "Column number of the function name (1-based, default: 1)",
                "required": False
            }
        }

    def execute(self, file_path: str, line: int, column: int = 1) -> Dict[str, Any]:
        """
        Execute call hierarchy query.

        Args:
            file_path: Path to file containing the function (relative to repo)
            line: Line number of function definition
            column: Column number of function name

        Returns:
            Dict containing:
            - success: bool
            - callees: List[Dict] with 'function_name', 'file', 'line', 'column'
            - count: int (number of callees)
            - error: str (if failed)
        """
        # TODO: Use ClangdManager.prepare_call_hierarchy()
        # TODO: Use ClangdManager.call_hierarchy_outgoing()
        # TODO: Format and return results
        pass


class GetHoverInfoTool(AgentTool):
    """
    Get type and documentation information for a symbol.

    Provides quick type information without needing to read full definitions.
    """

    def __init__(self, repo_path: str, compile_commands_path: str, clangd_path: str = "clangd"):
        """
        Initialize GetHoverInfoTool.

        Args:
            repo_path: Absolute path to the repository root
            compile_commands_path: Path to compile_commands.json
            clangd_path: Path to clangd executable
        """
        self.repo_path = Path(repo_path).resolve()
        self.compile_commands_path = Path(compile_commands_path).resolve()
        self.clangd_path = clangd_path
        # TODO: Get or create ClangdManager instance
        pass

    def name(self) -> str:
        return "get_symbol_hover_info"

    def description(self) -> str:
        return (
            "Get type information and documentation for a symbol (function, variable, type). "
            "Returns the symbol's type signature and any available documentation comments. "
            "Useful for quickly understanding what a symbol is without reading its full definition. "
            "Works on any symbol at a specific location in the code."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "file_path": {
                "type": "string",
                "description": "Path to file containing the symbol (relative to repo root)",
                "required": True
            },
            "line": {
                "type": "integer",
                "description": "Line number where the symbol appears (1-based)",
                "required": True
            },
            "column": {
                "type": "integer",
                "description": "Column number of the symbol (1-based, default: 1)",
                "required": False
            }
        }

    def execute(self, file_path: str, line: int, column: int = 1) -> Dict[str, Any]:
        """
        Execute hover query.

        Args:
            file_path: Path to file containing the symbol (relative to repo)
            line: Line number of the symbol
            column: Column number of the symbol

        Returns:
            Dict containing:
            - success: bool
            - type_info: str (type signature)
            - documentation: str (if available)
            - error: str (if failed)
        """
        # TODO: Use ClangdManager.hover()
        # TODO: Parse hover contents (handle markdown/plaintext)
        # TODO: Extract type and documentation
        # TODO: Return formatted result
        pass
