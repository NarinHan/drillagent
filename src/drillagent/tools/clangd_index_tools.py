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

import json
import os
import subprocess
import threading
import re
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import quote, unquote
from urllib.request import pathname2url, url2pathname

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

    _instance: Optional['ClangdManager'] = None
    _lock = threading.Lock()

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

        # Validate paths
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {repo_path}")
        if not self.compile_commands_path.exists():
            raise ValueError(f"compile_commands.json not found: {compile_commands_path}")

        # LSP process and communication state
        self._process: Optional[subprocess.Popen] = None
        self._request_id = 0
        self._pending_requests: Dict[int, threading.Event] = {}
        self._responses: Dict[int, Any] = {}
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False
        self._comm_lock = threading.Lock()

        # Track opened documents to avoid duplicate didOpen
        self._opened_documents: set = set()

    @classmethod
    def get_instance(cls, repo_path: str, compile_commands_path: str, clangd_path: str = "clangd") -> 'ClangdManager':
        """
        Get or create ClangdManager singleton instance.

        Args:
            repo_path: Absolute path to the repository root
            compile_commands_path: Path to compile_commands.json
            clangd_path: Path to clangd executable

        Returns:
            ClangdManager instance
        """
        with cls._lock:
            # Check if existing instance needs to be replaced (different paths)
            if cls._instance is not None:
                if (cls._instance.repo_path != Path(repo_path).resolve() or
                    cls._instance.compile_commands_path != Path(compile_commands_path).resolve()):
                    # Different paths, need to reset
                    cls._instance.stop()
                    cls._instance = None

            if cls._instance is None:
                cls._instance = cls(repo_path, compile_commands_path, clangd_path)

            return cls._instance

    @classmethod
    def reset_instance(cls):
        """
        Reset singleton instance.
        Useful when switching to a different repository or commit.
        """
        with cls._lock:
            if cls._instance is not None:
                cls._instance.stop()
                cls._instance = None

    def start(self):
        """
        Start clangd LSP server process.

        Raises:
            RuntimeError: If clangd fails to start
        """
        if self._running:
            return

        try:
            # Start clangd subprocess with stdio communication
            # --compile-commands-dir specifies where to find compile_commands.json
            compile_commands_dir = str(self.compile_commands_path.parent)

            cmd = [
                self.clangd_path,
                f"--compile-commands-dir={compile_commands_dir}",
                "--background-index",  # Enable background indexing
                "--clang-tidy=false",  # Disable clang-tidy for speed
                "--header-insertion=never",  # Don't auto-insert headers
                "-j=4",  # Use 4 worker threads
            ]

            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.repo_path)
            )

            self._running = True

            # Start reader thread
            self._reader_thread = threading.Thread(target=self._read_responses, daemon=True)
            self._reader_thread.start()

            # Send LSP initialize request
            init_result = self._send_request("initialize", {
                "processId": os.getpid(),
                "rootUri": self._path_to_uri(str(self.repo_path)),
                "rootPath": str(self.repo_path),
                "capabilities": {
                    "textDocument": {
                        "hover": {"contentFormat": ["markdown", "plaintext"]},
                        "definition": {"linkSupport": True},
                        "references": {},
                        "callHierarchy": {},
                        "synchronization": {
                            "didOpen": True,
                            "didClose": True,
                        }
                    },
                    "workspace": {
                        "symbol": {"symbolKind": {"valueSet": list(range(1, 27))}},
                        "workspaceFolders": True,
                    }
                },
                "workspaceFolders": [
                    {"uri": self._path_to_uri(str(self.repo_path)), "name": self.repo_path.name}
                ]
            })

            if init_result is None:
                raise RuntimeError("Failed to initialize clangd - no response received")

            # Send initialized notification
            self._send_notification("initialized", {})

        except FileNotFoundError:
            self._running = False
            raise RuntimeError(f"clangd executable not found: {self.clangd_path}")
        except Exception as e:
            self._running = False
            if self._process:
                self._process.kill()
                self._process = None
            raise RuntimeError(f"Failed to start clangd: {e}")

    def stop(self):
        """
        Stop clangd LSP server process.
        """
        if not self._running:
            return

        self._running = False

        try:
            # Send LSP shutdown request
            self._send_request("shutdown", None, timeout=5)
            # Send exit notification
            self._send_notification("exit", None)
        except Exception:
            pass  # Ignore errors during shutdown

        # Terminate process
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

        # Clear state
        self._opened_documents.clear()
        self._pending_requests.clear()
        self._responses.clear()

    def restart(self):
        """
        Restart clangd LSP server.

        Useful when switching git commits - forces re-indexing.
        """
        self.stop()
        self.start()

    def is_running(self) -> bool:
        """
        Check if clangd process is running.

        Returns:
            True if running, False otherwise
        """
        return self._running and self._process is not None and self._process.poll() is None

    def _path_to_uri(self, file_path: str) -> str:
        """Convert file path to file:// URI."""
        path = Path(file_path).resolve()
        return "file://" + pathname2url(str(path))

    def _uri_to_path(self, uri: str) -> str:
        """Convert file:// URI to file path."""
        if uri.startswith("file://"):
            return url2pathname(uri[7:])
        return uri

    def _read_responses(self):
        """Background thread that reads LSP responses from clangd."""
        buffer = b""

        while self._running and self._process and self._process.stdout:
            try:
                # Read data
                chunk = self._process.stdout.read(1)
                if not chunk:
                    break
                buffer += chunk

                # Try to parse Content-Length header
                while b"\r\n\r\n" in buffer:
                    header_end = buffer.index(b"\r\n\r\n")
                    header = buffer[:header_end].decode("utf-8")

                    # Parse Content-Length
                    content_length = None
                    for line in header.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            content_length = int(line.split(":")[1].strip())
                            break

                    if content_length is None:
                        # Invalid header, skip
                        buffer = buffer[header_end + 4:]
                        continue

                    # Check if we have the full content
                    total_length = header_end + 4 + content_length
                    if len(buffer) < total_length:
                        # Need more data
                        break

                    # Extract content
                    content = buffer[header_end + 4:total_length].decode("utf-8")
                    buffer = buffer[total_length:]

                    # Parse JSON
                    try:
                        message = json.loads(content)
                        self._handle_message(message)
                    except json.JSONDecodeError:
                        pass  # Ignore malformed messages

            except Exception:
                break

    def _handle_message(self, message: Dict[str, Any]):
        """Handle incoming LSP message."""
        if "id" in message and "method" not in message:
            # This is a response to a request we sent
            request_id = message["id"]
            with self._comm_lock:
                if request_id in self._pending_requests:
                    if "result" in message:
                        self._responses[request_id] = message["result"]
                    elif "error" in message:
                        self._responses[request_id] = {"_error": message["error"]}
                    else:
                        self._responses[request_id] = None
                    self._pending_requests[request_id].set()

    def _send_message(self, message: Dict[str, Any]):
        """Send a JSON-RPC message to clangd."""
        if not self._process or not self._process.stdin:
            raise RuntimeError("clangd process not running")

        content = json.dumps(message)
        header = f"Content-Length: {len(content)}\r\n\r\n"

        self._process.stdin.write(header.encode("utf-8"))
        self._process.stdin.write(content.encode("utf-8"))
        self._process.stdin.flush()

    def _send_request(self, method: str, params: Any, timeout: float = 30) -> Any:
        """
        Send LSP request and wait for response.

        Args:
            method: LSP method name
            params: Request parameters
            timeout: Timeout in seconds

        Returns:
            Response result or None
        """
        with self._comm_lock:
            self._request_id += 1
            request_id = self._request_id
            event = threading.Event()
            self._pending_requests[request_id] = event

        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params
        }

        self._send_message(message)

        # Wait for response
        if event.wait(timeout):
            with self._comm_lock:
                result = self._responses.pop(request_id, None)
                self._pending_requests.pop(request_id, None)

                if isinstance(result, dict) and "_error" in result:
                    return None  # Return None on error
                return result
        else:
            # Timeout
            with self._comm_lock:
                self._pending_requests.pop(request_id, None)
            return None

    def _send_notification(self, method: str, params: Any):
        """Send LSP notification (no response expected)."""
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
        self._send_message(message)

    def _ensure_document_open(self, file_path: str):
        """Ensure a document is opened in clangd."""
        uri = self._path_to_uri(file_path)

        if uri in self._opened_documents:
            return

        # Read file content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception:
            return

        # Determine language ID
        suffix = Path(file_path).suffix.lower()
        language_id = {
            '.c': 'c',
            '.h': 'c',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.hpp': 'cpp',
            '.hxx': 'cpp',
        }.get(suffix, 'cpp')

        # Send didOpen notification
        self._send_notification("textDocument/didOpen", {
            "textDocument": {
                "uri": uri,
                "languageId": language_id,
                "version": 1,
                "text": content
            }
        })

        self._opened_documents.add(uri)

    def _resolve_file_path(self, file_path: str) -> str:
        """Resolve file path relative to repo if needed."""
        p = Path(file_path)
        if p.is_absolute():
            return str(p.resolve())
        else:
            return str((self.repo_path / file_path).resolve())

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
        if not self.is_running():
            self.start()

        resolved_path = self._resolve_file_path(file_path)
        if not Path(resolved_path).exists():
            return {"success": False, "locations": [], "error": f"File not found: {file_path}"}

        self._ensure_document_open(resolved_path)
        uri = self._path_to_uri(resolved_path)

        # LSP uses 0-based line/column
        result = self._send_request("textDocument/definition", {
            "textDocument": {"uri": uri},
            "position": {"line": line - 1, "character": column - 1}
        })

        if result is None:
            return {"success": False, "locations": [], "error": "No definition found or request timed out"}

        # Result can be Location, Location[], or LocationLink[]
        locations = []
        if isinstance(result, dict):
            locations = [result]
        elif isinstance(result, list):
            locations = result

        # Normalize LocationLink to Location format
        normalized = []
        for loc in locations:
            if "targetUri" in loc:
                # LocationLink format
                normalized.append({
                    "uri": loc["targetUri"],
                    "range": loc.get("targetRange", loc.get("targetSelectionRange", {}))
                })
            else:
                # Location format
                normalized.append(loc)

        return {"success": True, "locations": normalized}

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
        if not self.is_running():
            self.start()

        resolved_path = self._resolve_file_path(file_path)
        if not Path(resolved_path).exists():
            return {"success": False, "references": [], "error": f"File not found: {file_path}"}

        self._ensure_document_open(resolved_path)
        uri = self._path_to_uri(resolved_path)

        result = self._send_request("textDocument/references", {
            "textDocument": {"uri": uri},
            "position": {"line": line - 1, "character": column - 1},
            "context": {"includeDeclaration": include_declaration}
        })

        if result is None:
            return {"success": False, "references": [], "error": "No references found or request timed out"}

        return {"success": True, "references": result if isinstance(result, list) else []}

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
        if not self.is_running():
            self.start()

        resolved_path = self._resolve_file_path(file_path)
        if not Path(resolved_path).exists():
            return {"success": False, "items": [], "error": f"File not found: {file_path}"}

        self._ensure_document_open(resolved_path)
        uri = self._path_to_uri(resolved_path)

        result = self._send_request("textDocument/prepareCallHierarchy", {
            "textDocument": {"uri": uri},
            "position": {"line": line - 1, "character": column - 1}
        })

        if result is None:
            return {"success": False, "items": [], "error": "Could not prepare call hierarchy or request timed out"}

        return {"success": True, "items": result if isinstance(result, list) else []}

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
        if not self.is_running():
            self.start()

        result = self._send_request("callHierarchy/incomingCalls", {"item": item})

        if result is None:
            return {"success": False, "calls": [], "error": "No incoming calls found or request timed out"}

        return {"success": True, "calls": result if isinstance(result, list) else []}

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
        if not self.is_running():
            self.start()

        result = self._send_request("callHierarchy/outgoingCalls", {"item": item})

        if result is None:
            return {"success": False, "calls": [], "error": "No outgoing calls found or request timed out"}

        return {"success": True, "calls": result if isinstance(result, list) else []}

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
        if not self.is_running():
            self.start()

        resolved_path = self._resolve_file_path(file_path)
        if not Path(resolved_path).exists():
            return {"success": False, "contents": "", "error": f"File not found: {file_path}"}

        self._ensure_document_open(resolved_path)
        uri = self._path_to_uri(resolved_path)

        result = self._send_request("textDocument/hover", {
            "textDocument": {"uri": uri},
            "position": {"line": line - 1, "character": column - 1}
        })

        if result is None:
            return {"success": False, "contents": "", "error": "No hover info found or request timed out"}

        # Parse hover contents
        contents = result.get("contents", "")
        if isinstance(contents, dict):
            # MarkupContent format
            contents = contents.get("value", "")
        elif isinstance(contents, list):
            # Array of MarkedString
            parts = []
            for item in contents:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(item.get("value", ""))
            contents = "\n".join(parts)

        return {
            "success": True,
            "contents": contents,
            "range": result.get("range")
        }

    def workspace_symbol(self, query: str) -> Dict[str, Any]:
        """
        Search for symbols in the workspace using LSP workspace/symbol.

        Args:
            query: Symbol name or partial name to search for

        Returns:
            Dict containing:
            - success: bool
            - symbols: List[Dict] with symbol information
            - error: str (if failed)
        """
        if not self.is_running():
            self.start()

        result = self._send_request("workspace/symbol", {"query": query})

        if result is None:
            return {"success": False, "symbols": [], "error": "Symbol search failed or timed out"}

        return {"success": True, "symbols": result if isinstance(result, list) else []}


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
        self._manager: Optional[ClangdManager] = None

    def _get_manager(self) -> ClangdManager:
        """Get or create ClangdManager instance."""
        if self._manager is None:
            self._manager = ClangdManager.get_instance(
                str(self.repo_path),
                str(self.compile_commands_path),
                self.clangd_path
            )
        return self._manager

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
        try:
            manager = self._get_manager()

            # If context_file provided, search within that file
            if context_file:
                return self._search_in_file(manager, function_name, context_file)
            else:
                # Use workspace symbol search to find the function
                return self._search_workspace(manager, function_name)

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to find function definition: {str(e)}",
                "function_name": function_name
            }

    def _search_in_file(self, manager: ClangdManager, function_name: str,
                        context_file: str) -> Dict[str, Any]:
        """Search for function definition within a specific file."""
        resolved_path = str((self.repo_path / context_file).resolve())

        if not Path(resolved_path).exists():
            return {
                "success": False,
                "error": f"File not found: {context_file}",
                "function_name": function_name
            }

        # Read the file and search for the function definition pattern
        try:
            with open(resolved_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to read file: {e}",
                "function_name": function_name
            }

        # Pattern to match function definition (simplified)
        # This looks for "function_name(" at the start of a potential function def
        func_pattern = re.compile(
            rf'\b{re.escape(function_name)}\s*\([^;]*\)\s*(?:const\s*)?(?:override\s*)?(?:final\s*)?\s*\{{',
            re.MULTILINE
        )

        # Find potential function definition locations
        for i, line in enumerate(lines):
            if function_name in line and '(' in line:
                # Check if this looks like a function definition (not a call)
                # Try to use clangd to verify by getting definition at this position
                col = line.find(function_name) + 1

                # Use hover to get info about this symbol
                hover_result = manager.hover(resolved_path, i + 1, col)
                if hover_result.get("success") and hover_result.get("contents"):
                    contents = hover_result["contents"]
                    # Check if this is a function definition (not a call or declaration)
                    if function_name in contents and ('function' in contents.lower() or
                                                       '(' in contents):
                        # Found potential match, now extract the full function
                        return self._extract_function_source(
                            lines, i, function_name, context_file
                        )

        # Fallback: try workspace symbol search
        return self._search_workspace(manager, function_name, context_file)

    def _search_workspace(self, manager: ClangdManager, function_name: str,
                          preferred_file: Optional[str] = None) -> Dict[str, Any]:
        """Search for function in workspace using workspace/symbol."""
        result = manager.workspace_symbol(function_name)

        if not result.get("success") or not result.get("symbols"):
            return {
                "success": False,
                "error": f"Function '{function_name}' not found in workspace",
                "function_name": function_name
            }

        # Filter for functions (SymbolKind.Function = 12, SymbolKind.Method = 6)
        function_kinds = {6, 12}
        matching_symbols = [
            s for s in result["symbols"]
            if s.get("kind") in function_kinds and s.get("name") == function_name
        ]

        if not matching_symbols:
            # Try partial match
            matching_symbols = [
                s for s in result["symbols"]
                if s.get("kind") in function_kinds and function_name in s.get("name", "")
            ]

        if not matching_symbols:
            return {
                "success": False,
                "error": f"No function named '{function_name}' found",
                "function_name": function_name
            }

        # If preferred_file specified, try to find match in that file
        chosen_symbol = matching_symbols[0]
        if preferred_file:
            for sym in matching_symbols:
                loc = sym.get("location", {})
                uri = loc.get("uri", "")
                if preferred_file in uri:
                    chosen_symbol = sym
                    break

        # Extract location info
        location = chosen_symbol.get("location", {})
        uri = location.get("uri", "")
        range_info = location.get("range", {})
        start = range_info.get("start", {})

        file_path = manager._uri_to_path(uri)
        start_line = start.get("line", 0) + 1  # Convert to 1-based

        # Read and extract function source
        try:
            rel_path = str(Path(file_path).relative_to(self.repo_path))
        except ValueError:
            rel_path = file_path

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.read().split('\n')

            return self._extract_function_source(lines, start_line - 1, function_name, rel_path)
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to read source file: {e}",
                "function_name": function_name,
                "file_path": rel_path,
                "start_line": start_line
            }

    def _extract_function_source(self, lines: List[str], start_idx: int,
                                  function_name: str, file_path: str) -> Dict[str, Any]:
        """Extract complete function source code from lines."""
        # Find the function start (line with function name and opening brace)
        func_start = start_idx

        # Look backwards for any comments/attributes
        while func_start > 0 and (lines[func_start - 1].strip().startswith('//') or
                                   lines[func_start - 1].strip().startswith('/*') or
                                   lines[func_start - 1].strip().startswith('*') or
                                   lines[func_start - 1].strip().startswith('@') or
                                   lines[func_start - 1].strip().startswith('__')):
            func_start -= 1

        # Find opening brace
        brace_count = 0
        found_open_brace = False
        end_idx = start_idx

        for i in range(start_idx, len(lines)):
            line = lines[i]
            for char in line:
                if char == '{':
                    brace_count += 1
                    found_open_brace = True
                elif char == '}':
                    brace_count -= 1

            if found_open_brace and brace_count == 0:
                end_idx = i
                break
        else:
            # Didn't find closing brace, limit to 500 lines
            end_idx = min(start_idx + 500, len(lines) - 1)

        # Extract source
        source_lines = lines[func_start:end_idx + 1]

        # Format with line numbers
        numbered_lines = []
        for i, line in enumerate(source_lines):
            line_num = func_start + i + 1  # 1-based
            numbered_lines.append(f"{line_num:4d} | {line}")

        source_code = '\n'.join(numbered_lines)

        # Truncate if too long
        if len(source_lines) > 400:
            numbered_lines = numbered_lines[:400]
            source_code = '\n'.join(numbered_lines)
            source_code += f"\n... (truncated, {len(source_lines)} total lines)"

        return {
            "success": True,
            "function_name": function_name,
            "file_path": file_path,
            "start_line": func_start + 1,  # 1-based
            "end_line": end_idx + 1,  # 1-based
            "source_code": source_code,
            "total_lines": len(source_lines)
        }


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
        self._manager: Optional[ClangdManager] = None

    def _get_manager(self) -> ClangdManager:
        """Get or create ClangdManager instance."""
        if self._manager is None:
            self._manager = ClangdManager.get_instance(
                str(self.repo_path),
                str(self.compile_commands_path),
                self.clangd_path
            )
        return self._manager

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
        try:
            manager = self._get_manager()

            result = manager.find_references(file_path, line, column, include_declaration=False)

            if not result.get("success"):
                return {
                    "success": False,
                    "references": [],
                    "count": 0,
                    "error": result.get("error", "Failed to find references")
                }

            # Format references with code snippets
            formatted_refs = []
            for ref in result.get("references", []):
                uri = ref.get("uri", "")
                range_info = ref.get("range", {})
                start = range_info.get("start", {})

                ref_file = manager._uri_to_path(uri)
                ref_line = start.get("line", 0) + 1  # 1-based
                ref_col = start.get("character", 0) + 1  # 1-based

                # Get relative path
                try:
                    rel_path = str(Path(ref_file).relative_to(self.repo_path))
                except ValueError:
                    rel_path = ref_file

                # Extract code snippet
                snippet = ""
                try:
                    with open(ref_file, 'r', encoding='utf-8', errors='replace') as f:
                        lines = f.read().split('\n')
                        if 0 <= ref_line - 1 < len(lines):
                            # Get context: 1 line before and after
                            start_ctx = max(0, ref_line - 2)
                            end_ctx = min(len(lines), ref_line + 1)
                            ctx_lines = []
                            for i in range(start_ctx, end_ctx):
                                prefix = ">" if i == ref_line - 1 else " "
                                ctx_lines.append(f"{prefix}{i+1:4d} | {lines[i]}")
                            snippet = '\n'.join(ctx_lines)
                except Exception:
                    pass

                formatted_refs.append({
                    "file": rel_path,
                    "line": ref_line,
                    "column": ref_col,
                    "code_snippet": snippet
                })

            # Limit results to prevent overwhelming output
            max_results = 50
            limited = len(formatted_refs) > max_results

            return {
                "success": True,
                "references": formatted_refs[:max_results],
                "count": len(formatted_refs[:max_results]),
                "total_found": len(formatted_refs),
                "limited": limited,
                "message": f"Found {len(formatted_refs)} reference(s)" +
                          (f" (showing first {max_results})" if limited else "")
            }

        except Exception as e:
            return {
                "success": False,
                "references": [],
                "count": 0,
                "error": f"Failed to find references: {str(e)}"
            }


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
        self._manager: Optional[ClangdManager] = None

    def _get_manager(self) -> ClangdManager:
        """Get or create ClangdManager instance."""
        if self._manager is None:
            self._manager = ClangdManager.get_instance(
                str(self.repo_path),
                str(self.compile_commands_path),
                self.clangd_path
            )
        return self._manager

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
        try:
            manager = self._get_manager()

            # Step 1: Prepare call hierarchy
            prep_result = manager.prepare_call_hierarchy(file_path, line, column)

            if not prep_result.get("success") or not prep_result.get("items"):
                return {
                    "success": False,
                    "callees": [],
                    "count": 0,
                    "error": prep_result.get("error", "Could not prepare call hierarchy for this location")
                }

            # Step 2: Get outgoing calls for each item
            all_callees = []
            for item in prep_result["items"]:
                outgoing_result = manager.call_hierarchy_outgoing(item)

                if outgoing_result.get("success"):
                    for call in outgoing_result.get("calls", []):
                        callee = call.get("to", {})
                        uri = callee.get("uri", "")
                        range_info = callee.get("range", {})
                        start = range_info.get("start", {})

                        callee_file = manager._uri_to_path(uri)
                        callee_line = start.get("line", 0) + 1
                        callee_col = start.get("character", 0) + 1

                        # Get relative path
                        try:
                            rel_path = str(Path(callee_file).relative_to(self.repo_path))
                        except ValueError:
                            rel_path = callee_file

                        all_callees.append({
                            "function_name": callee.get("name", "unknown"),
                            "file": rel_path,
                            "line": callee_line,
                            "column": callee_col,
                            "kind": callee.get("kind", 0)  # LSP SymbolKind
                        })

            # Remove duplicates (same function called multiple times)
            seen = set()
            unique_callees = []
            for callee in all_callees:
                key = (callee["function_name"], callee["file"], callee["line"])
                if key not in seen:
                    seen.add(key)
                    unique_callees.append(callee)

            return {
                "success": True,
                "callees": unique_callees,
                "count": len(unique_callees),
                "message": f"Found {len(unique_callees)} unique function(s) called"
            }

        except Exception as e:
            return {
                "success": False,
                "callees": [],
                "count": 0,
                "error": f"Failed to get call hierarchy: {str(e)}"
            }


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
        self._manager: Optional[ClangdManager] = None

    def _get_manager(self) -> ClangdManager:
        """Get or create ClangdManager instance."""
        if self._manager is None:
            self._manager = ClangdManager.get_instance(
                str(self.repo_path),
                str(self.compile_commands_path),
                self.clangd_path
            )
        return self._manager

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
        try:
            manager = self._get_manager()

            result = manager.hover(file_path, line, column)

            if not result.get("success"):
                return {
                    "success": False,
                    "type_info": "",
                    "documentation": "",
                    "error": result.get("error", "Failed to get hover info")
                }

            contents = result.get("contents", "")

            # Try to parse type info and documentation from contents
            # clangd typically returns markdown with code blocks for type info
            type_info = ""
            documentation = ""

            if contents:
                lines = contents.split('\n')
                in_code_block = False
                code_lines = []
                doc_lines = []

                for line_content in lines:
                    if line_content.startswith('```'):
                        in_code_block = not in_code_block
                        continue

                    if in_code_block:
                        code_lines.append(line_content)
                    else:
                        # Filter out empty lines and separator lines
                        stripped = line_content.strip()
                        if stripped and stripped != '---':
                            doc_lines.append(line_content)

                type_info = '\n'.join(code_lines).strip()
                documentation = '\n'.join(doc_lines).strip()

                # If no code block found, use full contents as type_info
                if not type_info:
                    type_info = contents

            return {
                "success": True,
                "type_info": type_info,
                "documentation": documentation,
                "raw_contents": contents
            }

        except Exception as e:
            return {
                "success": False,
                "type_info": "",
                "documentation": "",
                "error": f"Failed to get hover info: {str(e)}"
            }
