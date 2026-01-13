import os
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, List, Optional

class AgentTool(ABC):
    """
    Base class for agent tools that can be called by LLMs.

    Each tool must define:
    - name: Unique identifier for the tool
    - description: Clear explanation for LLM to understand when to use it
    - parameters_schema: JSON schema defining expected parameters
    - execute: Implementation of the tool's functionality
    """

    @abstractmethod
    def name(self) -> str:
        """Return the unique name of this tool"""
        pass

    @abstractmethod
    def description(self) -> str:
        """
        Return a clear description of what this tool does and when to use it.
        This helps the LLM decide when to invoke this tool.
        """
        pass

    @abstractmethod
    def parameters_schema(self) -> Dict[str, Any]:
        """
        Return JSON schema describing the tool's parameters.
        Format:
        {
            "param_name": {
                "type": "string" | "integer" | "boolean" | "array" | "object",
                "description": "Clear description of this parameter",
                "required": True | False
            },
            ...
        }
        """
        pass

    @abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the tool with given parameters.
        Args:
            **kwargs: Parameters matching the schema
        Returns:
            Dict containing:
            - success: bool indicating if execution succeeded
            - Additional fields with results or error messages
        """
        pass

    def to_claude_schema(self) -> Dict[str, Any]:
        """
        Convert tool definition to Claude's tool format.
        See: https://docs.anthropic.com/claude/docs/tool-use
        """
        params_schema = self.parameters_schema()
        required_params = [
            name for name, spec in params_schema.items()
            if spec.get("required", False)
        ]

        # Remove 'required' from individual params (it goes in top-level)
        cleaned_params = {}
        for name, spec in params_schema.items():
            cleaned_spec = {k: v for k, v in spec.items() if k != "required"}
            cleaned_params[name] = cleaned_spec

        return {
            "name": self.name(),
            "description": self.description(),
            "input_schema": {
                "type": "object",
                "properties": cleaned_params,
                "required": required_params
            }
        }

    def to_openai_schema(self) -> Dict[str, Any]:
        """
        Convert tool definition to OpenAI's function calling format.
        See: https://platform.openai.com/docs/guides/function-calling
        """
        params_schema = self.parameters_schema()
        required_params = [
            name for name, spec in params_schema.items()
            if spec.get("required", False)
        ]

        # Remove 'required' from individual params
        cleaned_params = {}
        for name, spec in params_schema.items():
            cleaned_spec = {k: v for k, v in spec.items() if k != "required"}
            cleaned_params[name] = cleaned_spec

        return {
            "type": "function",
            "function": {
                "name": self.name(),
                "description": self.description(),
                "parameters": {
                    "type": "object",
                    "properties": cleaned_params,
                    "required": required_params
                }
            }
        }


class ReadFileTool(AgentTool):
    """
    Tool for reading source code files with line numbers.
    Useful for examining code mentioned in sanitizer reports or call traces.
    """

    def __init__(self, repo_path: str):
        """
        Initialize ReadFile tool.

        Args:
            repo_path: Absolute path to the repository root
        """
        self.repo_path = Path(repo_path).resolve()

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {repo_path}")

    def name(self) -> str:
        return "read_file"

    def description(self) -> str:
        return (
            "Read file contents in text mode (with line numbers) or hex mode (binary dump). "
            "\n\n"
            "TEXT MODE (default): Reads as UTF-8 text with line numbers. "
            "Use this for source code files mentioned in error messages, call traces, etc. "
            "Non-UTF-8 bytes are replaced with � (U+FFFD) to indicate binary content. "
            "\n\n"
            "HEX MODE (hex_mode=true): Reads as raw binary and returns hexadecimal dump. "
            "Use this for binary files, executables, or when you suspect binary data. "
            "Output format (16 bytes per line):\n"
            "00000000: 7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  .ELF............\n"
            "00000010: 02 00 3e 00 01 00 00 00 50 10 40 00 00 00 00 00  ..>.....P.@.....\n"
            "\n"
            "Use start_offset and read_length to examine specific byte ranges in hex mode."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "file_path": {
                "type": "string",
                "description": (
                    "Path to the file relative to repository root. "
                    "Examples: 'src/parser.c', 'lib/buffer.cpp', 'main.c'"
                ),
                "required": True
            },
            "start_line": {
                "type": "integer",
                "description": (
                    "Starting line number (1-indexed, inclusive). "
                    "If not specified, reads from the beginning. "
                    "Use this to focus on specific sections mentioned in traces. "
                    "Ignored if hex_mode is true."
                ),
                "required": False
            },
            "end_line": {
                "type": "integer",
                "description": (
                    "Ending line number (1-indexed, inclusive). "
                    "If not specified, reads up to 50 lines from start_line, "
                    "or entire file if start_line is also not specified. "
                    "Ignored if hex_mode is true."
                ),
                "required": False
            },
            "hex_mode": {
                "type": "boolean",
                "description": (
                    "If true, read file in binary mode and return hexadecimal dump. "
                    "Useful for examining binary files or detecting binary content. "
                    "When enabled, start_line/end_line are ignored; use start_offset/read_length instead."
                ),
                "required": False
            },
            "start_offset": {
                "type": "integer",
                "description": (
                    "Byte offset to start reading from (0-indexed). "
                    "Only used when hex_mode is true. Default: 0"
                ),
                "required": False
            },
            "read_length": {
                "type": "integer",
                "description": (
                    "Number of bytes to read. "
                    "Only used when hex_mode is true. "
                    "If not specified, reads up to 1024 bytes from start_offset."
                ),
                "required": False
            }
        }

    def execute(self, file_path: str, start_line: Optional[int] = None,
                end_line: Optional[int] = None, hex_mode: bool = False,
                start_offset: Optional[int] = None, read_length: Optional[int] = None) -> Dict[str, Any]:
        """
        Read file contents with optional line range or hex dump.
        Args:
            file_path: Relative path to file
            start_line: Optional starting line (1-indexed)
            end_line: Optional ending line (1-indexed, inclusive)
            hex_mode: If true, read in binary mode and return hex dump
            start_offset: Byte offset for hex mode (0-indexed)
            read_length: Number of bytes to read in hex mode
        Returns:
            Dict with success status, file content, and metadata
        """
        try:
            # Resolve file path
            full_path = self.repo_path / file_path

            # Check if file exists
            if not full_path.exists():
                return {
                    "success": False,
                    "error": f"File not found: {file_path}",
                    "file_path": file_path
                }

            if not full_path.is_file():
                return {
                    "success": False,
                    "error": f"Path is not a file: {file_path}",
                    "file_path": file_path
                }

            # Handle hex mode
            if hex_mode:
                return self._read_as_hex(full_path, file_path, start_offset, read_length)

            # Read file in text mode
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()

            total_lines = len(lines)

            # Determine line range to display
            if start_line is not None and end_line is not None:
                # Both specified: use exact range
                start_idx = max(0, start_line - 1)
                end_idx = min(total_lines, end_line)
                display_lines = lines[start_idx:end_idx]
                line_offset = start_line
            elif start_line is not None:
                # Only start specified: show 50 lines from start
                start_idx = max(0, start_line - 1)
                end_idx = min(total_lines, start_idx + 50)
                display_lines = lines[start_idx:end_idx]
                line_offset = start_line
            else:
                # Neither specified: show entire file (or first 200 lines if too large)
                if total_lines > 200:
                    display_lines = lines[:200]
                    truncated = True
                else:
                    display_lines = lines
                    truncated = False
                line_offset = 1

            # Format with line numbers
            content_lines = []
            for i, line in enumerate(display_lines):
                line_num = line_offset + i
                # Remove trailing newline for cleaner formatting
                line_content = line.rstrip('\n')
                content_lines.append(f"{line_num:4d} | {line_content}")

            content = '\n'.join(content_lines)

            result = {
                "success": True,
                "file_path": file_path,
                "content": content,
                "total_lines": total_lines,
                "displayed_lines": len(display_lines),
                "display_range": f"{line_offset}-{line_offset + len(display_lines) - 1}"
            }

            # Add truncation warning if applicable
            if start_line is None and end_line is None and total_lines > 200:
                result["truncated"] = True
                result["message"] = f"File has {total_lines} lines. Showing first 200. Use start_line/end_line to see more."

            return result

        except UnicodeDecodeError:
            return {
                "success": False,
                "error": "File contains binary data or unsupported encoding",
                "file_path": file_path
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to read file: {str(e)}",
                "file_path": file_path
            }

    def _read_as_hex(self, full_path: Path, file_path: str,
                     start_offset: Optional[int], read_length: Optional[int]) -> Dict[str, Any]:
        """
        Read file in binary mode and return hex dump.
        Args:
            full_path: Absolute path to file
            file_path: Relative path for display
            start_offset: Byte offset to start from
            read_length: Number of bytes to read
        Returns:
            Dict with success status and hex dump content
        """
        try:
            # Default values
            offset = start_offset if start_offset is not None else 0
            length = read_length if read_length is not None else 1024

            # Get file size
            file_size = full_path.stat().st_size

            # Validate offset
            if offset < 0:
                return {
                    "success": False,
                    "error": f"Invalid start_offset: {offset} (must be >= 0)",
                    "file_path": file_path
                }

            if offset >= file_size:
                return {
                    "success": False,
                    "error": f"start_offset {offset} exceeds file size {file_size}",
                    "file_path": file_path
                }

            # Read binary data
            with open(full_path, 'rb') as f:
                f.seek(offset)
                data = f.read(length)

            actual_length = len(data)

            # Generate hex dump
            hex_lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                addr = offset + i

                # Hex representation
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                # Pad to maintain alignment
                hex_part = hex_part.ljust(48)  # 16 bytes * 3 chars - 1 space

                # ASCII representation
                ascii_part = ''.join(
                    chr(b) if 32 <= b < 127 else '.'
                    for b in chunk
                )

                hex_lines.append(f"{addr:08x}: {hex_part}  {ascii_part}")

            hex_dump = '\n'.join(hex_lines)

            return {
                "success": True,
                "file_path": file_path,
                "content": hex_dump,
                "mode": "hex",
                "file_size": file_size,
                "start_offset": offset,
                "bytes_read": actual_length,
                "read_range": f"0x{offset:x}-0x{offset + actual_length - 1:x}",
                "message": f"Read {actual_length} bytes from offset {offset} (file size: {file_size} bytes)"
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to read file in hex mode: {str(e)}",
                "file_path": file_path
            }


class WriteFileTool(AgentTool):
    pass


class GrepTool(AgentTool):
    """
    Tool for searching code patterns across the repository.
    Useful for finding function definitions, symbol usages, or specific code patterns.
    """

    def __init__(self, repo_path: str):
        """
        Initialize Grep tool.
        Args:
            repo_path: Absolute path to the repository root
        """
        self.repo_path = Path(repo_path).resolve()

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {repo_path}")

        # Check if ripgrep is available (faster alternative)
        self.has_rg = self._check_ripgrep()

    def _check_ripgrep(self) -> bool:
        """Check if ripgrep (rg) is available"""
        try:
            subprocess.run(['rg', '--version'],
                          capture_output=True,
                          timeout=2)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def name(self) -> str:
        return "grep_code"

    def description(self) -> str:
        return (
            "Search for text patterns or regular expressions across the codebase. "
            "Use this to find function definitions, variable usages, or specific code patterns. "
            "Very useful for tracing function calls mentioned in sanitizer stack traces. "
            "Returns matching files with line numbers and surrounding context."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "pattern": {
                "type": "string",
                "description": (
                    "Search pattern (supports regex). "
                    "Examples: 'malloc', 'void.*parse', 'buffer\\[.*\\]', 'CVE-2024'"
                ),
                "required": True
            },
            "file_extension": {
                "type": "string",
                "description": (
                    "Filter by file extension (without dot). "
                    "Examples: 'c', 'cpp', 'h', 'py'. "
                    "If not specified, searches common source file types (c, cpp, h, hpp)."
                ),
                "required": False
            },
            "case_sensitive": {
                "type": "boolean",
                "description": "Whether search should be case-sensitive. Default: true",
                "required": False
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of matching lines to return. Default: 50",
                "required": False
            }
        }

    def execute(self, pattern: str, file_extension: Optional[str] = None,
                case_sensitive: bool = True, max_results: int = 50) -> Dict[str, Any]:
        """
        Search for pattern in codebase.
        Args:
            pattern: Search pattern (regex supported)
            file_extension: Optional file extension filter
            case_sensitive: Whether to match case
            max_results: Maximum results to return
        Returns:
            Dict with success status and matching results
        """
        try:
            if self.has_rg:
                return self._grep_with_ripgrep(pattern, file_extension,
                                               case_sensitive, max_results)
            else:
                return self._grep_with_native(pattern, file_extension,
                                              case_sensitive, max_results)
        except Exception as e:
            return {
                "success": False,
                "error": f"Search failed: {str(e)}",
                "pattern": pattern
            }

    def _grep_with_ripgrep(self, pattern: str, file_extension: Optional[str],
                          case_sensitive: bool, max_results: int) -> Dict[str, Any]:
        """Use ripgrep for fast searching"""
        # Note: We don't use --max-count because it limits PER FILE, not globally.
        # Global limiting is done in Python below (line ~421-422)
        cmd = ['rg', '-n', '--color', 'never']

        # Case sensitivity
        if not case_sensitive:
            cmd.append('-i')

        # File type filtering
        if file_extension:
            cmd.extend(['-g', f'*.{file_extension}'])
        else:
            # Default to common C/C++ extensions
            for ext in ['c', 'cpp', 'h', 'hpp', 'cc', 'cxx']:
                cmd.extend(['-g', f'*.{ext}'])

        cmd.append(pattern)
        cmd.append(str(self.repo_path))

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            matches = []
            for line in result.stdout.strip().split('\n'):
                if not line or ':' not in line:
                    continue

                # Format: filepath:line_num:content
                parts = line.split(':', 2)
                if len(parts) >= 3:
                    file_path = parts[0].replace(str(self.repo_path) + '/', '')
                    try:
                        line_num = int(parts[1])
                        content = parts[2].strip()
                        matches.append({
                            "file": file_path,
                            "line": line_num,
                            "content": content
                        })
                    except ValueError:
                        continue

                if len(matches) >= max_results:
                    break

            return {
                "success": True,
                "pattern": pattern,
                "matches": matches,
                "count": len(matches),
                "truncated": len(matches) >= max_results,
                "message": f"Found {len(matches)} matches" +
                          (f" (limited to {max_results})" if len(matches) >= max_results else "")
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Search timeout (>30s). Try a more specific pattern.",
                "pattern": pattern
            }

    def _grep_with_native(self, pattern: str, file_extension: Optional[str],
                         case_sensitive: bool, max_results: int) -> Dict[str, Any]:
        """Fallback using Python's built-in search (slower but portable)"""
        import re

        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            regex = re.compile(pattern, flags)
        except re.error as e:
            return {
                "success": False,
                "error": f"Invalid regex pattern: {str(e)}",
                "pattern": pattern
            }

        matches = []

        # Determine file extensions to search
        if file_extension:
            extensions = [f'.{file_extension}']
        else:
            extensions = ['.c', '.cpp', '.h', '.hpp', '.cc', '.cxx']

        # Walk through repository
        for root, dirs, files in os.walk(self.repo_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', 'build', '.venv']]

            for filename in files:
                if not any(filename.endswith(ext) for ext in extensions):
                    continue

                file_path = Path(root) / filename
                rel_path = file_path.relative_to(self.repo_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_num, line in enumerate(f, 1):
                            if regex.search(line):
                                matches.append({
                                    "file": str(rel_path),
                                    "line": line_num,
                                    "content": line.strip()
                                })

                                if len(matches) >= max_results:
                                    break
                except (IOError, OSError):
                    continue

                if len(matches) >= max_results:
                    break

            if len(matches) >= max_results:
                break

        return {
            "success": True,
            "pattern": pattern,
            "matches": matches,
            "count": len(matches),
            "truncated": len(matches) >= max_results,
            "message": f"Found {len(matches)} matches" +
                      (f" (limited to {max_results})" if len(matches) >= max_results else "")
        }


class FindFileTool(AgentTool):
    """
    Tool for finding files by name or pattern.
    Useful for locating specific source files mentioned in error messages.
    """

    def __init__(self, repo_path: str):
        """
        Initialize FindFile tool.

        Args:
            repo_path: Absolute path to the repository root
        """
        self.repo_path = Path(repo_path).resolve()

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {repo_path}")

    def name(self) -> str:
        return "find_file"

    def description(self) -> str:
        return (
            "Find files by name or pattern in the repository. "
            "Use this when you need to locate a specific file mentioned in error messages "
            "or when you know the filename but not its exact path. "
            "Supports wildcards (* and ?)."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "filename_pattern": {
                "type": "string",
                "description": (
                    "Filename or pattern to search for. Supports wildcards. "
                    "Examples: 'parser.c', '*.h', 'test_*.cpp', 'buffer.*'"
                ),
                "required": True
            },
            "max_results": {
                "type": "integer",
                "description": "Maximum number of files to return. Default: 30",
                "required": False
            }
        }

    def execute(self, filename_pattern: str, max_results: int = 30) -> Dict[str, Any]:
        """
        Find files matching the pattern.

        Args:
            filename_pattern: Filename or glob pattern
            max_results: Maximum number of results

        Returns:
            Dict with success status and list of matching file paths
        """
        try:
            import fnmatch

            matches = []

            # Walk through repository
            for root, dirs, files in os.walk(self.repo_path):
                # Skip common non-source directories
                dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', '.venv', '.claude']] # Fixed: 'build' was in it!

                for filename in files:
                    if fnmatch.fnmatch(filename, filename_pattern):
                        file_path = Path(root) / filename
                        rel_path = file_path.relative_to(self.repo_path)
                        matches.append(str(rel_path))

                        if len(matches) >= max_results:
                            break

                if len(matches) >= max_results:
                    break

            return {
                "success": True,
                "pattern": filename_pattern,
                "matches": sorted(matches),
                "count": len(matches),
                "truncated": len(matches) >= max_results,
                "message": f"Found {len(matches)} files" +
                          (f" (limited to {max_results})" if len(matches) >= max_results else "")
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"File search failed: {str(e)}",
                "pattern": filename_pattern
            }


class ListDirTool(AgentTool):
    """
    Tool for listing directory contents.
    Useful for exploring the repository structure and understanding file organization.
    """

    def __init__(self, repo_path: str):
        """
        Initialize ListDir tool.
        Args:
            repo_path: Absolute path to the repository root
        """
        self.repo_path = Path(repo_path).resolve()

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {repo_path}")

    def name(self) -> str:
        return "list_directory"

    def description(self) -> str:
        return (
            "List files and subdirectories in a specific directory. "
            "Use this to explore the repository structure and understand how code is organized. "
            "Returns a simple list of files and directories with type indicators."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "path": {
                "type": "string",
                "description": (
                    "Directory path relative to repository root. "
                    "Use '.' for repository root, 'src' for src directory, etc."
                ),
                "required": True
            }
        }

    def execute(self, path: str = ".") -> Dict[str, Any]:
        """
        List directory contents.
        Args:
            path: Relative path to directory

        Returns:
            Dict with success status and directory contents
        """
        try:
            # Resolve directory path
            if path == ".":
                target_dir = self.repo_path
            else:
                target_dir = self.repo_path / path

            # Check if directory exists
            if not target_dir.exists():
                return {
                    "success": False,
                    "error": f"Directory not found: {path}",
                    "path": path
                }

            if not target_dir.is_dir():
                return {
                    "success": False,
                    "error": f"Path is not a directory: {path}",
                    "path": path
                }

            # List contents
            entries = []
            directories = []
            files = []

            for item in sorted(target_dir.iterdir()):
                # Skip hidden files
                if item.name.startswith('.'):
                    continue

                if item.is_dir():
                    directories.append(f"{item.name}/")
                else:
                    # Add file with size info
                    size = item.stat().st_size
                    size_str = self._format_size(size)
                    files.append(f"{item.name} ({size_str})")

            # Combine: directories first, then files
            entries = directories + files

            return {
                "success": True,
                "path": path,
                "entries": entries,
                "directory_count": len(directories),
                "file_count": len(files),
                "total_count": len(entries)
            }

        except PermissionError:
            return {
                "success": False,
                "error": f"Permission denied: {path}",
                "path": path
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to list directory: {str(e)}",
                "path": path
            }

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}TB"


class TreeTool(AgentTool):
    """
    Tool for displaying directory tree structure.
    Useful for getting an overview of repository organization.
    """

    def __init__(self, repo_path: str):
        """
        Initialize Tree tool.
        Args:
            repo_path: Absolute path to the repository root
        """
        self.repo_path = Path(repo_path).resolve()

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {repo_path}")

    def name(self) -> str:
        return "tree"

    def description(self) -> str:
        return (
            "Display directory tree structure showing hierarchical organization. "
            "Use this to get an overview of how the repository is organized, "
            "especially useful when first exploring an unfamiliar codebase. "
            "Returns an indented tree view of directories and files."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "path": {
                "type": "string",
                "description": (
                    "Starting directory path relative to repository root. "
                    "Use '.' for full repository tree, or specify a subdirectory like 'src'."
                ),
                "required": True
            },
            "max_depth": {
                "type": "integer",
                "description": (
                    "Maximum depth to traverse. Default: 3. "
                    "Use 1 for immediate children only, 2-3 for moderate depth, 4+ for deep exploration."
                ),
                "required": False
            },
            "show_files": {
                "type": "boolean",
                "description": "Whether to show files (true) or only directories (false). Default: true",
                "required": False
            }
        }

    def execute(self, path: str = ".", max_depth: int = 3,
                show_files: bool = True) -> Dict[str, Any]:
        """
        Generate directory tree.
        Args:
            path: Starting directory path
            max_depth: Maximum depth to traverse
            show_files: Whether to show files or directories only

        Returns:
            Dict with success status and tree structure
        """
        try:
            # Resolve directory path
            if path == ".":
                target_dir = self.repo_path
                display_path = "."
            else:
                target_dir = self.repo_path / path
                display_path = path

            # Check if directory exists
            if not target_dir.exists():
                return {
                    "success": False,
                    "error": f"Directory not found: {path}",
                    "path": path
                }

            if not target_dir.is_dir():
                return {
                    "success": False,
                    "error": f"Path is not a directory: {path}",
                    "path": path
                }

            # Build tree
            tree_lines = [f"{display_path}/"]
            stats = {"dirs": 0, "files": 0}

            self._build_tree_recursive(target_dir, "", max_depth, 0,
                                      show_files, tree_lines, stats)

            tree_output = '\n'.join(tree_lines)

            return {
                "success": True,
                "path": path,
                "tree": tree_output,
                "directory_count": stats["dirs"],
                "file_count": stats["files"],
                "max_depth": max_depth
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to generate tree: {str(e)}",
                "path": path
            }

    def _build_tree_recursive(self, directory: Path, prefix: str, max_depth: int,
                             current_depth: int, show_files: bool,
                             tree_lines: List[str], stats: Dict[str, int]):
        """Recursively build tree structure"""
        if current_depth >= max_depth:
            return

        try:
            # Get all items
            items = sorted(directory.iterdir(), key=lambda x: (not x.is_dir(), x.name))

            # Filter out hidden items and common build artifacts
            items = [
                item for item in items
                if not item.name.startswith('.') and
                   item.name not in ['__pycache__', 'node_modules', 'build', 'dist', '.venv']
            ]

            for i, item in enumerate(items):
                is_last = (i == len(items) - 1)

                # Determine tree characters
                if is_last:
                    connector = "└── "
                    extension = "    "
                else:
                    connector = "├── "
                    extension = "│   "

                # Handle directories
                if item.is_dir():
                    stats["dirs"] += 1
                    tree_lines.append(f"{prefix}{connector}{item.name}/")

                    # Recurse into subdirectory
                    self._build_tree_recursive(
                        item,
                        prefix + extension,
                        max_depth,
                        current_depth + 1,
                        show_files,
                        tree_lines,
                        stats
                    )

                # Handle files
                elif show_files:
                    stats["files"] += 1
                    tree_lines.append(f"{prefix}{connector}{item.name}")

        except PermissionError:
            tree_lines.append(f"{prefix}[Permission Denied]")
