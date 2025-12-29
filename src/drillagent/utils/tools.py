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
            "Read the contents of a source code file with line numbers. "
            "Use this when you need to examine specific code mentioned in error messages, "
            "call traces, or to understand implementation details. "
            "Returns file content with line numbers for easy reference to specific lines."
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
                    "Use this to focus on specific sections mentioned in traces."
                ),
                "required": False
            },
            "end_line": {
                "type": "integer",
                "description": (
                    "Ending line number (1-indexed, inclusive). "
                    "If not specified, reads up to 50 lines from start_line, "
                    "or entire file if start_line is also not specified."
                ),
                "required": False
            }
        }

    def execute(self, file_path: str, start_line: Optional[int] = None,
                end_line: Optional[int] = None) -> Dict[str, Any]:
        """
        Read file contents with optional line range.
        Args:
            file_path: Relative path to file
            start_line: Optional starting line (1-indexed)
            end_line: Optional ending line (1-indexed, inclusive)
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

            # Read file
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
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
        cmd = ['rg', '-n', '--color', 'never', '--max-count', str(max_results)]

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


class FuncLineCovTool(AgentTool):
    """
    Tool for retrieving detailed line-by-line coverage for a specific function.
    Uses llvm-cov show command to display execution counts and source code.
    """

    def __init__(self, repo_path: str, llvm_cov_path: str = "llvm-cov"):
        """
        Initialize FuncLineCovTool.

        Args:
            repo_path: Absolute path to the repository root
            llvm_cov_path: Path to llvm-cov executable (default: "llvm-cov")
        """
        self.repo_path = Path(repo_path).resolve()
        self.llvm_cov_path = llvm_cov_path

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")
        if not self.repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {repo_path}")

    def name(self) -> str:
        return "retrieve_function_line_coverage"

    def description(self) -> str:
        return (
            "Retrieve detailed line-by-line coverage information for a specific function. "
            "Shows execution counts for each line of code within the function. "
            "Use this when you need to understand which lines in a function were executed "
            "and how many times during test runs. "
            "Requires an instrumented binary and corresponding profdata coverage file."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "binary_path": {
                "type": "string",
                "description": (
                    "Absolute path to the instrumented binary executable. "
                    "This binary must have been compiled with coverage instrumentation "
                    "(e.g., -fprofile-instr-generate -fcoverage-mapping). "
                    "Example: '/path/to/project/build/myapp'"
                ),
                "required": True
            },
            "profdata_path": {
                "type": "string",
                "description": (
                    "Absolute path to the profdata coverage data file. "
                    "This file is generated by merging profraw files using llvm-profdata. "
                    "Example: '/path/to/coverage.profdata'"
                ),
                "required": True
            },
            "file_path": {
                "type": "string",
                "description": (
                    "Path to the source file containing the function. "
                    "Can be absolute or relative to repository root. "
                    "Examples: 'src/parser.c', '/absolute/path/to/parser.c'"
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
            }
        }

    def execute(self, binary_path: str, profdata_path: str,
                file_path: str, function_name: str) -> Dict[str, Any]:
        """
        Execute llvm-cov show to retrieve function line coverage.

        Args:
            binary_path: Path to instrumented binary
            profdata_path: Path to profdata file
            file_path: Path to source file (absolute or relative to repo)
            function_name: Function name to analyze

        Returns:
            Dict containing:
            - success: bool indicating if execution succeeded
            - coverage_output: str with line-by-line coverage information
            - function_name: str the queried function name
            - file_path: str the resolved file path
            - error: str error message if failed
        """
        try:
            # Resolve paths
            binary_path = os.path.abspath(binary_path)
            profdata_path = os.path.abspath(profdata_path)

            # Handle file_path: if relative, resolve against repo_path
            file_path_obj = Path(file_path)
            if file_path_obj.is_absolute():
                resolved_file_path = file_path_obj
            else:
                resolved_file_path = self.repo_path / file_path

            resolved_file_path = resolved_file_path.resolve()

            # Validate inputs
            if not Path(binary_path).exists():
                return {
                    "success": False,
                    "error": f"Binary file not found: {binary_path}",
                    "function_name": function_name,
                    "file_path": str(resolved_file_path)
                }

            if not Path(profdata_path).exists():
                return {
                    "success": False,
                    "error": f"Profdata file not found: {profdata_path}",
                    "function_name": function_name,
                    "file_path": str(resolved_file_path)
                }

            if not resolved_file_path.exists():
                return {
                    "success": False,
                    "error": f"Source file not found: {resolved_file_path}",
                    "function_name": function_name,
                    "file_path": str(resolved_file_path)
                }

            # Construct llvm-cov show command
            # Format: llvm-cov show <binary> <source_file> -instr-profile=<profdata> --name=<function_name>
            cmd = [
                self.llvm_cov_path,
                'show',
                binary_path,
                str(resolved_file_path),
                f'-instr-profile={profdata_path}',
                f'--name={function_name}'
            ]

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
                    "file_path": str(resolved_file_path)
                }

            # Check if output is empty (function might not exist or not covered)
            output = result.stdout.strip()
            if not output:
                return {
                    "success": False,
                    "error": (
                        f"No coverage data found for function '{function_name}' in {resolved_file_path}. "
                        f"The function may not exist, or it was not executed during coverage collection."
                    ),
                    "function_name": function_name,
                    "file_path": str(resolved_file_path)
                }

            return {
                "success": True,
                "coverage_output": output,
                "function_name": function_name,
                "file_path": str(resolved_file_path),
                "message": f"Successfully retrieved coverage for function '{function_name}'"
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "llvm-cov command timed out (>30s)",
                "function_name": function_name,
                "file_path": file_path
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "function_name": function_name,
                "file_path": file_path
            }
