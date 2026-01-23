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

    def __init__(self, code_repo_path: str):
        """
        Initialize ReadFile tool.

        Args:
            code_repo_path: Absolute path to the repository root
        """
        self.code_repo_path = Path(code_repo_path).resolve()

        if not self.code_repo_path.exists():
            raise ValueError(f"Repository path does not exist: {code_repo_path}")
        if not self.code_repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {code_repo_path}")

    def name(self) -> str:
        return "read_file"

    def description(self) -> str:
        return (
            "Read file contents in text mode (with line numbers) or hex mode (binary dump). "
            "Supports both relative paths (from code repository root) and absolute paths (any file on the system). "
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
            "\n\n"
            "TIP: You can call this tool multiple times in a single response to read multiple files at once. "
            "This is more efficient than reading files one by one across multiple turns."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "file_path": {
                "type": "string",
                "description": (
                    "Path to the file. Can be either: "
                    "1) Relative path from code repository root (e.g., 'src/parser.c', 'lib/buffer.cpp'), or "
                    "2) Absolute path to any file on the system (e.g., '/tmp/crash_input.bin', '/var/log/output.txt', 'path/to/testcase')."
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
            # Resolve file path - support both absolute and relative paths
            if os.path.isabs(file_path):
                # Absolute path: use as-is
                full_path = Path(file_path)
            else:
                # Relative path: resolve relative to code_repo_path
                full_path = self.code_repo_path / file_path

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

            # Apply byte size limit (max 8KB) to prevent overly large responses
            MAX_CONTENT_BYTES = 8 * 1024
            content_bytes = len(content.encode('utf-8'))
            byte_truncated = False
            if content_bytes > MAX_CONTENT_BYTES:
                # Truncate by lines until under limit
                while content_lines and len('\n'.join(content_lines).encode('utf-8')) > MAX_CONTENT_BYTES:
                    content_lines.pop()
                content = '\n'.join(content_lines)
                byte_truncated = True

            result = {
                "success": True,
                "file_path": file_path,
                "content": content,
                "total_lines": total_lines,
                "displayed_lines": len(content_lines),
                "display_range": f"{line_offset}-{line_offset + len(content_lines) - 1}"
            }

            # Add truncation warning if applicable
            if start_line is None and end_line is None and total_lines > 200:
                result["truncated"] = True
                result["message"] = f"File has {total_lines} lines. Showing first 200. Use start_line/end_line to see more."

            if byte_truncated:
                result["truncated"] = True
                result["message"] = result.get("message", "") + f" Content truncated to {MAX_CONTENT_BYTES // 1024}KB limit ({len(content_lines)} lines shown)."

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

            # Apply byte size limit (max 16KB) to prevent overly large responses
            MAX_CONTENT_BYTES = 16 * 1024
            hex_dump_bytes = len(hex_dump.encode('utf-8'))
            byte_truncated = False
            if hex_dump_bytes > MAX_CONTENT_BYTES:
                # Truncate by lines until under limit
                while hex_lines and len('\n'.join(hex_lines).encode('utf-8')) > MAX_CONTENT_BYTES:
                    hex_lines.pop()
                hex_dump = '\n'.join(hex_lines)
                byte_truncated = True
                # Recalculate actual bytes shown
                actual_length = len(hex_lines) * 16

            result = {
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

            if byte_truncated:
                result["truncated"] = True
                result["message"] += f" (truncated to {MAX_CONTENT_BYTES // 1024}KB limit)"

            return result

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to read file in hex mode: {str(e)}",
                "file_path": file_path
            }


class WriteFileTool(AgentTool):
    """
    Tool for writing content to files in text or binary (hex) mode.
    Supports create, insert, and append operations.
    """

    def __init__(self, code_repo_path: str):
        """
        Initialize WritFile tool.

        Args:
            code_repo_path: Absolute path to the repository root
        """
        self.code_repo_path = Path(code_repo_path).resolve()

        if not self.code_repo_path.exists():
            raise ValueError(f"Repository path does not exist: {code_repo_path}")
        if not self.code_repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {code_repo_path}")

    def name(self) -> str:
        return "write_file"

    def description(self) -> str:
        return (
            "Write content to a file in text mode or hex mode with different write strategies. "
            "Supports both relative paths (from code repository root) and absolute paths (any location on the system). "
            "\n\n"
            "WRITE MODES:\n"
            "- create: Overwrite file completely (creates new file if doesn't exist)\n"
            "- insert: Insert content at specific position (requires start_line or start_offset)\n"
            "- append: Append content to end of file\n"
            "\n"
            "TEXT MODE (default, hex_mode=false):\n"
            "Write text content as-is. For insert mode, use start_line (1-indexed) to specify "
            "where to insert. Content is inserted BEFORE the specified line.\n"
            "\n"
            "HEX MODE (hex_mode=true):\n"
            "Write binary data from hexadecimal representation. For insert mode, use start_offset "
            "(0-indexed byte position). Hex input formats supported:\n"
            "  - Simple hex string: '7f454c4602010100'\n"
            "  - Spaced hex bytes: '7f 45 4c 46 02 01 01 00'\n"
            "  - Hex dump format (extracts hex, ignores address/ASCII):\n"
            "    '00000000: 7f 45 4c 46 02 01 01 00  .ELF....'\n"
            "\n"
            "Examples:\n"
            "- Create text file: write_mode='create', content='Hello\\nWorld'\n"
            "- Append to file: write_mode='append', content='New line\\n'\n"
            "- Insert at line 5: write_mode='insert', start_line=5, content='Inserted\\n'\n"
            "- Write binary: hex_mode=true, content='504b0304', write_mode='create'\n"
            "- Insert bytes at offset 0x10: hex_mode=true, write_mode='insert', start_offset=16, content='deadbeef'"
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "file_path": {
                "type": "string",
                "description": (
                    "Path to the file. Can be either: "
                    "1) Relative path from code repository root (e.g., 'output.txt', 'data/result.bin'), or "
                    "2) Absolute path to any location on the system (e.g., '/tmp/poc.bin', '/var/data/output.txt')"
                ),
                "required": True
            },
            "content": {
                "type": "string",
                "description": (
                    "Content to write. In text mode, write as plain text. "
                    "In hex mode, provide hexadecimal string (see description for formats)."
                ),
                "required": True
            },
            "write_mode": {
                "type": "string",
                "description": (
                    "Write strategy: 'create' (overwrite), 'insert' (at position), or 'append' (at end). "
                    "Default: 'create'"
                ),
                "required": False
            },
            "hex_mode": {
                "type": "boolean",
                "description": (
                    "If true, treat content as hexadecimal and write binary data. "
                    "If false, write as text. Default: false"
                ),
                "required": False
            },
            "start_line": {
                "type": "integer",
                "description": (
                    "Line number (1-indexed) to insert content BEFORE. "
                    "Only used when write_mode='insert' and hex_mode=false. "
                    "Example: start_line=5 inserts before line 5."
                ),
                "required": False
            },
            "start_offset": {
                "type": "integer",
                "description": (
                    "Byte offset (0-indexed) to insert content at. "
                    "Only used when write_mode='insert' and hex_mode=true."
                ),
                "required": False
            }
        }

    def execute(self, file_path: str, content: str, write_mode: str = "create",
                hex_mode: bool = False, start_line: Optional[int] = None,
                start_offset: Optional[int] = None) -> Dict[str, Any]:
        """
        Write content to file.

        Args:
            file_path: Relative path to file
            content: Content to write (text or hex string)
            write_mode: 'create', 'insert', or 'append'
            hex_mode: If true, parse content as hex and write binary
            start_line: Line number for insert in text mode (1-indexed)
            start_offset: Byte offset for insert in hex mode (0-indexed)

        Returns:
            Dict with success status and operation details
        """
        try:
            # Validate write_mode
            if write_mode not in ["create", "insert", "append"]:
                return {
                    "success": False,
                    "error": f"Invalid write_mode: {write_mode}. Must be 'create', 'insert', or 'append'",
                    "file_path": file_path
                }

            # Resolve file path - support both absolute and relative paths
            if os.path.isabs(file_path):
                # Absolute path: use as-is
                full_path = Path(file_path)
            else:
                # Relative path: resolve relative to code_repo_path
                full_path = self.code_repo_path / file_path

            # Ensure parent directory exists
            full_path.parent.mkdir(parents=True, exist_ok=True)

            # Handle hex mode
            if hex_mode:
                return self._write_as_hex(full_path, file_path, content, write_mode, start_offset)
            else:
                return self._write_as_text(full_path, file_path, content, write_mode, start_line)

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to write file: {str(e)}",
                "file_path": file_path
            }

    def _parse_hex_content(self, hex_string: str) -> bytes:
        """
        Parse hex string into bytes, supporting multiple formats.

        Args:
            hex_string: Hex string in various formats

        Returns:
            Parsed bytes
        """
        # Remove common hex dump artifacts: addresses, colons, ASCII representation
        lines = hex_string.strip().split('\n')
        hex_parts = []

        for line in lines:
            # Check if line contains address (e.g., "00000000: ...")
            if ':' in line:
                # Extract hex part between ':' and any double-space or end
                parts = line.split(':', 1)
                if len(parts) == 2:
                    hex_part = parts[1].strip()
                    # Remove ASCII representation (after double space)
                    if '  ' in hex_part:
                        hex_part = hex_part.split('  ')[0]
                    hex_parts.append(hex_part)
            else:
                hex_parts.append(line.strip())

        # Combine all hex parts
        combined = ' '.join(hex_parts)

        # Remove all whitespace
        hex_clean = ''.join(combined.split())

        # Validate hex string
        if not all(c in '0123456789abcdefABCDEF' for c in hex_clean):
            raise ValueError(f"Invalid hex string: contains non-hex characters")

        if len(hex_clean) % 2 != 0:
            raise ValueError(f"Invalid hex string: odd number of hex digits")

        # Convert to bytes
        return bytes.fromhex(hex_clean)

    def _write_as_hex(self, full_path: Path, file_path: str, content: str,
                      write_mode: str, start_offset: Optional[int]) -> Dict[str, Any]:
        """
        Write file in hex mode (binary).
        """
        try:
            # Parse hex content
            data = self._parse_hex_content(content)
            bytes_to_write = len(data)

            if write_mode == "create":
                # Overwrite file
                with open(full_path, 'wb') as f:
                    f.write(data)

                return {
                    "success": True,
                    "file_path": file_path,
                    "write_mode": "create",
                    "mode": "hex",
                    "bytes_written": bytes_to_write,
                    "message": f"Created file with {bytes_to_write} bytes"
                }

            elif write_mode == "append":
                # Append to end
                with open(full_path, 'ab') as f:
                    f.write(data)

                new_size = full_path.stat().st_size

                return {
                    "success": True,
                    "file_path": file_path,
                    "write_mode": "append",
                    "mode": "hex",
                    "bytes_written": bytes_to_write,
                    "new_file_size": new_size,
                    "message": f"Appended {bytes_to_write} bytes (new size: {new_size} bytes)"
                }

            elif write_mode == "insert":
                if start_offset is None:
                    return {
                        "success": False,
                        "error": "start_offset is required for insert mode in hex mode",
                        "file_path": file_path
                    }

                # Read existing content
                if full_path.exists():
                    with open(full_path, 'rb') as f:
                        existing_data = f.read()
                else:
                    existing_data = b''

                # Validate offset
                if start_offset < 0:
                    return {
                        "success": False,
                        "error": f"Invalid start_offset: {start_offset} (must be >= 0)",
                        "file_path": file_path
                    }

                if start_offset > len(existing_data):
                    return {
                        "success": False,
                        "error": f"start_offset {start_offset} exceeds file size {len(existing_data)}",
                        "file_path": file_path
                    }

                # Insert data
                new_data = existing_data[:start_offset] + data + existing_data[start_offset:]

                # Write back
                with open(full_path, 'wb') as f:
                    f.write(new_data)

                return {
                    "success": True,
                    "file_path": file_path,
                    "write_mode": "insert",
                    "mode": "hex",
                    "insert_offset": start_offset,
                    "bytes_written": bytes_to_write,
                    "new_file_size": len(new_data),
                    "message": f"Inserted {bytes_to_write} bytes at offset {start_offset} (new size: {len(new_data)} bytes)"
                }

        except ValueError as e:
            return {
                "success": False,
                "error": f"Failed to parse hex content: {str(e)}",
                "file_path": file_path
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to write file in hex mode: {str(e)}",
                "file_path": file_path
            }

    def _write_as_text(self, full_path: Path, file_path: str, content: str,
                       write_mode: str, start_line: Optional[int]) -> Dict[str, Any]:
        """
        Write file in text mode.
        """
        try:
            if write_mode == "create":
                # Overwrite file
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                lines_written = content.count('\n') + (1 if content and not content.endswith('\n') else 0)

                return {
                    "success": True,
                    "file_path": file_path,
                    "write_mode": "create",
                    "mode": "text",
                    "bytes_written": len(content.encode('utf-8')),
                    "lines_written": lines_written,
                    "message": f"Created file with {lines_written} lines"
                }

            elif write_mode == "append":
                # Append to end
                with open(full_path, 'a', encoding='utf-8') as f:
                    f.write(content)

                lines_written = content.count('\n') + (1 if content and not content.endswith('\n') else 0)
                total_lines = sum(1 for _ in open(full_path, 'r', encoding='utf-8'))

                return {
                    "success": True,
                    "file_path": file_path,
                    "write_mode": "append",
                    "mode": "text",
                    "bytes_written": len(content.encode('utf-8')),
                    "lines_written": lines_written,
                    "total_lines": total_lines,
                    "message": f"Appended {lines_written} lines (total: {total_lines} lines)"
                }

            elif write_mode == "insert":
                if start_line is None:
                    return {
                        "success": False,
                        "error": "start_line is required for insert mode in text mode",
                        "file_path": file_path
                    }

                # Read existing content
                if full_path.exists():
                    with open(full_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                else:
                    lines = []

                # Validate line number
                if start_line < 1:
                    return {
                        "success": False,
                        "error": f"Invalid start_line: {start_line} (must be >= 1)",
                        "file_path": file_path
                    }

                if start_line > len(lines) + 1:
                    return {
                        "success": False,
                        "error": f"start_line {start_line} exceeds file length {len(lines)} + 1",
                        "file_path": file_path
                    }

                # Insert content (before the specified line)
                insert_idx = start_line - 1

                # Ensure content ends with newline if inserting in middle
                insert_content = content
                if insert_idx < len(lines) and not insert_content.endswith('\n'):
                    insert_content += '\n'

                lines.insert(insert_idx, insert_content)

                # Write back
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)

                lines_inserted = insert_content.count('\n') + (1 if insert_content and not insert_content.endswith('\n') else 0)

                return {
                    "success": True,
                    "file_path": file_path,
                    "write_mode": "insert",
                    "mode": "text",
                    "insert_line": start_line,
                    "lines_inserted": lines_inserted,
                    "total_lines": len(lines),
                    "message": f"Inserted {lines_inserted} lines before line {start_line} (total: {len(lines)} lines)"
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to write file in text mode: {str(e)}",
                "file_path": file_path
            }


class BashTool(AgentTool):
    """
    Tool for executing bash commands with whitelist-based security.
    Useful for file operations, binary analysis, and running Python scripts.
    """

    def __init__(self, code_repo_path: str):
        """
        Initialize BashTool.

        Args:
            code_repo_path: Absolute path to the repository root
        """
        self.code_repo_path = Path(code_repo_path).resolve()

        if not self.code_repo_path.exists():
            raise ValueError(f"Repository path does not exist: {code_repo_path}")
        if not self.code_repo_path.is_dir():
            raise ValueError(f"Repository path is not a directory: {code_repo_path}")

        # Whitelist of allowed commands
        self.allowed_commands = {
            # File operations
            'ls', 'cat', 'head', 'tail', 'tree', 'wc', 'file', 'stat', 'chmod',
            # Search/find
            'grep', 'find', 'locate',
            # Binary analysis
            'strings', 'xxd', 'hexdump', 'od', 'objdump', 'readelf', 'nm', 'ldd',
            # Python execution
            'python3',
            # Utilities
            'diff', 'base64', 'md5sum', 'sha256sum', 'timeout',
            # Additional common tools
            'echo', 'realpath', 'pwd', 'mkdir', 'touch', 'cp', 'mv',
            # Compilation/build
            # 'gcc', 'g++', 'clang', 'make', 'cmake',
            # Advanced tools
            # 'llvm-cov', 'ast-grep', 'clangd', 'ksc'
        }

        # Forbidden patterns (regex)
        # Note: Use \b word boundaries to avoid false positives (e.g., "nc" in "include")
        self.forbidden_patterns = [
            (r"\brm\s+-rf\b", "Recursive deletion (rm -rf) is forbidden"),
            (r"\bwget\b|\bcurl\b", "Network downloads (wget/curl) are forbidden"),
            (r"\bnc\b|\bnetcat\b", "Network connections (nc/netcat) are forbidden"),
            (r">\s*/etc", "Writing to /etc is forbidden"),
            (r">\s*/dev/sd", "Writing to disk devices is forbidden"),
            (r"\bmkfs\b", "Filesystem operations (mkfs) are forbidden"),
            (r"\bdd\b\s+.*of=/dev", "Dangerous dd operations to devices are forbidden"),
        ]

        # Timeout for command execution (seconds)
        self.timeout = 30

        # Maximum output length (characters) - reduced from 30000 to control context size
        self.max_output_chars = 10000

    def name(self) -> str:
        return "execute_bash"

    def description(self) -> str:
        cmd_list = ", ".join(sorted(self.allowed_commands))
        forbidden_desc = "\n".join([f"  - {desc}" for _, desc in self.forbidden_patterns])

        return (
            "Execute bash commands for file operations, binary analysis, and running scripts.\n"
            "\n"
            "COMMAND EXECUTION:\n"
            "- You can only execute ONE bash command at a time. To run multiple commands sequentially, use `&&` or `;` to chain them together.\n"
            "- Use efficient commands (ls, find, grep, etc.) with appropriate filters to minimize unnecessary operations.\n"
            "\n"
            "ALLOWED COMMANDS:\n"
            f"{cmd_list}\n"
            "\n"
            "FORBIDDEN OPERATIONS:\n"
            f"{forbidden_desc}\n"
            "\n"
            "PYTHON EXECUTION:\n"
            "To run Python code:\n"
            "1. Use write_file to create a .py script\n"
            "2. Use execute_bash to run: python3 /path/to/your_script.py\n"
            "3. Common python libraries: os, struct, io(.BytesIO), binascii, zlib, etc.\n"
            "4. Do NOT attempt pip install - all necessary libraries are pre-installed\n"
            "\n"
            "WORKING DIRECTORY:\n"
            f"Commands execute in the specified `working_dir` (default: code repository root).\n"
            "`working_dir` can be relative (to repo root) or absolute path.\n"
            "Try to maintain working directory by using absolute paths and avoiding excessive use of `cd`.\n"
            "\n"
            "OUTPUT TRUNCATION:\n"
            f"If the output exceeds {self.max_output_chars} characters, it will be truncated.\n"
            "Control output size yourself using:\n"
            "  - head -n 100 (first 100 lines)\n"
            "  - tail -n 50 (last 50 lines)\n"
            "  - grep with filters\n"
            "\n"
            f"TIMEOUT: {self.timeout} seconds per command\n"
            "\n"
            "EXAMPLES:\n"
            "  - List files: ls -la\n"
            "  - Examine binary: readelf -h ./target\n"
            "  - Search strings: strings ./binary | grep 'flag'\n"
            "  - Run analysis: python3 /path/to/analyze.py\n"
            "  - Chain commands: mkdir -p output && cp file.txt output/\n"
            "TIP: You can call this tool multiple times in a single response to conduct multiple read operations at once, which could be more efficient. "
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "command": {
                "type": "string",
                "description": (
                    "The bash command to execute. "
                    f"Must start with one of the allowed commands: {', '.join(sorted(self.allowed_commands))}. "
                    "Use pipes, redirects, and command substitution as needed."
                ),
                "required": True
            },
            "working_dir": {
                "type": "string",
                "description": (
                    "Working directory for command execution. Can be either: "
                    "1) Relative path from code repository root (e.g., '.', 'src', 'build'), or "
                    "2) Absolute path to any directory on the system (e.g., '/tmp', '/var/data', '/path/to/agent/workspace/'). "
                    "Default: '.' (code repository root)"
                ),
                "required": False
            }
        }

    def execute(self, command: str, working_dir: str = ".") -> Dict[str, Any]:
        """
        Execute a bash command with security checks.

        Args:
            command: The bash command to execute
            working_dir: Working directory relative to repo root (default: ".")

        Returns:
            Dict with execution results:
            - success: Always True unless validation fails
            - stdout: Command standard output
            - stderr: Command standard error
            - exit_code: Command exit code (0 = success)
            - command: The executed command
            - working_dir: The actual working directory used
            - blocked_reason: Present if command was blocked (success=False)
        """
        try:
            # Step 1: Resolve working directory
            if working_dir.startswith('/'):
                # Absolute path
                work_path = Path(working_dir)
            else:
                # Relative to code_repo_path
                work_path = self.code_repo_path / working_dir

            work_path = work_path.resolve()

            # Ensure working directory exists
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

            # Step 2: Parse command to extract command name
            import shlex
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

            # Extract the base command (first token)
            base_command = tokens[0]

            # Step 3: Whitelist validation
            if base_command not in self.allowed_commands:
                allowed_list = ", ".join(sorted(self.allowed_commands))
                return {
                    "success": False,
                    "error": (
                        f"Command '{base_command}' is not allowed. "
                        f"Allowed commands: {allowed_list}"
                    ),
                    "command": command,
                    "blocked_reason": "command_not_in_whitelist"
                }

            # Step 4: Forbidden patterns 
            # TODO: also avoid visiting gt_povs and success_povs (these are our debug data)
            import re
            for pattern, description in self.forbidden_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    return {
                        "success": False,
                        "error": (
                            f"Command matches forbidden pattern: {description}\n"
                            f"Pattern: {pattern}\n"
                            f"Command: {command}"
                        ),
                        "command": command,
                        "blocked_reason": "forbidden_pattern"
                    }

            # Step 5: Execute command
            result = subprocess.run(
                command,
                shell=True,
                cwd=str(work_path),
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            # Step 6: Truncate output if necessary
            stdout = result.stdout
            stderr = result.stderr
            truncated = False

            if len(stdout) > self.max_output_chars:
                stdout = stdout[:self.max_output_chars] + f"\n\n... [OUTPUT TRUNCATED: {len(result.stdout)} chars total, showing first {self.max_output_chars}]"
                truncated = True

            if len(stderr) > self.max_output_chars:
                stderr = stderr[:self.max_output_chars] + f"\n\n... [STDERR TRUNCATED: {len(result.stderr)} chars total, showing first {self.max_output_chars}]"
                truncated = True

            # Return results (success=True even if exit_code != 0)
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


class FinishTool(AgentTool):
    """
    Tool to signal the completion of the agent's task.
    Requires a summary message and task completion status.
    """

    def name(self) -> str:
        return "finish"

    def description(self) -> str:
        return """Signals the completion of the current task or conversation.

Use this tool when:
- You have successfully completed the user's requested task
- You have partially completed the task but cannot proceed further
- You cannot proceed further due to technical limitations or missing information

The message should include:
- A clear summary of actions taken and their results
- The path to the generated PoV file (if applicable)
- Explanation if you're unable to complete the task
- Any relevant findings or observations

The task_completed field indicates your completion status:
- "true": Task fully completed successfully
- "false": Task could not be completed
- "partial": Task partially completed (some progress made but not fully done)
"""

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "message": {
                "type": "string",
                "description": (
                    "Final message summarizing the task outcome. "
                    "Include: actions taken, results achieved, PoV file path (if generated), "
                    "and any important observations or limitations encountered."
                ),
                "required": True
            },
            "task_completed": {
                "type": "string",
                "description": (
                    "Task completion status: "
                    "'true' if fully completed, "
                    "'false' if unable to complete, "
                    "'partial' if some progress was made but task is not fully done."
                ),
                "enum": ["true", "false", "partial"],
                "required": True
            }
        }

    def execute(self, message: str, task_completed: str) -> Dict[str, Any]:
        """
        Execute finish tool.

        Args:
            message: Final summary message describing what was accomplished
            task_completed: Completion status ('true', 'false', or 'partial')

        Returns:
            Dict indicating completion with the provided message and status
        """
        # Validate task_completed value
        valid_statuses = ["true", "false", "partial"]
        if task_completed not in valid_statuses:
            return {
                "success": False,
                "error": f"Invalid task_completed value: {task_completed}. Must be one of: {valid_statuses}"
            }

        return {
            "success": True,
            "message": message,
            "task_completed": task_completed
        }