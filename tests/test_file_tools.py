#!/usr/bin/env python3
"""
Test script for ReadFileTool and WriteFileTool.
Focuses on testing binary data handling and various read/write modes.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path to import the tools
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from drillagent.tools.basic_tools import ReadFileTool, WriteFileTool


def print_result(test_name, result):
    """Pretty print test result"""
    print(f"\n{'='*60}")
    print(f"TEST: {test_name}")
    print(f"{'='*60}")
    print(f"Success: {result.get('success', False)}")

    if result.get('success'):
        # Print key information
        for key in ['message', 'content', 'mode', 'file_path',
                    'bytes_written', 'bytes_read', 'lines_written',
                    'total_lines', 'file_size', 'read_range']:
            if key in result:
                if key == 'content':
                    # Limit content display
                    content = result[key]
                    if len(content) > 500:
                        print(f"{key}: {content[:500]}... (truncated)")
                    else:
                        print(f"{key}:\n{content}")
                else:
                    print(f"{key}: {result[key]}")
    else:
        print(f"Error: {result.get('error', 'Unknown error')}")

    print(f"{'='*60}\n")


def test_write_tool():
    """Test WriteFileTool with various modes"""
    print("\n" + "="*80)
    print("TESTING WriteFileTool")
    print("="*80)

    # Create temporary directory
    with tempfile.TemporaryDirectory() as tmpdir:
        write_tool = WriteFileTool(tmpdir)

        # Test 1: Create text file
        result = write_tool.execute(
            file_path="test_text.txt",
            content="Line 1\nLine 2\nLine 3\n",
            write_mode="create"
        )
        print_result("Create text file", result)

        # Test 2: Append to text file
        result = write_tool.execute(
            file_path="test_text.txt",
            content="Line 4\nLine 5\n",
            write_mode="append"
        )
        print_result("Append to text file", result)

        # Test 3: Insert into text file
        result = write_tool.execute(
            file_path="test_text.txt",
            content="INSERTED LINE\n",
            write_mode="insert",
            start_line=2
        )
        print_result("Insert at line 2 in text file", result)

        # Test 4: Create binary file (simple hex)
        result = write_tool.execute(
            file_path="test_binary.bin",
            content="504b0304",  # ZIP file magic number
            write_mode="create",
            hex_mode=True
        )
        print_result("Create binary file (simple hex)", result)

        # Test 5: Create binary file (spaced hex)
        result = write_tool.execute(
            file_path="test_binary2.bin",
            content="7f 45 4c 46 02 01 01 00",  # ELF magic number
            write_mode="create",
            hex_mode=True
        )
        print_result("Create binary file (spaced hex)", result)

        # Test 6: Create binary file (hex dump format)
        hex_dump_content = """00000000: 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52  .PNG........IHDR
00000010: 00 00 00 20 00 00 00 20 08 02 00 00 00 fc 18 ed  ... ... ........"""

        result = write_tool.execute(
            file_path="test_png_header.bin",
            content=hex_dump_content,
            write_mode="create",
            hex_mode=True
        )
        print_result("Create binary file (hex dump format - PNG header)", result)

        # Test 7: Append binary data
        result = write_tool.execute(
            file_path="test_binary.bin",
            content="deadbeef",
            write_mode="append",
            hex_mode=True
        )
        print_result("Append binary data", result)

        # Test 8: Insert binary data at offset
        result = write_tool.execute(
            file_path="test_binary2.bin",
            content="ff ff",
            write_mode="insert",
            start_offset=4,
            hex_mode=True
        )
        print_result("Insert binary data at offset 4", result)

        # Test 9: Create file in subdirectory (auto-create parent)
        result = write_tool.execute(
            file_path="subdir/nested/file.txt",
            content="Auto-created subdirectories\n",
            write_mode="create"
        )
        print_result("Create file in auto-created subdirectory", result)

        # Test 10: Error case - invalid write_mode
        result = write_tool.execute(
            file_path="error.txt",
            content="test",
            write_mode="invalid_mode"
        )
        print_result("Error case: invalid write_mode", result)

        # Test 11: Error case - insert without start_line
        result = write_tool.execute(
            file_path="test_text.txt",
            content="test",
            write_mode="insert"
        )
        print_result("Error case: insert without start_line", result)

        # Test 12: Error case - invalid hex string
        result = write_tool.execute(
            file_path="error.bin",
            content="not hex content!",
            write_mode="create",
            hex_mode=True
        )
        print_result("Error case: invalid hex string", result)


def test_read_tool():
    """Test ReadFileTool with various modes"""
    print("\n" + "="*80)
    print("TESTING ReadFileTool")
    print("="*80)

    # Create temporary directory with test files
    with tempfile.TemporaryDirectory() as tmpdir:
        write_tool = WriteFileTool(tmpdir)
        read_tool = ReadFileTool(tmpdir)

        # Setup: Create test files
        # Text file with multiple lines
        text_content = "\n".join([f"Line {i}" for i in range(1, 101)])
        write_tool.execute("test_lines.txt", text_content, "create")

        # Binary file with known pattern
        binary_hex = "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f " * 64  # 1024 bytes
        write_tool.execute("test_binary.bin", binary_hex, "create", hex_mode=True)

        # Mixed content file (text with some binary bytes)
        mixed_hex = "48 65 6c 6c 6f 00 ff fe fd 57 6f 72 6c 64"  # "Hello\x00\xff\xfe\xfdWorld"
        write_tool.execute("test_mixed.dat", mixed_hex, "create", hex_mode=True)

        # Test 1: Read entire text file
        result = read_tool.execute("test_lines.txt")
        print_result("Read entire text file (auto-truncated at 200 lines)", result)

        # Test 2: Read specific line range
        result = read_tool.execute("test_lines.txt", start_line=10, end_line=20)
        print_result("Read lines 10-20", result)

        # Test 3: Read 50 lines from start_line
        result = read_tool.execute("test_lines.txt", start_line=80)
        print_result("Read 50 lines from line 80", result)

        # Test 4: Read binary file in hex mode (default 1024 bytes)
        result = read_tool.execute("test_binary.bin", hex_mode=True)
        print_result("Read binary file in hex mode (1024 bytes)", result)

        # Test 5: Read binary file with offset and length
        result = read_tool.execute(
            "test_binary.bin",
            hex_mode=True,
            start_offset=256,
            read_length=64
        )
        print_result("Read 64 bytes from offset 256 in hex mode", result)

        # Test 6: Read mixed content in text mode (should show � for binary bytes)
        result = read_tool.execute("test_mixed.dat")
        print_result("Read mixed content in text mode (binary bytes shown as �)", result)

        # Test 7: Read mixed content in hex mode
        result = read_tool.execute("test_mixed.dat", hex_mode=True)
        print_result("Read mixed content in hex mode", result)

        # Test 8: Create actual binary file (ELF header example)
        elf_header_hex = """
        7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
        02 00 3e 00 01 00 00 00 50 10 40 00 00 00 00 00
        40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 40 00 38 00 01 00 00 00 00 00 00 00
        """
        write_tool.execute("elf_header.bin", elf_header_hex, "create", hex_mode=True)

        result = read_tool.execute("elf_header.bin", hex_mode=True)
        print_result("Read ELF binary header in hex mode", result)

        # Test 9: Error case - file not found
        result = read_tool.execute("nonexistent.txt")
        print_result("Error case: file not found", result)

        # Test 10: Error case - invalid offset
        result = read_tool.execute(
            "test_binary.bin",
            hex_mode=True,
            start_offset=99999
        )
        print_result("Error case: offset exceeds file size", result)


def test_read_write_roundtrip():
    """Test writing and reading back the same data"""
    print("\n" + "="*80)
    print("TESTING Read/Write Roundtrip")
    print("="*80)

    with tempfile.TemporaryDirectory() as tmpdir:
        write_tool = WriteFileTool(tmpdir)
        read_tool = ReadFileTool(tmpdir)

        # Test 1: Binary roundtrip
        original_hex = "deadbeef cafebabe 0123456789abcdef"

        # Write binary data
        write_result = write_tool.execute(
            "roundtrip.bin",
            original_hex,
            "create",
            hex_mode=True
        )
        print_result("Write binary data", write_result)

        # Read it back
        read_result = read_tool.execute(
            "roundtrip.bin",
            hex_mode=True,
            read_length=100
        )
        print_result("Read binary data back", read_result)

        # Verify content
        if write_result['success'] and read_result['success']:
            # Extract hex from read result
            content = read_result['content']
            # Parse hex dump to get actual bytes
            hex_bytes = []
            for line in content.split('\n'):
                if ':' in line:
                    hex_part = line.split(':')[1].split('  ')[0].strip()
                    hex_bytes.append(hex_part)

            recovered_hex = ' '.join(hex_bytes)
            print(f"\nOriginal hex:  {original_hex}")
            print(f"Recovered hex: {recovered_hex}")

            # Compare byte values (normalize spacing)
            orig_clean = ''.join(original_hex.split()).lower()
            recov_clean = ''.join(recovered_hex.split()).lower()

            if orig_clean == recov_clean:
                print("✓ Roundtrip successful - data matches!")
            else:
                print("✗ Roundtrip failed - data mismatch!")

        # Test 2: Text roundtrip with insert
        write_tool.execute("text_roundtrip.txt", "Line 1\nLine 2\nLine 3\n", "create")
        write_tool.execute("text_roundtrip.txt", "Inserted\n", "insert", start_line=2)

        result = read_tool.execute("text_roundtrip.txt")
        print_result("Text file after insert operation", result)


def test_edge_cases():
    """Test edge cases and special scenarios"""
    print("\n" + "="*80)
    print("TESTING Edge Cases")
    print("="*80)

    with tempfile.TemporaryDirectory() as tmpdir:
        write_tool = WriteFileTool(tmpdir)
        read_tool = ReadFileTool(tmpdir)

        # Test 1: Empty file
        write_tool.execute("empty.txt", "", "create")
        result = read_tool.execute("empty.txt")
        print_result("Read empty file", result)

        # Test 2: Single byte file
        write_tool.execute("single.bin", "ff", "create", hex_mode=True)
        result = read_tool.execute("single.bin", hex_mode=True)
        print_result("Read single byte file in hex mode", result)

        # Test 3: File with null bytes
        null_hex = "48 65 6c 6c 6f 00 00 00 57 6f 72 6c 64"  # Hello\0\0\0World
        write_tool.execute("nulls.dat", null_hex, "create", hex_mode=True)

        result_text = read_tool.execute("nulls.dat")
        print_result("Read file with null bytes in text mode", result_text)

        result_hex = read_tool.execute("nulls.dat", hex_mode=True)
        print_result("Read file with null bytes in hex mode", result_hex)

        # Test 4: Very long line (no newlines)
        long_line = "A" * 3000
        write_tool.execute("long_line.txt", long_line, "create")
        result = read_tool.execute("long_line.txt")
        print_result("Read file with very long line (truncated at 2000 chars per line)", result)

        # Test 5: Binary insert at beginning
        write_tool.execute("insert_test.bin", "11 22 33 44", "create", hex_mode=True)
        write_tool.execute("insert_test.bin", "ff fe", "insert", start_offset=0, hex_mode=True)
        result = read_tool.execute("insert_test.bin", hex_mode=True)
        print_result("Binary insert at offset 0 (beginning)", result)

        # Test 6: Binary insert at end (append-like)
        file_size = Path(tmpdir) / "insert_test.bin"
        size = file_size.stat().st_size
        write_tool.execute("insert_test.bin", "aa bb", "insert", start_offset=size, hex_mode=True)
        result = read_tool.execute("insert_test.bin", hex_mode=True)
        print_result("Binary insert at end (offset = file_size)", result)

        # Test 7: Unicode text
        unicode_text = "Hello 世界 🌍 Ñoño\n"
        write_tool.execute("unicode.txt", unicode_text, "create")
        result = read_tool.execute("unicode.txt")
        print_result("Read Unicode text file", result)


def main():
    """Run all tests"""
    print("\n" + "#"*80)
    print("#" + " "*78 + "#")
    print("#" + "  FILE TOOLS TEST SUITE".center(78) + "#")
    print("#" + " "*78 + "#")
    print("#"*80)

    try:
        test_write_tool()
        test_read_tool()
        test_read_write_roundtrip()
        test_edge_cases()

        print("\n" + "#"*80)
        print("#" + " "*78 + "#")
        print("#" + "  ALL TESTS COMPLETED".center(78) + "#")
        print("#" + " "*78 + "#")
        print("#"*80 + "\n")

    except Exception as e:
        print(f"\n{'!'*80}")
        print(f"UNEXPECTED ERROR: {e}")
        print(f"{'!'*80}\n")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
