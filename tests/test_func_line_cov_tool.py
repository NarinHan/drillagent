#!/usr/bin/env python3
"""
Unit tests for FuncLineCovTool

This script tests the FuncLineCovTool using mocked subprocess calls
to ensure the tool correctly handles various scenarios.
"""

import sys
import os
import json
import tempfile
from pathlib import Path
from unittest import mock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from drillagent.utils.tools import FuncLineCovTool


def print_section(title: str):
    """Print a formatted section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_result(result: dict):
    """Print tool execution result in a readable format"""
    if result.get("success"):
        print("[SUCCESS]")
        for key, value in result.items():
            if key == "success":
                continue
            if key == "coverage_output" and len(str(value)) > 300:
                print(f"{key}:\n{str(value)[:300]}...\n   (truncated)")
            else:
                print(f"{key}: {value}")
    else:
        print(f"[FAILED] {result.get('error', 'Unknown error')}")
    print()


def test_schema_conversion():
    """Test schema conversion to Claude and OpenAI formats"""
    print_section("Test 1: Schema Conversion")

    with tempfile.TemporaryDirectory() as tmpdir:
        tool = FuncLineCovTool(tmpdir)

        # Test Claude schema
        claude_schema = tool.to_claude_schema()
        print("\nClaude Schema:")
        print(json.dumps(claude_schema, indent=2))

        # Test OpenAI schema
        openai_schema = tool.to_openai_schema()
        print("\nOpenAI Schema:")
        print(json.dumps(openai_schema, indent=2))

        # Verify required fields
        assert claude_schema["name"] == "retrieve_function_line_coverage"
        assert "description" in claude_schema
        assert "input_schema" in claude_schema
        assert "properties" in claude_schema["input_schema"]

        print("\n[OK] Schema conversion tests passed")


def test_successful_execution():
    """Test successful coverage retrieval with mocked subprocess"""
    print_section("Test 2: Successful Coverage Retrieval (Mocked)")

    # Mock coverage output
    mock_coverage_output = """    1|      1|int add(int a, int b) {
    2|      1|    return a + b;
    3|      1|}
    4|       |
    5|      5|int main() {
    6|      5|    int result = add(2, 3);
    7|      5|    return 0;
    8|      5|}"""

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create dummy files
        binary_path = Path(tmpdir) / "test_binary"
        profdata_path = Path(tmpdir) / "coverage.profdata"
        source_path = Path(tmpdir) / "test.c"

        binary_path.touch()
        profdata_path.touch()
        source_path.write_text("int add(int a, int b) { return a + b; }")

        tool = FuncLineCovTool(tmpdir)

        # Mock subprocess.run to return success
        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = mock_coverage_output
        mock_result.stderr = ""

        with mock.patch('subprocess.run', return_value=mock_result) as mock_run:
            result = tool.execute(
                binary_path=str(binary_path),
                profdata_path=str(profdata_path),
                file_path=str(source_path),
                function_name="add"
            )

            print_result(result)

            # Verify result
            assert result["success"] == True
            assert "coverage_output" in result
            assert result["function_name"] == "add"
            # Check that the coverage output contains expected content
            assert "int add(int a, int b)" in result["coverage_output"]
            assert "return a + b" in result["coverage_output"]

            # Verify subprocess was called correctly
            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert "llvm-cov" in call_args[0]
            assert "show" in call_args
            assert "--name=add" in call_args

            print("[OK] Successful execution test passed")


def test_binary_not_found():
    """Test error handling when binary file doesn't exist"""
    print_section("Test 3: Binary File Not Found")

    with tempfile.TemporaryDirectory() as tmpdir:
        tool = FuncLineCovTool(tmpdir)

        result = tool.execute(
            binary_path="/nonexistent/binary",
            profdata_path="/tmp/coverage.profdata",
            file_path="/tmp/test.c",
            function_name="main"
        )

        print_result(result)

        assert result["success"] == False
        assert "Binary file not found" in result["error"]
        print("[OK] Binary not found test passed")


def test_profdata_not_found():
    """Test error handling when profdata file doesn't exist"""
    print_section("Test 4: Profdata File Not Found")

    with tempfile.TemporaryDirectory() as tmpdir:
        binary_path = Path(tmpdir) / "test_binary"
        binary_path.touch()

        tool = FuncLineCovTool(tmpdir)

        result = tool.execute(
            binary_path=str(binary_path),
            profdata_path="/nonexistent/coverage.profdata",
            file_path="/tmp/test.c",
            function_name="main"
        )

        print_result(result)

        assert result["success"] == False
        assert "Profdata file not found" in result["error"]
        print("[OK] Profdata not found test passed")


def test_source_file_not_found():
    """Test error handling when source file doesn't exist"""
    print_section("Test 5: Source File Not Found")

    with tempfile.TemporaryDirectory() as tmpdir:
        binary_path = Path(tmpdir) / "test_binary"
        profdata_path = Path(tmpdir) / "coverage.profdata"
        binary_path.touch()
        profdata_path.touch()

        tool = FuncLineCovTool(tmpdir)

        result = tool.execute(
            binary_path=str(binary_path),
            profdata_path=str(profdata_path),
            file_path="nonexistent.c",
            function_name="main"
        )

        print_result(result)

        assert result["success"] == False
        assert "Source file not found" in result["error"]
        print("[OK] Source file not found test passed")


def test_llvm_cov_command_failure():
    """Test error handling when llvm-cov command fails"""
    print_section("Test 6: llvm-cov Command Failure")

    with tempfile.TemporaryDirectory() as tmpdir:
        binary_path = Path(tmpdir) / "test_binary"
        profdata_path = Path(tmpdir) / "coverage.profdata"
        source_path = Path(tmpdir) / "test.c"

        binary_path.touch()
        profdata_path.touch()
        source_path.touch()

        tool = FuncLineCovTool(tmpdir)

        # Mock subprocess.run to return failure
        mock_result = mock.Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: Invalid profdata format"

        with mock.patch('subprocess.run', return_value=mock_result):
            result = tool.execute(
                binary_path=str(binary_path),
                profdata_path=str(profdata_path),
                file_path=str(source_path),
                function_name="main"
            )

            print_result(result)

            assert result["success"] == False
            assert "llvm-cov command failed" in result["error"]
            assert "Invalid profdata format" in result["error"]
            print("[OK] Command failure test passed")


def test_empty_coverage_output():
    """Test handling of empty coverage output (function not found)"""
    print_section("Test 7: Empty Coverage Output")

    with tempfile.TemporaryDirectory() as tmpdir:
        binary_path = Path(tmpdir) / "test_binary"
        profdata_path = Path(tmpdir) / "coverage.profdata"
        source_path = Path(tmpdir) / "test.c"

        binary_path.touch()
        profdata_path.touch()
        source_path.touch()

        tool = FuncLineCovTool(tmpdir)

        # Mock subprocess.run to return empty output
        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""

        with mock.patch('subprocess.run', return_value=mock_result):
            result = tool.execute(
                binary_path=str(binary_path),
                profdata_path=str(profdata_path),
                file_path=str(source_path),
                function_name="nonexistent_function"
            )

            print_result(result)

            assert result["success"] == False
            assert "No coverage data found" in result["error"]
            print("[OK] Empty output test passed")


def test_relative_path_resolution():
    """Test that relative paths are resolved correctly"""
    print_section("Test 8: Relative Path Resolution")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create subdirectory
        src_dir = Path(tmpdir) / "src"
        src_dir.mkdir()

        binary_path = Path(tmpdir) / "test_binary"
        profdata_path = Path(tmpdir) / "coverage.profdata"
        source_path = src_dir / "test.c"

        binary_path.touch()
        profdata_path.touch()
        source_path.touch()

        tool = FuncLineCovTool(tmpdir)

        # Mock successful execution
        mock_result = mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Coverage data for function main"
        mock_result.stderr = ""

        with mock.patch('subprocess.run', return_value=mock_result) as mock_run:
            # Use relative path
            result = tool.execute(
                binary_path=str(binary_path),
                profdata_path=str(profdata_path),
                file_path="src/test.c",  # Relative path
                function_name="main"
            )

            print_result(result)

            assert result["success"] == True
            # Verify the resolved path is absolute
            assert Path(result["file_path"]).is_absolute()
            assert result["file_path"].endswith("src/test.c")

            # Verify subprocess was called with absolute path
            call_args = mock_run.call_args[0][0]
            assert Path(call_args[3]).is_absolute()  # Source file path should be absolute

            print("[OK] Relative path resolution test passed")


def test_timeout_handling():
    """Test timeout handling for long-running commands"""
    print_section("Test 9: Command Timeout")

    with tempfile.TemporaryDirectory() as tmpdir:
        binary_path = Path(tmpdir) / "test_binary"
        profdata_path = Path(tmpdir) / "coverage.profdata"
        source_path = Path(tmpdir) / "test.c"

        binary_path.touch()
        profdata_path.touch()
        source_path.touch()

        tool = FuncLineCovTool(tmpdir)

        # Mock subprocess.run to raise TimeoutExpired
        import subprocess
        with mock.patch('subprocess.run', side_effect=subprocess.TimeoutExpired('llvm-cov', 30)):
            result = tool.execute(
                binary_path=str(binary_path),
                profdata_path=str(profdata_path),
                file_path=str(source_path),
                function_name="main"
            )

            print_result(result)

            assert result["success"] == False
            assert "timed out" in result["error"]
            print("[OK] Timeout handling test passed")


def main():
    """Run all tests"""
    print("=" * 70)
    print("  FuncLineCovTool Unit Tests")
    print("=" * 70)

    try:
        test_schema_conversion()
        test_successful_execution()
        test_binary_not_found()
        test_profdata_not_found()
        test_source_file_not_found()
        test_llvm_cov_command_failure()
        test_empty_coverage_output()
        test_relative_path_resolution()
        test_timeout_handling()

        print_section("All Tests Passed ✓")
        return 0
    except AssertionError as e:
        print(f"\n[FAILED] Assertion error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n[FAILED] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
