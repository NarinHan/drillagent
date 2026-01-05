#!/usr/bin/env python3
"""
Test script for agent tools

This script tests all the basic tools (ReadFile, Grep, FindFile, ListDir, Tree)
to ensure they work correctly before integrating with LLM.
"""

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from drillagent.tools.basic_tools import (
    ReadFileTool,
    GrepTool,
    FindFileTool,
    ListDirTool,
    TreeTool
)


def print_section(title: str):
    """Print a formatted section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_result(result: dict):
    """Print tool execution result in a readable format"""
    if result.get("success"):
        print("[SUCCESS]")
        # Print relevant fields (excluding 'success')
        for key, value in result.items():
            if key == "success":
                continue
            if key == "content" or key == "tree":
                # Truncate long output
                if len(str(value)) > 500:
                    print(f"{key}: {str(value)[:500]}...\n   (truncated)")
                else:
                    print(f"{key}:\n{value}")
            elif key == "matches":
                print(f"{key}: ({len(value)} items)")
                for i, match in enumerate(value[:5]):  # Show first 5
                    print(f"  [{i+1}] {match}")
                if len(value) > 5:
                    print(f"  ... and {len(value) - 5} more")
            elif key == "entries":
                print(f"{key}: ({len(value)} items)")
                for item in value[:10]:  # Show first 10
                    print(f"  - {item}")
                if len(value) > 10:
                    print(f"  ... and {len(value) - 10} more")
            else:
                print(f"{key}: {value}")
    else:
        print(f"[FAILED] {result.get('error', 'Unknown error')}")
    print()


def test_schema_conversion(tool):
    """Test schema conversion to Claude and OpenAI formats"""
    print(f"\nTesting schema conversion for: {tool.name()}")

    # Test Claude schema
    claude_schema = tool.to_claude_schema()
    print("\nClaude Schema:")
    print(json.dumps(claude_schema, indent=2))

    # Test OpenAI schema
    openai_schema = tool.to_openai_schema()
    print("\nOpenAI Schema:")
    print(json.dumps(openai_schema, indent=2))


def main():
    """Run all tool tests"""
    # Use the DrillAgent repository itself as test target
    repo_path = Path(__file__).parent.parent
    print(f"Testing tools on repository: {repo_path}")

    # Initialize all tools
    try:
        read_file = ReadFileTool(str(repo_path))
        grep = GrepTool(str(repo_path))
        find_file = FindFileTool(str(repo_path))
        list_dir = ListDirTool(str(repo_path))
        tree = TreeTool(str(repo_path))
        print("[OK] All tools initialized successfully")
    except Exception as e:
        print(f"[ERROR] Failed to initialize tools: {e}")
        return 1

    # Test 1: ReadFile Tool
    print_section("Test 1: ReadFile Tool")

    print("1.1 Read entire README.md")
    result = read_file.execute(file_path="README.md")
    print_result(result)

    print("1.2 Read specific line range from config.py")
    result = read_file.execute(
        file_path="src/drillagent/config.py",
        start_line=10,
        end_line=25
    )
    print_result(result)

    print("1.3 Try to read non-existent file")
    result = read_file.execute(file_path="nonexistent.txt")
    print_result(result)

    # Test 2: Grep Tool
    print_section("Test 2: Grep Tool")

    print("2.1 Search for 'class' keyword")
    result = grep.execute(pattern="class", max_results=10)
    print_result(result)

    print("2.2 Search for 'DrillAgent' in Python files")
    result = grep.execute(pattern="DrillAgent", file_extension="py", max_results=5)
    print_result(result)

    print("2.3 Case-insensitive search for 'agent'")
    result = grep.execute(pattern="agent", case_sensitive=False, max_results=8)
    print_result(result)

    # Test 3: FindFile Tool
    print_section("Test 3: FindFile Tool")

    print("3.1 Find all Python files")
    result = find_file.execute(filename_pattern="*.py", max_results=15)
    print_result(result)

    print("3.2 Find config files")
    result = find_file.execute(filename_pattern="config.*")
    print_result(result)

    print("3.3 Find README files")
    result = find_file.execute(filename_pattern="README*")
    print_result(result)

    # Test 4: ListDir Tool
    print_section("Test 4: ListDir Tool")

    print("4.1 List root directory")
    result = list_dir.execute(path=".")
    print_result(result)

    print("4.2 List src/drillagent directory")
    result = list_dir.execute(path="src/drillagent")
    print_result(result)

    print("4.3 Try to list non-existent directory")
    result = list_dir.execute(path="nonexistent_dir")
    print_result(result)

    # Test 5: Tree Tool
    print_section("Test 5: Tree Tool")

    print("5.1 Show tree of src directory (depth=2)")
    result = tree.execute(path="src", max_depth=2, show_files=True)
    print_result(result)

    print("5.2 Show directory-only tree (depth=3)")
    result = tree.execute(path=".", max_depth=3, show_files=False)
    print_result(result)

    print("5.3 Show deep tree of utils (depth=1)")
    result = tree.execute(path="src/drillagent/utils", max_depth=1, show_files=True)
    print_result(result)

    # Test 6: Schema Conversion
    print_section("Test 6: Schema Conversion")
    test_schema_conversion(read_file)
    test_schema_conversion(grep)

    print_section("All Tests Completed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
