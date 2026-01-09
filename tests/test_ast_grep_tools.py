#!/usr/bin/env python3
"""
Test script for ast-grep tools

This script tests the ast-grep based code search tools
to ensure they work correctly before integrating with LLM.
"""

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from drillagent.tools.ast_grep_tools import (
    AstGrepManager,
    AstGrepFunctionSearchTool,
    AstGrepPatternSearchTool
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
            elif key == "matches":
                print(f"{key}: ({len(value)} items)")
                for i, match in enumerate(value[:3]):  # Show first 3
                    print(f"\n  Match {i+1}:")
                    for match_key, match_value in match.items():
                        if match_key in ["text", "source_snippet", "matched_code", "signature"]:
                            # Truncate long code snippets
                            if len(str(match_value)) > 200:
                                print(f"    {match_key}: {str(match_value)[:200]}...")
                            else:
                                print(f"    {match_key}: {match_value}")
                        else:
                            print(f"    {match_key}: {match_value}")
                if len(value) > 3:
                    print(f"\n  ... and {len(value) - 3} more matches")
            else:
                print(f"{key}: {value}")
    else:
        print(f"[FAILED] {result.get('error', 'Unknown error')}")
    print()


def test_manager(repo_path: Path):
    """Test AstGrepManager with C code"""
    print_section("Test 1: AstGrepManager - C Code")

    try:
        manager = AstGrepManager(str(repo_path))
        print("[OK] AstGrepManager initialized successfully")
    except Exception as e:
        print(f"[ERROR] Failed to initialize AstGrepManager: {e}")
        return False

    # Test 1.1: Check availability
    print("\n1.1 Check ast-grep availability")
    if manager.is_available():
        print("[OK] ast-grep is available")
    else:
        print("[ERROR] ast-grep is not available")
        return False

    # Test 1.2: Search for function pattern in C - non-pointer return
    print("\n1.2 Search for C functions with non-pointer return types")
    result = manager.search_pattern(
        pattern="$$$MODS $FUNC($$$PARAMS) { $$$BODY }",
        path="tests/example.c",
        language="c"
    )
    print(f"Found {result.get('count', 0)} functions")
    if result.get('count', 0) > 0:
        print("[OK] Pattern matching works for non-pointer functions")
    print_result(result)

    # Test 1.3: Search for specific function - pointer return type
    print("\n1.3 Search for allocate_user function (returns pointer)")
    result = manager.search_function(
        function_name="allocate_user",
        path="tests/example.c",
        language="c"
    )
    print_result(result)

    # Test 1.4: Search for main function
    print("\n1.4 Search for main function")
    result = manager.search_function(
        function_name="main",
        path="tests/example.c",
        language="c"
    )
    print_result(result)

    return True


def test_function_search_tool(repo_path: Path):
    """Test AstGrepFunctionSearchTool with C code"""
    print_section("Test 2: AstGrepFunctionSearchTool - C Code")

    try:
        tool = AstGrepFunctionSearchTool(str(repo_path))
        print(f"[OK] Tool initialized: {tool.name()}")
        print(f"Description: {tool.description()[:100]}...")
    except Exception as e:
        print(f"[ERROR] Failed to initialize tool: {e}")
        return False

    # Test 2.1: Search for main function
    print("\n2.1 Search for 'main' function in example.c")
    result = tool.execute(
        function_name="main",
        search_path="tests/example.c",
        language="c"
    )
    if result.get("count", 0) == 1:
        print("[OK] Found main function")
    print_result(result)

    # Test 2.2: Search for static function returning pointer
    print("\n2.2 Search for 'allocate_user' (static, pointer return)")
    result = tool.execute(
        function_name="allocate_user",
        search_path="tests/example.c",
        language="c"
    )
    if result.get("count", 0) == 1:
        print("[OK] Found allocate_user function")
    print_result(result)

    # Test 2.3: Search for static function returning const pointer
    print("\n2.3 Search for 'role_to_string' (static const char *)")
    result = tool.execute(
        function_name="role_to_string",
        search_path="tests/example.c",
        language="c"
    )
    if result.get("count", 0) == 1:
        print("[OK] Found role_to_string function")
    print_result(result)

    # Test 2.4: Search for static void function
    print("\n2.4 Search for 'print_user' (static void)")
    result = tool.execute(
        function_name="print_user",
        search_path="tests/example.c",
        language="c"
    )
    if result.get("count", 0) == 1:
        print("[OK] Found print_user function")
    print_result(result)

    # Test 2.5: Search for multiple occurrences
    print("\n2.5 Search in entire tests directory")
    result = tool.execute(
        function_name="sum_array",
        search_path="tests/",
        language="c"
    )
    print_result(result)

    # Test 2.6: Search for non-existent function
    print("\n2.6 Search for non-existent function")
    result = tool.execute(
        function_name="nonexistent_func_xyz123",
        search_path="tests/example.c",
        language="c"
    )
    if result.get("count", 0) == 0:
        print("[OK] Correctly returned zero matches")
    print_result(result)

    return True


def test_pattern_search_tool(repo_path: Path):
    """Test AstGrepPatternSearchTool with C code"""
    print_section("Test 3: AstGrepPatternSearchTool - C Code")

    try:
        tool = AstGrepPatternSearchTool(str(repo_path))
        print(f"[OK] Tool initialized: {tool.name()}")
        print(f"Description: {tool.description()[:100]}...")
    except Exception as e:
        print(f"[ERROR] Failed to initialize tool: {e}")
        return False

    # Test 3.1: Search for malloc calls
    print("\n3.1 Search for malloc() calls")
    result = tool.execute(
        pattern="malloc($SIZE)",
        language="c",
        search_path="tests/example.c"
    )
    print_result(result)

    # Test 3.2: Search for strcpy calls (unsafe pattern)
    print("\n3.2 Search for strcpy() calls")
    result = tool.execute(
        pattern="strcpy($DEST, $SRC)",
        language="c",
        search_path="tests/example.c",
        context_lines=2
    )
    print_result(result)

    # Test 3.3: Search for return statements
    print("\n3.3 Search for return statements")
    result = tool.execute(
        pattern="return $VALUE",
        language="c",
        search_path="tests/example.c",
        context_lines=0
    )
    print_result(result)

    # Test 3.4: Search for typedef struct
    print("\n3.4 Search for typedef struct definitions")
    result = tool.execute(
        pattern="typedef struct { $$$FIELDS } $NAME",
        language="c",
        search_path="tests/example.c"
    )
    print_result(result)

    # Test 3.5: Search for enum definitions
    print("\n3.5 Search for enum definitions")
    result = tool.execute(
        pattern="typedef enum { $$$VALUES } $NAME",
        language="c",
        search_path="tests/example.c"
    )
    print_result(result)

    # Test 3.6: Search for if statements
    print("\n3.6 Search for if statements")
    result = tool.execute(
        pattern="if ($COND) { $$$BODY }",
        language="c",
        search_path="tests/example.c",
        context_lines=1
    )
    print_result(result)

    return True


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
    """Run all ast-grep tool tests"""
    # Use the DrillAgent repository itself as test target
    repo_path = Path(__file__).parent.parent
    print(f"Testing ast-grep tools on repository: {repo_path}")

    # Check if ast-grep is available
    print("\nChecking ast-grep availability...")
    try:
        import subprocess
        result = subprocess.run(
            ["ast-grep", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print(f"[OK] ast-grep is installed: {result.stdout.strip()}")
        else:
            print("[ERROR] ast-grep is not working properly")
            return 1
    except FileNotFoundError:
        print("[ERROR] ast-grep is not installed")
        print("Please install ast-grep: https://ast-grep.github.io/")
        return 1
    except Exception as e:
        print(f"[ERROR] Failed to check ast-grep: {e}")
        return 1

    # Run tests
    success = True

    # Test 1: AstGrepManager
    if not test_manager(repo_path):
        success = False

    # Test 2: AstGrepFunctionSearchTool
    if not test_function_search_tool(repo_path):
        success = False

    # Test 3: AstGrepPatternSearchTool
    if not test_pattern_search_tool(repo_path):
        success = False

    # Test 4: Schema Conversion
    print_section("Test 4: Schema Conversion")
    try:
        function_tool = AstGrepFunctionSearchTool(str(repo_path))
        pattern_tool = AstGrepPatternSearchTool(str(repo_path))

        test_schema_conversion(function_tool)
        test_schema_conversion(pattern_tool)
        print("[OK] Schema conversion successful")
    except Exception as e:
        print(f"[ERROR] Schema conversion failed: {e}")
        success = False

    # Summary
    print_section("Test Summary")
    if success:
        print("[SUCCESS] All tests passed!")
        return 0
    else:
        print("[FAILED] Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
