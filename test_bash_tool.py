#!/usr/bin/env python3
"""
Quick test script for BashTool functionality.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from drillagent.tools import BashTool

def test_bash_tool():
    """Test BashTool with various scenarios."""

    # Initialize tool
    repo_path = Path(__file__).parent.resolve()
    bash = BashTool(code_repo_path=str(repo_path))

    print("=" * 60)
    print("BashTool Test Suite")
    print("=" * 60)

    # Test 1: Simple allowed command
    print("\n[Test 1] Simple ls command:")
    result = bash.execute("ls -la")
    print(f"  Success: {result['success']}")
    print(f"  Exit code: {result.get('exit_code', 'N/A')}")
    if result['success']:
        print(f"  Output (first 200 chars): {result['stdout'][:200]}")
    else:
        print(f"  Error: {result.get('error', 'N/A')}")

    # Test 2: Command not in whitelist
    print("\n[Test 2] Forbidden command (rm):")
    result = bash.execute("rm test.txt")
    print(f"  Success: {result['success']}")
    print(f"  Error: {result.get('error', 'N/A')}")
    print(f"  Blocked reason: {result.get('blocked_reason', 'N/A')}")

    # Test 3: Forbidden pattern
    print("\n[Test 3] Forbidden pattern (rm -rf):")
    result = bash.execute("rm -rf /tmp/test")
    print(f"  Success: {result['success']}")
    print(f"  Error: {result.get('error', 'N/A')}")
    print(f"  Blocked reason: {result.get('blocked_reason', 'N/A')}")

    # Test 4: Working directory
    print("\n[Test 4] Working directory (src/):")
    result = bash.execute("pwd", working_dir="src")
    print(f"  Success: {result['success']}")
    if result['success']:
        print(f"  PWD: {result['stdout'].strip()}")

    # Test 5: Command with non-zero exit code
    print("\n[Test 5] Command with non-zero exit code (grep no match):")
    result = bash.execute("grep 'NONEXISTENT_PATTERN' README.md")
    print(f"  Success: {result['success']}")
    print(f"  Exit code: {result.get('exit_code', 'N/A')}")
    print(f"  Note: Success=True even with exit_code=1 (design choice)")

    # Test 6: Python execution
    print("\n[Test 6] Python execution:")
    result = bash.execute("python3 -c 'print(\"Hello from Python\")'")
    print(f"  Success: {result['success']}")
    if result['success']:
        print(f"  Output: {result['stdout'].strip()}")

    # Test 7: Tool schema generation
    print("\n[Test 7] Tool schema generation:")
    claude_schema = bash.to_claude_schema()
    print(f"  Tool name: {claude_schema['name']}")
    print(f"  Parameters: {list(claude_schema['input_schema']['properties'].keys())}")
    print(f"  Required: {claude_schema['input_schema']['required']}")

    print("\n" + "=" * 60)
    print("Test suite completed!")
    print("=" * 60)

if __name__ == "__main__":
    test_bash_tool()
