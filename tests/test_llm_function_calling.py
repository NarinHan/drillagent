#!/usr/bin/env python3
"""
Test LLM Function Calling

This script tests the LLM's ability to autonomously call tools to complete tasks.
Uses the njs repository as test target.
"""

import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from drillagent.models.llm import LLM
from drillagent.utils.tools import (
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


def print_tool_call(tool_call: dict):
    """Pretty print a tool call"""
    print(f"\n[TOOL CALL] {tool_call['name']}")
    print(f"  Arguments: {json.dumps(tool_call['arguments'], indent=4)}")


def print_tool_result(result: dict):
    """Pretty print tool execution result"""
    if result.get("success"):
        print(f"[TOOL RESULT] Success")
        # Print key information
        for key, value in result.items():
            if key in ["success", "content", "tree", "matches"]:
                continue
            print(f"  {key}: {value}")
    else:
        print(f"[TOOL RESULT] Failed: {result.get('error')}")


def test_basic_function_calling():
    """Test basic function calling with a simple task"""
    print_section("Test 1: Basic Function Calling")

    # Configuration
    api_key_file = "/home/ubuntu/PoV/DrillAgent/openai.key"
    repo_path = "/home/shared_project/repos/njs"

    # Check if repo exists
    if not Path(repo_path).exists():
        print(f"[ERROR] Repository not found: {repo_path}")
        return False

    # Initialize LLM
    print(f"Initializing OpenAI LLM with API key from: {api_key_file}")
    try:
        llm = LLM(
            provider="openai",
            model_name="gpt-4-turbo",
            api_key_file=api_key_file
        )
        print(f"[OK] LLM initialized: {llm.provider}/{llm.model_name}")
    except Exception as e:
        print(f"[ERROR] Failed to initialize LLM: {e}")
        return False

    # Initialize tools
    print(f"\nInitializing tools for repository: {repo_path}")
    tools = [
        ReadFileTool(repo_path),
        GrepTool(repo_path),
        FindFileTool(repo_path),
        ListDirTool(repo_path),
        TreeTool(repo_path)
    ]
    print(f"[OK] Initialized {len(tools)} tools")

    # Create tool registry for execution
    tool_registry = {tool.name(): tool for tool in tools}

    # System prompt
    system_prompt = """You are a code analysis assistant. You have access to tools to explore and analyze code repositories.

Available tools:
- read_file: Read source code files with line numbers
- grep_code: Search for patterns across the codebase
- find_file: Find files by name or pattern
- list_directory: List directory contents
- tree: Show directory tree structure

Your task is to systematically use these tools to answer user questions about the codebase."""

    # Test task
    task = """Please explore the njs repository and tell me:
1. What is the overall structure of the repository?
2. Find the main README file and read its first 30 lines
3. What programming language is primarily used?"""

    print(f"\n[USER TASK]\n{task}")

    # Single turn interaction (no loop yet, just test the API)
    print("\n[CALLING LLM WITH TOOLS]")
    try:
        text_response, tool_calls = llm.generate_with_tools(
            prompt=task,
            tools=tools,
            system_prompt=system_prompt,
            temperature=0.3,  # Lower temperature for more focused responses
            max_tokens=2000
        )

        # Print LLM's reasoning
        if text_response:
            print(f"\n[LLM THINKING]\n{text_response}")

        # Print tool calls
        if tool_calls:
            print(f"\n[LLM REQUESTED {len(tool_calls)} TOOL CALLS]")
            for i, tool_call in enumerate(tool_calls, 1):
                print(f"\n--- Tool Call {i}/{len(tool_calls)} ---")
                print_tool_call(tool_call)

                # Execute the tool
                tool_name = tool_call["name"]
                tool_args = tool_call["arguments"]

                if tool_name in tool_registry:
                    tool = tool_registry[tool_name]
                    result = tool.execute(**tool_args)
                    print_tool_result(result)

                    # Show sample output for content-heavy results
                    if result.get("success"):
                        if "content" in result:
                            content = result["content"]
                            if len(content) > 500:
                                print(f"\n  Content (first 500 chars):\n{content[:500]}...")
                            else:
                                print(f"\n  Content:\n{content}")
                        elif "tree" in result:
                            print(f"\n  Tree:\n{result['tree']}")
                        elif "matches" in result:
                            print(f"\n  Matches ({len(result['matches'])} total):")
                            for match in result["matches"][:3]:
                                print(f"    - {match}")
                else:
                    print(f"  [ERROR] Unknown tool: {tool_name}")
        else:
            print("\n[NO TOOL CALLS] LLM decided not to use tools")

        print("\n[SUCCESS] Function calling test completed")
        return True

    except Exception as e:
        print(f"\n[ERROR] Function calling failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_multi_turn_interaction():
    """Test multi-turn interaction with conversation history"""
    print_section("Test 2: Multi-Turn Interaction")

    api_key_file = "/home/ubuntu/PoV/DrillAgent/openai.key"
    repo_path = "/home/shared_project/repos/njs"

    # Initialize
    llm = LLM(provider="openai", api_key_file=api_key_file)
    tools = [
        ReadFileTool(repo_path),
        GrepTool(repo_path),
        FindFileTool(repo_path)
    ]
    tool_registry = {tool.name(): tool for tool in tools}

    system_prompt = "You are a helpful code assistant. Use tools to answer questions about the codebase."

    # Conversation history
    conversation_history = []

    # Turn 1
    prompt1 = "Find all C source files (*.c) in the repository"
    print(f"\n[TURN 1] User: {prompt1}")

    text_response, tool_calls = llm.generate_with_tools(
        prompt=prompt1,
        tools=tools,
        system_prompt=system_prompt,
        conversation_history=conversation_history,
        temperature=0.3
    )

    print(f"LLM Response: {text_response}")
    if tool_calls:
        print(f"Tool Calls: {len(tool_calls)}")
        for call in tool_calls:
            print(f"  - {call['name']}({call['arguments']})")

    # Add to conversation history
    conversation_history.append({"role": "user", "content": prompt1})
    conversation_history.append({"role": "assistant", "content": text_response})

    # Turn 2 (references previous context)
    prompt2 = "Now read the first file you found"
    print(f"\n[TURN 2] User: {prompt2}")

    text_response, tool_calls = llm.generate_with_tools(
        prompt=prompt2,
        tools=tools,
        system_prompt=system_prompt,
        conversation_history=conversation_history,
        temperature=0.3
    )

    print(f"LLM Response: {text_response}")
    if tool_calls:
        print(f"Tool Calls: {len(tool_calls)}")
        for call in tool_calls:
            print(f"  - {call['name']}({call['arguments']})")

    print("\n[SUCCESS] Multi-turn interaction test completed")
    return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("  LLM Function Calling Test Suite")
    print("=" * 70)

    results = []

    # Test 1: Basic function calling
    try:
        result = test_basic_function_calling()
        results.append(("Basic Function Calling", result))
    except Exception as e:
        print(f"[ERROR] Test 1 failed with exception: {e}")
        results.append(("Basic Function Calling", False))

    # Test 2: Multi-turn interaction
    # Commented out to save API calls during initial testing
    # Uncomment when ready to test
    """
    try:
        result = test_multi_turn_interaction()
        results.append(("Multi-Turn Interaction", result))
    except Exception as e:
        print(f"[ERROR] Test 2 failed with exception: {e}")
        results.append(("Multi-Turn Interaction", False))
    """

    # Summary
    print_section("Test Summary")
    for test_name, result in results:
        status = "PASSED" if result else "FAILED"
        print(f"{test_name}: {status}")

    all_passed = all(result for _, result in results)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
