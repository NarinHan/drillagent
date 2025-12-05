#!/usr/bin/env python3
"""
Complete Task Test - LLM uses tools to fully answer a question

This demonstrates the full agent loop where LLM:
1. Receives a task
2. Decides which tools to call
3. Executes tools
4. Processes results
5. Provides final answer
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
    TreeTool
)


def main():
    """Run complete agent task"""
    print("=" * 70)
    print("  Complete Agent Task Test")
    print("=" * 70)

    # Configuration
    api_key_file = "/home/ubuntu/PoV/DrillAgent/openai.key"
    repo_path = "/home/shared_project/repos/njs"

    # Initialize LLM
    print(f"\nInitializing LLM...")
    llm = LLM(
        provider="openai",
        model_name="gpt-4-turbo",
        api_key_file=api_key_file
    )
    print(f"✓ LLM ready: {llm.provider}/{llm.model_name}")

    # Initialize tools
    print(f"\nInitializing tools for: {repo_path}")
    tools = [
        ReadFileTool(repo_path),
        GrepTool(repo_path),
        FindFileTool(repo_path),
        TreeTool(repo_path)
    ]
    tool_registry = {tool.name(): tool for tool in tools}
    print(f"✓ {len(tools)} tools ready")

    # System prompt
    system_prompt = """You are a code exploration assistant with access to file system tools.

Your approach should be:
1. Use tools systematically to gather information
2. After calling tools, wait for results before making conclusions
3. Be thorough but efficient

Available tools:
- read_file: Read source files with line numbers
- grep_code: Search for patterns in code
- find_file: Find files by name
- tree: Show directory structure"""

    # Task
    # e.g., What are the main source code directories?
    task = """Explore the njs repository and answer:

1. What is this project about? (read the README)
2. Find the main function of the njs program, give me the source file and line numbers, ignore all the files in `test/`.
3. Find a file named 'njs_array.c' and show me lines 1-30

Use the tools systematically to answer each question."""

    print(f"\n{'=' * 70}")
    print("TASK:")
    print(task)
    print('=' * 70)

    # Multi-turn agent loop
    conversation_history = []
    max_iterations = 5
    iteration = 0

    current_prompt = task

    while iteration < max_iterations:
        iteration += 1
        print(f"\n{'▼' * 70}")
        print(f"  ITERATION {iteration}/{max_iterations}")
        print('▼' * 70)

        # Call LLM with tools
        print("\n[Calling LLM...]")
        text_response, tool_calls = llm.generate_with_tools(
            prompt=current_prompt,
            tools=tools,
            system_prompt=system_prompt,
            conversation_history=conversation_history,
            temperature=0.3,
            max_tokens=3000
        )

        # Show LLM's thinking
        if text_response:
            print(f"\n[LLM Reasoning]")
            print(text_response)

        # Add to history
        conversation_history.append({
            "role": "user",
            "content": current_prompt
        })
        conversation_history.append({
            "role": "assistant",
            "content": text_response
        })

        # If no tool calls, LLM is done
        if not tool_calls:
            print("\n[Agent Complete] No more tools needed")
            print("\n" + "=" * 70)
            print("  FINAL ANSWER")
            print("=" * 70)
            print(text_response)
            break

        # Execute tool calls
        print(f"\n[Executing {len(tool_calls)} tool(s)]")
        tool_results_text = ""

        for i, tool_call in enumerate(tool_calls, 1):
            tool_name = tool_call["name"]
            tool_args = tool_call["arguments"]

            print(f"\n  Tool {i}: {tool_name}")
            print(f"  Args: {json.dumps(tool_args, indent=8)}")

            # Execute tool
            if tool_name in tool_registry:
                tool = tool_registry[tool_name]
                result = tool.execute(**tool_args)

                if result.get("success"):
                    print(f"  ✓ Success")

                    # Build result text for next LLM prompt
                    if "content" in result:
                        content = result["content"]
                        if len(content) > 1000:
                            tool_results_text += f"\nTool '{tool_name}' result:\n{content[:1000]}...\n(truncated)\n"
                        else:
                            tool_results_text += f"\nTool '{tool_name}' result:\n{content}\n"
                    elif "tree" in result:
                        tool_results_text += f"\nTool '{tool_name}' result:\n{result['tree']}\n"
                    elif "matches" in result:
                        matches_summary = f"Found {result['count']} matches:\n"
                        for match in result["matches"][:10]:
                            matches_summary += f"  - {match}\n"
                        tool_results_text += f"\nTool '{tool_name}' result:\n{matches_summary}\n"
                    else:
                        tool_results_text += f"\nTool '{tool_name}' result: {json.dumps(result, indent=2)}\n"
                else:
                    print(f"  ✗ Failed: {result.get('error')}")
                    tool_results_text += f"\nTool '{tool_name}' failed: {result.get('error')}\n"
            else:
                print(f"  ✗ Unknown tool: {tool_name}")
                tool_results_text += f"\nUnknown tool: {tool_name}\n"

        # Prepare next prompt with tool results
        current_prompt = f"""Based on the tool results below, continue with the task:

{tool_results_text}

Remember the original task:
{task}

Provide your analysis or call more tools if needed."""

    else:
        # Max iterations reached
        print(f"\n[Max iterations ({max_iterations}) reached]")
        print("\n" + "=" * 70)
        print("  LAST RESPONSE")
        print("=" * 70)
        print(text_response)

    print("\n" + "=" * 70)
    print("  Test Complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
