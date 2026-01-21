#!/usr/bin/env python3
"""
Script to view LLM interaction history in a readable Markdown-like format.

Usage:
    python3 scripts/view_llm_history.py <path_to_llm_history.json>
    python3 scripts/view_llm_history.py  # Uses default path: output/*/llm_history.json
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List


def format_timestamp(ts_str: str) -> str:
    """Format ISO timestamp to readable format"""
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        return ts_str


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate text to max length"""
    if not text or len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def format_phase_separator(entry: Dict[str, Any]) -> str:
    """Format a phase separator entry"""
    phase_name = entry.get("phase_name", "Unknown")
    timestamp = format_timestamp(entry.get("timestamp", ""))

    output = []
    output.append("\n" + "=" * 100)
    output.append(f"PHASE: {phase_name}")
    output.append(f"Time: {timestamp}")
    output.append("=" * 100 + "\n")

    return "\n".join(output)


def format_agent_loop_start(entry: Dict[str, Any]) -> str:
    """Format an agent loop start entry"""
    provider = entry.get("provider", "Unknown")
    model = entry.get("model_name", "Unknown")
    timestamp = format_timestamp(entry.get("timestamp", ""))
    system_prompt = entry.get("system_prompt")

    output = []
    output.append("-" * 100)
    output.append("🤖 AGENT LOOP START")
    output.append("-" * 100)
    output.append(f"Provider: {provider} | Model: {model} | Time: {timestamp}")

    if system_prompt:
        output.append("\n### System Prompt:")
        output.append(system_prompt)

    output.append("(Task and interactions will follow below)")
    output.append("-" * 100 + "\n")

    return "\n".join(output)


def format_agent_loop_end(entry: Dict[str, Any]) -> str:
    """Format an agent loop end entry"""
    success = entry.get("success", False)
    iterations = entry.get("iterations", 0)
    stop_reason = entry.get("stop_reason", "Unknown")
    error = entry.get("error")
    timestamp = format_timestamp(entry.get("timestamp", ""))

    output = []
    output.append("\n" + "-" * 100)
    output.append("🏁 AGENT LOOP END")
    output.append("-" * 100)
    output.append(f"Success: {'✓ Yes' if success else '✗ No'}")
    output.append(f"Iterations: {iterations}")
    output.append(f"Stop Reason: {stop_reason}")
    output.append(f"Time: {timestamp}")

    if error:
        output.append(f"\n⚠️  Error: {error}")

    output.append("\n(Final response is shown in the last interaction above)")
    output.append("-" * 100 + "\n")

    return "\n".join(output)


def format_llm_interaction(entry: Dict[str, Any], index: int, inside_agent_loop: bool = False) -> str:
    """Format an LLM interaction entry"""
    provider = entry.get("provider", "Unknown")
    model = entry.get("model_name", "Unknown")
    timestamp = format_timestamp(entry.get("timestamp", ""))
    system_prompt = entry.get("system_prompt")
    user_prompt = entry.get("user_prompt", "")
    assistant_response = entry.get("assistant_response", "")
    tool_calls = entry.get("tool_calls", [])
    tool_results = entry.get("tool_results")
    stop_reason = entry.get("stop_reason", "Unknown")
    usage_stats = entry.get("usage_stats")

    output = []
    output.append("\n" + "~" * 100)
    output.append(f"💬 LLM INTERACTION #{index}")
    output.append("~" * 100)
    output.append(f"Provider: {provider} | Model: {model} | Time: {timestamp}")

    # System prompt - only show if NOT inside agent loop (to avoid repetition)
    if system_prompt and not inside_agent_loop:
        output.append("\n### 📋 System Prompt:")
        output.append(f"  {system_prompt}")

    # User prompt
    output.append("\n### 👤 User Prompt:")
    output.append(user_prompt)

    # Assistant response
    output.append("\n### 🤖 Assistant Response:")
    output.append(assistant_response if assistant_response else "[No text response]")

    # Tool calls
    if tool_calls:
        output.append(f"\n### 🔧 Tool Calls: {len(tool_calls)} calls")
        for i, tool_call in enumerate(tool_calls):
            tool_name = tool_call.get("name", "unknown")
            tool_id = tool_call.get("id", "")
            tool_args = tool_call.get("arguments", {})
            output.append(f"\n  [{i+1}] {tool_name} (ID: {tool_id})")
            # Show arguments
            args_str = json.dumps(tool_args, indent=4)
            output.append(f"      Arguments: {args_str}")

    # Tool results
    if tool_results and tool_calls:
        # Filter to only show results for coverage_query
        whilelist_tools = ["coverage_query"]
        coverage_results = []
        for i, (tool_call, result) in enumerate(zip(tool_calls, tool_results)):
            tool_name = tool_call.get("name", "unknown")
            if tool_name in whilelist_tools:
                coverage_results.append((i, result))

        if coverage_results:
            output.append(f"\n### 📤 Tool Results: {len(coverage_results)} results")
            for i, result in coverage_results:
                result_str = str(result)
                # Don't truncate coverage results - show them in full
                output.append(f"  [Call #{i+1}] {result_str}")

    # Stop reason and usage
    output.append(f"\n### ⏹️  Stop Reason: {stop_reason}")

    if usage_stats:
        total_tokens = usage_stats.get("total_tokens", 0)
        prompt_tokens = usage_stats.get("prompt_tokens", 0)
        completion_tokens = usage_stats.get("completion_tokens", 0)
        api_calls = usage_stats.get("api_calls", 0)
        # output.append(f"\n### 📊 Usage Stats:")
        # output.append(f"  Total Tokens: {total_tokens:,} (Prompt: {prompt_tokens:,} | Completion: {completion_tokens:,})")
        # output.append(f"  API Calls: {api_calls}")

    output.append("~" * 100 + "\n")

    return "\n".join(output)


def format_llm_history(log_data: Dict[str, Any], show_full: bool = False) -> str:
    """Format the entire LLM history log"""
    version = log_data.get("llm_history_version", "Unknown")
    initialized_at = format_timestamp(log_data.get("initialized_at", ""))
    interactions = log_data.get("interactions", [])

    output = []

    # Header
    output.append("\n" + "█" * 100)
    output.append("LLM INTERACTION HISTORY")
    output.append("█" * 100)
    output.append(f"Version: {version}")
    output.append(f"Initialized: {initialized_at}")
    output.append(f"Total Interactions: {len(interactions)}")
    output.append("█" * 100)

    # Statistics
    stats = {}
    for interaction in interactions:
        itype = interaction.get("type", "unknown")
        stats[itype] = stats.get(itype, 0) + 1

    output.append("\n### 📈 Interaction Breakdown:")
    for itype, count in sorted(stats.items()):
        output.append(f"  - {itype}: {count}")

    # Process each interaction
    llm_interaction_count = 0
    inside_agent_loop = False  # Track whether we're inside an agent loop

    for interaction in interactions:
        itype = interaction.get("type", "unknown")

        if itype == "phase_separator":
            output.append(format_phase_separator(interaction))
            inside_agent_loop = False  # Reset when entering a new phase

        elif itype == "agent_loop_start":
            output.append(format_agent_loop_start(interaction))
            inside_agent_loop = True  # Mark that we're now inside an agent loop

        elif itype == "agent_loop_end":
            output.append(format_agent_loop_end(interaction))
            inside_agent_loop = False  # Mark that we've exited the agent loop

        elif itype == "llm_interaction":
            llm_interaction_count += 1
            output.append(format_llm_interaction(interaction, llm_interaction_count, inside_agent_loop))

        else:
            output.append(f"\n[Unknown interaction type: {itype}]\n")

    # Footer
    output.append("\n" + "█" * 100)
    output.append("END OF LLM HISTORY")
    output.append("█" * 100 + "\n")

    return "\n".join(output)


def main():
    """Main entry point"""
    if len(sys.argv) > 1:
        log_file_path = Path(sys.argv[1])
    else:
        # Try to find llm_history.json in output directory
        output_dir = Path("output")
        if output_dir.exists():
            # Find the first llm_history.json
            log_files = list(output_dir.rglob("llm_history.json"))
            if log_files:
                log_file_path = log_files[0]
                print(f"Using: {log_file_path}", file=sys.stderr)
            else:
                print("Error: No llm_history.json found in output directory", file=sys.stderr)
                print("Usage: python scripts/view_llm_history.py <path_to_llm_history.json>", file=sys.stderr)
                sys.exit(1)
        else:
            print("Error: No log file specified and output directory not found", file=sys.stderr)
            print("Usage: python scripts/view_llm_history.py <path_to_llm_history.json>", file=sys.stderr)
            sys.exit(1)

    # Read and parse log file
    if not log_file_path.exists():
        print(f"Error: File not found: {log_file_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            log_data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in log file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading log file: {e}", file=sys.stderr)
        sys.exit(1)

    # Format and print
    formatted_output = format_llm_history(log_data)
    print(formatted_output)


if __name__ == "__main__":
    main()
