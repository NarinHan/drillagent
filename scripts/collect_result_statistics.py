#!/usr/bin/env python3
"""
Collect and display result statistics for a DrillAgent task output directory.

This script analyzes:
1. POV file counts (pov-*, final-pov-*, variant-pov-*)
2. Time overhead from time_overhead.json
3. Token usage and costs from tokens_overhead.json
4. LLM interaction statistics from llm_history.json
"""

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Any, List, Tuple


def find_pov_files(task_dir: Path) -> Dict[str, List[Path]]:
    """
    Find all POV-related files in a task directory.

    Returns:
        Dictionary with keys 'pov', 'final_pov', 'variant_pov' containing lists of paths.
    """
    result = {
        "pov": [],
        "final_pov": [],
        "variant_pov": [],
    }

    # Pattern: pov-{project}-{timestamp}-PEA-round{N}
    pov_pattern = re.compile(r"^pov-.*-PEA-round\d+$")
    # Pattern: final-pov-{project}-{timestamp}-CTA(-round{N})?
    final_pov_pattern = re.compile(r"^final-pov-.*-CTA(-round\d+)?$")
    # Pattern: variant-pov-{project}-{timestamp}-CTA-round{N}
    variant_pov_pattern = re.compile(r"^variant-pov-.*-CTA-round\d+$")

    for f in task_dir.iterdir():
        if not f.is_file():
            continue
        name = f.name
        if final_pov_pattern.match(name):
            result["final_pov"].append(f)
        elif variant_pov_pattern.match(name):
            result["variant_pov"].append(f)
        elif pov_pattern.match(name):
            result["pov"].append(f)

    return result


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to 'Xmin Xsec' format.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted string like '2min 35sec'
    """
    total_seconds = int(seconds)
    minutes = total_seconds // 60
    secs = total_seconds % 60
    if minutes > 0:
        return f"{minutes}min {secs}sec"
    return f"{secs}sec"


def load_time_overhead(task_dir: Path) -> Dict[str, float]:
    """
    Load time overhead data from time_overhead.json.

    Returns:
        Dictionary with phase names as keys and duration in seconds as values.
    """
    time_file = task_dir / "time_overhead.json"
    if not time_file.exists():
        return {}

    with open(time_file, "r", encoding="utf-8") as f:
        return json.load(f)


def load_tokens_overhead(task_dir: Path) -> Dict[str, Dict[str, Any]]:
    """
    Load token overhead data from tokens_overhead.json.

    Returns:
        Dictionary with phase names (VAA, PEA, CTA) as keys.
    """
    tokens_file = task_dir / "tokens_overhead.json"
    if not tokens_file.exists():
        return {}

    with open(tokens_file, "r", encoding="utf-8") as f:
        return json.load(f)


def load_llm_history(task_dir: Path) -> Dict[str, Any]:
    """
    Load LLM history data from llm_history.json.

    Returns:
        The parsed JSON data or empty dict if file doesn't exist.
    """
    history_file = task_dir / "llm_history.json"
    if not history_file.exists():
        return {}

    with open(history_file, "r", encoding="utf-8") as f:
        return json.load(f)


def analyze_llm_history(history_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze LLM history to extract statistics.

    Returns:
        Dictionary containing:
        - agent_loop_count: Total number of agent loops
        - agent_loop_by_phase: Tuple of (VAA, CIA, PEA, CTA) agent loop counts
        - llm_interaction_count: Total number of LLM interactions
        - llm_interaction_by_phase: Tuple of (VAA, CIA, PEA, CTA) interaction counts
        - total_tool_calls: Total number of tool calls
        - tool_call_counts: Counter of tool calls by name
    """
    # Phase name mapping from llm_history phase_separator to our short names
    phase_map = {
        "VulnerabilityAnalysis": "VAA",
        "CodeInstrumentation": "CIA",
        "PathExploration": "PEA",
        "CrashTrigger": "CTA",
        "CrashTriggering": "CTA",  # Alternative name
    }
    phase_order = ["VAA", "CIA", "PEA", "CTA"]

    result = {
        "agent_loop_count": 0,
        "agent_loop_by_phase": {p: 0 for p in phase_order},
        "llm_interaction_count": 0,
        "llm_interaction_by_phase": {p: 0 for p in phase_order},
        "total_tool_calls": 0,
        "tool_call_counts": Counter(),
    }

    interactions = history_data.get("interactions", [])
    current_phase = None

    for interaction in interactions:
        interaction_type = interaction.get("type", "")

        if interaction_type == "phase_separator":
            phase_name = interaction.get("phase_name", "")
            current_phase = phase_map.get(phase_name, None)

        elif interaction_type == "agent_loop_start":
            result["agent_loop_count"] += 1
            if current_phase:
                result["agent_loop_by_phase"][current_phase] += 1

        elif interaction_type == "llm_interaction":
            result["llm_interaction_count"] += 1
            if current_phase:
                result["llm_interaction_by_phase"][current_phase] += 1

            # Count tool calls
            tool_calls = interaction.get("tool_calls", [])
            for tool_call in tool_calls:
                tool_name = tool_call.get("name", "unknown")
                result["tool_call_counts"][tool_name] += 1
                result["total_tool_calls"] += 1

    # Convert dicts to tuples in order (VAA, CIA, PEA, CTA)
    result["agent_loop_by_phase"] = tuple(
        result["agent_loop_by_phase"][p] for p in phase_order
    )
    result["llm_interaction_by_phase"] = tuple(
        result["llm_interaction_by_phase"][p] for p in phase_order
    )

    return result


def print_statistics(task_dir: Path) -> None:
    """
    Print all statistics for a task directory.

    Args:
        task_dir: Path to the task output directory
    """
    task_name = task_dir.name
    print("=" * 70)
    print(f"STATISTICS FOR: {task_name}")
    print("=" * 70)

    # 1. POV file counts
    print("[1] POV Files")
    pov_files = find_pov_files(task_dir)
    print(f"  pov         files (PEA): {len(pov_files['pov'])}")
    print(f"  final-pov   files (CTA): {len(pov_files['final_pov'])}")
    print(f"  variant-pov files (CTA): {len(pov_files['variant_pov'])}")

    # 2. Time overhead
    print("\n[2] Time Overhead")
    time_data = load_time_overhead(task_dir)
    if time_data:
        total_time = 0.0
        for phase, seconds in time_data.items():
            total_time += seconds
            # Convert phase name to readable format
            phase_display = phase.replace("phase_", "").replace("_", " ").title()
            print(f"  - {phase_display:25s}: {format_duration(seconds)}")
        print(f"  Total: {format_duration(total_time)}")
    else:
        print("  No time_overhead.json found")

    # 3. Token usage and costs
    print("\n[3] Token Usage & Costs")
    tokens_data = load_tokens_overhead(task_dir)
    if tokens_data:
        total_cost = 0.0
        input_cost = 0.0
        output_cost = 0.0
        for phase in ["VAA", "PEA", "CTA"]:
            if phase in tokens_data:
                phase_data = tokens_data[phase]
                input_tokens = phase_data.get("input_tokens", 0)
                output_tokens = phase_data.get("output_tokens", 0)
                total_tokens = phase_data.get("total_tokens", 0)
                cost = phase_data.get("cost_total_usd", 0.0)
                input_cost += phase_data.get("cost_input_usd", 0.0)
                output_cost += phase_data.get("cost_output_usd", 0.0)
                total_cost += cost
                print(f"  {phase}: input_tokens={input_tokens:,}, output_tokens={output_tokens:,} (${cost:.4f})")
                # print(f"       Cost:  ${cost:.4f}")
        print(f"  Total Cost: ${total_cost:.4f} ({input_cost:.4f} + {output_cost:.4f})")
    else:
        print("  No tokens_overhead.json found")

    # 4. LLM interaction statistics
    print("\n[4] LLM Interaction Statistics (VAA, CIA, PEA, CTA)")
    history_data = load_llm_history(task_dir)
    if history_data:
        stats = analyze_llm_history(history_data)
        print(f"  Agent loops:       {stats['agent_loop_by_phase']}")
        print(f"  LLM interactions:  {stats['llm_interaction_by_phase']}")
        print(f"  Total tool calls:  {stats['total_tool_calls']}")

        if stats["tool_call_counts"]:
            # Sort by count descending
            for tool_name, count in stats["tool_call_counts"].most_common():
                print(f"    {tool_name:20s}: {count}")
    else:
        print("  No llm_history.json found")

    # print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Collect and display result statistics for DrillAgent task output."
    )
    parser.add_argument(
        "output_dir",
        nargs="?",
        default=None,
        help="Path to the task output directory (default: ../output/ relative to script)",
    )

    args = parser.parse_args()

    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        # Default: parent directory of scripts, then output/
        script_dir = Path(__file__).parent
        output_dir = script_dir.parent / "output"

    output_dir = output_dir.resolve()

    if not output_dir.exists():
        print(f"Error: Output directory '{output_dir}' does not exist.")
        return

    # Check if this is a single task directory or a parent with multiple tasks
    # A task directory typically contains JSON files directly
    json_files = list(output_dir.glob("*.json"))

    if json_files:
        # This is a single task directory
        print_statistics(output_dir)
    else:
        # This is a parent directory containing multiple task directories
        task_dirs = sorted([d for d in output_dir.iterdir() if d.is_dir()])
        if not task_dirs:
            print(f"No task directories found in '{output_dir}'")
            return

        print(f"Found {len(task_dirs)} task directories in {output_dir}\n")

        for task_dir in task_dirs:
            print_statistics(task_dir)
            print()


if __name__ == "__main__":
    main()

# Usage:                                                                                                                               
#   # Analyze a single task directory                                                                                                    
#   python3 scripts/collect_result_statistics.py output/exiv2.cve-2017-17669                                                             
                                                                                                                                       
#   # Analyze all tasks in output directory                                                                                              
#   python3 scripts/collect_result_statistics.py output/                                                                                 
                                                                                                                                       
#   # Use default (../output/ relative to script)                                                                                        
#   python3 scripts/collect_result_statistics.py