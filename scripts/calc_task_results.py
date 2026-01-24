#!/usr/bin/env python3
"""
Calculate task results by checking for successful POV files in output directories.

A task is considered successful if it contains a file matching the pattern:
    final-pov-{project}-{timestamp}-CTA-round{N}
or the older format:
    final-pov-{project}-{timestamp}-CTA
"""

import argparse
import re
from datetime import datetime
from pathlib import Path


def find_final_pov_files(task_dir: Path) -> list[Path]:
    """Find all final-pov files in a task directory."""
    pov_files = []
    pattern = re.compile(r"^final-pov-.*-CTA(-round\d+)?$")

    for f in task_dir.iterdir():
        if f.is_file() and pattern.match(f.name):
            pov_files.append(f)

    return pov_files


def find_variant_pov_files(task_dir: Path) -> list[Path]:
    """Find all variant-pov- files in a task directory."""
    variant_files = []

    for f in task_dir.iterdir():
        if f.is_file() and f.name.startswith("variant-pov-"):
            variant_files.append(f)

    return variant_files


def get_file_mtime(filepath: Path) -> datetime:
    """Get the modification time of a file."""
    return datetime.fromtimestamp(filepath.stat().st_mtime)


def analyze_output_dir(output_dir: Path) -> dict:
    """
    Analyze the output directory and return results.

    Returns:
        dict with keys:
            - successful_tasks: list of dicts with task info
            - failed_tasks: list of task names
            - total_tasks: int
    """
    results = {
        "successful_tasks": [],
        "failed_tasks": [],
        "newfind_tasks": [],
        "total_tasks": 0,
    }

    if not output_dir.exists():
        print(f"Error: Output directory '{output_dir}' does not exist.")
        return results

    # Get all subdirectories (tasks)
    task_dirs = sorted([d for d in output_dir.iterdir() if d.is_dir()])
    results["total_tasks"] = len(task_dirs)

    for task_dir in task_dirs:
        task_name = task_dir.name
        pov_files = find_final_pov_files(task_dir)

        if pov_files:
            # Find the latest POV file by modification time
            latest_pov = max(pov_files, key=lambda f: f.stat().st_mtime)
            mtime = get_file_mtime(latest_pov)

            results["successful_tasks"].append({
                "task_name": task_name,
                "pov_path": str(latest_pov.resolve()),
                "created_time": mtime.strftime("%Y-%m-%d %H:%M:%S"),
            })
        else:
            # Check for variant-pov files (newfind)
            variant_files = find_variant_pov_files(task_dir)
            if variant_files:
                latest_variant = max(variant_files, key=lambda f: f.stat().st_mtime)
                mtime = get_file_mtime(latest_variant)

                results["newfind_tasks"].append({
                    "task_name": task_name,
                    "pov_path": str(latest_variant.resolve()),
                    "created_time": mtime.strftime("%Y-%m-%d %H:%M:%S"),
                    "variant_count": len(variant_files),
                })
            else:
                results["failed_tasks"].append(task_name)

    return results


def print_results(results: dict):
    """Print the analysis results."""
    successful = results["successful_tasks"]
    failed = results["failed_tasks"]
    newfind = results["newfind_tasks"]
    total = results["total_tasks"]

    print("=" * 80)
    print("TASK RESULTS SUMMARY")
    print("=" * 80)
    print(f"Total tasks: {total}")
    print(f"Successful:  {len(successful)}")
    print(f"Newfind:     {len(newfind)}")
    # print(f"Failed:      {len(failed)}")
    # print(f"Success rate: {len(successful) / total * 100:.1f}%" if total > 0 else "N/A")
    print()

    successful_tasks_str = ""
    if successful:
        print("-" * 80)
        print("SUCCESSFUL TASKS:")
        print("-" * 80)
        for task in successful:
            print(f"Task: {task['task_name']}")
            print(f"  POV file: {task['pov_path']}")
            print(f"  Created:  {task['created_time']}")
            print()
            successful_tasks_str += f"{task['task_name']},"

    newfind_tasks_str = ""
    if newfind:
        print("-" * 80)
        print("NEWFIND TASKS (variant-pov):")
        print("-" * 80)
        for task in newfind:
            print(f"Task: {task['task_name']}")
            print(f"  POV file: {task['pov_path']}")
            print(f"  Created:  {task['created_time']}")
            print(f"  Variants: {task['variant_count']}")
            print()
            newfind_tasks_str += f"{task['task_name']},"

    failed_tasks_str = ""
    if failed:
        for task_name in failed:
            failed_tasks_str += f"{task_name},"

    # if failed:
    #     print()
    #     print("-" * 80)
    #     print("FAILED TASKS:")
    #     print("-" * 80)
    #     for task_name in failed:
    #         print(f"  - {task_name}")

    print()
    print("All successful tasks: " + successful_tasks_str + "\n")
    print("All newfind tasks: " + newfind_tasks_str + "\n")
    print("All failed tasks: " + failed_tasks_str)
    print("=" * 80)


def main():
    # USAGE: python3 scripts/calc_task_results.py [./test_output/output]
    parser = argparse.ArgumentParser(
        description="Calculate task results by checking for successful POV files."
    )
    parser.add_argument(
        "output_dir",
        nargs="?",
        default=None,
        help="Path to the output directory (default: ../output/ relative to script)",
    )

    args = parser.parse_args()

    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        # Default: parent directory of scripts, then output/
        script_dir = Path(__file__).parent
        output_dir = script_dir.parent / "output"

    output_dir = output_dir.resolve()
    print(f"Analyzing output directory: {output_dir}")
    print()

    results = analyze_output_dir(output_dir)
    print_results(results)


if __name__ == "__main__":
    main()
