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
import sys
from datetime import datetime
from pathlib import Path

# Import RawSecbTaskLoader directly to avoid pulling in the full drillagent package
import importlib.util
_sec_bench_path = str(Path(__file__).parent.parent / "src" / "drillagent" / "task_loader" / "sec_bench.py")
_spec = importlib.util.spec_from_file_location("sec_bench", _sec_bench_path)
_sec_bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_sec_bench)
RawSecbTaskLoader = _sec_bench.RawSecbTaskLoader


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
        "direct_success_tasks": [],    # only final-pov, no variant-pov
        "indirect_success_tasks": [],  # both final-pov and variant-pov
        "newfind_tasks": [],           # only variant-pov, no final-pov
        "failed_tasks": [],
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
        variant_files = find_variant_pov_files(task_dir)

        has_final = len(pov_files) > 0
        has_variant = len(variant_files) > 0

        if has_final and has_variant:
            # Indirect Success: both final-pov and variant-pov
            latest_pov = max(pov_files, key=lambda f: f.stat().st_mtime)
            mtime = get_file_mtime(latest_pov)
            results["indirect_success_tasks"].append({
                "task_name": task_name,
                "pov_path": str(latest_pov.resolve()),
                "created_time": mtime.strftime("%Y-%m-%d %H:%M:%S"),
                "variant_count": len(variant_files),
            })
        elif has_final:
            # Direct Success: only final-pov
            latest_pov = max(pov_files, key=lambda f: f.stat().st_mtime)
            mtime = get_file_mtime(latest_pov)
            results["direct_success_tasks"].append({
                "task_name": task_name,
                "pov_path": str(latest_pov.resolve()),
                "created_time": mtime.strftime("%Y-%m-%d %H:%M:%S"),
            })
        elif has_variant:
            # New Find: only variant-pov
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


def load_united_solved_task_ids() -> set:
    """Load the united solved task IDs from SEC-bench."""
    try:
        dataset_path = Path(__file__).parent.parent / "datasets" / "sec-bench" / "CVE-instances"
        loader = RawSecbTaskLoader(dataset_path=str(dataset_path))
        loader.load_cve_tasks()
        united = loader.get_united_solved_tasks()
        return set(united.keys())
    except Exception as e:
        print(f"[!] Warning: Could not load united solved tasks: {e}")
        return set()


def print_results(results: dict):
    """Print the analysis results."""
    direct = results["direct_success_tasks"]
    indirect = results["indirect_success_tasks"]
    newfind = results["newfind_tasks"]
    failed = results["failed_tasks"]
    total = results["total_tasks"]

    united_solved_ids = load_united_solved_task_ids()

    print("=" * 80)
    print("TASK RESULTS SUMMARY")
    print("=" * 80)
    print(f"Total tasks:      {total}")
    print(f"Direct Success:   {len(direct)}  (only final-pov)")
    print(f"Indirect Success: {len(indirect)}  (final-pov + variant-pov)")
    print(f"New Find:         {len(newfind)}  (only variant-pov)")
    print()

    direct_tasks_str = ""
    if direct:
        print("-" * 80)
        print("DIRECT SUCCESS TASKS (only final-pov):")
        print("-" * 80)
        for task in direct:
            task_label = "Task" if task['task_name'] in united_solved_ids else "Task*"
            print(f"{task_label}: {task['task_name']}")
            print(f"  POV file: {task['pov_path']}")
            print(f"  Created:  {task['created_time']}")
            print()
            direct_tasks_str += f"{task['task_name']}\n"

    indirect_tasks_str = ""
    if indirect:
        print("-" * 80)
        print("INDIRECT SUCCESS TASKS (final-pov + variant-pov):")
        print("-" * 80)
        for task in indirect:
            task_label = "Task" if task['task_name'] in united_solved_ids else "Task*"
            print(f"{task_label}: {task['task_name']}")
            print(f"  POV file: {task['pov_path']}")
            print(f"  Created:  {task['created_time']}")
            print(f"  Variants: {task['variant_count']}")
            print()
            indirect_tasks_str += f"{task['task_name']}\n"

    newfind_tasks_str = ""
    if newfind:
        print("-" * 80)
        print("NEW FIND TASKS (only variant-pov):")
        print("-" * 80)
        for task in newfind:
            task_label = "Task" if task['task_name'] in united_solved_ids else "Task*"
            print(f"{task_label}: {task['task_name']}")
            print(f"  POV file: {task['pov_path']}")
            print(f"  Created:  {task['created_time']}")
            print(f"  Variants: {task['variant_count']}")
            print()
            newfind_tasks_str += f"{task['task_name']}\n"

    failed_tasks_str = ""
    if failed:
        for task_name in failed:
            failed_tasks_str += f"{task_name}\n"

    print()
    print("All Direct Success tasks:\n" + direct_tasks_str)
    print("All Indirect Success tasks:\n" + indirect_tasks_str)
    print("All New Find tasks:\n" + newfind_tasks_str)
    print("All failed tasks:\n" + failed_tasks_str)
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
