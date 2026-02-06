#!/usr/bin/env python3
"""
Analyze task statistics from a task list file.

This script reads a text file containing task IDs (one per line) and outputs:
1. Statistics of projects involved
2. Statistics of vulnerability types (using get_sanitizer_crash_type)

Usage:
    python scripts/analyze_task_statistics.py <task_list_file>

Example:
    python scripts/analyze_task_statistics.py task_lists/solved_tasks.txt
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from drillagent.task_loader.sec_bench import RawSecbTaskLoader
from drillagent.utils.utils import get_sanitizer_crash_type


def load_task_ids(task_list_file: str) -> list[str]:
    """Load task IDs from a text file (one per line)."""
    task_ids = []
    with open(task_list_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):  # Skip empty lines and comments
                task_ids.append(line)
    return task_ids


def analyze_tasks(task_ids: list[str], dataset_path: str) -> tuple[Counter, Counter]:
    """
    Analyze tasks and return statistics.

    Returns:
        Tuple of (project_counter, vuln_type_counter)
    """
    # Load all tasks from the dataset
    loader = RawSecbTaskLoader(dataset_path=dataset_path)
    loader.load_cve_tasks()

    project_counter = Counter()
    vuln_type_counter = Counter()
    not_found = []

    for task_id in task_ids:
        task = loader.get_task(task_id)
        if task is None:
            not_found.append(task_id)
            continue

        # Extract project name from instance_id (format: "project_name.cve-xxxx")
        project_name = task_id.split('.')[0]
        project_counter[project_name] += 1

        # Get vulnerability type from sanitizer report
        if task.sanitizer_report:
            vuln_type = get_sanitizer_crash_type(task.sanitizer_report)
        else:
            vuln_type = "no-sanitizer-report"
        vuln_type_counter[vuln_type] += 1

    if not_found:
        print(f"\n[Warning] {len(not_found)} task(s) not found in dataset:")
        for tid in not_found:
            print(f"  - {tid}")

    return project_counter, vuln_type_counter


def print_statistics(project_counter: Counter, vuln_type_counter: Counter, total_tasks: int):
    """Print formatted statistics."""
    print(f"\n{'='*60}")
    print(f"Task Statistics Summary (Total: {total_tasks} tasks)")
    print(f"{'='*60}")

    # Project statistics
    print(f"\n--- Projects ({len(project_counter)} unique) ---")
    for project, count in sorted(project_counter.items(), key=lambda x: (-x[1], x[0])):
        percentage = count / total_tasks * 100
        print(f"  {project:<20} {count:>4} ({percentage:>5.1f}%)")

    # Vulnerability type statistics
    print(f"\n--- Vulnerability Types ({len(vuln_type_counter)} unique) ---")
    for vuln_type, count in sorted(vuln_type_counter.items(), key=lambda x: (-x[1], x[0])):
        percentage = count / total_tasks * 100
        print(f"  {vuln_type:<35} {count:>4} ({percentage:>5.1f}%)")

    print(f"\n{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze task statistics from a task list file."
    )
    parser.add_argument(
        "task_list_file",
        help="Path to the text file containing task IDs (one per line)"
    )
    parser.add_argument(
        "--dataset-path",
        default="datasets/sec-bench/CVE-instances",
        help="Path to the SEC-bench CVE instances directory (default: datasets/sec-bench/CVE-instances)"
    )

    args = parser.parse_args()

    # Validate input file exists
    if not Path(args.task_list_file).exists():
        print(f"Error: Task list file not found: {args.task_list_file}")
        sys.exit(1)

    # Load task IDs
    task_ids = load_task_ids(args.task_list_file)
    if not task_ids:
        print("Error: No task IDs found in the input file.")
        sys.exit(1)

    print(f"Loaded {len(task_ids)} task IDs from {args.task_list_file}")

    # Analyze tasks
    project_counter, vuln_type_counter = analyze_tasks(task_ids, args.dataset_path)

    # Print statistics
    print_statistics(project_counter, vuln_type_counter, len(task_ids))


if __name__ == "__main__":
    main()
