#!/usr/bin/env python3
"""
Evaluation script for OpenHands subset (75 CVE tasks from oh-subset.txt).

This script runs DrillAgent on the OpenHands subset tasks with simplified configuration.
Filters can be modified directly in the script (see FILTER CONFIGURATION section).
"""

import sys
import argparse
from pathlib import Path
from typing import List, Dict, Any
import json
from datetime import datetime

# Add src directory to Python path
src_dir = Path(__file__).resolve().parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from drillagent.config import AgentConfig
from drillagent.drill_agent import DrillAgent
from drillagent.task_loader import RawSecbTaskLoader, SecbTask


# =============================================================================
# FILTER CONFIGURATION - Modify these lists to filter tasks
# =============================================================================

# Skip tasks from these repo/project names (e.g., ["gpac", "imagemagick"])
SKIP_REPO_NAMES: List[str] = [
    "gpac",  # fix cov-feedback issue later
    "faad2",
    "libredwg",
    "libiec61850",
]

# Skip these specific instance IDs (e.g., ["gpac.cve-2021-32437", "njs.cve-2019-13617"])
SKIP_INSTANCE_IDS: List[str] = [
    # Mainly tasks still have compilation errors
    "liblouis.cve-2023-26768",
    "libmodbus.cve-2022-0367",
    "libplist.cve-2017-5545",
    "upx.cve-2023-23457",
]

# =============================================================================
# END FILTER CONFIGURATION
# =============================================================================


def load_api_key(model_provider: str) -> str:
    """Load API key from default location based on model provider."""
    base_dir = Path("/home/ubuntu/PoV/DrillAgent")
    key_file = base_dir / f"{model_provider}.key"

    if not key_file.exists():
        print(f"✗ Error: API key file not found at {key_file}")
        sys.exit(1)

    try:
        with open(key_file, 'r') as f:
            api_key = f.read().strip()
        print(f"✓ Loaded API key from: {key_file}")
        return api_key
    except Exception as e:
        print(f"✗ Error reading API key file: {e}")
        sys.exit(1)


def infer_model_provider(model_name: str) -> str:
    """Infer model provider from model name."""
    model_lower = model_name.lower()
    if 'gpt' in model_lower or 'o1' in model_lower or 'o3' in model_lower:
        return 'openai'
    elif 'claude' in model_lower or 'sonnet' in model_lower or 'opus' in model_lower:
        return 'claude'
    elif 'gemini' in model_lower:
        return 'gemini'
    else:
        print(f"✗ Error: Cannot infer model provider from model name '{model_name}'")
        sys.exit(1)


def parse_model_spec(model_spec: str):
    """
    Parse model specification in format "provider:model_name".

    Args:
        model_spec: String in format "provider:model_name" or None

    Returns:
        Tuple of (provider, model_name) or ("", "") if None
    """
    if not model_spec:
        return ("", "")

    parts = model_spec.split(":", 1)
    if len(parts) != 2:
        print(f"✗ Error: Invalid model specification '{model_spec}'")
        print("   Expected format: 'provider:model_name' (e.g., 'openai:gpt-4.1-mini-2025-04-14')")
        sys.exit(1)

    provider, model_name = parts
    if provider not in ['openai', 'claude', 'gemini']:
        print(f"✗ Error: Invalid model provider '{provider}'")
        print("   Valid providers: openai, claude, gemini")
        sys.exit(1)

    return (provider, model_name)


def find_repo_path(repos_dir: Path, project_name: str) -> Path:
    """Find repository path for a given project name."""
    if not repos_dir.exists():
        raise FileNotFoundError(f"Repositories directory not found: {repos_dir}")

    # Try exact match first
    exact_match = repos_dir / project_name
    if exact_match.exists() and exact_match.is_dir():
        return exact_match

    # Hard-encoded mapping for SEC-bench projects
    secb_mappings = {
        "libdwarf": "libdwarf-code",
        "php": "php-src",
    }
    if project_name in secb_mappings:
        mapped_name = secb_mappings[project_name]
        mapped_path = repos_dir / mapped_name
        if mapped_path.exists() and mapped_path.is_dir():
            return mapped_path

    # Try with common suffixes
    for suffix in ['-cov', '-instrumented', '-coverage', '-src', '-cpp']:
        candidate = repos_dir / f"{project_name}{suffix}"
        if candidate.exists() and candidate.is_dir():
            return candidate

    # Try case-insensitive search
    project_lower = project_name.lower()
    for item in repos_dir.iterdir():
        if item.is_dir() and item.name.lower() == project_lower:
            return item
        for suffix in ['-cov', '-instrumented', '-coverage', '-src', '-cpp']:
            if item.is_dir() and item.name.lower() == f"{project_lower}{suffix}":
                return item

    raise FileNotFoundError(
        f"Repository not found for project '{project_name}' in {repos_dir}"
    )


def is_task_completed(output_dir: Path) -> bool:
    """
    Check if a task has already been completed.
    A task is considered completed if both time_overhead.json and tokens_overhead.json exist.
    """
    time_file = output_dir / "time_overhead.json"
    tokens_file = output_dir / "tokens_overhead.json"
    return time_file.exists() and tokens_file.exists()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Run DrillAgent on OpenHands subset (75 CVE tasks)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 eval_on_oh_subset.py \\
      --repos-dir /home/ubuntu/PoV/Repos \\
      --basic-model gpt-5.1-2025-11-13

  python3 eval_on_oh_subset.py \\
      --repos-dir /home/ubuntu/PoV/Repos \\
      --basic-model claude-sonnet-4-5-20250929 \\
      --output-dir ./output/oh-subset-eval
        """
    )

    parser.add_argument(
        '--repos-dir',
        required=True,
        help='Directory containing repositories (subdirs named by project)'
    )
    parser.add_argument(
        '--basic-model',
        required=True,
        help='Basic model name (e.g., gpt-5.1-2025-11-13, claude-sonnet-4-5-20250929)'
    )
    parser.add_argument(
        '--dataset-path',
        default='datasets/sec-bench/CVE-instances',
        help='Path to SecBench dataset (default: datasets/sec-bench/CVE-instances)'
    )
    parser.add_argument(
        '--work-dir',
        default='./workspace',
        help='Base working directory (default: ./workspace)'
    )
    parser.add_argument(
        '--output-dir',
        default='./output',
        help='Base output directory (default: ./output)'
    )
    parser.add_argument(
        '--max-iterations',
        type=int,
        default=10,
        help='Maximum iterations (default: 10)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=1200,
        help='Timeout in seconds (default: 1200)'
    )
    parser.add_argument(
        '--low-cost-model',
        help='Low-cost model in format "provider:model_name" (e.g., "openai:gpt-4.1-mini-2025-04-14")'
    )
    parser.add_argument(
        '--no-verbose',
        action='store_true',
        help='Disable verbose output'
    )
    parser.add_argument(
        '--force-rerun',
        action='store_true',
        help='Force rerun even if task was already completed'
    )

    return parser.parse_args()


def run_single_task(task: SecbTask, repo_path: Path, args, api_key: str, model_provider: str) -> Dict[str, Any]:
    """Run DrillAgent on a single task."""
    instance_id = task.instance_id

    # Set up directories
    base_work_dir = Path(args.work_dir)
    base_output_dir = Path(args.output_dir)

    work_dir = base_work_dir / instance_id
    output_dir = base_output_dir / instance_id

    print("\n" + "=" * 70)
    print(f"Running Task: {instance_id}")
    print("=" * 70)
    print(f"Repository: {repo_path}")
    print(f"Model: {args.basic_model} ({model_provider})")
    print(f"Project: {task.project_name}")
    print(f"CVE: {task.cve_id}")
    print("=" * 70)

    # Parse low-cost model configuration
    low_cost_model = parse_model_spec(args.low_cost_model)

    # Create configuration
    config = AgentConfig(
        # Task information
        project_name=task.project_name,
        cve_id=task.cve_id,
        lang=task.lang,
        target_repo_path=str(repo_path),
        vuln_location=task.vuln_location,
        base_commit=task.base_commit,
        build_sh=task.build_sh,
        harness_command=task.harness_command,
        sanitizer_report=task.sanitizer_report,

        # LLM configuration
        model_provider=model_provider,
        api_key=api_key,
        basic_model=args.basic_model,
        low_cost_model=low_cost_model,

        # Analysis options
        max_iterations=args.max_iterations,
        timeout=args.timeout,

        # Output options
        work_dir=str(work_dir),
        output_dir=str(output_dir),
        verbose=not args.no_verbose,
    )

    # Create output directories
    output_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    if not args.no_verbose:
        config.print_config()

    # Initialize and run DrillAgent
    start_time = datetime.now()
    result = {
        'instance_id': instance_id,
        'project_name': task.project_name,
        'cve_id': task.cve_id,
        'repo_path': str(repo_path),
        'start_time': start_time.isoformat(),
        'success': False,
        'error': None
    }

    try:
        agent = DrillAgent(config)
        agent_result = agent.run()

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        result.update({
            'success': True,
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'final_phase': agent_result['final_phase'],
            'crashes_found': agent_result['crashes_found'],
            'errors': agent_result['errors'],
            'output_dir': str(output_dir)
        })

        print("\n" + "-" * 70)
        print(f"Task {instance_id} Summary:")
        print(f"  Final Phase: {agent_result['final_phase']}")
        print(f"  Crashes Found: {agent_result['crashes_found']}")
        print(f"  Duration: {duration:.1f}s")
        if agent_result['errors']:
            print(f"  Errors: {len(agent_result['errors'])}")
        print(f"  Output: {output_dir}")
        print("-" * 70)

    except Exception as e:
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        result.update({
            'success': False,
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'error': str(e)
        })

        print(f"\n✗ Error running task {instance_id}: {e}")
        if not args.no_verbose:
            import traceback
            traceback.print_exc()

    return result


def main():
    args = parse_args()

    # Infer model provider and load API key
    model_provider = infer_model_provider(args.basic_model)
    print(f"✓ Inferred model provider: {model_provider}")
    api_key = load_api_key(model_provider)

    # Load tasks from oh-subset
    print(f"\n✓ Loading tasks from dataset: {args.dataset_path}")
    loader = RawSecbTaskLoader(dataset_path=args.dataset_path)
    loader.load_cve_tasks()

    oh_subset_tasks = loader.get_tasks_oh_subset()
    print(f"✓ Loaded {len(oh_subset_tasks)} tasks from oh-subset.txt")

    # Apply filters
    tasks: List[SecbTask] = []
    skipped_by_repo = 0
    skipped_by_id = 0
    skipped_completed = 0

    base_output_dir = Path(args.output_dir)

    for instance_id, task in oh_subset_tasks.items():
        # Filter by repo name
        repo_name = instance_id.split('.')[0]
        if repo_name in SKIP_REPO_NAMES:
            skipped_by_repo += 1
            continue

        # Filter by instance ID
        if instance_id in SKIP_INSTANCE_IDS:
            skipped_by_id += 1
            continue

        # Check if already completed
        task_output_dir = base_output_dir / instance_id
        if not args.force_rerun and is_task_completed(task_output_dir):
            skipped_completed += 1
            print(f"  [SKIP] {instance_id} - already completed")
            continue

        tasks.append(task)

    # Print filter summary
    print(f"\n--- Filter Summary ---")
    print(f"  Total in oh-subset: {len(oh_subset_tasks)}")
    print(f"  Skipped by repo name: {skipped_by_repo}")
    print(f"  Skipped by instance ID: {skipped_by_id}")
    print(f"  Skipped (already completed): {skipped_completed}")
    print(f"  Tasks to run: {len(tasks)}")

    if not tasks:
        print("\n✓ No tasks to run. All tasks are either filtered or already completed.")
        sys.exit(0)

    # Print task list
    print("\nTasks to run:")
    for i, task in enumerate(tasks, 1):
        print(f"  {i}. {task.instance_id} ({task.project_name}, {task.cve_id})")

    # Execute tasks
    print("\n" + "=" * 70)
    print(f"Starting execution of {len(tasks)} tasks")
    print("=" * 70)

    results = []
    successful = 0
    failed = 0
    repos_dir = Path(args.repos_dir)

    for i, task in enumerate(tasks, 1):
        print(f"\n[{i}/{len(tasks)}] Processing: {task.instance_id}")

        # Determine repository path
        try:
            repo_path = find_repo_path(repos_dir, task.project_name)
            print(f"✓ Found repository: {repo_path}")
        except FileNotFoundError as e:
            print(f"✗ {e}")
            result = {
                'instance_id': task.instance_id,
                'project_name': task.project_name,
                'cve_id': task.cve_id,
                'success': False,
                'error': str(e)
            }
            results.append(result)
            failed += 1
            continue

        # Run the task
        result = run_single_task(task, repo_path, args, api_key, model_provider)
        results.append(result)

        if result['success']:
            successful += 1
        else:
            failed += 1

    # Print final summary
    print("\n" + "=" * 70)
    print("EXECUTION SUMMARY")
    print("=" * 70)
    print(f"Total Tasks: {len(tasks)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Skipped (completed): {skipped_completed}")
    print(f"Completion Rate: {successful}/{len(tasks)} ({100*successful/len(tasks) if tasks else 0:.1f}%)")

    # Print per-task results
    print("\nDetailed Results:")
    for result in results:
        status = "✓" if result['success'] else "✗"
        instance_id = result['instance_id']

        if result['success']:
            crashes = result.get('crashes_found', 0)
            duration = result.get('duration_seconds', 0)
            print(f"  {status} {instance_id}: {crashes} crash(es) found ({duration:.1f}s)")
        else:
            error = result.get('error', 'Unknown error')
            print(f"  {status} {instance_id}: {error}")

    # Save summary
    summary_file = base_output_dir / "oh_subset_summary.json"
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    summary_data = {
        'execution_time': datetime.now().isoformat(),
        'model': args.basic_model,
        'model_provider': model_provider,
        'total_tasks': len(tasks),
        'successful': successful,
        'failed': failed,
        'skipped_completed': skipped_completed,
        'results': results
    }
    with open(summary_file, 'w') as f:
        json.dump(summary_data, f, indent=2)
    print(f"\n✓ Summary saved to: {summary_file}")
    print("=" * 70)

    # Exit with appropriate code
    if failed == 0:
        print("\n✓ All tasks completed successfully!")
        sys.exit(0)
    elif successful > 0:
        print(f"\n⚠ Completed with {failed} failures")
        sys.exit(1)
    else:
        print("\n✗ All tasks failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
