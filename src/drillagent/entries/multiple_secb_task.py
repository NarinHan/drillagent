#!/usr/bin/env python3
"""
Multiple SecBench Tasks Runner

A script for running DrillAgent on multiple SecBench tasks.
Supports running all tasks for a project or specific task instances.
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


def load_api_key(args):
    """Load API key from file or command line argument."""
    # If API key is directly provided
    if args.api_key:
        print("✓ Using API key from command line argument")
        return args.api_key

    # If API key file is specified
    if args.api_key_file:
        key_file = Path(args.api_key_file)
        if not key_file.exists():
            print(f"✗ Error: API key file not found at {key_file}")
            sys.exit(1)
        try:
            with open(key_file, 'r') as f:
                api_key = f.read().strip()
            print(f"✓ Loaded API key from {key_file}")
            return api_key
        except Exception as e:
            print(f"✗ Error reading API key file: {e}")
            sys.exit(1)

    # Default: infer from model provider
    provider = args.model_provider
    if not provider:
        # Infer provider from model name
        model_lower = args.basic_model.lower()
        if 'gpt' in model_lower or 'o1' in model_lower or 'o3' in model_lower:
            provider = 'openai'
        elif 'claude' in model_lower or 'sonnet' in model_lower or 'opus' in model_lower:
            provider = 'claude'
        elif 'gemini' in model_lower:
            provider = 'gemini'
        else:
            print(f"✗ Error: Cannot infer model provider from model name '{args.basic_model}'")
            print("   Please specify --model-provider or provide --api-key/--api-key-file")
            sys.exit(1)

    # Try default key file locations
    base_dir = Path("/home/ubuntu/PoV/DrillAgent")
    key_file = base_dir / f"{provider}.key"

    if not key_file.exists():
        print(f"✗ Error: Default API key file not found at {key_file}")
        print(f"   Please create the file or use --api-key-file or --api-key")
        sys.exit(1)

    try:
        with open(key_file, 'r') as f:
            api_key = f.read().strip()
        print(f"✓ Loaded API key from default location: {key_file}")
        return api_key
    except Exception as e:
        print(f"✗ Error reading API key file: {e}")
        sys.exit(1)


def infer_model_provider(model_name):
    """Infer model provider from model name."""
    model_lower = model_name.lower()
    if 'gpt' in model_lower or 'o1' in model_lower or 'o3' in model_lower:
        return 'openai'
    elif 'claude' in model_lower or 'sonnet' in model_lower or 'opus' in model_lower:
        return 'claude'
    elif 'gemini' in model_lower:
        return 'gemini'
    else:
        return None


def find_repo_path(repos_dir: Path, project_name: str) -> Path:
    """
    Find repository path for a given project name.

    Looks for directories matching the project name (case-insensitive).
    Common patterns: project_name, project_name-cov, project_name-instrumented
    """
    # TODO: We should maintain a mapping file from project names to repo names (e.g., php -> php-src).
    if not repos_dir.exists():
        raise FileNotFoundError(f"Repositories directory not found: {repos_dir}")

    # Try exact match first
    exact_match = repos_dir / project_name
    if exact_match.exists() and exact_match.is_dir():
        return exact_match
    
    # Use hard-encoded mapping for SEC-bench projects
    secb_mappings = { # From project_name to repo_name
        "libdwarf" : "libdwarf-code",
        "php"      : "php-src",
        # "yaml"     : "yaml-cpp"
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
        # Also check with suffixes
        for suffix in ['-cov', '-instrumented', '-coverage', '-src', '-cpp']:
            if item.is_dir() and item.name.lower() == f"{project_lower}{suffix}":
                return item

    raise FileNotFoundError(
        f"Repository not found for project '{project_name}' in {repos_dir}\n"
        f"Tried: {project_name}, {project_name}-cov, {project_name}-instrumented, etc."
    )


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Run DrillAgent on multiple SecBench tasks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all tasks for a specific project
  python3 multiple_secb_task.py --project-name njs \\
      --repos-dir /home/ubuntu/PoV/Repos \\
      --basic-model gpt-5.1-2025-11-13

  # Run specific tasks
  python3 multiple_secb_task.py \\
      --instance-ids njs.cve-2023-27727,njs.cve-2024-12345 \\
      --repos-dir /home/ubuntu/PoV/Repos \\
      --basic-model claude-sonnet-4-5-20250929

  # Run all tasks for a project with single repo path
  python3 multiple_secb_task.py --project-name njs \\
      --repo-path /home/ubuntu/PoV/Repos/njs-cov \\
      --basic-model gpt-5.1-2025-11-13

  # Run all 200 SEC-bench tasks (excluding blacklisted ones)
  python3 multiple_secb_task.py --all-supported-tasks \\
      --repos-dir /home/ubuntu/PoV/Repos \\
      --basic-model claude-sonnet-4-5-20250929
        """
    )

    # Task selection (mutually exclusive)
    task_group = parser.add_mutually_exclusive_group(required=True)
    task_group.add_argument(
        '--project-name',
        help='Run all tasks for this project'
    )
    task_group.add_argument(
        '--instance-ids',
        help='Comma-separated list of instance IDs to run'
    )
    task_group.add_argument(
        '--solved-tasks',
        action='store_true',
        help='Run the union of get_openhands_solved_tasks and get_swea_solved_tasks'
    )
    task_group.add_argument(
        '--all-supported-tasks',
        action='store_true',
        help='Run all 200 SEC-bench tasks, excluding blacklisted ones (is_labelled_blacklist)'
    )

    # Repository location (mutually exclusive)
    repo_group = parser.add_mutually_exclusive_group(required=True)
    repo_group.add_argument(
        '--repos-dir',
        help='Directory containing multiple repositories (subdirs named by project)'
    )
    repo_group.add_argument(
        '--repo-path',
        help='Single repository path (for running all tasks of one project)'
    )

    # Required arguments
    parser.add_argument(
        '--basic-model',
        required=True,
        help='Basic model name (e.g., gpt-5.1-2025-11-13, claude-sonnet-4-5-20250929)'
    )

    # API key options (mutually exclusive)
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument(
        '--api-key',
        help='API key string (alternative to --api-key-file)'
    )
    key_group.add_argument(
        '--api-key-file',
        help='Path to API key file (default: /home/ubuntu/PoV/DrillAgent/{provider}.key)'
    )

    # Model provider (optional, can be inferred)
    parser.add_argument(
        '--model-provider',
        choices=['openai', 'claude', 'gemini'],
        help='Model provider (auto-inferred from model name if not specified)'
    )

    # Additional model configurations
    parser.add_argument(
        '--reasoning-model',
        help='Reasoning model in format "provider:model_name" (e.g., "openai:o1-2025-12-17")'
    )
    parser.add_argument(
        '--low-cost-model',
        help='Low-cost model in format "provider:model_name" (e.g., "openai:gpt-4.5-turbo-2025-04-09")'
    )

    # Dataset configuration
    parser.add_argument(
        '--dataset-path',
        default='datasets/sec-bench/CVE-instances',
        help='Path to SecBench dataset (default: datasets/sec-bench/CVE-instances)'
    )

    # Output directories
    parser.add_argument(
        '--work-dir',
        help='Base working directory (default: ./workspace)'
    )
    parser.add_argument(
        '--output-dir',
        help='Base output directory (default: ./output)'
    )

    # Agent configuration
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

    # Ablation options
    parser.add_argument(
        '--disable-vuln-analysis',
        action='store_true',
        help='Skip Phase 1 (vulnerability analysis)'
    )
    parser.add_argument(
        '--disable-instrumentation',
        action='store_true',
        help='Skip Phase 2 (program instrumentation)'
    )
    parser.add_argument(
        '--disable-path-exploration',
        action='store_true',
        help='Skip Phase 3 (path exploration)'
    )
    parser.add_argument(
        '--disable-crash-analysis',
        action='store_true',
        help='Skip Phase 4 (crash trigger analysis)'
    )

    # Task filtering
    parser.add_argument(
        '--skip-instance-ids',
        help='Comma-separated list of instance IDs to skip (applied after task selection)'
    )

    # Other options
    parser.add_argument(
        '--no-verbose',
        action='store_true',
        help='Disable verbose output'
    )
    parser.add_argument(
        '--continue-on-error',
        action='store_true',
        help='Continue running remaining tasks even if one fails'
    )
    parser.add_argument(
        '--summary-file',
        help='Path to save execution summary JSON (default: output_dir/summary.json)'
    )
    parser.add_argument(
        '--force-clear-cache',
        action='store_true',
        help='Force clear VulnAnalysisAgent cache before analysis (re-run from scratch)'
    )
    parser.add_argument(
        '--no-skip-completed',
        action='store_true',
        help='Disable skipping tasks that have already been fully tested (by default, tasks with non-zero PEA or CTA tokens are skipped)'
    )

    return parser.parse_args()


def parse_model_spec(model_spec):
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
        print("   Expected format: 'provider:model_name' (e.g., 'openai:o1-2025-12-17')")
        sys.exit(1)

    provider, model_name = parts
    if provider not in ['openai', 'claude', 'gemini']:
        print(f"✗ Error: Invalid model provider '{provider}'")
        print("   Valid providers: openai, claude, gemini")
        sys.exit(1)

    return (provider, model_name)


def is_task_completed(instance_id: str, output_dir: Path) -> bool:
    """
    Check if a task has already been fully tested.

    A task is considered completed if either PEA or CTA has non-zero total_tokens
    in the tokens_overhead.json file.

    Args:
        instance_id: The task instance ID
        output_dir: Base output directory

    Returns:
        True if the task has been completed (should be skipped), False otherwise
    """
    tokens_file = output_dir / instance_id / "tokens_overhead.json"

    if not tokens_file.exists():
        return False

    try:
        with open(tokens_file, 'r') as f:
            data = json.load(f)

        pea_tokens = data.get("PEA", {}).get("total_tokens", 0)
        cta_tokens = data.get("CTA", {}).get("total_tokens", 0)

        # If either PEA or CTA has non-zero tokens, the task has been run
        return pea_tokens != 0 or cta_tokens != 0
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        # If there's an error reading the file, assume not completed
        print(f"  Warning: Error reading tokens_overhead.json for {instance_id}: {e}")
        return False


def run_single_task(task: SecbTask, repo_path: Path, args, api_key: str, model_provider: str) -> Dict[str, Any]:
    """
    Run DrillAgent on a single task.

    Returns:
        Dict containing execution results and metadata
    """
    instance_id = task.instance_id

    # Set up directories
    base_work_dir = Path(args.work_dir or "./workspace")
    base_output_dir = Path(args.output_dir or "./output")

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

    # Parse additional model configurations
    reasoning_model = parse_model_spec(args.reasoning_model)
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
        basic_model=args.basic_model,
        api_key=api_key,
        reasoning_model=reasoning_model,
        low_cost_model=low_cost_model,

        # Ablation options
        disable_program_instrumentation=args.disable_instrumentation,
        disable_vulnerability_analysis=args.disable_vuln_analysis,
        disable_path_exploration=args.disable_path_exploration,
        disable_crash_triggering=args.disable_crash_analysis,

        # Analysis options
        max_iterations=args.max_iterations,
        timeout=args.timeout,

        # Output options
        work_dir=str(work_dir),
        output_dir=str(output_dir),
        verbose=not args.no_verbose,
        force_clear_cache=args.force_clear_cache
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

        # Update result
        result.update({
            'success': True,
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'final_phase': agent_result['final_phase'],
            'crashes_found': agent_result['crashes_found'],
            'errors': agent_result['errors'],
            'output_dir': str(output_dir)
        })

        # Print summary
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

    # Load API key
    api_key = load_api_key(args)

    # Determine model provider
    if args.model_provider:
        model_provider = args.model_provider
    else:
        model_provider = infer_model_provider(args.basic_model)
        if model_provider is None:
            print(f"✗ Error: Cannot infer model provider from model name '{args.basic_model}'")
            print("   Please specify --model-provider")
            sys.exit(1)
        print(f"✓ Inferred model provider: {model_provider}")

    # Load tasks
    print(f"\n✓ Loading tasks from dataset: {args.dataset_path}")

    if args.project_name:
        # Load all tasks for the project
        loader = RawSecbTaskLoader(
            dataset_path=args.dataset_path,
            project_names=[args.project_name]
        )
        loader.load_cve_tasks()
        tasks = loader.get_tasks_by_project(args.project_name)
        if not tasks:
            print(f"✗ Error: No tasks found for project '{args.project_name}'")
            sys.exit(1)

        print(f"✓ Found {len(tasks)} tasks for project '{args.project_name}'")

    elif args.instance_ids:
        # Load specific instance IDs
        instance_ids = [id.strip() for id in args.instance_ids.split(',')]
        loader = RawSecbTaskLoader(
            dataset_path=args.dataset_path,
            instance_ids=instance_ids
        )
        loader.load_cve_tasks()

        tasks = []
        for instance_id in instance_ids:
            task = loader.get_task(instance_id)
            if task is None:
                print(f"✗ Warning: Task '{instance_id}' not found in dataset")
            else:
                tasks.append(task)
        if not tasks:
            print(f"✗ Error: None of the specified tasks were found")
            sys.exit(1)

        print(f"✓ Found {len(tasks)} out of {len(instance_ids)} requested tasks")
    elif args.solved_tasks:
        # Load union of OpenHands-solved and SWEA-solved tasks
        loader = RawSecbTaskLoader(dataset_path=args.dataset_path)
        loader.load_cve_tasks()
        tasks = list(loader.get_united_solved_tasks().values())
        if not tasks:
            print("✗ Error: No solved tasks found")
            sys.exit(1)

        print(f"✓ Found {len(tasks)} solved tasks (OpenHands + SWEA)")
    elif args.all_supported_tasks:
        # Load all 200 SEC-bench tasks, excluding blacklisted ones
        loader = RawSecbTaskLoader(dataset_path=args.dataset_path)
        loader.load_cve_tasks()
        tasks = [task for instance_id, task in loader.cve_tasks.items()
                 if not loader.is_labelled_blacklist(instance_id)]
        if not tasks:
            print("✗ Error: No supported tasks found")
            sys.exit(1)

        print(f"✓ Found {len(tasks)} supported tasks (all minus blacklist)")
    else:
        print("✗ Error: No task selection provided")
        sys.exit(1)

    # Filter out skipped tasks
    if args.skip_instance_ids:
        skip_ids = set(id.strip() for id in args.skip_instance_ids.split(','))
        original_count = len(tasks)
        tasks = [t for t in tasks if t.instance_id not in skip_ids]
        skipped_count = original_count - len(tasks)
        if skipped_count > 0:
            print(f"✓ Skipped {skipped_count} tasks via --skip-instance-ids")
        if not tasks:
            print("✗ Error: All tasks were skipped")
            sys.exit(1)

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
    skipped = 0

    # Determine base output directory for completion check
    base_output_dir = Path(args.output_dir or "./output")

    for i, task in enumerate(tasks, 1):
        print(f"\n[{i}/{len(tasks)}] Processing: {task.instance_id}")

        # Check if task has already been completed (skip by default)
        if not args.no_skip_completed:
            if is_task_completed(task.instance_id, base_output_dir):
                print(f"  ⏭ Skipping: task already completed (PEA or CTA has non-zero tokens)")
                skipped += 1
                continue

        # Determine repository path
        try:
            if args.repo_path:
                # Single repo path provided
                repo_path = Path(args.repo_path)
                if not repo_path.exists():
                    raise FileNotFoundError(f"Repository not found: {repo_path}")
            else:
                # Find repo in repos_dir
                repos_dir = Path(args.repos_dir)
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

            if not args.continue_on_error:
                print("\n✗ Stopping execution (use --continue-on-error to continue)")
                break
            continue

        # Run the task
        result = run_single_task(task, repo_path, args, api_key, model_provider)
        results.append(result)

        if result['success']:
            successful += 1
        else:
            failed += 1

            if not args.continue_on_error:
                print("\n✗ Stopping execution (use --continue-on-error to continue)")
                break

    # Print final summary
    print("\n" + "=" * 70)
    print("EXECUTION SUMMARY")
    print("=" * 70)
    print(f"Total Tasks: {len(tasks)}")
    print(f"Skipped (already completed): {skipped}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    executed = successful + failed
    print(f"Completion Rate: {successful}/{executed} ({100*successful/executed if executed else 0:.1f}%)")

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

    # Save summary to file
    base_output_dir = Path(args.output_dir or "./output")
    if args.summary_file:
        summary_file = Path(args.summary_file)
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        summary_data = {
            'execution_time': datetime.now().isoformat(),
            'model': args.basic_model,
            'model_provider': model_provider,
            'total_tasks': len(tasks),
            'successful': successful,
            'failed': failed,
            'results': results
        }
        with open(summary_file, 'w') as f:
            json.dump(summary_data, f, indent=2)
        print(f"\n✓ Summary saved to: {summary_file}")
    else:
        summary_file = base_output_dir / "summary.json"
        # But we do nothing here...
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
