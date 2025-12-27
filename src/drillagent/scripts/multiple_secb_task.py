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
from drillagent.task_loader import RawSecbTaskLoader


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
        model_lower = args.model_name.lower()
        if 'gpt' in model_lower or 'o1' in model_lower or 'o3' in model_lower:
            provider = 'openai'
        elif 'claude' in model_lower or 'sonnet' in model_lower or 'opus' in model_lower:
            provider = 'claude'
        elif 'gemini' in model_lower:
            provider = 'gemini'
        else:
            print(f"✗ Error: Cannot infer model provider from model name '{args.model_name}'")
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
    if not repos_dir.exists():
        raise FileNotFoundError(f"Repositories directory not found: {repos_dir}")

    # Try exact match first
    exact_match = repos_dir / project_name
    if exact_match.exists() and exact_match.is_dir():
        return exact_match

    # Try with common suffixes
    for suffix in ['-cov', '-instrumented', '-coverage']:
        candidate = repos_dir / f"{project_name}{suffix}"
        if candidate.exists() and candidate.is_dir():
            return candidate

    # Try case-insensitive search
    project_lower = project_name.lower()
    for item in repos_dir.iterdir():
        if item.is_dir() and item.name.lower() == project_lower:
            return item
        # Also check with suffixes
        for suffix in ['-cov', '-instrumented', '-coverage']:
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
      --model-name gpt-5.1-2025-11-13

  # Run specific tasks
  python3 multiple_secb_task.py \\
      --instance-ids njs.cve-2023-27727,njs.cve-2024-12345 \\
      --repos-dir /home/ubuntu/PoV/Repos \\
      --model-name claude-sonnet-4-5-20250929

  # Run all tasks for a project with single repo path
  python3 multiple_secb_task.py --project-name njs \\
      --repo-path /home/ubuntu/PoV/Repos/njs-cov \\
      --model-name gpt-5.1-2025-11-13
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
        '--model-name',
        required=True,
        help='Model name (e.g., gpt-5.1-2025-11-13, claude-sonnet-4-5-20250929)'
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
        '--disable-crash-analysis',
        action='store_true',
        help='Skip Phase 4 (crash trigger analysis)'
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

    return parser.parse_args()


def run_single_task(task, repo_path: Path, args, api_key: str, model_provider: str) -> Dict[str, Any]:
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
    print(f"Model: {args.model_name} ({model_provider})")
    print(f"Project: {task.project_name}")
    print(f"CVE: {task.cve_id}")
    print("=" * 70)

    # Create configuration
    config = AgentConfig(
        # Task information
        project_name=task.project_name,
        cve_id=task.cve_id,
        lang=task.lang,
        target_repo_path=str(repo_path),
        vuln_location=task.vuln_location,
        base_commit=task.base_commit,
        build_sh=None,  # Skip build since project is assumed to be already built
        harness_command=task.harness_command,
        sanitizer_report=task.sanitizer_report,

        # LLM configuration
        model_provider=model_provider,
        model_name=args.model_name,
        api_key=api_key,

        # Ablation options
        disable_program_instrumentation=args.disable_instrumentation,
        disable_vulnerability_analysis=args.disable_vuln_analysis,
        disable_crash_trigger_analysis=args.disable_crash_analysis,

        # Analysis options
        max_iterations=args.max_iterations,
        timeout=args.timeout,

        # Output options
        work_dir=str(work_dir),
        output_dir=str(output_dir),
        verbose=not args.no_verbose
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
            'iterations': agent_result['iterations'],
            'povs_generated': agent_result['povs_generated'],
            'crashes_found': agent_result['crashes_found'],
            'errors': agent_result['errors'],
            'output_dir': str(output_dir)
        })

        # Print summary
        print("\n" + "-" * 70)
        print(f"Task {instance_id} Summary:")
        print(f"  Final Phase: {agent_result['final_phase']}")
        print(f"  Iterations: {agent_result['iterations']}")
        print(f"  PoVs Generated: {agent_result['povs_generated']}")
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
        model_provider = infer_model_provider(args.model_name)
        if model_provider is None:
            print(f"✗ Error: Cannot infer model provider from model name '{args.model_name}'")
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

    else:
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

    for i, task in enumerate(tasks, 1):
        print(f"\n[{i}/{len(tasks)}] Processing: {task.instance_id}")

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
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Completion Rate: {successful}/{len(tasks)} ({100*successful/len(tasks) if tasks else 0:.1f}%)")

    # Print per-task results
    print("\nDetailed Results:")
    for result in results:
        status = "✓" if result['success'] else "✗"
        instance_id = result['instance_id']

        if result['success']:
            povs = result.get('povs_generated', 0)
            crashes = result.get('crashes_found', 0)
            duration = result.get('duration_seconds', 0)
            print(f"  {status} {instance_id}: {povs} PoVs, {crashes} crashes ({duration:.1f}s)")
        else:
            error = result.get('error', 'Unknown error')
            print(f"  {status} {instance_id}: {error}")

    # Save summary to file
    base_output_dir = Path(args.output_dir or "./output")
    summary_file = Path(args.summary_file) if args.summary_file else base_output_dir / "summary.json"
    summary_file.parent.mkdir(parents=True, exist_ok=True)

    summary_data = {
        'execution_time': datetime.now().isoformat(),
        'model': args.model_name,
        'model_provider': model_provider,
        'total_tasks': len(tasks),
        'successful': successful,
        'failed': failed,
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
