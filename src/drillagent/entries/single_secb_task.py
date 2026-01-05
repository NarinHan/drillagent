#!/usr/bin/env python3
"""
Single SecBench Task Runner

A general-purpose script for running DrillAgent on a single SecBench task.
Supports flexible configuration via command-line arguments.
"""

import sys
import argparse
from pathlib import Path

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


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Run DrillAgent on a single SecBench task',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with default API key
  python3 single_secb_task.py --instance-id njs.cve-2023-27727 \\
      --repo-path /home/ubuntu/PoV/Repos/njs-cov \\
      --basic-model gpt-5.1-2025-11-13

  # Specify API key file
  python3 single_secb_task.py --instance-id njs.cve-2023-27727 \\
      --repo-path /home/ubuntu/PoV/Repos/njs-cov \\
      --basic-model claude-sonnet-4-5-20250929 \\
      --api-key-file /path/to/claude.key

  # Provide API key directly
  python3 single_secb_task.py --instance-id njs.cve-2023-27727 \\
      --repo-path /home/ubuntu/PoV/Repos/njs-cov \\
      --basic-model gpt-5.1-2025-11-13 \\
      --api-key sk-xxx...
        """
    )

    # Required arguments
    parser.add_argument(
        '--instance-id',
        required=True,
        help='SecBench task instance ID (e.g., njs.cve-2023-27727)'
    )
    parser.add_argument(
        '--repo-path',
        required=True,
        help='Path to the target repository'
    )
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
        help='Working directory (default: ./workspace/{instance_id})'
    )
    parser.add_argument(
        '--output-dir',
        help='Output directory (default: ./output/{instance_id})'
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
        action='store_true', # This means the default is False
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

    # Other options
    parser.add_argument(
        '--no-verbose',
        action='store_true',
        help='Disable verbose output'
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


def main():
    args = parse_args()

    # Set default directories if not specified
    work_dir = args.work_dir or f"./workspace/{args.instance_id}"
    output_dir = args.output_dir or f"./output/{args.instance_id}"

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

    # Parse additional model configurations
    reasoning_model = parse_model_spec(args.reasoning_model)
    low_cost_model = parse_model_spec(args.low_cost_model)

    print("=" * 70)
    print(f"DrillAgent Single Task Test: {args.instance_id}")
    print("=" * 70)
    print(f"Repository: {args.repo_path}")
    print(f"Model: {args.basic_model} ({model_provider})")
    print(f"Dataset: {args.dataset_path}")
    print("=" * 70)

    # Load task
    loader = RawSecbTaskLoader(
        dataset_path=args.dataset_path,
        instance_ids=[args.instance_id]
    )
    loader.load_cve_tasks()
    task = loader.get_task(args.instance_id)

    if task is None:
        print(f"✗ Error: Task '{args.instance_id}' not found in dataset")
        sys.exit(1)

    # Display task information
    print(f"\nTask Information:")
    print(f"  Project: {task.project_name}")
    print(f"  CVE: {task.cve_id}")
    print(f"  Language: {task.lang}")
    print(f"  Base Commit: {task.base_commit}")
    print(f"  Vuln Location: {task.vuln_location}")
    print(f"  Harness Command: {task.harness_command}")
    print()

    # Create configuration
    config = AgentConfig(
        # Task information
        project_name=task.project_name,
        cve_id=task.cve_id,
        lang=task.lang,
        target_repo_path=args.repo_path,
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
        work_dir=work_dir,
        output_dir=output_dir,
        verbose=not args.no_verbose
    )

    # Create output directories
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)
    Path(config.work_dir).mkdir(parents=True, exist_ok=True)
    config.print_config()

    # Initialize and run DrillAgent
    try:
        agent = DrillAgent(config)
        result = agent.run()

        # Print results
        print("\n" + "=" * 70)
        print("DrillAgent Execution Summary")
        print("=" * 70)
        print(f"Final Phase: {result['final_phase']}")
        print(f"Crashes Found: {result['crashes_found']}")

        if result['errors']:
            print(f"\nErrors ({len(result['errors'])}):")
            for error in result['errors']:
                print(f"  - {error}")

        print(f"\nResults saved to: {config.output_dir}")
        print("=" * 70)

        # Exit with appropriate code
        if result['final_phase'] == 'completed':
            print("\n✓ SUCCESS: PoVs generated successfully!")
            sys.exit(0)
        else:
            print("\n⚠ WARNING: Completed but no PoVs generated or incomplete execution")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n⚠ Interrupted by user. Exiting...")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
