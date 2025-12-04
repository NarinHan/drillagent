#!/usr/bin/env python3
"""
DrillAgent - Automated PoV Generation for Real-world CVE Instances

This is the main entry point for our testing.
"""

import argparse
import sys
from pathlib import Path

# Add src directory to Python path so we can import drillagent like a package.
# This allows running the script from anywhere: python3 src/drillagent/scripts/main_test.py
src_dir = Path(__file__).resolve().parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from drillagent.config import AgentConfig
from drillagent.drill_agent import DrillAgent
from drillagent.task_loader import RawSecbTaskLoader

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="DrillAgent - Automated PoV Generation for CVE Instances",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test loading all SEC-bench tasks
  python main_test.py --test-loader datasets/sec-bench/CVE-instances

  # Test loading specific instances only
  python main_test.py --test-loader datasets/sec-bench/CVE-instances --instances libplist.cve-2017-5545 gpac.cve-2023-4682

  # Analyze a repository with default settings
  python main_test.py /path/to/repo --cve CVE-2024-1234

  # Interactive mode for debugging
  python main_test.py /path/to/repo --interactive

For more information, see: https://github.com/learjet5/DrillAgent
        """
    )

    # Required arguments (optional when using --test-loader)
    parser.add_argument(
        "target_repo",
        nargs='?',
        help="Path to target repository or binary"
    )

    # Optional arguments
    parser.add_argument(
        "--cve",
        dest="cve_id",
        help="CVE identifier (e.g., CVE-2024-1234)"
    )

    parser.add_argument(
        "--binary",
        dest="target_binary",
        help="Specific binary to analyze (if not provided, will auto-detect)"
    )

    parser.add_argument(
        "--model",
        default="claude",
        choices=["claude", "openai", "google"],
        help="LLM provider to use (default: claude)"
    )

    parser.add_argument(
        "--model-name",
        default="claude-sonnet-4",
        help="Specific model name to use"
    )

    parser.add_argument(
        "--api-key",
        help="API key for LLM provider (or set via environment variable)"
    )

    parser.add_argument(
        "--output",
        dest="output_dir",
        default="./output",
        help="Output directory for results (default: ./output)"
    )

    parser.add_argument(
        "--work-dir",
        default="./workspace",
        help="Working directory for intermediate files (default: ./workspace)"
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        default=100,
        help="Maximum number of mutation iterations (default: 100)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Overall timeout in seconds (default: 3600)"
    )

    parser.add_argument(
        "--no-coverage",
        action="store_true",
        help="Disable coverage instrumentation"
    )

    parser.add_argument(
        "--no-distance",
        action="store_true",
        help="Disable distance calculation"
    )

    parser.add_argument(
        "--no-sanitizer",
        action="store_true",
        help="Disable memory sanitizer"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Start in interactive mode"
    )

    # Test mode for RawSecbTaskLoader
    parser.add_argument(
        "--test-loader",
        dest="test_loader_path",
        help="Test RawSecbTaskLoader with the given dataset path (e.g., datasets/sec-bench/CVE-instances/)"
    )

    parser.add_argument(
        "--instances",
        nargs='+',
        help="Specific instance IDs to load when testing loader (e.g., libplist.cve-2017-5545)"
    )

    return parser.parse_args()


def test_task_loader(dataset_path: str, instance_ids: list = None):
    """Test the RawSecbTaskLoader functionality"""
    print("\n" + "="*60)
    print("Testing RawSecbTaskLoader")
    print("="*60)

    # Create loader
    loader = RawSecbTaskLoader(dataset_path, instance_ids)

    # Load tasks
    tasks = loader.load_cve_tasks()

    # Print statistics
    print(f"\n[+] Total tasks loaded: {len(tasks)}")

    if len(tasks) > 0:
        # Show first few instance IDs
        all_ids = loader.get_all_instance_ids()
        print(f"[+] Instance IDs (showing first 5): {all_ids[:5]}")

        # Print detailed summary for the first task
        first_id = all_ids[0]
        loader.print_task_summary(first_id)

        # If specific instances were requested, show all of them
        if instance_ids:
            for instance_id in instance_ids:
                loader.print_task_summary(instance_id)


def main():
    """Main entry point for DrillAgent CLI"""
    args = parse_arguments()

    # Test mode: just test the RawSecbTaskLoader
    if args.test_loader_path:
        test_task_loader(args.test_loader_path, args.instances)
        return

    # Validate required arguments for normal mode
    if not args.target_repo:
        print("Error: target_repo is required (unless using --test-loader)")
        sys.exit(1)

    # Create configuration from arguments
    config = AgentConfig(
        target_repo=args.target_repo,
        target_binary=args.target_binary,
        cve_id=args.cve_id,
        model_provider=args.model,
        model_name=args.model_name,
        api_key=args.api_key,
        enable_coverage=not args.no_coverage,
        enable_distance=not args.no_distance,
        enable_sanitizer=not args.no_sanitizer,
        max_iterations=args.max_iterations,
        timeout=args.timeout,
        output_dir=args.output_dir,
        work_dir=args.work_dir,
        verbose=args.verbose,
    )

    # Create output directories
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)
    Path(config.work_dir).mkdir(parents=True, exist_ok=True)

    # Initialize DrillAgent
    try:
        agent = DrillAgent(config)

        if args.interactive:
            agent.interactive_mode()
        else:
            result = agent.run()

            # Exit with appropriate code
            if result['final_phase'] == 'completed' and result['povs_generated'] > 0:
                sys.exit(0)
            else:
                sys.exit(1)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Exiting...")
        sys.exit(130)
    except Exception as e:
        print(f"\nFatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
