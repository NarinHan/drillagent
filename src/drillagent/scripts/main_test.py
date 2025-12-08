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

For more information, see: https://github.com/learjet5/DrillAgent
        """
    )

    # Required arguments (optional when using --test-loader)
    parser.add_argument(
        "target_repo_path",
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
        "--model",
        default="claude",
        choices=["claude", "openai", "google"],
        help="LLM provider to use (default: claude)"
    )

    parser.add_argument(
        "--model-name",
        default="claude-sonnet-4-5-20250929",
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


def load_cve_data(cve_id: str) -> dict:
    """
    Load CVE data from SEC-bench dataset
    
    Args:
        cve_id: CVE instance ID (e.g., "mruby.cve-2022-1934")
    
    Returns:
        Dictionary with CVE data or empty dict if not found
    """
    import json
    
    # Get project root
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    
    # Try CVE-instances directory first
    instance_file = project_root / 'datasets' / 'sec-bench' / 'CVE-instances' / f'{cve_id}.json'
    
    if instance_file.exists():
        print(f"[+] Loading CVE data from: {instance_file}")
        with open(instance_file, 'r') as f:
            data = json.load(f)
        print(f"[+] Loaded CVE data with {len(data)} fields")
        return data
    else:
        print(f"[!] Warning: CVE instance file not found: {instance_file}")
        return {}


def main():
    """Main entry point for DrillAgent CLI"""
    args = parse_arguments()

    # Test mode: just test the RawSecbTaskLoader
    if args.test_loader_path:
        test_task_loader(args.test_loader_path, args.instances)
        return

    # Validate required arguments for normal mode
    if not args.target_repo_path:
        print("Error: target_repo_path is required (unless using --test-loader)")
        sys.exit(1)

    # Load CVE data if CVE ID is provided
    cve_data = {}
    if args.cve_id:
        cve_data = load_cve_data(args.cve_id)
    
    # Create configuration from arguments, with CVE data as defaults
    config = AgentConfig(
        target_repo_path=args.target_repo_path,
        cve_id=args.cve_id,
        project_name=cve_data.get('project_name'),
        lang=cve_data.get('lang'),
        base_commit=cve_data.get('base_commit', 'af5acf3566d5732871b1dcb007aee4f474369d93'),
        sanitizer_report=cve_data.get('sanitizer_report'),
        build_sh=cve_data.get('build_sh'),
        harness_command=cve_data.get('harness_command'),
        model_provider=args.model,
        model_name=args.model_name,
        api_key=args.api_key,
        max_iterations=args.max_iterations,
        timeout=args.timeout,
        output_dir=args.output_dir,
        work_dir=args.work_dir,
        verbose=args.verbose,
    )
    
    # Print loaded config summary
    if args.verbose:
        print(f"\n[Config Summary]")
        print(f"  CVE ID: {config.cve_id}")
        print(f"  Project: {config.project_name}")
        print(f"  Language: {config.lang}")
        print(f"  Base Commit: {config.base_commit[:12] if config.base_commit else 'N/A'}...")
        print(f"  Sanitizer Report: {len(config.sanitizer_report) if config.sanitizer_report else 0} chars")
        print()

    # Create output directories
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)
    Path(config.work_dir).mkdir(parents=True, exist_ok=True)

    # Initialize DrillAgent
    try:
        agent = DrillAgent(config)

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
