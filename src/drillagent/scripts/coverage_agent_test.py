#!/usr/bin/env python3
"""
Coverage Agent Test Script

Test script for testing CoverageInstrumentAgent functionality.
Similar to main_test.py but focused on coverage instrumentation.
"""

import argparse
import sys
import json
from pathlib import Path
from dotenv import load_dotenv

# Add src directory to Python path
src_dir = Path(__file__).resolve().parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from drillagent.config import AgentConfig
from drillagent.drill_agent import DrillAgent

# Load .env file from project root
project_root = Path(__file__).resolve().parent.parent.parent.parent
env_file = project_root / '.env'
if env_file.exists():
    load_dotenv(env_file)


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Coverage Agent Test - Test LLVM Coverage Instrumentation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test coverage instrumentation for a specific CVE
  python coverage_agent_test.py --cve-id CVE-2017-5924 --repo /path/to/repo

  # Test with specific model
  python coverage_agent_test.py --cve-id CVE-2022-43284 --repo /path/to/njs --model openai

  # Run with verbose output
  python coverage_agent_test.py --cve-id CVE-2017-5924 --repo /path/to/repo -v
        """
    )

    # Required arguments
    parser.add_argument(
        "--cve-id",
        required=True,
        help="CVE identifier (e.g., CVE-2017-5924)"
    )

    parser.add_argument(
        "--repo",
        dest="target_repo_path",
        help="Path to target repository (if not provided, will use default location)"
    )

    # Optional arguments
    parser.add_argument(
        "--model",
        default="openai",
        choices=["claude", "openai", "google"],
        help="LLM provider to use (default: openai)"
    )

    parser.add_argument(
        "--model-name",
        # default="gpt-4o",
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
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    return parser.parse_args()


def load_cve_data(cve_id: str) -> dict:
    """
    Load CVE data from SEC-bench dataset
    
    Args:
        cve_id: CVE ID (e.g., "CVE-2017-5924")
    
    Returns:
        Dictionary with CVE data or empty dict if not found
    """
    # Get project root
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    
    # Convert CVE-2017-5924 to cve-2017-5924 for filename
    cve_lower = cve_id.lower()
    
    # Search for JSON file with this CVE ID
    instances_dir = project_root / 'datasets' / 'sec-bench' / 'CVE-instances'
    
    # Find file matching pattern *.cve-id.json
    matches = list(instances_dir.glob(f'*.{cve_lower}.json'))
    
    if matches:
        instance_file = matches[0]
        print(f"[+] Loading CVE data from: {instance_file}")
        with open(instance_file, 'r') as f:
            data = json.load(f)
        print(f"[+] Loaded CVE data with {len(data)} fields")
        return data
    else:
        print(f"[!] Warning: CVE instance file not found for {cve_id}")
        print(f"[!] Searched in: {instances_dir}")
        return {}


def determine_repo_path(cve_data: dict, target_repo_path: str = None) -> str:
    """
    Determine the repository path based on CVE data and command line args
    
    Args:
        cve_data: CVE data dictionary
        target_repo_path: Optional path from command line
    
    Returns:
        Path to target repository
    """
    if target_repo_path:
        return target_repo_path
    
    # Try to infer from CVE data
    project_name = cve_data.get('project_name')
    if project_name:
        # Default location: /home/ray/cs562/repos/<project>
        default_path = f"/home/ray/cs562/repos/{project_name}"
        print(f"[+] Using default repository path: {default_path}")
        return default_path
    
    raise ValueError("Could not determine repository path. Please provide --repo argument.")


def main():
    """Main entry point for coverage agent testing"""
    args = parse_arguments()

    print("\n" + "=" * 60)
    print("Coverage Agent Test")
    print("=" * 60)

    # Load CVE data to get project_name and display summary
    cve_data = load_cve_data(args.cve_id)
    
    if not cve_data:
        print(f"[!] Error: Could not load CVE data for {args.cve_id}")
        sys.exit(1)

    # Determine repository path
    try:
        repo_path = determine_repo_path(cve_data, args.target_repo_path)
    except ValueError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    # Print CVE summary
    print(f"\n[CVE Summary]")
    print(f"  CVE ID: {args.cve_id}")
    print(f"  Project: {cve_data.get('project_name', 'N/A')}")
    print(f"  Repository: {repo_path}")
    print()

    # Create minimal configuration
    # Only provide essentials - DrillAgent will load full CVE instance data internally
    config = AgentConfig(
        target_repo_path=repo_path,
        cve_id=args.cve_id,
        project_name=cve_data.get('project_name'),  # Needed to locate instance file
        base_commit=cve_data.get('base_commit'),    # Needed for git checkout
        # model_provider=args.model,
        # model_name=args.model_name,
        api_key=args.api_key,
        output_dir=args.output_dir,
        verbose=args.verbose,
        # Enable only coverage instrumentation for this test
        enable_coverage=True,
        enable_distance=False,
        enable_sanitizer=False,
        # disable_program_instrumentation=True,
        # Skip other phases
        disable_vulnerability_analysis=True,
        disable_path_exploration=True,
        disable_pov_generation=True,
    )

    # Create output directory
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)

    # Initialize and run DrillAgent
    try:
        print("\n" + "=" * 60)
        print("Initializing DrillAgent")
        print("=" * 60)
        
        agent = DrillAgent(config)
        
        # Run the full DrillAgent workflow
        # This will execute Phase 1 (instrumentation) which includes coverage agent
        print("\n" + "=" * 60)
        print("Running DrillAgent Workflow")
        print("=" * 60)
        
        result = agent.run()
        
        # Check results
        print("\n" + "=" * 60)
        print("DrillAgent Workflow Complete")
        print("=" * 60)
        
        # Check if coverage binary was generated
        if hasattr(agent, 'coverage_binary') and agent.coverage_binary:
            print(f"✓ Coverage instrumentation SUCCESSFUL")
            print(f"  Instrumented Binary: {agent.coverage_binary}")
            
            # The coverage agent already ran test_coverage_instrumentation() as Phase 4
            # Results should be logged, but we can verify exit status
            print("\n" + "=" * 60)
            print("Test PASSED ✓")
            print("=" * 60)
            print(f"\nFinal phase: {result.get('final_phase')}")
            print(f"Errors: {len(result.get('errors', []))}")
            
            sys.exit(0)
        else:
            print("✗ Coverage instrumentation FAILED")
            print("  No coverage binary was generated")
            
            if agent.errors:
                print("\n  Errors:")
                for error in agent.errors:
                    print(f"    - {error}")
            
            print("\n" + "=" * 60)
            print("Test FAILED ✗")
            print("=" * 60)
            print(f"\nFinal phase: {result.get('final_phase')}")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
