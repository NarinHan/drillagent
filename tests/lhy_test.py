#!/usr/bin/env python3
"""
LHY Test Script for njs CVE-2022-27007 PoV Generation

This script generates PoV for njs.cve-2022-27007 using DrillAgent.
It skips the instrumentation and root cause analysis phases.

Date: 2025.12.06
Purpose: Test PoV generation for njs.cve-2022-27007. Skip root cause analysis to speed up.
"""
# python3 src/drillagent/scripts/lhy_test.py

# /home/ubuntu/PoV/test-njs/njs.cve-2022-27007/poc-njs-2022-27007.js

import sys
from pathlib import Path

# Add src directory to Python path
src_dir = Path(__file__).resolve().parent.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from drillagent.config import AgentConfig
from drillagent.drill_agent import DrillAgent
from drillagent.task_loader import RawSecbTaskLoader


def main():
    """Main entry point for LHY's njs CVE-2022-27007 test"""

    print("=" * 70)
    print("DrillAgent Test: njs.cve-2022-27007")
    print("=" * 70)

    # Load OpenAI API key
    api_key_file = Path(__file__).resolve().parent.parent.parent.parent / "openai.key"
    try:
        with open(api_key_file, 'r') as f:
            api_key = f.read().strip()
        print(f"✓ Loaded API key from {api_key_file}")
    except FileNotFoundError:
        print(f"✗ Error: API key file not found at {api_key_file}")
        sys.exit(1)

    # All llvm-cov projects: /home/shared_project/repos-llvm-cov/
    # curr_repo_path = "/home/shared_project/repos/njs" # Specified by LHY
    curr_repo_path = "/home/ubuntu/PoV/Repos/njs-cov"
    instance_id = "njs.cve-2022-27007"
    # curr_repo_path = "/home/shared_project/repos/mruby/"
    # instance_id = "mruby.cve-2022-1934"

    loader = RawSecbTaskLoader(dataset_path="datasets/sec-bench/CVE-instances", instance_ids=[instance_id])
    loader.load_cve_tasks()
    task = loader.get_task(instance_id)
    

    # Maybe we need to refine these two fields manually for now...
    print(f"vuln_location: {task.vuln_location}\nharness_command: {task.harness_command}")

    # Create configuration
    config = AgentConfig(
        # Task information
        project_name=task.project_name,
        cve_id=task.cve_id,
        lang=task.lang,
        target_repo_path=curr_repo_path,
        vuln_location=task.vuln_location,
        base_commit=task.base_commit,
        build_sh=None,  # Skip build since project is already built
        harness_command=task.harness_command,
        sanitizer_report=task.sanitizer_report,

        # LLM configuration
        model_provider="openai",
        model_name="gpt-5.1-2025-11-13",
        # model_name="gpt-5-mini-2025-08-07",
        api_key=api_key,

        # Ablation options - skip instrumentation and root cause analysis
        disable_program_instrumentation=True, # Skip Phase 1
        # disable_vulnerability_analysis=True,  # Skip Phase 2
        disable_crash_trigger_analysis=True,  # Skip Phase 4

        # Analysis options
        max_iterations=10,  # 
        timeout=1200,       # 20 minutes

        # Output options
        work_dir   = f"./workspace/{instance_id}",
        output_dir = f"./output/{instance_id}",
        verbose=True
    )

    # Create output directories
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)
    Path(config.work_dir).mkdir(parents=True, exist_ok=True)
    config.print_config()

    # Initialize and run DrillAgent!!!!
    try:
        # Assume that the project is already built with llvm-cov instrumentation
        agent = DrillAgent(config)
        result = agent.run()

        # Print results
        print("\n" + "=" * 70)
        print("DrillAgent Execution Summary")
        print("=" * 70)
        print(f"Final Phase: {result['final_phase']}")
        print(f"Iterations: {result['iterations']}")
        print(f"PoVs Generated: {result['povs_generated']}")
        print(f"Crashes Found: {result['crashes_found']}")

        if result['errors']:
            print(f"\nErrors ({len(result['errors'])}):")
            for error in result['errors']:
                print(f"  - {error}")

        print(f"\nResults saved to: {config.output_dir}")
        print("=" * 70)

        # Exit with appropriate code
        if result['final_phase'] == 'completed' and result['povs_generated'] > 0:
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
