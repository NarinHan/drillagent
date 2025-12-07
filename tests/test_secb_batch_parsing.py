#!/usr/bin/env python3
# python3 tests/test_secb_batch_parsing.py --output tests/batch_parsing_results.txt
"""
Batch test script for SecbTask parsing
Tests vulnerability location and harness command extraction for all CVE instances
"""
import os
import sys
import json
from pathlib import Path
from typing import List, Dict, Tuple

# Add src to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / 'src'))

from drillagent.task_loader.sec_bench import RawSecbTaskLoader


def get_all_cve_instances(dataset_path: str) -> List[str]:
    """Get list of all CVE instance IDs"""
    instance_files = sorted(Path(dataset_path).glob('*.json'))
    return [f.stem for f in instance_files]


def parse_all_cves(dataset_path: str, max_count: int = 200) -> Dict:
    """Parse all CVE instances and extract vuln_location and harness_command

    Args:
        dataset_path: Path to CVE instances directory
        max_count: Maximum number of CVEs to process

    Returns:
        Dictionary with parsing results and statistics
    """
    # Get all instance IDs
    instance_ids = get_all_cve_instances(dataset_path)[:max_count]

    print(f"{'='*80}")
    print(f"Batch Parsing Test for SEC-bench CVE Instances")
    print(f"{'='*80}")
    print(f"Total CVE instances to process: {len(instance_ids)}")
    print(f"Dataset path: {dataset_path}")
    print(f"{'='*80}\n")

    # Load all tasks
    loader = RawSecbTaskLoader(dataset_path, instance_ids)
    tasks = loader.load_cve_tasks()

    # Statistics
    stats = {
        'total': len(instance_ids),
        'loaded': len(tasks),
        'vuln_location_found': 0,
        'vuln_location_missing': 0,
        'harness_command_found': 0,
        'harness_command_missing': 0,
        'both_found': 0,
        'results': []
    }

    # Process each task
    for instance_id in instance_ids:
        if instance_id not in tasks:
            print(f"⚠️  Warning: Failed to load {instance_id}")
            continue

        task = tasks[instance_id]

        # Extract information
        vuln_location = task.vuln_location
        harness_command = task.harness_command
        print(f"\n{instance_id}\n{vuln_location}\n{harness_command}") # by LHY
        # print(f"\n{instance_id}\n{vuln_location}") # by LHY
        # print(f"\n{instance_id}\n{harness_command}") # by LHY


        # Update statistics
        has_location = vuln_location is not None
        has_command = harness_command is not None

        if has_location:
            stats['vuln_location_found'] += 1
        else:
            stats['vuln_location_missing'] += 1

        if has_command:
            stats['harness_command_found'] += 1
        else:
            stats['harness_command_missing'] += 1

        if has_location and has_command:
            stats['both_found'] += 1

        # Store result
        result = {
            'instance_id': instance_id,
            'project_name': task.project_name,
            'vuln_location': vuln_location,
            'harness_command': harness_command,
            'has_location': has_location,
            'has_command': has_command
        }
        stats['results'].append(result)

    return stats


def print_results(stats: Dict, verbose: bool = False, output_file: str = None):
    """Print parsing results

    Args:
        stats: Statistics dictionary from parse_all_cves
        verbose: If True, print detailed results for each CVE
        output_file: Optional file path to save results
    """
    output_lines = []

    # Print summary statistics
    line = f"\n{'='*80}"
    output_lines.append(line)
    print(line)

    line = "SUMMARY STATISTICS"
    output_lines.append(line)
    print(line)

    line = f"{'='*80}"
    output_lines.append(line)
    print(line)

    line = f"Total CVE instances: {stats['total']}"
    output_lines.append(line)
    print(line)

    line = f"Successfully loaded: {stats['loaded']}"
    output_lines.append(line)
    print(line)

    line = f"\nVulnerability Location:"
    output_lines.append(line)
    print(line)

    line = f"  ✓ Found: {stats['vuln_location_found']} ({stats['vuln_location_found']/stats['loaded']*100:.1f}%)"
    output_lines.append(line)
    print(line)

    line = f"  ✗ Missing: {stats['vuln_location_missing']} ({stats['vuln_location_missing']/stats['loaded']*100:.1f}%)"
    output_lines.append(line)
    print(line)

    line = f"\nHarness Command:"
    output_lines.append(line)
    print(line)

    line = f"  ✓ Found: {stats['harness_command_found']} ({stats['harness_command_found']/stats['loaded']*100:.1f}%)"
    output_lines.append(line)
    print(line)

    line = f"  ✗ Missing: {stats['harness_command_missing']} ({stats['harness_command_missing']/stats['loaded']*100:.1f}%)"
    output_lines.append(line)
    print(line)

    line = f"\nBoth Found: {stats['both_found']} ({stats['both_found']/stats['loaded']*100:.1f}%)"
    output_lines.append(line)
    print(line)

    # Print detailed results if verbose
    if verbose:
        line = f"\n{'='*80}"
        output_lines.append(line)
        print(line)

        line = "DETAILED RESULTS"
        output_lines.append(line)
        print(line)

        line = f"{'='*80}\n"
        output_lines.append(line)
        print(line)

        for i, result in enumerate(stats['results'], 1):
            line = f"[{i}/{stats['loaded']}] {result['instance_id']} ({result['project_name']})"
            output_lines.append(line)
            print(line)

            line = f"  📍 Vuln Location: {result['vuln_location'] or 'N/A'}"
            output_lines.append(line)
            print(line)

            line = f"  🔧 Harness Command:"
            output_lines.append(line)
            print(line)

            if result['harness_command']:
                for cmd_line in result['harness_command'].split('\n'):
                    line = f"     {cmd_line}"
                    output_lines.append(line)
                    print(line)
            else:
                line = "     N/A"
                output_lines.append(line)
                print(line)

            line = ""
            output_lines.append(line)
            print(line)

    # Print examples of missing data
    line = f"\n{'='*80}"
    output_lines.append(line)
    print(line)

    line = "EXAMPLES OF MISSING DATA"
    output_lines.append(line)
    print(line)

    line = f"{'='*80}\n"
    output_lines.append(line)
    print(line)

    # Show first 5 CVEs missing location
    missing_location = [r for r in stats['results'] if not r['has_location']]
    if missing_location:
        line = "CVEs missing vulnerability location:"
        output_lines.append(line)
        print(line)

        for result in missing_location:
            line = f"  - {result['instance_id']}"
            output_lines.append(line)
            print(line)
    else:
        line = "All CVEs have vulnerability location! ✓"
        output_lines.append(line)
        print(line)

    line = ""
    output_lines.append(line)
    print(line)

    # Show first 5 CVEs missing harness command
    missing_command = [r for r in stats['results'] if not r['has_command']]
    if missing_command:
        line = "CVEs missing harness command (first 5):"
        output_lines.append(line)
        print(line)

        for result in missing_command[:5]:
            line = f"  - {result['instance_id']}"
            output_lines.append(line)
            print(line)
    else:
        line = "All CVEs have harness command! ✓"
        output_lines.append(line)
        print(line)

    line = f"\n{'='*80}"
    output_lines.append(line)
    print(line)

    # Save to file if requested
    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(output_lines))
        print(f"\n✓ Results saved to: {output_file}")


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Batch test for CVE vulnerability location and harness command parsing'
    )
    parser.add_argument(
        '--dataset-path',
        default='datasets/sec-bench/CVE-instances',
        help='Path to SEC-bench CVE instances directory'
    )
    parser.add_argument(
        '--max-count',
        type=int,
        default=200,
        help='Maximum number of CVEs to process (default: 200)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print detailed results for each CVE'
    )
    parser.add_argument(
        '--output', '-o',
        help='Save results to file'
    )

    args = parser.parse_args()

    # Parse all CVEs
    stats = parse_all_cves(args.dataset_path, args.max_count)

    # Print results
    print_results(stats, verbose=args.verbose, output_file=args.output)

    # Exit with error code if success rate is too low
    success_rate = stats['both_found'] / stats['loaded'] * 100
    if success_rate < 80:
        print(f"\n⚠️  Warning: Success rate ({success_rate:.1f}%) is below 80%")
        return 1
    else:
        print(f"\n✓ Success rate: {success_rate:.1f}%")
        return 0


if __name__ == '__main__':
    sys.exit(main())
