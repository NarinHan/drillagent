#!/usr/bin/env python3
"""Test script for LLVMCovUtils"""

import sys
import os
from pathlib import Path

# Add src to path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root / 'src'))

from drillagent.utils import LLVMCovUtils

def test_basic_functionality():
    """Test basic functionality of LLVMCovUtils"""

    binary_path = '/home/ubuntu/PoV/Repos/njs-cov/build/njs'
    profdata_path = '/home/ubuntu/PoV/test-njs/njs.cve-2022-27007/default.profdata'

    print("=" * 80)
    print("Initializing LLVMCovUtils...")
    print("=" * 80)

    cov_utils = LLVMCovUtils(
        binary_path=binary_path,
        profdata_path=profdata_path
    )

    print("✓ Initialization successful\n")

    # Test 1: Generate full report
    print("=" * 80)
    print("Test 1: Generate Full Report")
    print("=" * 80)
    try:
        report = cov_utils.generate_full_report()
        lines = report.split('\n')
        print(f"✓ Report generated successfully ({len(lines)} lines)")
        print(f"First 5 lines:")
        for line in lines[:5]:
            print(f"  {line}")
        print()
    except Exception as e:
        print(f"✗ Failed: {e}\n")
        return False

    # Test 2: Get coverage data and find an executed function
    print("=" * 80)
    print("Test 2: Finding Executed Functions")
    print("=" * 80)
    try:
        cov_data = cov_utils._get_coverage_data()

        # Find some executed functions
        executed_funcs = []
        for func in cov_data['data'][0]['functions']:
            if func['count'] > 0 and len(func['filenames']) > 0:
                main_file = func['filenames'][0]
                if '/njs_shell.c' in main_file or '/njs_builtin.c' in main_file:
                    executed_funcs.append({
                        'name': func['name'],
                        'file': main_file,
                        'count': func['count'],
                        'regions': len(func['regions'])
                    })
                    if len(executed_funcs) >= 3:
                        break

        print(f"✓ Found {len(executed_funcs)} executed functions:")
        for func in executed_funcs:
            print(f"  - {func['name']} in {os.path.basename(func['file'])}")
            print(f"    Execution count: {func['count']}, Regions: {func['regions']}")
        print()

    except Exception as e:
        print(f"✗ Failed: {e}\n")
        import traceback
        traceback.print_exc()
        return False

    # Test 3: Query function coverage
    print("=" * 80)
    print("Test 3: Query Function Coverage")
    print("=" * 80)
    if executed_funcs:
        test_func = executed_funcs[0]
        try:
            result = cov_utils.get_function_coverage(test_func['file'], test_func['name'])
            print(f"✓ Function coverage for '{test_func['name']}':")
            print(f"  - Executed: {result['is_executed']}")
            print(f"  - Execution count: {result['execution_count']}")
            print(f"  - Regions: {result['regions_covered']}/{result['regions_total']} covered")
            print()
        except Exception as e:
            print(f"✗ Failed: {e}\n")
            import traceback
            traceback.print_exc()
            return False

    # Test 4: Query function regions
    print("=" * 80)
    print("Test 4: Query Function Regions")
    print("=" * 80)
    if executed_funcs:
        test_func = executed_funcs[0]
        try:
            regions = cov_utils.get_function_regions(test_func['file'], test_func['name'])
            print(f"✓ Function regions for '{test_func['name']}':")
            print(f"  - Total regions: {len(regions)}")
            covered_count = sum(1 for r in regions if r['is_covered'])
            print(f"  - Covered regions: {covered_count}")
            if regions:
                print(f"  - First region:")
                r = regions[0]
                status = "COVERED" if r['is_covered'] else "NOT COVERED"
                print(f"    [{r['start_line']}:{r['start_col']} - {r['end_line']}:{r['end_col']}]")
                print(f"    Count: {r['execution_count']} ({status})")
            print()
        except Exception as e:
            print(f"✗ Failed: {e}\n")
            import traceback
            traceback.print_exc()
            return False

    # Test 5: Query line coverage
    print("=" * 80)
    print("Test 5: Query Line Coverage")
    print("=" * 80)
    if executed_funcs:
        test_func = executed_funcs[0]
        # Get regions to find a valid line
        try:
            regions = cov_utils.get_function_regions(test_func['file'], test_func['name'])
            if regions:
                # Get the first region's start line
                test_line = regions[0]['start_line']
                result = cov_utils.get_line_coverage(test_func['file'], test_line)
                print(f"✓ Line coverage for {os.path.basename(test_func['file'])}:{test_line}:")
                print(f"  - Executed: {result['is_executed']}")
                print(f"  - Execution count: {result['execution_count']}")
                print(f"  - Function: {result['function_name']}")
                print()
        except Exception as e:
            print(f"✗ Failed: {e}\n")
            import traceback
            traceback.print_exc()
            return False

    # Test 6: Get detailed function coverage (new test)
    print("=" * 80)
    print("Test 6: Get Detailed Function Coverage")
    print("=" * 80)
    if executed_funcs:
        test_func = executed_funcs[0]
        try:
            detailed_cov = cov_utils.get_detailed_function_coverage(test_func['file'], test_func['name'])
            print(f"✓ Detailed coverage for '{test_func['name']}':")
            print()
            # Print the detailed coverage output
            lines = detailed_cov.split('\n')
            # Print all lines for detailed coverage
            for line in lines:
                print(line)
            # Print first 20 lines to avoid too much output
            # for line in lines[:20]:
            #     print(line)
            # if len(lines) > 20:
            #     print(f"... ({len(lines) - 20} more lines)")
            print()
        except Exception as e:
            print(f"✗ Failed: {e}\n")
            import traceback
            traceback.print_exc()
            return False

    print("=" * 80)
    print("All tests passed! ✓")
    print("=" * 80)
    return True

if __name__ == '__main__':
    success = test_basic_functionality()
    sys.exit(0 if success else 1)
