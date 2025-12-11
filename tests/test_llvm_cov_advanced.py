#!/usr/bin/env python3
"""Advanced test script for specific use cases"""

import sys
import os
import importlib.util

# Load the module
spec = importlib.util.spec_from_file_location(
    "llvm_cov",
    "/home/ubuntu/PoV/DrillAgent/src/drillagent/utils/llvm-cov.py"
)
llvm_cov_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(llvm_cov_module)
LLVMCovUtils = llvm_cov_module.LLVMCovUtils

def main():
    binary_path = '/home/ubuntu/PoV/Repos/njs-cov/build/njs'
    profdata_path = '/home/ubuntu/PoV/test-njs/njs.cve-2022-27007/default.profdata'

    cov_utils = LLVMCovUtils(
        binary_path=binary_path,
        profdata_path=profdata_path
    )

    print("=" * 80)
    print("Advanced Coverage Analysis")
    print("=" * 80)
    print()

    # Test: Query a specific function we're interested in
    print("Test: Query specific functions from different files")
    print("-" * 80)

    test_cases = [
        ('/home/ubuntu/PoV/Repos/njs-cov/src/njs_shell.c', 'main'),
        ('/home/ubuntu/PoV/Repos/njs-cov/src/njs_builtin.c', 'njs_builtin_objects_create'),
        ('/home/ubuntu/PoV/Repos/njs-cov/src/njs_lexer.c', 'njs_lexer_init'),
    ]

    for file_path, func_name in test_cases:
        try:
            result = cov_utils.get_function_coverage(file_path, func_name)
            print(f"\n✓ {os.path.basename(file_path)}::{func_name}")
            print(f"  Executed: {result['is_executed']}")
            print(f"  Execution count: {result['execution_count']}")
            print(f"  Coverage: {result['regions_covered']}/{result['regions_total']} regions")
            if result['execution_count'] > 0:
                print(f"  Covered lines count: {len(result['covered_lines'])}")
                if result['covered_lines']:
                    print(f"  First covered line: {result['covered_lines'][0]}")
        except ValueError as e:
            print(f"\n✗ {os.path.basename(file_path)}::{func_name}")
            print(f"  Error: {e}")
        except Exception as e:
            print(f"\n✗ {os.path.basename(file_path)}::{func_name}")
            print(f"  Unexpected error: {e}")
            import traceback
            traceback.print_exc()

    # Test: Line coverage for specific lines
    print("\n" + "=" * 80)
    print("Test: Line Coverage Analysis")
    print("-" * 80)

    line_test_cases = [
        ('/home/ubuntu/PoV/Repos/njs-cov/src/njs_shell.c', 233),  # Should be executed
        ('/home/ubuntu/PoV/Repos/njs-cov/src/njs_shell.c', 240),  # Should be executed
        ('/home/ubuntu/PoV/Repos/njs-cov/src/njs_shell.c', 250),  # Check if executed
    ]

    for file_path, line_num in line_test_cases:
        try:
            result = cov_utils.get_line_coverage(file_path, line_num)
            status = "EXECUTED" if result['is_executed'] else "NOT EXECUTED"
            print(f"\n{os.path.basename(file_path)}:{line_num}")
            print(f"  Status: {status}")
            print(f"  Count: {result['execution_count']}")
            print(f"  Function: {result['function_name'] or 'N/A'}")
        except Exception as e:
            print(f"\n{os.path.basename(file_path)}:{line_num}")
            print(f"  Error: {e}")

    # Test: Get regions for a function
    print("\n" + "=" * 80)
    print("Test: Function Region Analysis")
    print("-" * 80)

    try:
        regions = cov_utils.get_function_regions(
            '/home/ubuntu/PoV/Repos/njs-cov/src/njs_shell.c',
            'main'
        )
        print(f"\nFunction 'main' has {len(regions)} regions")
        covered = [r for r in regions if r['is_covered']]
        uncovered = [r for r in regions if not r['is_covered']]
        print(f"  Covered: {len(covered)}")
        print(f"  Uncovered: {len(uncovered)}")

        if covered:
            print(f"\n  Sample covered region:")
            r = covered[0]
            print(f"    Lines {r['start_line']}-{r['end_line']}")
            print(f"    Execution count: {r['execution_count']}")

        if uncovered:
            print(f"\n  Sample uncovered region:")
            r = uncovered[0]
            print(f"    Lines {r['start_line']}-{r['end_line']}")
            print(f"    Execution count: {r['execution_count']}")

    except Exception as e:
        print(f"  Error: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "=" * 80)
    print("Advanced tests completed!")
    print("=" * 80)

if __name__ == '__main__':
    main()
