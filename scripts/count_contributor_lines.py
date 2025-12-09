#!/usr/bin/env python3
"""
Script to count lines of code contributed by each contributor in a specific path.

Usage:
    python count_contributor_lines.py [path] [options]

Options:
    --since=YYYY-MM-DD    Only count commits after this date
    --until=YYYY-MM-DD    Only count commits before this date
    --format=table|csv|json   Output format (default: table)
    --min-lines=N         Only show contributors with at least N net lines
    --help                Show this help message

Examples:
    python count_contributor_lines.py src
    python count_contributor_lines.py src --since=2024-01-01
    python count_contributor_lines.py src --format=csv > contributors.csv
    python count_contributor_lines.py . --min-lines=100
"""

import subprocess
import sys
import argparse
import json
from collections import defaultdict


def run_git_command(args):
    """Run a git command and return output."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running git command: {e}", file=sys.stderr)
        sys.exit(1)


def is_git_repo():
    """Check if current directory is a git repository."""
    try:
        subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            capture_output=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def get_contributors(path, git_args):
    """Get list of all contributors for the specified path."""
    cmd = ['git', 'log', '--format=%aN'] + git_args + ['--', path]
    output = run_git_command(cmd)

    if not output:
        return []

    contributors = sorted(set(output.split('\n')))
    return [c for c in contributors if c]  # Filter empty strings


def get_author_stats(author, path, git_args, ignore_blank=False):
    """Get statistics for a specific author."""
    if ignore_blank:
        # Use git log with diff to count non-blank lines
        # Get list of commits by this author
        cmd = ['git', 'log', '--author=' + author, '--format=%H'] + git_args + ['--', path]
        output = run_git_command(cmd)

        if not output:
            return {
                'author': author,
                'net_lines': 0,
                'added': 0,
                'removed': 0,
                'commits': 0
            }

        commit_hashes = output.split('\n')

        added = 0
        removed = 0

        for commit_hash in commit_hashes:
            if not commit_hash.strip():
                continue

            # Get diff for this commit, ignoring blank lines
            cmd = ['git', 'show', commit_hash, '--format=', '--unified=0', '--', path]
            try:
                diff_output = run_git_command(cmd)
            except:
                continue

            for line in diff_output.split('\n'):
                # Skip if line is empty or just whitespace
                if not line.strip():
                    continue
                # Count added lines (starting with '+' but not '+++')
                if line.startswith('+') and not line.startswith('+++'):
                    # Check if the line contains non-whitespace content
                    content = line[1:]  # Remove the '+' prefix
                    if content.strip():  # Only count if there's actual content
                        added += 1
                # Count removed lines (starting with '-' but not '---')
                elif line.startswith('-') and not line.startswith('---'):
                    # Check if the line contains non-whitespace content
                    content = line[1:]  # Remove the '-' prefix
                    if content.strip():  # Only count if there's actual content
                        removed += 1

        commits = len([h for h in commit_hashes if h.strip()])
    else:
        # Original method using --numstat (includes blank lines)
        cmd = ['git', 'log', '--author=' + author, '--pretty=tformat:', '--numstat'] + git_args + ['--', path]
        output = run_git_command(cmd)

        added = 0
        removed = 0

        for line in output.split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                try:
                    # Handle binary files (marked as '-')
                    add = int(parts[0]) if parts[0] != '-' else 0
                    rem = int(parts[1]) if parts[1] != '-' else 0
                    added += add
                    removed += rem
                except ValueError:
                    continue

        # Get commit count
        cmd = ['git', 'log', '--author=' + author, '--oneline'] + git_args + ['--', path]
        output = run_git_command(cmd)
        commits = len([l for l in output.split('\n') if l.strip()])

    net = added - removed

    return {
        'author': author,
        'net_lines': net,
        'added': added,
        'removed': removed,
        'commits': commits
    }


def format_table(stats, show_totals=True):
    """Format statistics as a table."""
    # Header
    print("=" * 90)
    print(f"{'Author':<30} {'Net Lines':>10} {'Added':>10} {'Removed':>10} {'Commits':>8}")
    print("-" * 90)

    # Data rows
    total_net = 0
    total_added = 0
    total_removed = 0
    total_commits = 0

    for stat in stats:
        print(f"{stat['author']:<30} {stat['net_lines']:>10,} {stat['added']:>10,} "
              f"{stat['removed']:>10,} {stat['commits']:>8,}")
        total_net += stat['net_lines']
        total_added += stat['added']
        total_removed += stat['removed']
        total_commits += stat['commits']

    print("-" * 90)

    if show_totals:
        print(f"\nSummary:")
        print(f"  Total Contributors: {len(stats)}")
        print(f"  Total Commits:      {total_commits:,}")
        print(f"  Total Lines Added:  {total_added:,}")
        print(f"  Total Lines Removed: {total_removed:,}")
        print(f"  Net Lines:          {total_net:,}")


def format_csv(stats):
    """Format statistics as CSV."""
    print("Author,Net Lines,Added,Removed,Commits")
    for stat in stats:
        print(f"{stat['author']},{stat['net_lines']},{stat['added']},"
              f"{stat['removed']},{stat['commits']}")


def format_json(stats):
    """Format statistics as JSON."""
    output = {
        'contributors': stats,
        'summary': {
            'total_contributors': len(stats),
            'total_commits': sum(s['commits'] for s in stats),
            'total_added': sum(s['added'] for s in stats),
            'total_removed': sum(s['removed'] for s in stats),
            'total_net': sum(s['net_lines'] for s in stats)
        }
    }
    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description='Count lines of code contributed by each contributor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('path', nargs='?', default='.',
                        help='Path to analyze (default: current directory)')
    parser.add_argument('--since', help='Only count commits after this date (YYYY-MM-DD)')
    parser.add_argument('--until', help='Only count commits before this date (YYYY-MM-DD)')
    parser.add_argument('--format', choices=['table', 'csv', 'json'], default='table',
                        help='Output format (default: table)')
    parser.add_argument('--min-lines', type=int, default=0,
                        help='Only show contributors with at least N net lines')
    parser.add_argument('--sort-by', choices=['net', 'added', 'removed', 'commits'],
                        default='net', help='Sort by this metric (default: net)')
    parser.add_argument('--ignore-blank', action='store_true',
                        help='Ignore blank/whitespace-only lines (slower but more accurate)')

    args = parser.parse_args()

    # Check git repository
    if not is_git_repo():
        print("Error: Not a git repository", file=sys.stderr)
        sys.exit(1)

    # Build git arguments
    git_args = []
    if args.since:
        git_args.append(f'--since={args.since}')
    if args.until:
        git_args.append(f'--until={args.until}')

    # Get contributors
    if args.format == 'table':
        print(f"\nAnalyzing code contributions in: {args.path}")
        if git_args:
            print(f"Filters: {' '.join(git_args)}")
        print()

    contributors = get_contributors(args.path, git_args)

    if not contributors:
        print("No contributors found for the specified path and filters.", file=sys.stderr)
        sys.exit(0)

    # Collect statistics
    stats = []
    for i, author in enumerate(contributors, 1):
        if args.format == 'table':
            mode = " (ignoring blanks)" if args.ignore_blank else ""
            print(f"\rProcessing contributors{mode}... {i}/{len(contributors)}", end='', file=sys.stderr)
        stat = get_author_stats(author, args.path, git_args, ignore_blank=args.ignore_blank)
        if stat['net_lines'] >= args.min_lines:
            stats.append(stat)

    if args.format == 'table':
        print("\r" + " " * 50 + "\r", end='', file=sys.stderr)  # Clear progress line

    # Sort statistics
    sort_key_map = {
        'net': 'net_lines',
        'added': 'added',
        'removed': 'removed',
        'commits': 'commits'
    }
    stats.sort(key=lambda x: x[sort_key_map[args.sort_by]], reverse=True)

    # Output results
    if args.format == 'table':
        format_table(stats)
    elif args.format == 'csv':
        format_csv(stats)
    elif args.format == 'json':
        format_json(stats)


if __name__ == '__main__':
    main()



# # Basic usage (count lines in the src directory):
# python3 scripts/count_contributor_lines.py src --ignore-blank

# # Show only contributors with more than 100 contributed lines
# python3 scripts/count_contributor_lines.py src --min-lines=100

# # Count contributions within a specific time range
# python3 scripts/count_contributor_lines.py src --since=2024-01-01

# # Sort by different metrics
# python3 scripts/count_contributor_lines.py src --sort-by=commits  # sort by number of commits
# python3 scripts/count_contributor_lines.py src --sort-by=added    # sort by number of added lines

# # Output in JSON format
# python3 scripts/count_contributor_lines.py src --format=json > contributors.json

# # Count the entire repository
# python3 scripts/count_contributor_lines.py . --ignore-blank