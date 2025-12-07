import os
import re
import json
import glob
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

@dataclass
class SecbTask:
    # Data class for storing SEC-bench task information.
    # Agent can use these easily.
    instance_id: str
    repo: str
    project_name: str
    lang: str
    work_dir: str
    sanitizer: str
    base_commit: str
    build_sh: str
    secb_sh: str
    sanitizer_report: str
    # Any additional fields from the JSON
    extra_fields: Dict = field(default_factory=dict)
    # Further parsed fields. (easy to extend if needed)
    vuln_location: Optional[str] = None 
    harness_command: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict) -> 'SecbTask':
        """Create a SecbTask from a dictionary, filtering out excluded fields."""
        task_data = {}
        extra_fields = {}

        # Required fields for the dataclass
        required_fields = {
            'instance_id', 'repo', 'project_name', 'lang', 'work_dir',
            'sanitizer', 'base_commit', 'build_sh', 'secb_sh', 'sanitizer_report'
        }

        for key, value in data.items():
            # Fields to exclude (not provided to the agent)
            if key in {'bug_description', 'dockerfile', 'patch', 'exit_code', 'bug_report'}:
                continue
            # Fields to include
            elif key in required_fields:
                task_data[key] = value
            else:
                # Store any additional fields not in the required set
                extra_fields[key] = value

        task_data['extra_fields'] = extra_fields
        return cls(**task_data)

    def get_vuln_location(self) -> Optional[str]:
        # TODO: Still many bugs. May need to utilize project name.
        """Extract vulnerability location from sanitizer report if possible.
        Returns:
            Relative path with line and column (e.g., "src/file.c:123:45"), or None if not found
        """
        if not self.sanitizer_report:
            return None

        # Pattern to match absolute path with line:column format
        # Matches: /path/to/file.c:123:45 or /path/to/file.c:123
        pattern = r'(/[^\s:]+\.[a-zA-Z]+):(\d+)(?::(\d+))?'

        match = re.search(pattern, self.sanitizer_report)
        if not match:
            return None

        abs_path = match.group(1)
        line_num = match.group(2)
        col_num = match.group(3) if match.group(3) else None

        # Convert absolute path to relative path
        # Try to find the project name in the path to determine the relative path
        path_parts = abs_path.split('/')

        # Look for common project root indicators (src, project_name, etc.)
        relative_start_idx = None

        # First, try to find the project name in the path
        if self.project_name:
            for i, part in enumerate(path_parts):
                if part == self.project_name:
                    relative_start_idx = i + 1
                    break

        # If not found by project name, try to find 'src' directory
        if relative_start_idx is None:
            for i, part in enumerate(path_parts):
                if part == 'src':
                    relative_start_idx = i
                    break

        # Special handling for system paths (keep more context)
        if relative_start_idx is None:
            # Check if it's a system path
            if abs_path.startswith('/usr/') or abs_path.startswith('/lib/'):
                # For system paths, keep from 'include' or 'lib' onwards
                for i, part in enumerate(path_parts):
                    if part in ['include', 'lib']:
                        relative_start_idx = i
                        break

        # If still not found, use the last few components
        if relative_start_idx is None:
            # Use last 2-3 path components as a fallback
            relative_start_idx = max(0, len(path_parts) - 3)

        # Build relative path
        relative_path = '/'.join(path_parts[relative_start_idx:])

        # Construct the location string
        if col_num:
            location = f"{relative_path}:{line_num}:{col_num}"
        else:
            location = f"{relative_path}:{line_num}"

        return location

    def get_harness_command(self) -> Optional[str]:
        """Extract harness command from SEC-bench script if possible.
        Returns:
            The harness command(s) from repro() function, or None if not found
        """
        if not self.secb_sh:
            return None

        # Find the repro() function
        lines = self.secb_sh.split('\n')
        in_repro_function = False
        commands = []

        for line in lines:
            stripped = line.strip()

            # Check if we're entering the repro() function
            if 'repro()' in line and '{' in line:
                in_repro_function = True
                continue

            if not in_repro_function:
                continue

            # Check if we're exiting the function
            if stripped.startswith('}'):
                break

            # Skip empty lines
            if not stripped:
                continue

            # Skip comments (lines starting with #)
            if stripped.startswith('#'):
                continue

            # Skip echo/print commands
            if stripped.startswith('echo ') or stripped.startswith('print ') and ' | ' not in stripped:
                continue

            # Extract actual commands
            # This is a real command line
            commands.append(stripped)

        if not commands:
            return None

        # Join multiple commands with newlines
        return '\n'.join(commands)

    def __post_init__(self):
        # Parse vuln_location if not provided
        if not self.vuln_location:
            self.vuln_location = self.get_vuln_location()
        # Parse harness_command if not provided
        if not self.harness_command:
            self.harness_command = self.get_harness_command()

class RawSecbTaskLoader:
    # Responsible for loading security benchmark tasks from JSON files.
    def __init__(self, dataset_path: str, instance_ids: Optional[List[str]] = None):
        """
        Args:
            dataset_path: Path to the SEC-bench CVE instances directory
            instance_ids: Optional list of specific instance IDs to load
        """
        self.dataset_path = dataset_path  # datasets/sec-bench/CVE-instances/
        self.instance_ids = instance_ids or []  # optional
        assert os.path.exists(dataset_path), f"SEC-bench Data path {dataset_path} does not exist."
        self.cve_tasks: Dict[str, SecbTask] = {}  # instance_id -> SecbTask

    def load_cve_tasks(self) -> Dict[str, SecbTask]:
        """
        Load CVE tasks from JSON files in the dataset directory.
        Returns:
            Dictionary mapping instance_id to SecbTask objects
        """
        if len(self.instance_ids) > 0:
            print(f"[+] Loading SEC-bench tasks from {self.dataset_path} for instances: {self.instance_ids}")
            json_files = [os.path.join(self.dataset_path, f"{instance_id}.json")
                         for instance_id in self.instance_ids]
            # Verify all requested files exist
            for json_file in json_files:
                if not os.path.exists(json_file):
                    print(f"[!] Warning: {json_file} not found, skipping...")
        else:
            print(f"[+] Loading all SEC-bench tasks from {self.dataset_path}")
            # Find all JSON files in the directory
            json_files = glob.glob(os.path.join(self.dataset_path, "*.json"))

        # Load each JSON file
        loaded_count = 0
        failed_count = 0

        for json_file in sorted(json_files):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    task_data = json.load(f)

                # Extract instance_id from the data
                instance_id = task_data.get('instance_id')
                if not instance_id: # TODO: Fallback: extract from filename
                    instance_id = Path(json_file).stem
                    task_data['instance_id'] = instance_id

                # Create SecbTask from the data (filtering is done in from_dict)
                task = SecbTask.from_dict(task_data)
                self.cve_tasks[instance_id] = task
                loaded_count += 1

            except json.JSONDecodeError as e:
                print(f"[!] Error parsing JSON file {json_file}: {e}")
                failed_count += 1
            except Exception as e:
                print(f"[!] Error loading file {json_file}: {e}")
                failed_count += 1

        print(f"[+] Successfully loaded {loaded_count} tasks")
        if failed_count > 0:
            print(f"[!] Failed to load {failed_count} tasks")

        return self.cve_tasks

    def get_task(self, instance_id: str) -> Optional[SecbTask]:
        """
        Get a specific task by instance_id.
        Args:
            instance_id: The instance ID to retrieve
        Returns:
            SecbTask object or None if not found
        """
        return self.cve_tasks.get(instance_id)

    def get_all_instance_ids(self) -> List[str]:
        """
        Get all loaded instance IDs.
        Returns:
            List of instance IDs
        """
        return list(self.cve_tasks.keys())

    # Below are 4 useful getters.
    def get_base_commit(self, instance_id: str) -> Optional[str]:
        """
        Get the base commit hash for a specific task.
        Returns:
            Base commit hash or None if not found
        """
        task = self.get_task(instance_id)
        return task.base_commit if task else None

    def get_build_sh(self, instance_id: str) -> Optional[str]:
        """
        Get the build script for a specific task.
        Returns:
            Build script content or None if not found
        """
        task = self.get_task(instance_id)
        return task.build_sh if task else None

    def get_secb_sh(self, instance_id: str) -> Optional[str]:
        """
        Get the SEC-bench script for a specific task.
        Returns:
            SEC-bench script content or None if not found
        """
        task = self.get_task(instance_id)
        return task.secb_sh if task else None

    def get_sanitizer_report(self, instance_id: str) -> Optional[str]:
        """
        Get the sanitizer report for a specific task.
        Returns:
            Sanitizer report content or None if not found
        """
        task = self.get_task(instance_id)
        return task.sanitizer_report if task else None

    def print_task_summary(self, instance_id: str):
        """
        Print a summary of a specific task.
        Args:
            instance_id: The instance ID to summarize
        """
        task = self.get_task(instance_id)
        if not task:
            print(f"[!] Task {instance_id} not found")
            return

        # Get all fields including extra_fields
        all_fields = ['instance_id', 'repo', 'project_name', 'lang', 'work_dir',
                     'sanitizer', 'base_commit', 'build_sh', 'secb_sh', 'sanitizer_report']
        if task.extra_fields:
            all_fields.extend(task.extra_fields.keys())

        print(f"\n{'='*60}")
        print(f"Task Summary: {instance_id}")
        print(f"task fields: {all_fields}")
        print(f"{'='*60}")
        print(f"Project: {task.project_name}")
        print(f"Repository: {task.repo}")
        print(f"Language: {task.lang}")
        print(f"Sanitizer: {task.sanitizer}")
        # Only 'base_commit', 'build_sh', 'secb_sh', 'sanitizer_report' are important for the agent
        print(f"Base Commit: {task.base_commit[:12]}...")
        print(f"Sanitizer Report:\n {task.sanitizer_report}\nSanitizer Report End.")

        # Print first few lines of bug description
        # bug_desc = task.get('bug_description', 'N/A')
        # if bug_desc != 'N/A' and len(bug_desc) > 200:
        #     print(f"Bug Description: {bug_desc[:200]}...")
        # else:
        #     print(f"Bug Description: {bug_desc}")
        # print(f"{'='*60}\n")


class SecbTaskLoader:
    # TODO: To be compatible with SEC-bench official eval process (load from docker images).
    pass

