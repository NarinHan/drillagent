import os
import json
import glob
from pathlib import Path
from typing import Dict, List, Optional


class RawSecbTaskLoader:
    """
    Responsible for loading security benchmark tasks from JSON files.

    Attributes:
        dataset_path: Path to the SEC-bench CVE instances directory
        instance_ids: Optional list of specific instance IDs to load
        cve_tasks: Dictionary mapping instance_id to task data
    """
    def __init__(self, dataset_path: str, instance_ids: Optional[List[str]] = None):
        self.dataset_path = dataset_path  # datasets/sec-bench/CVE-instances/
        self.instance_ids = instance_ids or []  # optional
        assert os.path.exists(dataset_path), f"SEC-bench Data path {dataset_path} does not exist."
        self.cve_tasks: Dict[str, Dict] = {}  # instance_id -> task data

    def load_cve_tasks(self) -> Dict[str, Dict]:
        """
        Load CVE tasks from JSON files in the dataset directory.
        Returns:
            Dictionary mapping instance_id to task data
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
                if not instance_id: # Fallback: extract from filename
                    instance_id = Path(json_file).stem

                # Before storing, remove some fields that should not be provided to the agent
                for field in ['bug_description', 'dockerfile', 'patch', 'exit_code', 'bug_report']:
                    if field in task_data:
                        del task_data[field]

                # Store the task data
                self.cve_tasks[instance_id] = task_data
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

    def get_task(self, instance_id: str) -> Optional[Dict]:
        """
        Get a specific task by instance_id.
        Args:
            instance_id: The instance ID to retrieve
        Returns:
            Task data dictionary or None if not found
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
        return task.get('base_commit') if task else None

    def get_build_sh(self, instance_id: str) -> Optional[str]:
        """
        Get the build script for a specific task.
        Returns:
            Build script content or None if not found
        """
        task = self.get_task(instance_id)
        return task.get('build_sh') if task else None

    def get_secb_sh(self, instance_id: str) -> Optional[str]:
        """
        Get the SEC-bench script for a specific task.
        Returns:
            SEC-bench script content or None if not found
        """
        task = self.get_task(instance_id)
        return task.get('secb_sh') if task else None

    def get_sanitizer_report(self, instance_id: str) -> Optional[str]:
        """
        Get the sanitizer report for a specific task.
        Returns:
            Sanitizer report content or None if not found
        """
        task = self.get_task(instance_id)
        return task.get('sanitizer_report') if task else None

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

        print(f"\n{'='*60}")
        print(f"Task Summary: {instance_id}")
        print(f"task fields: {list(task.keys())}")
        print(f"{'='*60}")
        print(f"Project: {task.get('project_name', 'N/A')}")
        print(f"Repository: {task.get('repo', 'N/A')}")
        print(f"Language: {task.get('lang', 'N/A')}")
        print(f"Sanitizer: {task.get('sanitizer', 'N/A')}")
        # Only 'base_commit', 'build_sh', 'secb_sh', 'sanitizer_report' are important for the agent
        print(f"Base Commit: {task.get('base_commit', 'N/A')[:12]}...")
        print(f"Sanitizer Report:\n {task.get('sanitizer_report', 'N/A')}\nSanitizer Report End.")

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

