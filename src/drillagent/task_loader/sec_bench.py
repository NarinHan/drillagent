import os
import re
import sys
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
    repo_name: str = ""  # e.g., "openssl" from "openssl.cve-2021-3711" # This concept is only used in this file.
    cve_id: Optional[str] = None
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
        
        location = None # What we want to return
        # print(f"Handling get_vuln_location for {self.instance_id}...")
        if not self.sanitizer_report:
            print(f"{self.instance_id} has no sanitizer report.")
            return None

        # We need to modify some project names manually for matching
        name_transforms = {
            "imagemagick": "ImageMagick",
        }
        if self.repo_name in name_transforms:
            self.repo_name = name_transforms[self.repo_name]

        skip_line_keywords = ["libsanitizer", "x86_64-linux-gnu", " __libc_start_main ", " _start ", "lib/asan/asan_malloc_linux.cc"]

        # Round1
        for report_line in self.sanitizer_report.split('\n'):
            if any(keyword in report_line for keyword in skip_line_keywords):
                continue
            # This pattern extracts call trace-like lines. 187 outof 200 sanitizer reports can match this pattern.
            pattern0 = re.compile(
                # rf"in\s([^/\s][^\s]*)\s([^/\s][^\s]*):(\d+)", # The file_path is allowed to start with '/' char.
                rf"in\s([^/\s][^\s]*)\s(\S+):(\d+)",
                re.IGNORECASE
            )
            match = re.search(pattern0, report_line)
            if not match:
                continue
            # Craft the crash location
            crash_function = match.group(1)
            file_path = match.group(2)
            line_num = match.group(3)
            location = f"^^^{file_path}:{line_num} ({crash_function})"
            if location is not None:
                break

        # Round2
        for report_line in self.sanitizer_report.split('\n'):
            if location is not None: break
            if any(keyword in report_line for keyword in skip_line_keywords):
                continue
            # To handle some weird cases: Only extract location from runtime error lines
            if "runtime error: " in self.sanitizer_report and "runtime error: " not in report_line:
                continue
            # Make sure we have the repo_name in current line
            if self.repo_name not in report_line:
                continue
            # pattern = re.compile(rf"({'/'+re.escape(self.repo_name)}.*):(\d+)") % 70.5%
            pattern1 = re.compile(
                rf"((?:/{re.escape(self.repo_name)}|{re.escape(self.repo_name)}/).*):(\d+)",
                re.IGNORECASE
            )
            match = re.search(pattern1, report_line)
            if not match:
                continue
            # Craft the crash location
            file_path = match.group(1)
            line_num = match.group(2)
            location = f"&&&{file_path}:{line_num}"
            if location is not None:
                break
        
        # Round3
        for report_line in self.sanitizer_report.split('\n'):
            if location is not None: break
            if any(keyword in report_line for keyword in skip_line_keywords):
                continue
            # To handle some weird cases: Only extract location from runtime error lines
            if "runtime error: " in self.sanitizer_report and "runtime error: " not in report_line:
                continue
            pattern2 = re.compile(
                rf"(?:^|\s)([^/\s][^\s]*):(\d+)",
                re.IGNORECASE
            )
            match = re.search(pattern2, report_line)
            if not match:
                continue
            # Craft the crash location
            file_path = match.group(1)
            line_num = match.group(2)
            location = f"***{file_path}:{line_num}"
            if location is not None:
                break

        # print(f"Extracted vuln_location: {location}\n")
        # if not location: # Current we have 9 "Extracted vuln_location: None"
        #     print(f"repo_name: {self.repo_name}")
        #     print(f"project_name: {self.project_name}")
        #     print(f"Sanitizer report for {self.instance_id}:\n{self.sanitizer_report}\nEnd of report.\n")

        # Remove the leading debug markers (^^^, &&&, ***)
        if location is not None and len(location) > 3:
            location = location[3:]
        return location

    def get_harness_command(self) -> Optional[str]:
        """Extract harness command from SEC-bench script if possible.
        Returns:
            The harness command(s) from repro() function, or None if not found
        """
        if not self.secb_sh:
            return None

        # print(f"Handling get_harness_command for {self.instance_id}...")
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
            if stripped.startswith('echo ') or stripped.startswith('print '):
                if ' | ' in stripped:
                    pass
                else:
                    continue

            # Extract actual commands
            # This is a real command line
            commands.append(stripped)

        if not commands:
            return None

        # Join multiple commands with newlines
        return '\n'.join(commands)

    def __post_init__(self):
        self.repo_name = self.instance_id.split('.')[0]  # e.g., "openssl" from "openssl.cve-2021-3711"
        self.cve_id = self.instance_id.split('.')[1] 
        # Parse vuln_location if not provided
        if self.vuln_location is None:
            self.vuln_location = self.get_vuln_location()
        # Parse harness_command if not provided
        if self.harness_command is None:
            self.harness_command = self.get_harness_command()

class RawSecbTaskLoader:
    # Responsible for loading security benchmark tasks from JSON files.
    def __init__(self, dataset_path: str = "datasets/sec-bench/CVE-instances",
                 instance_ids: Optional[List[str]] = None,
                 project_names: Optional[List[str]] = None):
        """
        Args:
            dataset_path: Path to the SEC-bench CVE instances directory
            instance_ids: Optional list of specific instance IDs to load
            project_names: Optional list of project names to filter tasks (e.g., ["openssl", "gpac"])
        """
        self.dataset_path = dataset_path  # datasets/sec-bench/CVE-instances/
        self.instance_ids = instance_ids or []  # optional
        self.project_names = project_names or []  # optional
        assert os.path.exists(dataset_path), f"SEC-bench Data path {dataset_path} does not exist."
        self.cve_tasks: Dict[str, SecbTask] = {}  # instance_id -> SecbTask

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

    def is_labelled_blacklist(self, instance_id: str) -> bool:
        # Returns True if the instance_id is among the blacklist!
        blacklist = [
            "gpac.cve-2023-3012",
            "gpac.cve-2023-5586",   # Only two frames have line numbers.
            "imagemagick.cve-2018-6405",
            "matio.cve-2019-9032",
            "matio.cve-2019-9035",
            "matio.cve-2019-9036",
            "matio.cve-2019-9037",
            "readstat.cve-2018-5698",
            "yaml-cpp.cve-2018-20574",
            "libarchive.cve-2019-11463"
        ] # These 9 tasks are very weird in SEC-bench!
        blacklist += [
            "php.cve-2018-12882",   # Cannot be compiled...
            "gpac.cve-2022-2454",   # "UndefinedBehaviorSanitizer"
            "gpac.cve-2023-42298",  # "UndefinedBehaviorSanitizer" (Don't have backtrace starting with "#")
        ] # These tasks just have no call trace. But still possible to handle.
        return instance_id in blacklist

    def load_cve_tasks(self) -> Dict[str, SecbTask]:
        """
        Load CVE tasks from JSON files in the dataset directory.
        Returns:
            Dictionary mapping instance_id to SecbTask objects
        """
        if len(self.instance_ids) > 0:
            print(f"[+] Loading {len(self.instance_ids)} SEC-bench tasks from {self.dataset_path} for instances: {self.instance_ids}")
            json_files = [os.path.join(self.dataset_path, f"{instance_id}.json")
                         for instance_id in self.instance_ids]
            # Verify all requested files exist
            for json_file in json_files:
                if not os.path.exists(json_file):
                    print(f"[!] Warning: {json_file} not found, skipping...")
        elif len(self.project_names) > 0:
            print(f"[+] Loading SEC-bench tasks from {self.dataset_path} for projects: {self.project_names}")
            # Find all JSON files in the directory
            all_json_files = glob.glob(os.path.join(self.dataset_path, "*.json"))
            # Filter by project names (instance_id format: "project_name.cve-xxxx")
            json_files = []
            for json_file in all_json_files:
                instance_id = Path(json_file).stem
                project_name = instance_id.split('.')[0]
                if project_name in self.project_names:
                    json_files.append(json_file)
            print(f"[+] Found {len(json_files)} tasks matching the specified projects")
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
                if not instance_id: # All SEC-bench tasks must have instance_id!
                    raise ValueError(f"instance_id missing in {json_file}!")

                # Create SecbTask from the data (filtering is done in from_dict)
                task = SecbTask.from_dict(task_data) # This line may raise exceptions!!!!!
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

    #
    # Various loaders to get different subsets of tasks
    #
    def get_tasks_by_project(self, project_name: str) -> List[SecbTask]:
        """
        Get all tasks for a specific project.
        Args:
            project_name: The project name (e.g., "openssl", "gpac", "imagemagick")
        Returns:
            List of SecbTask objects for the specified project
        """
        returned_tasks = []
        for instance_id, task in self.cve_tasks.items():
            # instance_id format: "project_name.cve-xxxx"
            proj_name = instance_id.split('.')[0]
            if self.is_labelled_blacklist(instance_id): # here we skip blacklisted tasks
                continue
            if proj_name == project_name:
                returned_tasks.append(task)
        return returned_tasks

    def get_nonbinary_tasks(self) -> Dict[str, SecbTask]:
        returned_tasks = dict()
        target_projects = ["mruby", "njs", "php", "yaml", "md4c", "jq"]
        for instance_id, task in self.cve_tasks.items():
            proj_name = instance_id.split('.')[0]
            if proj_name not in target_projects:
                continue
            if self.is_labelled_blacklist(instance_id):
                continue
            returned_tasks[instance_id] = task
        return returned_tasks

    # Get a subset of tasks from SEC-bench
    def get_openhands_solved_tasks(self) -> Dict[str, SecbTask]:
        assert len(self.cve_tasks)==200, "Please load all 200 SEC-bench tasks first."
        # Get tasks that were successfully solved by OpenHands (oh_sonnet).
        oh_sonnet_instances = [
            "exiv2.cve-2017-17669",
            "exiv2.cve-2017-18005",
            "exiv2.cve-2018-17229",
            "exiv2.cve-2018-17230",
            "exiv2.cve-2020-18899",
            "gpac.cve-2021-32438",
            "gpac.cve-2023-0819",
            "gpac.cve-2023-3291",
            "gpac.cve-2023-42298",
            "gpac.cve-2023-4758",
            "gpac.cve-2023-5586",
            "imagemagick.cve-2017-11539",
            "imagemagick.cve-2017-12641",
            "imagemagick.cve-2017-12644",
            "imagemagick.cve-2017-18022",
            "imagemagick.cve-2018-5246",
            "imagemagick.cve-2018-5247",
            "imagemagick.cve-2018-5248",
            "imagemagick.cve-2019-13297",
            "imagemagick.cve-2019-13301",
            "imagemagick.cve-2019-13303",
            "imagemagick.cve-2019-13306",
            "liblouis.cve-2023-26768",
            "libmodbus.cve-2022-0367",
            "libplist.cve-2017-5545",
            "libsndfile.cve-2018-19432",
            "libxls.cve-2023-38855",
            "matio.cve-2019-9036",
            "matio.cve-2020-19497",
            "njs.cve-2022-27007",
            "openjpeg.cve-2016-10507",
            "openjpeg.cve-2016-7445",
            "openjpeg.cve-2017-14041",
            "readstat.cve-2018-5698",
            "upx.cve-2017-15056",
            "wabt.cve-2022-43282",
        ]
        # Filter the loaded tasks to only include oh_sonnet instances
        res = dict()
        for instance_id, task in self.cve_tasks.items():
            if self.is_labelled_blacklist(instance_id):
                continue
            if instance_id in oh_sonnet_instances:
                res[instance_id] = task
        return res

    def get_swea_solved_tasks(self) -> Dict[str, SecbTask]:
        assert len(self.cve_tasks)==200, "Please load all 200 SEC-bench tasks first."
        # Get tasks that were successfully solved by SWEA (swea_sonnet).
        swea_sonnet_instances = [
            "exiv2.cve-2017-17669",
            "faad2.cve-2018-20195",
            "faad2.cve-2018-20357",
            "faad2.cve-2018-20359",
            "faad2.cve-2018-20361",
            "faad2.cve-2018-20362",
            "gpac.cve-2023-0819",
            "gpac.cve-2023-4758",
            "gpac.cve-2024-0321",
            "imagemagick.cve-2017-11539",
            "imagemagick.cve-2017-12644",
            "imagemagick.cve-2017-14400",
            "imagemagick.cve-2017-18022",
            "imagemagick.cve-2018-5246",
            "imagemagick.cve-2019-13306",
            "imagemagick.cve-2019-13309",
            "imagemagick.cve-2022-48541",
            "libplist.cve-2017-5545",
            "libredwg.cve-2021-28237",
            "libsndfile.cve-2018-19432",
            "matio.cve-2020-19497",
            "mruby.cve-2018-14337",
            "njs.cve-2022-27007",
            "openjpeg.cve-2016-7445",
            "openjpeg.cve-2017-14041",
        ]
        # Filter the loaded tasks to only include swea_sonnet instances
        res = dict()
        for instance_id, task in self.cve_tasks.items():
            if self.is_labelled_blacklist(instance_id):
                continue
            if instance_id in swea_sonnet_instances:
                res[instance_id] = task
        return res

    def get_overlap_solved_tasks(self) -> Dict[str, SecbTask]:
        """Get tasks solved by both OpenHands and SWEA (intersection)."""
        oh_tasks = self.get_openhands_solved_tasks()
        swea_tasks = self.get_swea_solved_tasks()
        # Return tasks that exist in both dictionaries
        return {k: v for k, v in oh_tasks.items() if k in swea_tasks}

    def get_united_solved_tasks(self) -> Dict[str, SecbTask]:
        """Get tasks solved by either OpenHands or SWEA (union)."""
        oh_tasks = self.get_openhands_solved_tasks()
        swea_tasks = self.get_swea_solved_tasks()
        # Combine both dictionaries (union)
        return {**oh_tasks, **swea_tasks}

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


def partition_tasks_by_repo(tasks: Dict[str, SecbTask], n_partitions: int) -> List[List[str]]:
    """
    Partition tasks into N groups, ensuring all tasks from the same repo
    (project_name) are in the same partition.

    Uses a greedy algorithm: sort projects by task count (descending),
    then assign each project to the partition with the fewest tasks.

    Args:
        tasks: Dictionary mapping instance_id to SecbTask
        n_partitions: Number of partitions to create

    Returns:
        List of N lists, each containing instance_ids for that partition
    """
    from collections import defaultdict

    # Group tasks by project_name
    project_to_tasks: Dict[str, List[str]] = defaultdict(list)
    for instance_id, task in tasks.items():
        project_to_tasks[task.project_name].append(instance_id)

    # Sort projects by task count (descending) for greedy assignment
    sorted_projects = sorted(project_to_tasks.items(), key=lambda x: -len(x[1]))

    # Initialize partitions
    partitions: List[List[str]] = [[] for _ in range(n_partitions)]
    partition_sizes = [0] * n_partitions

    # Greedy assignment: assign each project to the partition with fewest tasks
    for project_name, task_ids in sorted_projects:
        # Find partition with minimum size
        min_idx = partition_sizes.index(min(partition_sizes))
        partitions[min_idx].extend(task_ids)
        partition_sizes[min_idx] += len(task_ids)

    return partitions


def print_partitioned_instance_ids(n_partitions: int = 3,
                                    dataset_path: str = "datasets/sec-bench/CVE-instances",
                                    exclude_blacklist: bool = True):
    """
    Load all tasks, partition them, and print each partition as a comma-separated
    string suitable for --instance-ids argument.

    Args:
        n_partitions: Number of partitions (default: 3)
        dataset_path: Path to SEC-bench dataset
        exclude_blacklist: Whether to exclude blacklisted tasks (default: True)
    """
    loader = RawSecbTaskLoader(dataset_path=dataset_path)
    # 
    # Load all tasks. We can customize loading here if needed.
    # 
    all_tasks = loader.load_cve_tasks()

    # Optionally filter out blacklisted tasks
    if exclude_blacklist:
        filtered_tasks = {k: v for k, v in all_tasks.items()
                         if not loader.is_labelled_blacklist(k)}
    else:
        filtered_tasks = all_tasks

    print(f"\nTotal tasks: {len(filtered_tasks)} (from {len(all_tasks)} loaded)")
    print(f"Partitioning into {n_partitions} groups...\n")

    partitions = partition_tasks_by_repo(filtered_tasks, n_partitions)

    # Print summary and instance_ids for each partition
    for i, partition in enumerate(partitions):
        # Group by project for summary
        projects = {}
        for instance_id in partition:
            proj = instance_id.split('.')[0]
            projects[proj] = projects.get(proj, 0) + 1

        print(f"=== Partition {i+1} ({len(partition)} tasks) ===")
        print(f"Projects: {dict(sorted(projects.items()))}")
        print(f"--instance-ids \"{','.join(sorted(partition))}\"")
        print()


if __name__ == "__main__":
    # Allow specifying number of partitions as command line argument
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    print_partitioned_instance_ids(n_partitions=n)
    