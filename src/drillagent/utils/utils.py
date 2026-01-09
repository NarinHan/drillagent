import os
import resource
import subprocess
from pathlib import Path
from typing import Tuple

# 
# Basic file utility functions
# 
def get_file_size(file_path: str) -> int:
    # Get the size of a file in bytes.
    return os.path.getsize(file_path)

def is_text_file(file_path: str) -> bool:
    # Check if a file is a text file using the file command.
    # Returns True if the file is a text file, False otherwise
    try:
        result = subprocess.run(
            ['file', '--mime-type', file_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Output format: "filename: text/plain" or "filename: application/octet-stream"
            mime_type = result.stdout.strip().split(':', 1)[-1].strip()
            return mime_type.startswith('text/')
        return False
    except Exception:
        return False

def is_binary_file(file_path: str) -> bool:
    # Check if a file is an ELF binary file using the file command.
    # Returns True if the file is an ELF binary (executable or shared library), False otherwise
    try:
        result = subprocess.run(
            ['file', file_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Output format for ELF files: "filename: ELF 64-bit LSB executable, ..." or
            # "filename: ELF 64-bit LSB shared object, ..."
            file_type = result.stdout.strip()
            return 'ELF' in file_type
        return False
    except Exception:
        return False

def check_llvmcov_binary_exists(actual_repo_path: str, binary_relative_path: str) -> bool:
    # Check if a binary exists and contains LLVM coverage instrumentation
    # Returns True if binary exists and contains __llvm_profile symbols, False otherwise
    binary_path = Path(actual_repo_path) / binary_relative_path

    # Check if file exists
    if not binary_path.exists():
        # print(f"Target binary does not exist: {binary_path}")
        return False

    # Check if binary contains LLVM coverage symbols
    try:
        result = subprocess.run(
            f'strings "{binary_path}" | grep -q "__llvm_profile"',
            shell=True,
            timeout=10
        )
        # grep -q returns 0 if pattern found, 1 if not found
        if result.returncode == 0:
            return True
        else:
            print(f"Target binary does not contain \"__llvm_profile\" strings: {binary_path}")
            return False
    except Exception:
        return False

def check_saninstr_binary_exists(actual_repo_path: str, binary_relative_path: str) -> bool:
    # Returns True if binary exists and contains __sanitizer symbols, False otherwise
    binary_path = Path(actual_repo_path) / binary_relative_path

    # Check if file exists
    if not binary_path.exists():
        # print(f"Target binary does not exist: {binary_path}")
        return False

    # Check if binary contains LLVM coverage symbols
    try:
        result = subprocess.run(
            f'strings "{binary_path}" | grep -q "__sanitizer"',
            shell=True,
            timeout=10
        )
        # grep -q returns 0 if pattern found, 1 if not found
        if result.returncode == 0:
            return True
        else:
            print(f"Target binary does not contain \"__sanitizer\" strings: {binary_path}")
            return False
    except Exception:
        return False

def get_current_git_commit(actual_repo_path: str) -> str:
    # Get the current commit hash (full SHA) of the git repository at actual_repo_path
    try:
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            cwd=actual_repo_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        current_commit = result.stdout.strip()
        return current_commit
    except subprocess.CalledProcessError as e:
        print(f"Failed to get current git commit: {e}")
        return ""
    except Exception as e:
        print(f"Unexpected error getting current git commit: {e}")
        return ""

def compare_gitrepo_commit(actual_repo_path: str, base_commit: str) -> bool:
    # Check if the current commit in the repo matches the base_commit
    # Returns True if current commit equals base_commit, False otherwise
    try:
        # Get the current HEAD commit hash (full SHA)
        current_result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            cwd=actual_repo_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        current_commit = current_result.stdout.strip()

        # Resolve base_commit to full SHA (handles short hash, branch name, tag, etc.)
        base_result = subprocess.run(
            ['git', 'rev-parse', base_commit],
            cwd=actual_repo_path,
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        resolved_base_commit = base_result.stdout.strip()

        # Compare the two full SHA hashes
        matches = current_commit == resolved_base_commit
        if matches:
            print(f"Current commit matches base_commit: {current_commit[:12]}")
        else:
            print(f"Current commit {current_commit[:12]} != base_commit {resolved_base_commit[:12]}")

        return matches

    except subprocess.CalledProcessError as e:
        print(f"Failed to compare commits: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error comparing commits: {e}")
        return False

def checkout_gitrepo_commit(actual_repo_path: str, base_commit: str):
    # Checkout the target repository to the specified base commit
    result = subprocess.run(
        ['git', 'checkout', base_commit],
        cwd=actual_repo_path,
        capture_output=True,
        text=True,
        check=True
    )
    print(f"✓ Successfully checked out commit: {base_commit[:12]}...")
    # if result.stdout:
    #     print(f"Git checkout output: {result.stdout.strip()}")
    
    # Update git submodules
    # print("Updating git submodules...")
    result = subprocess.run(
        ['git', 'submodule', 'update', '--init', '--recursive'],
        cwd=actual_repo_path,
        capture_output=True,
        text=True,
        check=True
    )
    print("✓ Successfully updated git submodules")
    if result.stdout:
        print(f"Submodule output: {result.stdout.strip()}")

def clean_gitrepo(actual_repo_path: str):
    # Clean build artifacts (make clean or equivalent)
    clean_result = subprocess.run(
        ['make', 'clean'],
        cwd=actual_repo_path,
        capture_output=True,
        text=True,
        timeout=60
    )
    if clean_result.returncode == 0:
        print("✓ Build artifacts cleaned")
    else:
        print("make clean failed or not available (this is OK if no Makefile exists)")
    
    # Reset git repository state - discard all local changes
    # print("Resetting git repository state...")
    subprocess.run(
        ['git', 'reset', '--hard', 'HEAD'],
        cwd=actual_repo_path,
        capture_output=True,
        text=True,
        check=True
    )
    print("✓ Git repository reset to HEAD")
    
    # Clean untracked files and directories
    print("Cleaning untracked files...")
    subprocess.run(
        ['git', 'clean', '-fdx'], # If set -x, also removes files ignored by .gitignore!
        cwd=actual_repo_path,
        capture_output=True,
        text=True,
        check=True
    )

# 
# For later two sub-agents. 
# 
def set_memory_limit(): # For subprocesses.run
    """Set memory limit to 12GB for the subprocess to prevent memory leaks"""
    max_memory_bytes = 12 * 1024 * 1024 * 1024  # 12GB in bytes
    # RLIMIT_AS limits the address space (total virtual memory)
    resource.setrlimit(resource.RLIMIT_AS, (max_memory_bytes, max_memory_bytes))

def execute_command(command: str, env: dict = None) -> Tuple[int, str]:
    # Execute a shell command and return exit code and output (stdout + stderr)
    if env is None:
        env = os.environ.copy()
    try:
        result = subprocess.run(
            command,
            shell=True,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            # preexec_fn=set_memory_limit # When running sanitizer-instrumented binaries, memory limit may cause issues!
        )
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
        exec_output = f"[STDOUT]\n{stdout}\n[STDERR]\n{stderr}"
        return exit_code, exec_output
    except subprocess.TimeoutExpired:
        return -1, "[ERROR] Command execution timed out."
    except Exception as e:
        return -1, f"[ERROR] Command execution failed: {str(e)}"

def detect_sanitizer_triggered(exec_output: str) -> bool:
    # Detect if sanitizer errors are present in the execution output
    sanitizer_indicators = [
        "AddressSanitizer",
        "MemorySanitizer",
        "UndefinedBehaviorSanitizer",
        "ThreadSanitizer",
        "LeakSanitizer",
        "sanitizer: error",
        # ...
    ]
    for indicator in sanitizer_indicators:
        if indicator in exec_output:
            return True
    return False

def switch_ruby_version(version: str = "3.0.6") -> Tuple[bool, str]:
    # Switch the system Ruby version using rbenv and verify the change
    # Returns (success, message) tuple
    try:
        # Run rbenv global to switch Ruby version
        rbenv_result = subprocess.run(
            ['rbenv', 'global', version],
            capture_output=True,
            text=True,
            timeout=10
        )

        if rbenv_result.returncode != 0:
            error_msg = f"Failed to switch Ruby version: {rbenv_result.stderr.strip()}"
            return False, error_msg

        # Verify the Ruby version
        ruby_result = subprocess.run(
            ['ruby', '-v'],
            capture_output=True,
            text=True,
            timeout=10,
            env=os.environ.copy()
        )

        if ruby_result.returncode != 0:
            error_msg = f"Failed to verify Ruby version: {ruby_result.stderr.strip()}"
            return False, error_msg

        ruby_version_output = ruby_result.stdout.strip()
        success_msg = f"✓ Ruby version switched successfully\n{ruby_version_output}"
        return True, success_msg

    except FileNotFoundError as e:
        error_msg = f"Command not found: {str(e)}. Make sure rbenv and ruby are installed."
        return False, error_msg
    except subprocess.TimeoutExpired:
        error_msg = "Command execution timed out."
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        return False, error_msg
