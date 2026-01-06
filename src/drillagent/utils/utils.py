import os
import yaml
import resource
import subprocess
import logging
from pathlib import Path
from typing import Optional

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
        print(f"Target binary does not exist: {binary_path}")
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
        print(f"Target binary does not exist: {binary_path}")
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

def set_memory_limit(): # For subprocesses.run
    """Set memory limit to 12GB for the subprocess to prevent memory leaks"""
    max_memory_bytes = 12 * 1024 * 1024 * 1024  # 12GB in bytes
    # RLIMIT_AS limits the address space (total virtual memory)
    resource.setrlimit(resource.RLIMIT_AS, (max_memory_bytes, max_memory_bytes))

# 
# Old instrumented binary check functions (legacy)
# 
def check_coverage_binary_exists(
    target_repo_path: Path,
    cve_id: str,
    logger: logging.Logger = None
) -> Optional[Path]:
    """High-level function to check if coverage-instrumented binary exists for a CVE
    
    This function handles loading the instrumentation config and checking for existing binary.
    
    Args:
        target_repo_path: Path to the target repository
        cve_id: CVE ID (e.g., 'CVE-2022-43284')
        logger: Logger instance (optional)
    
    Returns:
        Path to instrumented binary if found, None otherwise
    """
    if logger is None:
        logger = logging.getLogger(__name__)
    
    try:
        # Load instrumentation config
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent.parent  # Go up from src/drillagent/utils/utils.py to DrillAgent root
        config_dir = project_root / 'datasets' / 'sec-bench' / 'instrumentation_configs'
        cve_pattern = f"*.{cve_id.lower()}.yaml"
        matches = list(config_dir.glob(cve_pattern))
        
        if not matches:
            logger.debug(f"No instrumentation config found for {cve_id}")
            return None
        
        config_path = matches[0]
        with open(config_path, 'r') as f:
            instr_config = yaml.safe_load(f)
        
        # Extract project name from repo_url
        repo_url = instr_config.get('repo_url', '')
        if repo_url:
            project_name = repo_url.rstrip('/').rstrip('.git').split('/')[-1]
        else:
            # Fallback to extracting from target_repo_path
            project_name = target_repo_path.name
        
        # Check for existing instrumentation
        return check_existing_coverage_instrumentation(
            target_repo=Path(target_repo_path),
            instr_config=instr_config,
            project_name=project_name,
            logger=logger
        )
    except Exception as e:
        logger.warning(f"Failed to check existing instrumentation: {e}")
        return None

def check_existing_coverage_instrumentation(
    target_repo: Path,
    instr_config: dict,
    project_name: str,
    logger: logging.Logger = None
) -> Optional[Path]:
    """Check if the repository has already been successfully instrumented with coverage
    
    Args:
        target_repo: Path to the target repository
        instr_config: Instrumentation configuration dictionary
        project_name: Name of the project
        logger: Logger instance (optional)
    
    Returns:
        Path to instrumented binary if found, None otherwise
    """
    if logger is None:
        logger = logging.getLogger(__name__)
    
    # Try to locate the binary first
    binary = locate_instrumented_binary(target_repo, instr_config, project_name, logger)
    
    if not binary or not binary.exists():
        logger.info("  No existing binary found")
        return None
    
    # Check if binary has LLVM coverage symbols
    try:
        logger.info(f"  Checking existing binary: {binary}")
        result = subprocess.run(
            f'strings "{binary}" | grep -q "__llvm_profile"',
            shell=True,
            timeout=10
        )
        
        if result.returncode == 0:
            logger.info(f"  ✓ Found instrumented binary with LLVM coverage symbols")
            return binary
        else:
            logger.info(f"  Binary exists but has no LLVM coverage symbols")
            return None
            
    except Exception as e:
        logger.warning(f"  Failed to check existing binary: {e}")
        return None

def locate_instrumented_binary(
    target_repo: Path,
    instr_config: dict,
    project_name: str,
    logger: logging.Logger
) -> Optional[Path]:
    """Locate the instrumented binary after build using config
    
    Args:
        target_repo: Path to the target repository
        instr_config: Instrumentation configuration dictionary
        project_name: Name of the project
        logger: Logger instance
    
    Returns:
        Path to binary if found, None otherwise
    """
    binary_name = instr_config.get('binary_name', '')
    binary_path = instr_config.get('binary_path', '')
    
    if binary_path:
        # binary_path may be Docker path like "/src/njs/build/njs"
        # Try multiple path variations:
        # 1. Strip Docker prefix and use relative to repo root
        # 2. Use just the relative part after project name
        
        # Remove leading slash and common Docker prefixes
        rel_path = binary_path.lstrip('/')
        
        # Try stripping /src/ prefix
        if rel_path.startswith('src/'):
            rel_path = rel_path[4:]
        
        # If path contains project name, try using part after it
        parts = Path(rel_path).parts
        if project_name in parts:
            idx = parts.index(project_name)
            rel_path = str(Path(*parts[idx+1:])) if idx + 1 < len(parts) else rel_path
        
        full_path = target_repo / rel_path
        
        if full_path.exists() and os.access(full_path, os.X_OK):
            # Check if it's a libtool wrapper script
            if is_libtool_wrapper(full_path):
                # Try to find actual binary in .libs directory
                libs_binary = full_path.parent / '.libs' / full_path.name
                if libs_binary.exists() and os.access(libs_binary, os.X_OK):
                    logger.debug(f"Found actual binary (libtool): {libs_binary}")
                    return libs_binary
            
            logger.debug(f"Found binary at: {full_path}")
            return full_path
    
    # Fallback: search by binary name
    if binary_name:
        candidates = list(target_repo.rglob(binary_name))
        executables = [c for c in candidates if os.access(c, os.X_OK)]
        
        if executables:
            # Prefer binaries in build directories, and actual binaries over wrappers
            for exe in executables:
                if 'build' in str(exe).lower() and not is_libtool_wrapper(exe):
                    logger.debug(f"Found binary at: {exe}")
                    return exe
            
            # If all are wrappers, try .libs version
            for exe in executables:
                if is_libtool_wrapper(exe):
                    libs_binary = exe.parent / '.libs' / exe.name
                    if libs_binary.exists() and os.access(libs_binary, os.X_OK):
                        logger.debug(f"Found actual binary (libtool): {libs_binary}")
                        return libs_binary
            
            logger.debug(f"Found binary at: {executables[0]}")
            return executables[0]
    
    logger.debug(f"Could not locate binary: {binary_name}")
    return None

def is_libtool_wrapper(path: Path) -> bool:
    """Check if a file is a libtool wrapper script

    Args:
        path: Path to check

    Returns:
        True if it's a libtool wrapper, False otherwise
    """
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            first_lines = f.read(200)
            return 'libtool' in first_lines.lower() and 'wrapper' in first_lines.lower()
    except:
        return False
