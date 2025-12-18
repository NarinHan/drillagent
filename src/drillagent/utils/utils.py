import os
import subprocess
import logging
from pathlib import Path
from typing import Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from drillagent.task_loader.sec_bench import SecbTask

def get_file_size(file_path: str) -> int:
    # Get the size of a file in bytes.
    return os.path.getsize(file_path)

def get_repo_commit(repo_path: Path, logger: logging.Logger = None) -> Optional[str]:
    """Get the current commit SHA of a git repository
    
    Args:
        repo_path: Path to the git repository
        logger: Logger instance (optional)
    
    Returns:
        40-character commit SHA if successful, None otherwise
    """
    if logger is None:
        logger = logging.getLogger(__name__)
    
    try:
        result = subprocess.run(
            ['git', 'rev-parse', 'HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            commit = result.stdout.strip()
            if len(commit) == 40:  # Valid SHA
                return commit
            else:
                logger.warning(f"Invalid commit SHA: {commit}")
                return None
        else:
            logger.warning(f"git rev-parse failed: {result.stderr}")
            return None
            
    except Exception as e:
        logger.warning(f"Failed to get repo commit: {e}")
        return None

def check_repo_at_commit(
    repo_path: Path,
    expected_commit: str,
    logger: logging.Logger = None
) -> bool:
    """Check if a repository is at the expected commit
    
    Args:
        repo_path: Path to the git repository
        expected_commit: Expected 40-character commit SHA
        logger: Logger instance (optional)
    
    Returns:
        True if repo is at expected commit, False otherwise
    """
    if logger is None:
        logger = logging.getLogger(__name__)
    
    current_commit = get_repo_commit(repo_path, logger)
    
    if not current_commit:
        logger.warning("Could not determine current commit")
        return False
    
    if current_commit == expected_commit:
        logger.debug(f"Repo at expected commit: {current_commit[:12]}...")
        return True
    else:
        logger.debug(f"Commit mismatch: current={current_commit[:12]}..., expected={expected_commit[:12]}...")
        return False

def check_coverage_binary_exists(
    target_repo_path: Path,
    secb_task: "SecbTask" = None,
    logger: logging.Logger = None
) -> Optional[Path]:
    """High-level function to check if coverage-instrumented binary exists for a CVE
    
    This function uses SecbTask data to check for existing instrumented binary.
    
    Args:
        target_repo_path: Path to the target repository
        secb_task: SecbTask instance with binary_name, binary_path, project_name
        logger: Logger instance (optional)
    
    Returns:
        Path to instrumented binary if found, None otherwise
    """
    if logger is None:
        logger = logging.getLogger(__name__)
    
    if not secb_task:
        logger.debug("No SecbTask provided, cannot check for existing binary")
        return None
    
    try:
        return check_existing_coverage_instrumentation(
            target_repo=Path(target_repo_path),
            binary_name=secb_task.binary_name,
            binary_path=secb_task.binary_path,
            project_name=secb_task.project_name,
            logger=logger
        )
    except Exception as e:
        logger.warning(f"Failed to check existing instrumentation: {e}")
        return None

def check_existing_coverage_instrumentation(
    target_repo: Path,
    binary_name: str,
    binary_path: str,
    project_name: str,
    logger: logging.Logger = None
) -> Optional[Path]:
    """Check if the repository has already been successfully instrumented with coverage
    
    Args:
        target_repo: Path to the target repository
        binary_name: Name of the binary (e.g., 'njs')
        binary_path: Path to binary from secb_sh (e.g., '/src/njs/build/njs')
        project_name: Name of the project
        logger: Logger instance (optional)
    
    Returns:
        Path to instrumented binary if found, None otherwise
    """
    if logger is None:
        logger = logging.getLogger(__name__)
    
    # Try to locate the binary first
    binary = locate_instrumented_binary(target_repo, binary_name, binary_path, project_name, logger)
    
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
    binary_name: str,
    binary_path: str,
    project_name: str,
    logger: logging.Logger
) -> Optional[Path]:
    """Locate the instrumented binary after build
    
    Args:
        target_repo: Path to the target repository
        binary_name: Name of the binary (e.g., 'njs')
        binary_path: Path to binary from secb_sh (e.g., '/src/njs/build/njs')
        project_name: Name of the project
        logger: Logger instance
    
    Returns:
        Path to binary if found, None otherwise
    """
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
            if _is_libtool_wrapper(full_path):
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
                if 'build' in str(exe).lower() and not _is_libtool_wrapper(exe):
                    logger.debug(f"Found binary at: {exe}")
                    return exe
            
            # If all are wrappers, try .libs version
            for exe in executables:
                if _is_libtool_wrapper(exe):
                    libs_binary = exe.parent / '.libs' / exe.name
                    if libs_binary.exists() and os.access(libs_binary, os.X_OK):
                        logger.debug(f"Found actual binary (libtool): {libs_binary}")
                        return libs_binary
            
            logger.debug(f"Found binary at: {executables[0]}")
            return executables[0]
    
    logger.debug(f"Could not locate binary: {binary_name}")
    return None

def _is_libtool_wrapper(path: Path) -> bool:
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

class BaseUtils:
    # General utility functions for the project
    pass