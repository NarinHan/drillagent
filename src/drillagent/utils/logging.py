#!/usr/bin/env python3
"""
LLM interaction logging utilities for DrillAgent.

This module provides functions to log all LLM interactions to a JSON-formatted
file for debugging and analysis purposes.
"""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime


def init_llm_history_log(output_dir: str) -> None:
    """
    Initialize (clear) the LLM history log file.

    This should be called once at DrillAgent initialization to clear any previous
    log content and start fresh.

    Args:
        output_dir: Directory where llm_history.json will be stored
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    log_file = output_path / "llm_history.json"

    # Clear the file and write initial structure
    with open(log_file, 'w', encoding='utf-8') as f:
        initial_log = {
            "llm_history_version": "1.0",
            "initialized_at": datetime.now().isoformat(),
            "interactions": []
        }
        f.write(json.dumps(initial_log, indent=2, ensure_ascii=False) + "\n")


def log_phase_separator(output_dir: str, phase_name: str) -> None:
    """
    Log a phase separator to mark transitions between major DrillAgent phases.

    Args:
        output_dir: Directory where llm_history.json is stored
        phase_name: Name of the phase (e.g., "VulnerabilityAnalysis", "PathExploration")
    """
    log_file = Path(output_dir) / "llm_history.json"

    if not log_file.exists():
        # If log file doesn't exist, initialize it first
        init_llm_history_log(output_dir)

    # Read existing content
    with open(log_file, 'r', encoding='utf-8') as f:
        log_data = json.load(f)

    # Add phase separator
    separator_entry = {
        "type": "phase_separator",
        "phase_name": phase_name,
        "timestamp": datetime.now().isoformat()
    }
    log_data["interactions"].append(separator_entry)

    # Write back
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(json.dumps(log_data, indent=2, ensure_ascii=False) + "\n")


def log_llm_interaction(
    output_dir: str,
    interaction_data: Dict[str, Any]
) -> None:
    """
    Log a single LLM interaction to llm_history.json.

    This function appends the interaction data to the JSON log file in a structured format.

    Args:
        output_dir: Directory where llm_history.json is stored
        interaction_data: Dictionary containing interaction details with keys:
            - provider: str (e.g., "claude", "openai")
            - model_name: str
            - system_prompt: Optional[str]
            - user_prompt: str
            - assistant_response: str (text response from LLM)
            - tool_calls: List[Dict] (tool calls made by LLM)
            - tool_results: Optional[List[Any]] (results from tool execution)
            - stop_reason: str
            - usage_stats: Optional[Dict] (token usage information)
    """
    log_file = Path(output_dir) / "llm_history.json"

    if not log_file.exists():
        # If log file doesn't exist, initialize it first
        init_llm_history_log(output_dir)

    # Read existing content
    with open(log_file, 'r', encoding='utf-8') as f:
        log_data = json.load(f)

    # Create interaction entry
    interaction_entry = {
        "type": "llm_interaction",
        "timestamp": datetime.now().isoformat(),
        "provider": interaction_data.get("provider", "unknown"),
        "model_name": interaction_data.get("model_name", "unknown"),
        "system_prompt": interaction_data.get("system_prompt"),
        "user_prompt": interaction_data.get("user_prompt", ""),
        "assistant_response": interaction_data.get("assistant_response", ""),
        "tool_calls": interaction_data.get("tool_calls", []),
        "tool_results": interaction_data.get("tool_results"),
        "stop_reason": interaction_data.get("stop_reason", "unknown"),
        "usage_stats": interaction_data.get("usage_stats")
    }

    # Append to interactions list
    log_data["interactions"].append(interaction_entry)

    # Write back to file
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(json.dumps(log_data, indent=2, ensure_ascii=False) + "\n")


def log_tool_results(output_dir: str, tool_results: List[Any]) -> None:
    """
    Update the last LLM interaction with tool execution results.

    This should be called after tools are executed to append their results
    to the most recent llm_interaction entry.

    Args:
        output_dir: Directory where llm_history.json is stored
        tool_results: List of tool execution results
    """
    log_file = Path(output_dir) / "llm_history.json"

    if not log_file.exists():
        return  # Nothing to update

    # Read existing content
    with open(log_file, 'r', encoding='utf-8') as f:
        log_data = json.load(f)

    # Find the last llm_interaction entry and update it
    interactions = log_data.get("interactions", [])
    for i in range(len(interactions) - 1, -1, -1):
        if interactions[i].get("type") == "llm_interaction":
            interactions[i]["tool_results"] = tool_results
            break

    # Write back
    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(json.dumps(log_data, indent=2, ensure_ascii=False) + "\n")


def log_agent_loop_start(
    output_dir: str,
    task: str,
    system_prompt: Optional[str],
    provider: str,
    model_name: str
) -> None:
    """
    Log the start of an agent loop (run_agent_loop).

    Args:
        output_dir: Directory where llm_history.json is stored
        task: The task description for the agent
        system_prompt: Optional system prompt
        provider: LLM provider
        model_name: LLM model name
    """
    log_file = Path(output_dir) / "llm_history.json"

    if not log_file.exists():
        init_llm_history_log(output_dir)

    with open(log_file, 'r', encoding='utf-8') as f:
        log_data = json.load(f)

    agent_loop_entry = {
        "type": "agent_loop_start",
        "timestamp": datetime.now().isoformat(),
        "provider": provider,
        "model_name": model_name,
        "task": task,
        "system_prompt": system_prompt
    }

    log_data["interactions"].append(agent_loop_entry)

    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(json.dumps(log_data, indent=2, ensure_ascii=False) + "\n")


def log_agent_loop_end(
    output_dir: str,
    success: bool,
    final_response: str,
    iterations: int,
    stop_reason: str,
    error: Optional[str] = None
) -> None:
    """
    Log the end of an agent loop.

    Args:
        output_dir: Directory where llm_history.json is stored
        success: Whether the agent loop succeeded
        final_response: Final response from the agent
        iterations: Number of iterations used
        stop_reason: Why the agent stopped
        error: Optional error message
    """
    log_file = Path(output_dir) / "llm_history.json"

    if not log_file.exists():
        init_llm_history_log(output_dir)

    with open(log_file, 'r', encoding='utf-8') as f:
        log_data = json.load(f)

    agent_loop_entry = {
        "type": "agent_loop_end",
        "timestamp": datetime.now().isoformat(),
        "success": success,
        "final_response": final_response,
        "iterations": iterations,
        "stop_reason": stop_reason,
        "error": error
    }

    log_data["interactions"].append(agent_loop_entry)

    with open(log_file, 'w', encoding='utf-8') as f:
        f.write(json.dumps(log_data, indent=2, ensure_ascii=False) + "\n")


def setup_drillagent_logger(
    output_dir: str,
    target_repo_path: str,
    cve_id: Optional[str] = None,
    verbose: bool = False
) -> logging.Logger:
    """
    Setup logging for DrillAgent.

    Args:
        output_dir: Output directory for logs
        target_repo_path: Path to the target repository (used for log filename)
        cve_id: CVE identifier (used for log filename)
        verbose: If True, set logger level to DEBUG

    Returns:
        Configured logger instance
    """
    # Determine log directory and filename
    if output_dir == str(Path("./output").resolve()):
        # User didn't set custom output_dir, use DrillAgent/logs
        # Find project root by going up from this file's location
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent  # Go up to DrillAgent root
        log_dir = project_root / "logs"
    else:
        # User set custom output_dir, use it
        log_dir = Path(output_dir)

    log_dir.mkdir(parents=True, exist_ok=True)

    # Generate log filename with repo name and CVE ID
    repo_name = Path(target_repo_path).name if target_repo_path else "unknown"
    cve_id_str = cve_id.lower() if cve_id else "no-cve"
    log_filename = f"drillagent_{repo_name}_{cve_id_str}.log"
    log_path = log_dir / log_filename

    # Clean the log file if it already exists
    if log_path.exists():
        log_path.unlink()

    # Also ensure output_dir exists for other files
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Configure root logger to INFO to avoid debug spam from third-party libs
    logging.basicConfig(
        level=logging.DEBUG,  # for root logger
        format='[%(asctime)s] %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(str(log_path), mode='w')  # Use 'w' mode to overwrite
        ]
    )

    # Get DrillAgent logger and set its level based on verbose flag
    logger = logging.getLogger("DrillAgent")
    if verbose:
        logger.setLevel(logging.DEBUG)

    # Suppress debug logs from noisy third-party libraries
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)

    return logger
