#!/usr/bin/env python3
"""
LLM-Driven AFLGo Config Generator

This module provides the ConfigGeneratorAgent class for intelligently generating 
AFLGo configuration files from SEC-bench CVE instance data using an LLM.

The agent analyzes CVE metadata, build scripts, and repository structure to create 
optimal AFLGo instrumentation configurations.
"""

import os
import sys
import json
import yaml
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

# Load .env file before anything else
try:
    from dotenv import load_dotenv
    # Try multiple locations for .env file
    project_root = Path(__file__).resolve().parent.parent.parent
    env_paths = [
        project_root / '.env',
        project_root.parent / '.env',  # One level up from src
        Path.cwd() / '.env',
    ]
    for env_path in env_paths:
        if env_path.exists():
            load_dotenv(env_path)
            break
    else:
        load_dotenv()  # Try default search
except ImportError:
    pass  # python-dotenv not installed

# Import DrillAgent's LLM interface and task loader
from drillagent.models.llm import LLM
from drillagent.task_loader.sec_bench import RawSecbTaskLoader


class ConfigGeneratorAgent:
    """LLM-driven AFLGo configuration generator"""
    
    SYSTEM_PROMPT = """You are an expert in directed fuzzing and AFLGo configuration.
Your task is to generate YAML configuration files for AFLGo instrumentation based on 
CVE instance data from SEC-bench.

**Your goal:** Create a valid YAML config file that follows this template:

```yaml
# AFLGo Configuration for <project> <CVE-ID>
# Brief description of the vulnerability

# Repository information
repo_url: "https://github.com/<owner>/<repo>.git"
commit_id: "<base_commit_hash>"  # The vulnerable version to instrument
cve_id: "<CVE-YYYY-NNNNN>"

# Directory paths (relative to workspace root or absolute)
repos_dir: "repos"           # or absolute path
temps_dir: "fuzzing/temps"   # or absolute path

# Binary name (target executable to fuzz)
binary_name: "<executable_name>"
binary_path: "<full_path_to_binary>"  # Full path from secb_sh

# Sanitizer report for target extraction
sanitizer_report: "<sanitizer_report_content>"

# Build configuration
build_config:
  # Exact build commands from SEC-bench build_sh field
  build_commands: |
    <exact build script from SEC-bench build_sh field>

# Logging
log_level: "INFO"
log_file: "aflgo_<project>.log"
```

**CRITICAL INSTRUCTIONS:**

1. **commit_id**: Use the base_commit from the CVE instance data.
   - base_commit is the VULNERABLE version that we want to instrument
   - AFLGo will instrument this version directly for directed fuzzing
   - Do NOT try to find or use the patch commit

2. **binary_name and binary_path**: Extract from secb_sh repro command.
   - binary_name: just the executable name (e.g., "exiv2")
   - binary_path: full path to the binary (e.g., "/src/exiv2/build/bin/exiv2")

3. **sanitizer_report**: Copy the EXACT content from the sanitizer_report field.
   - This contains the stack trace used for target extraction
   - Include it verbatim as a multi-line YAML string
   
4. **build_commands**: Use the EXACT content from the build_sh field.
   - Do NOT modify or analyze it
   - Copy it verbatim into the build_config.build_commands field
   - This is the complete build script that will be executed

5. **Response format**: Return ONLY valid YAML, no markdown code blocks, no explanations.
   Start directly with the comment line.

6. **Validation**: Ensure all required fields are present and values are reasonable.
"""
    
    def __init__(self, 
                 llm_provider: str = "openai",
                 llm_model: str = "gpt-4-turbo",
                 api_key: Optional[str] = None,
                 secbench_dir: Path = None):
        
        # Initialize DrillAgent LLM interface
        self.llm = LLM(provider=llm_provider, model_name=llm_model, api_key=api_key)
        
        # Default to relative path from project root
        if secbench_dir is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            self.secbench_dir = project_root / 'datasets' / 'sec-bench'
        else:
            self.secbench_dir = secbench_dir
        self.instances_dir = self.secbench_dir / 'CVE-instances'
        
        # Initialize task loader
        self.task_loader = RawSecbTaskLoader(dataset_path=str(self.instances_dir))
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def extract_binary_name(self, instance_id: str) -> tuple[str, str]:
        """Extract binary name and path from secb_sh repro script
        
        Returns:
            tuple: (binary_name, binary_path) e.g., ('exiv2', '/src/exiv2/build/bin/exiv2')
        """
        # Get secb_sh from task loader
        secb_sh = self.task_loader.get_secb_sh(instance_id)
        
        if not secb_sh:
            raise ValueError(f"No secb_sh field found for {instance_id}")
        
        # Look for repro() function execution paths like /src/faad2/frontend/faad
        # Pattern: /src/<project>/...path.../binary_name followed by space, arg, or end of line
        # Need to handle paths that may have multiple directory levels (build/bin/, frontend/, .libs/, etc.)
        match = re.search(r'(/src/[^/]+/(?:[^/\s]+/)*(?:frontend/|build/bin/|build/|bin/|\.libs/)?([a-zA-Z0-9_-]+))(?:\s|$)', secb_sh)
        if match:
            full_path = match.group(1)
            binary = match.group(2)
            # Skip common directory names
            if binary not in ['bin', 'build', 'frontend', 'libs', 'src']:
                return binary, full_path
        
        raise ValueError(f"Could not extract binary name from secb_sh for {instance_id}")
    
    def generate_config_with_llm(self, instance_id: str) -> str:
        """Generate config using LLM"""
        # Get task data from loader
        task = self.task_loader.get_task(instance_id)
        if not task:
            raise ValueError(f"Task {instance_id} not found")
        
        # Use base_commit (vulnerable version)
        commit_id = self.task_loader.get_base_commit(instance_id)
        build_sh = self.task_loader.get_build_sh(instance_id)
        secb_sh = self.task_loader.get_secb_sh(instance_id)
        
        # Extract binary name and path
        binary_name, binary_path = self.extract_binary_name(instance_id)
        
        # Build context for LLM
        prompt = f"""Generate an AFLGo YAML configuration file for this CVE instance:

**CVE Instance Data:**
- instance_id: {instance_id}
- repo: {task.get('repo', 'N/A')}
- project_name: {task.get('project_name', 'N/A')}
- base_commit: {commit_id}

**Build Script (from SEC-bench build_sh field):**
```bash
{build_sh}
```

**CRITICAL: Copy the EXACT build script above into build_config.build_commands field verbatim.**
**Do NOT analyze or modify it - use it exactly as provided.**

**Reproduction Script (secb_sh - for binary name detection):**
```bash
{secb_sh[:500] if secb_sh else 'No repro script'}
```

**Extracted binary information:**
- binary_name: {binary_name}
- binary_path: {binary_path}

**Task:**
Generate a complete YAML configuration following the template in your instructions.

IMPORTANT: 
- For commit_id, use the base_commit: {commit_id}
- This is the VULNERABLE version that we want to instrument
- For build_config.build_commands, use the EXACT build_sh content above (no analysis, no extraction)
- For binary_name, use: {binary_name}
- For binary_path, use: {binary_path}
- Include all required fields
- Return ONLY valid YAML with no markdown formatting
"""
        
        # Use DrillAgent's LLM interface
        response = self.llm.generate(
            prompt=prompt,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.3,  # Lower temperature for more consistent configs
            max_tokens=2048
        )
        
        # Clean up response (remove markdown if present)
        response = response.strip()
        if response.startswith('```yaml'):
            response = response[7:]
        if response.startswith('```'):
            response = response[3:]
        if response.endswith('```'):
            response = response[:-3]
        
        return response.strip()
    
    def generate_config(self, instance_path: Path, output_path: Optional[Path] = None) -> str:
        """Generate config for a CVE instance"""
        # Extract instance_id from path
        instance_id = instance_path.stem
        
        self.logger.info(f"Generating config for {instance_id}")
        
        # Load task if not already loaded
        if instance_id not in self.task_loader.cve_tasks:
            self.task_loader.instance_ids = [instance_id]
            self.task_loader.load_cve_tasks()
        
        # Generate config with LLM
        config_yaml = self.generate_config_with_llm(instance_id)
        
        # Validate YAML
        try:
            config_dict = yaml.safe_load(config_yaml)
        except yaml.YAMLError as e:
            self.logger.error(f"Generated invalid YAML: {e}")
            raise ValueError(f"LLM generated invalid YAML: {e}")
        
        # Add sanitizer_report directly (hardcoded, not from LLM)
        sanitizer_report = self.task_loader.get_sanitizer_report(instance_id)
        if sanitizer_report:
            config_dict['sanitizer_report'] = sanitizer_report
        
        # Convert back to YAML
        config_yaml = yaml.dump(config_dict, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        # Save if output path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(config_yaml)
            self.logger.info(f"Config saved to {output_path}")
        
        return config_yaml
    
    def generate_batch(self, output_dir: Path, filter_pattern: Optional[str] = None):
        """Generate configs for all CVE instances"""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load all tasks using task loader
        self.task_loader.load_cve_tasks()
        instance_ids = self.task_loader.get_all_instance_ids()
        
        # Apply filter if provided
        if filter_pattern:
            instance_ids = [iid for iid in instance_ids if filter_pattern in iid]
        
        self.logger.info(f"Generating configs for {len(instance_ids)} CVE instances")
        
        for instance_id in instance_ids:
            # Generate output filename
            output_name = instance_id + '.yaml'
            output_path = output_dir / output_name
            
            # Skip if already exists (optional)
            if output_path.exists():
                self.logger.info(f"Skipping {instance_id} - config already exists")
                continue
            
            try:
                # Create a fake path for compatibility with generate_config
                instance_path = self.instances_dir / f"{instance_id}.json"
                self.generate_config(instance_path, output_path)
            except Exception as e:
                self.logger.error(f"Error generating config for {instance_id}: {e}")
                continue
        
        self.logger.info("Batch generation complete!")
