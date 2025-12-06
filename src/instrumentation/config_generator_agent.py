#!/usr/bin/env python3
"""
LLM-Driven AFLGo Config Generator

This agent uses an LLM to intelligently generate AFLGo configuration files
from SEC-bench CVE instance data. It analyzes the CVE metadata, patch information,
build scripts, and repository structure to create optimal configs.

Usage:
    ./config_generator_agent.py --cve-instance SEC-bench-data/CVE-instances/jq.cve-2023-50246.json
    ./config_generator_agent.py --cve-id jq.cve-2023-50246
    ./config_generator_agent.py --batch --output-dir fuzzing/configs
"""

import os
import sys
import json
import yaml
import argparse
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

# Import DrillAgent's LLM interface
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from drillagent.models.llm import LLM


@dataclass
class CVEInstance:
    """Parsed CVE instance data"""
    instance_id: str
    repo: str
    project_name: str
    base_commit: str
    build_sh: str
    sanitizer_report: Optional[str]
    bug_description: Optional[str]
    secb_sh: Optional[str] = None
    
    @classmethod
    def from_json(cls, data: Dict) -> 'CVEInstance':
        """Create CVEInstance from JSON data"""
        return cls(
            instance_id=data['instance_id'],
            repo=data['repo'],
            project_name=data['project_name'],
            base_commit=data['base_commit'],
            build_sh=data.get('build_sh', ''),
            sanitizer_report=data.get('sanitizer_report'),
            bug_description=data.get('bug_description'),
            secb_sh=data.get('secb_sh')
        )


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
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def load_cve_instance(self, instance_path: Path) -> CVEInstance:
        """Load a CVE instance from JSON file"""
        with open(instance_path) as f:
            data = json.load(f)
        return CVEInstance.from_json(data)
    
    def extract_binary_name(self, cve: CVEInstance) -> tuple[str, str]:
        """Extract binary name and path from secb_sh repro script
        
        Returns:
            tuple: (binary_name, binary_path) e.g., ('exiv2', '/src/exiv2/build/bin/exiv2')
        """
        
        if not cve.secb_sh:
            raise ValueError(f"No secb_sh field found for {cve.instance_id}")
        
        # Look for repro() function execution paths like /src/faad2/frontend/faad
        # Pattern: /src/<project>/...path.../binary_name followed by space, arg, or end of line
        # Need to handle paths that may have multiple directory levels (build/bin/, frontend/, .libs/, etc.)
        match = re.search(r'(/src/[^/]+/(?:[^/\s]+/)*(?:frontend/|build/bin/|build/|bin/|\.libs/)?([a-zA-Z0-9_-]+))(?:\s|$)', cve.secb_sh)
        if match:
            full_path = match.group(1)
            binary = match.group(2)
            # Skip common directory names
            if binary not in ['bin', 'build', 'frontend', 'libs', 'src']:
                return binary, full_path
        
        raise ValueError(f"Could not extract binary name from secb_sh for {cve.instance_id}")
    
    def generate_config_with_llm(self, cve: CVEInstance) -> str:
        """Generate config using LLM"""
        # Use base_commit (vulnerable version)
        commit_id = cve.base_commit
        
        # Extract binary name and path
        binary_name, binary_path = self.extract_binary_name(cve)
        
        # Build context for LLM
        prompt = f"""Generate an AFLGo YAML configuration file for this CVE instance:

**CVE Instance Data:**
- instance_id: {cve.instance_id}
- repo: {cve.repo}
- project_name: {cve.project_name}
- base_commit: {cve.base_commit}

**Build Script (from SEC-bench build_sh field):**
```bash
{cve.build_sh}
```

**CRITICAL: Copy the EXACT build script above into build_config.build_commands field verbatim.**
**Do NOT analyze or modify it - use it exactly as provided.**

**Reproduction Script (secb_sh - for binary name detection):**
```bash
{cve.secb_sh[:500] if cve.secb_sh else 'No repro script'}
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
        self.logger.info(f"Generating config for {instance_path.name}")
        
        # Load CVE instance
        cve = self.load_cve_instance(instance_path)
        
        # Generate config with LLM
        config_yaml = self.generate_config_with_llm(cve)
        
        # Validate YAML
        try:
            config_dict = yaml.safe_load(config_yaml)
        except yaml.YAMLError as e:
            self.logger.error(f"Generated invalid YAML: {e}")
            raise ValueError(f"LLM generated invalid YAML: {e}")
        
        # Add sanitizer_report directly (hardcoded, not from LLM)
        if cve.sanitizer_report:
            config_dict['sanitizer_report'] = cve.sanitizer_report
        
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
        
        # Get all instance files
        instance_files = sorted(self.instances_dir.glob('*.json'))
        
        if filter_pattern:
            instance_files = [f for f in instance_files if filter_pattern in f.name]
        
        self.logger.info(f"Generating configs for {len(instance_files)} CVE instances")
        
        for instance_file in instance_files:
            # Generate output filename
            output_name = instance_file.stem + '.yaml'
            output_path = output_dir / output_name
            
            # Skip if already exists (optional)
            if output_path.exists():
                self.logger.info(f"Skipping {instance_file.name} - config already exists")
                continue
            
            try:
                self.generate_config(instance_file, output_path)
            except Exception as e:
                self.logger.error(f"Error generating config for {instance_file.name}: {e}")
                continue
        
        self.logger.info("Batch generation complete!")


def main():
    parser = argparse.ArgumentParser(
        description='LLM-Driven AFLGo Config Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate config for a specific CVE instance
  ./config_generator_agent.py --cve-instance DrillAgent/datasets/sec-bench/CVE-instances/jq.cve-2023-50246.json
  
  # Generate config by CVE ID
  ./config_generator_agent.py --cve-id jq.cve-2023-50246
  
  # Generate all configs
  ./config_generator_agent.py --batch --output-dir fuzzing/configs
  
  # Generate configs for specific project
  ./config_generator_agent.py --batch --filter gpac --output-dir fuzzing/configs
"""
    )
    
    parser.add_argument('--cve-instance', type=Path,
                       help='Path to CVE instance JSON file')
    parser.add_argument('--cve-id', 
                       help='CVE instance ID (e.g., jq.cve-2023-50246)')
    parser.add_argument('--batch', action='store_true',
                       help='Generate configs for all CVE instances')
    parser.add_argument('--filter',
                       help='Filter pattern for batch generation (e.g., "gpac", "jq")')
    parser.add_argument('--output-dir', type=Path, default=Path('fuzzing/configs'),
                       help='Output directory for generated configs')
    parser.add_argument('--output', type=Path,
                       help='Output file path (for single config)')
    parser.add_argument('--secbench-dir', type=Path,
                       default=None,
                       help='Path to SEC-bench data directory (default: <project_root>/datasets/sec-bench)')
    parser.add_argument('--llm-provider', default='openai',
                       help='LLM provider to use: "openai" or "claude" (default: openai)')
    parser.add_argument('--llm-model', default='gpt-4-turbo',
                       help='LLM model to use (default: gpt-4-turbo for OpenAI, claude-3-7-sonnet-20250219 for Claude)')
    parser.add_argument('--api-key',
                       help='API key (or set OPENAI_API_KEY/ANTHROPIC_API_KEY env var)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.batch and not args.cve_instance and not args.cve_id:
        parser.error("Must specify --cve-instance, --cve-id, or --batch")
    
    # Create agent
    agent = ConfigGeneratorAgent(
        llm_provider=args.llm_provider,
        llm_model=args.llm_model,
        api_key=args.api_key,
        secbench_dir=args.secbench_dir
    )
    
    # Execute
    if args.batch:
        agent.generate_batch(args.output_dir, args.filter)
    else:
        # Determine instance path
        if args.cve_instance:
            instance_path = args.cve_instance
        else:
            instance_path = agent.instances_dir / f"{args.cve_id}.json"
            if not instance_path.exists():
                print(f"Error: CVE instance not found: {instance_path}")
                return 1
        
        # Determine output path
        if args.output:
            output_path = args.output
        else:
            output_name = instance_path.stem + '.yaml'
            output_path = args.output_dir / output_name
        
        # Generate
        config = agent.generate_config(instance_path, output_path)
        
        # Also print to stdout
        print("\n" + "="*60)
        print("Generated Configuration:")
        print("="*60)
        print(config)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
