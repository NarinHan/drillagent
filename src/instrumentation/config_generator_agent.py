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

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("Warning: openai package not installed. Install with: pip install openai")

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
except ImportError:
    DOTENV_AVAILABLE = False


@dataclass
class CVEInstance:
    """Parsed CVE instance data"""
    instance_id: str
    repo: str
    project_name: str
    lang: str
    base_commit: str
    build_sh: str
    patch: str
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
            lang=data.get('lang', 'c++'),
            base_commit=data['base_commit'],
            build_sh=data.get('build_sh', ''),
            patch=data.get('patch', ''),
            sanitizer_report=data.get('sanitizer_report'),
            bug_description=data.get('bug_description'),
            secb_sh=data.get('secb_sh')
        )


class LLMInterface:
    """Interface to LLM for config generation"""
    
    def __init__(self, model: str = "gpt-5.1", api_key: Optional[str] = None):
        self.model = model
        
        # Load .env file if available
        if DOTENV_AVAILABLE:
            env_path = Path.home() / 'cs562' / '.env'
            if env_path.exists():
                load_dotenv(env_path)
            else:
                load_dotenv()
        
        # Get API key
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.use_openai = OPENAI_AVAILABLE and self.api_key
        
        if self.use_openai:
            self.client = openai.OpenAI(api_key=self.api_key)
            print(f"Using OpenAI model: {self.model}")
        else:
            self.client = None
            if not OPENAI_AVAILABLE:
                print("OpenAI package not available")
            elif not self.api_key:
                print("No OpenAI API key found. Set OPENAI_API_KEY or use .env file")
            print("Using rule-based fallback logic")
    
    def query(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Query the LLM with a prompt"""
        if self.use_openai:
            try:
                return self._query_openai(prompt, system_prompt)
            except Exception as e:
                print(f"OpenAI API error: {e}")
                print("Falling back to rule-based logic")
                return self._fallback_logic(prompt)
        else:
            return self._fallback_logic(prompt)
    
    def _query_openai(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Query OpenAI API"""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        messages.append({"role": "user", "content": prompt})
        
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.3,  # Lower temperature for more consistent configs
            max_completion_tokens=2048,
        )
        
        return response.choices[0].message.content
    
    def _fallback_logic(self, prompt: str) -> str:
        """Fallback when LLM is not available"""
        # Extract basic info from prompt
        config = {
            "repo_url": "",
            "commit_id": "",
            "cve_id": "",
            "binary_name": "",
            "build_config": {},
            "log_level": "INFO"
        }
        
        # Try to extract values from prompt
        if "repo:" in prompt:
            repo_match = re.search(r'repo:\s*([^\s]+)', prompt)
            if repo_match:
                repo = repo_match.group(1)
                config['repo_url'] = f"https://github.com/{repo}.git"
                config['binary_name'] = repo.split('/')[-1]
        
        if "base_commit:" in prompt:
            commit_match = re.search(r'base_commit:\s*([a-f0-9]+)', prompt)
            if commit_match:
                config['commit_id'] = commit_match.group(1)
        
        if "instance_id:" in prompt:
            id_match = re.search(r'instance_id:\s*([^\s]+)', prompt)
            if id_match:
                instance_id = id_match.group(1)
                cve_part = instance_id.split('.', 1)[-1]
                config['cve_id'] = cve_part.upper().replace('.', '-')
        
        # Detect build system
        if 'cmake' in prompt.lower():
            config['build_config']['cmake_args'] = ""
        elif 'configure' in prompt.lower() or 'autotools' in prompt.lower():
            config['build_config']['configure_args'] = ""
        
        return json.dumps(config, indent=2)


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

# Directory paths (usually these defaults are fine)
aflgo_dir: "/home/ray/cs562/fuzzing/aflgo"
repos_dir: "/home/ray/cs562/repos"
temps_dir: "/home/ray/cs562/fuzzing/temps"

# Binary name (target executable to fuzz)
binary_name: "<executable_name>"

# Build configuration
build_config:
  # For CMake projects:
  cmake_args: "<cmake arguments>"
  
  # For autotools projects:
  configure_args: "<configure arguments>"
  
  # Build commands from SEC-bench (for LLM guidance)
  build_commands: |
    <actual build script from SEC-bench>
  
  # Additional flags
  cflags: ""
  ldflags: ""

# Logging
log_level: "INFO"
log_file: "aflgo_<project>.log"
```

**CRITICAL INSTRUCTIONS:**

1. **commit_id**: Use the base_commit from the CVE instance data.
   - base_commit is the VULNERABLE version that we want to instrument
   - AFLGo will instrument this version directly for directed fuzzing
   - Do NOT try to find or use the patch commit

2. **binary_name**: Determine from:
   - The build script (look for what gets compiled)
   - The repro command in secb_sh
   - The project name (often matches)
   - Sanitizer report paths
   
3. **Build system detection**:
   - CMake: Look for "cmake" in build_sh
   - Autotools: Look for "configure", "autoreconf", "./configure" in build_sh
   - Make: Look for just "make" in build_sh
   
4. **Build arguments**: Extract from build_sh script:
   - CMake: arguments after "cmake"
   - Configure: arguments after "./configure"
   - Common: --with-oniguruma=builtin, -DBUILD_SHARED_LIBS=OFF, etc.
   - Also include the FULL build_sh content in build_commands field for LLM guidance

5. **Response format**: Return ONLY valid YAML, no markdown code blocks, no explanations.
   Start directly with the comment line.

6. **Validation**: Ensure all required fields are present and values are reasonable.
"""
    
    def __init__(self, 
                 llm_model: str = "gpt-5.1",
                 api_key: Optional[str] = None,
                 secbench_dir: Path = None):
        
        self.llm = LLMInterface(model=llm_model, api_key=api_key)
        self.secbench_dir = secbench_dir or Path('/home/ray/cs562/SEC-bench-data')
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
    
    def find_patch_commit(self, cve: CVEInstance) -> Optional[str]:
        """Try to extract patch commit from patch data"""
        # Look for commit hash in patch header
        # Git patches often have: "From <commit_hash>"
        if cve.patch:
            # Try to find commit hash in patch
            commit_match = re.search(r'From ([a-f0-9]{40})', cve.patch)
            if commit_match:
                return commit_match.group(1)
            
            # Sometimes patches have commit references in comments
            commit_match = re.search(r'commit ([a-f0-9]{40})', cve.patch, re.IGNORECASE)
            if commit_match:
                return commit_match.group(1)
        
        return None
    
    def extract_binary_name(self, cve: CVEInstance) -> str:
        """Extract binary name from CVE data"""
        
        # Try from secb_sh repro script - most reliable
        if cve.secb_sh:
            # Look for repro() function execution paths like /src/faad2/frontend/faad
            # Pattern: /src/<project>/path/to/binary_name followed by space or args
            match = re.search(r'/src/[^/]+/(?:frontend/|build/|bin/|\.libs/)?(\w+)(?:\s|$)', cve.secb_sh)
            if match:
                binary = match.group(1)
                # Skip common directory names
                if binary not in ['bin', 'build', 'frontend', 'libs']:
                    return binary
        
        # Try from bug description - look for execution commands
        if cve.bug_description:
            # Look for ./binary_name pattern
            match = re.search(r'(?:^|\s)\./([\w-]+)(?:\s|$)', cve.bug_description, re.MULTILINE)
            if match:
                binary = match.group(1)
                if binary not in ['configure', 'build', 'bootstrap']:
                    return binary
        
        # Try from sanitizer report stack traces
        if cve.sanitizer_report:
            # Look for binary names in paths like /usr/local/faad-asan/bin/faad
            match = re.search(r'/bin/([\w-]+)\+', cve.sanitizer_report)
            if match:
                return match.group(1)
            # Also try frontend paths
            match = re.search(r'/frontend/\.(libs|)/(\w+)\+', cve.sanitizer_report)
            if match:
                return match.group(2)
        
        # Try from build script
        if cve.build_sh:
            # Look for executable names after -o flag
            match = re.search(r'-o\s+([^\s/]+)', cve.build_sh)
            if match:
                return match.group(1)
        
        # Default to project name
        return cve.project_name
    
    def analyze_build_system(self, cve: CVEInstance) -> Dict[str, any]:
        """Analyze build system and extract configuration"""
        build_info = {
            'type': 'unknown',
            'args': {}
        }
        
        if not cve.build_sh:
            return build_info
        
        build_lower = cve.build_sh.lower()
        
        # Always include the full build script for LLM guidance
        build_info['args']['build_commands'] = cve.build_sh.strip()
        
        # Detect build system
        if 'cmake' in build_lower:
            build_info['type'] = 'cmake'
            # Extract cmake arguments
            cmake_match = re.search(r'cmake\s+([^\n]+)', cve.build_sh)
            if cmake_match:
                args = cmake_match.group(1).strip()
                # Remove common noise
                args = re.sub(r'\s*\.\./?\s*', '', args)
                if args:
                    build_info['args']['cmake_args'] = args
        
        elif 'configure' in build_lower or 'autoreconf' in build_lower:
            build_info['type'] = 'autotools'
            # Extract configure arguments
            configure_match = re.search(r'\./configure\s+([^\n]+)', cve.build_sh)
            if configure_match:
                args = configure_match.group(1).strip()
                if args and args not in ['', '&&', '\\']:
                    build_info['args']['configure_args'] = args
        
        elif 'make' in build_lower:
            build_info['type'] = 'make'
        
        return build_info
    
    def generate_config_with_llm(self, cve: CVEInstance) -> str:
        """Generate config using LLM"""
        # Use base_commit (vulnerable version)
        commit_id = cve.base_commit
        
        # Analyze build system
        build_info = self.analyze_build_system(cve)
        
        # Extract binary name
        binary_name = self.extract_binary_name(cve)
        
        # Build context for LLM
        prompt = f"""Generate an AFLGo YAML configuration file for this CVE instance:

**CVE Instance Data:**
- instance_id: {cve.instance_id}
- repo: {cve.repo}
- project_name: {cve.project_name}
- language: {cve.lang}
- base_commit: {cve.base_commit}

**Build Script (from SEC-bench):**
```bash
{cve.build_sh}
```

**CRITICAL: Include the FULL build script above in the build_config.build_commands field.**
**This script shows the EXACT commands needed to build this project.**

**Patch (first 1500 chars):**
```diff
{cve.patch[:1500] if cve.patch else 'No patch data'}
```

**My Analysis:**
- Detected build system: {build_info['type']}
- Build arguments: {build_info['args']}
- Likely binary name: {binary_name}
- Commit to use: {commit_id} (base_commit - vulnerable version)

**Task:**
Generate a complete YAML configuration following the template in your instructions.

IMPORTANT: 
- For commit_id, use the base_commit: {commit_id}
- This is the VULNERABLE version that we want to instrument
- Include all required fields
- Extract actual build arguments from the build script
- Return ONLY valid YAML with no markdown formatting
"""
        
        response = self.llm.query(prompt, self.SYSTEM_PROMPT)
        
        # Clean up response (remove markdown if present)
        response = response.strip()
        if response.startswith('```yaml'):
            response = response[7:]
        if response.startswith('```'):
            response = response[3:]
        if response.endswith('```'):
            response = response[:-3]
        
        return response.strip()
    
    def generate_config_fallback(self, cve: CVEInstance) -> str:
        """Generate config using rule-based fallback"""
        build_info = self.analyze_build_system(cve)
        binary_name = self.extract_binary_name(cve)
        commit_id = cve.base_commit
        
        cve_id = cve.instance_id.split('.', 1)[-1].upper().replace('.', '-')
        
        config = {
            'repo_url': f"https://github.com/{cve.repo}.git",
            'commit_id': commit_id,
            'cve_id': cve_id,
            'aflgo_dir': '/home/ray/cs562/fuzzing/aflgo',
            'repos_dir': '/home/ray/cs562/repos',
            'temps_dir': '/home/ray/cs562/fuzzing/temps',
            'binary_name': binary_name,
            'build_config': build_info['args'],
            'log_level': 'INFO',
            'log_file': f"aflgo_{cve.project_name}.log"
        }
        
        # Generate YAML with comments
        lines = [
            f"# AFLGo Configuration for {cve.project_name} {cve_id}",
            f"# Generated from SEC-bench instance: {cve.instance_id}",
            "",
            "# Repository information",
            f"repo_url: \"{config['repo_url']}\"",
            f"commit_id: \"{config['commit_id']}\"",
            f"cve_id: \"{config['cve_id']}\"",
            "",
            "# Directory paths",
            f"aflgo_dir: \"{config['aflgo_dir']}\"",
            f"repos_dir: \"{config['repos_dir']}\"",
            f"temps_dir: \"{config['temps_dir']}\"",
            "",
            f"# Binary name",
            f"binary_name: \"{config['binary_name']}\"",
            "",
            "# Build configuration",
            "build_config:",
        ]
        
        if build_info['args']:
            for key, value in build_info['args'].items():
                if key == 'build_commands':
                    # Format multiline YAML string with proper indentation
                    lines.append(f"  {key}: |")
                    for line in value.split('\n'):
                        lines.append(f"    {line}")
                else:
                    lines.append(f"  {key}: \"{value}\"")
        else:
            lines.append("  # No specific build arguments detected")
        
        lines.extend([
            "",
            "# Logging",
            f"log_level: \"{config['log_level']}\"",
            f"log_file: \"{config['log_file']}\"",
        ])
        
        return "\n".join(lines)
    
    def generate_config(self, instance_path: Path, output_path: Optional[Path] = None) -> str:
        """Generate config for a CVE instance"""
        self.logger.info(f"Generating config for {instance_path.name}")
        
        # Load CVE instance
        cve = self.load_cve_instance(instance_path)
        
        # Generate config with LLM
        if self.llm.use_openai:
            config_yaml = self.generate_config_with_llm(cve)
        else:
            config_yaml = self.generate_config_fallback(cve)
        
        # Validate YAML
        try:
            yaml.safe_load(config_yaml)
        except yaml.YAMLError as e:
            self.logger.error(f"Generated invalid YAML: {e}")
            self.logger.warning("Using fallback config generation")
            config_yaml = self.generate_config_fallback(cve)
        
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
  ./config_generator_agent.py --cve-instance SEC-bench-data/CVE-instances/jq.cve-2023-50246.json
  
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
                       default=Path('/home/ray/cs562/SEC-bench-data'),
                       help='Path to SEC-bench-data directory')
    parser.add_argument('--llm-model', default='gpt-5.1',
                       help='OpenAI model to use (default: gpt-5.1)')
    parser.add_argument('--api-key',
                       help='OpenAI API key (or set OPENAI_API_KEY env var)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.batch and not args.cve_instance and not args.cve_id:
        parser.error("Must specify --cve-instance, --cve-id, or --batch")
    
    # Create agent
    agent = ConfigGeneratorAgent(
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
