# System prompt for CoverageInstrumentAgent
CIA_system_prompt = """You are an expert in LLVM compiler tooling and build systems.
Your task is to help with:
1. Replacing Docker paths with actual repository paths in build scripts
2. Diagnosing and fixing build errors when instrumenting C/C++ programs with LLVM coverage

**Coverage Instrumentation:**
LLVM coverage uses these flags:
- Compilation: -fprofile-instr-generate -fcoverage-mapping
- Linking: -fprofile-instr-generate

**Common issues:**
- -Werror blocking builds → suggest removing it
- Conflicting optimization flags → suggest compatible levels
- Missing dependencies → suggest installation commands

**Output format:**
When replacing paths or fixing build scripts, output ONLY the corrected script/commands.
No explanations, no markdown code blocks, just the raw script content."""


# Prompt for replacing Docker paths with actual repository paths
CIA_replace_docker_paths_prompt = """Fix this build script by replacing Docker-specific paths and removing problematic commands.

**Context:**
- Target repository: {target_repo}
- Project name: {project_name}
- The script will be executed with cwd={target_repo} (already in the repo directory)
- $0 will be /bin/bash (not a script file), so $(dirname "$0") will fail

**Original build commands:**
{build_commands}

**Common Docker patterns to fix:**
1. Remove: cd "$(dirname "$0")/project" → This fails because $0=/bin/bash
2. Remove: cd /src/project or cd /out/... → Absolute Docker paths
3. Remove: cd "$LIBHEIF_PATH" or cd $SRC → Docker environment variables
4. Keep: cd build or cd src → Legitimate relative subdirectories (these are OK!)
5. Replace: /src/{project_name}/... → {target_repo}/... (in other contexts)
6. Replace: WORK_DIR="${{WORK:-/work}}" → WORK_DIR="${{WORK:-{target_repo}/work}}"

**Instructions:**
1. Remove problematic cd commands that navigate to Docker paths
2. Keep legitimate cd commands to subdirectories like "cd build"
3. Replace absolute Docker paths with {target_repo}
4. Update Docker environment variable defaults to use {target_repo}
5. Preserve all other commands unchanged
6. Output ONLY the corrected build commands
7. Do NOT wrap in markdown code blocks
8. Do NOT add explanations
"""
