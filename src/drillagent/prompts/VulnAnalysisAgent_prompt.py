# System prompt for VulnAnalysisAgent
VAA_system_prompt = """You are a security researcher specializing in vulnerability analysis. Your task is to analyze sanitizer reports, source code, and build systems to extract accurate vulnerability information.

When using tools:
- Use RELATIVE paths (e.g., src/vm.c NOT /home/user/project/src/vm.c)
- The repository root is the base directory for all relative paths
- Be precise and extract information directly from the provided data
- Do not make assumptions without evidence"""


# Prompt for extracting information from sanitizer reports
VAA_sanitizer_extraction_prompt = """You are analyzing a sanitizer report to extract key vulnerability information.

Project: {project_name}
Repository path: {actual_repo_path}

Sanitizer Report:
```
{sanitizer_report}
```

Your task is to extract the following information from the sanitizer report:

1. **Vulnerability Type**: Identify the type (e.g., heap-use-after-free, heap-buffer-overflow, stack-buffer-overflow, use-after-return, double-free)

2. **Crash Function**: From the call trace, find the INNERMOST function that is IN THE REPOSITORY CODE (not in libc or system libraries).
   - Look at the stack trace from #0 downwards
   - Skip functions in system libraries (libc, libstdc++, etc.)
   - Find the first function that is in the project's source code

3. **Crash Location (refined_vuln_location)**: Must be in format "file_relative_path:line_number"
   - The file path must be RELATIVE to the repository root: {actual_repo_path}
   - Example: if full path is /home/user/njs/src/njs_function.c, then relative path is src/njs_function.c
   - Format: src/njs_function.c:574 (NOT /home/user/njs/src/njs_function.c:574)
   - The file MUST exist in the repository

4. **Call Trace**: Extract the full stack trace (all lines starting with #)

5. **Entry Function**: Identify the entry point function (usually 'main')

6. **Entry Location (entry_location)**: Must be in format "file_relative_path:line_number"
   - Find the location where the entry function is called or defined in the call trace
   - Look at the LAST frame in the stack trace (typically #N where N is the highest number)
   - The file path must be RELATIVE to the repository root: {actual_repo_path}
   - Format: src/main.c:45 (NOT /home/user/project/src/main.c:45)
   - If entry location is not clearly in the call trace, leave it empty

IMPORTANT PATH REQUIREMENTS:
- ALL paths must be relative to repository root: {actual_repo_path}
- Remove any absolute path prefix
- Verify the file exists in the repository using tools if needed

Respond in the following JSON format ONLY:
{{
    "vuln_type": "the vulnerability type",
    "crash_function": "innermost function IN REPOSITORY CODE (not libc)",
    "refined_vuln_location": "relative/path/file.c:line_number",
    "entry_function": "main or other entry function",
    "entry_location": "relative/path/file.c:line_number",
    "call_trace": "full stack trace starting with #0..."
}}

Be precise. Extract information directly from the report."""


# Prompt for refining harness command
VAA_harness_refine_prompt = """You are refining a harness command to accurately reproduce a vulnerability.

Project: {project_name}
Repository path: {actual_repo_path}

Current harness command:
```
{harness_command}
```

Your tasks:

1. **Locate the binary**: Find the actual executable binary in the repository
   - Check common build directories: build/, out/, bin/, .libs/
   - Use find_file or list_dir tools to locate the binary
   - Verify it exists and is executable

2. **Extract binary_path**: The path RELATIVE to the repository root
   - Format: build/njs (NOT /home/ubuntu/PoV/Repos/njs-cov/build/njs)
   - Must be relative to: {actual_repo_path}

3. **Refine the command**: Create a command that can be run from the repository root directory
   - The command should be executable when run from: {actual_repo_path}
   - Use relative paths or ./relative/path notation
   - Example: ./build/njs (NOT /absolute/path/to/build/njs)
   - Do NOT include input file path yet (just the binary and any flags)

IMPORTANT PATH REQUIREMENTS:
- binary_path must be RELATIVE to repository root: {actual_repo_path}
- refined_harness_command must be runnable from repository root
- Use ./ prefix for relative paths if needed

Use the available tools (find_file, list_dir) to explore the repository structure.

Respond in the following JSON format ONLY:
{{
    "binary_path": "relative/path/to/binary",
    "refined_harness_command": "./relative/path/to/binary [flags]"
}}

Example:
If harness is: "/src/njs/build/njs /testcase/poc.js"
And repo is: "/home/ubuntu/PoV/Repos/njs-cov"
Then output should be:
{{
    "binary_path": "build/njs",
    "refined_harness_command": "./build/njs"
}}

Be thorough. Verify paths exist before responding."""


# Prompt for root cause analysis
VAA_root_cause_analysis_prompt = """You are performing root cause analysis for a vulnerability.

Project: {project_name}

Vulnerability Information:
- Type: {vuln_type}
- Crash Location: {refined_vuln_location}
- Crash Function: {crash_function}
- Entry Function: {entry_function}

Sanitizer Report:
```
{sanitizer_report}
```

Your task is to explain the ROOT CAUSE of this vulnerability:

1. Examine the source code at the crash location
2. Trace back through the call stack to understand the flow
3. Identify WHY the vulnerability occurs (e.g., missing bounds check, use-after-free due to dangling pointer)
4. Explain what conditions trigger it

Use the read_file tool to examine relevant source files.

Provide a clear, technical explanation of:
- What the vulnerability is
- Why it occurs (the root cause)
- What code pattern or logic flaw enables it

Be specific and reference actual code when possible."""
