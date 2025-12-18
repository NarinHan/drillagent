# System prompt for VulnAnalysisAgent
VAA_system_prompt = """You are a security researcher specializing in vulnerability analysis. Your task is to analyze sanitizer reports and corresponding vulnerable source code to extract accurate vulnerability information.

When using tools and generating paths, please adhere to the following guidelines:
- Use RELATIVE paths (e.g., src/vm.c NOT /home/user/project/src/vm.c)
- The repository root is the base directory for all relative paths
- Be precise and extract information directly from the provided data
- Do not make assumptions without evidence!
"""


# Prompt for extracting information from sanitizer reports
VAA_sanitizer_extraction_prompt = """You are analyzing a sanitizer report to extract key vulnerability information.

Project: {project_name}
Repository path: {actual_repo_path}

Sanitizer Report:
```
{sanitizer_report}
```

Your task is to extract the following information from the sanitizer report:

1. **Vulnerability Type**: Identify the type (e.g., heap-use-after-free, heap-buffer-overflow, stack-buffer-overflow, use-after-return, double-free and so on)

2. **Crash Function**: From the call trace, find the INNERMOST function that is IN THE REPOSITORY CODE (not in libc or system libraries).
   - Look at the stack trace from #0 downwards
   - Skip functions in system libraries (libc, libstdc++, etc.)
   - Find the first function that is in the project's source code

3. **Crash Location (refined_vuln_location)**: Must be in format "file_relative_path:line_number"
   - The file path must be RELATIVE to the repository root: {actual_repo_path}
   - Example: if full path is /home/user/njs/src/njs_function.c, then relative path is src/njs_function.c
   - Format: src/njs_function.c:574 (NOT /home/user/njs/src/njs_function.c:574)
   - The file MUST exist in the repository

4. **Entry Function**: Identify the entry point function (usually the 'main' function or equivalent IN THE REPOSITORY CODE)

5. **Entry Location (entry_location)**: Must be in format "file_relative_path:line_number"
   - Find the location where the entry function is called or defined in the call trace
   - Look at the LAST frame in the stack trace (typically #N where N is the highest number)
   - The file path must be RELATIVE to the repository root: {actual_repo_path}
   - Format: src/main.c:45 (NOT /home/user/project/src/main.c:45)
   - If entry location is not clearly in the call trace, leave it empty

6. **Call Trace**: Extract the full stack trace (all lines starting with #) 
   - If there are multiple sets of call traces, only keep the first one and ignore the other sets of traces!!

IMPORTANT PATH REQUIREMENTS:
- ALL paths must be relative to repository root: {actual_repo_path}
- Remove any absolute path prefix
- Verify the file exists in the repository using tools if needed!!

Respond in the following JSON format ONLY:
{{
    "vuln_type": "the vulnerability type",
    "crash_function": "innermost function IN REPOSITORY CODE (not libc)",
    "refined_vuln_location": "relative/path/file.c:line_number",
    "entry_function": "main or other entry function",
    "entry_location": "relative/path/file.c:line_number",
    "call_trace": "full stack trace starting with #0..."
}}

Be precise. Extract information directly from the report.
"""

# Follow-up prompt after tool execution for sanitizer extraction
VAA_sanitizer_followup_prompt = """Based on the file verification results above, now extract the vulnerability information from the sanitizer report.

Provide your response in the following JSON format ONLY:
{{
    "vuln_type": "the vulnerability type",
    "crash_function": "innermost function IN REPOSITORY CODE (not libc)",
    "refined_vuln_location": "relative/path/file.c:line_number",
    "entry_function": "main or other entry function",
    "entry_location": "relative/path/file.c:line_number",
    "call_trace": "full stack trace starting with #0... (If there are multiple sets of call traces, only keep the first one and ignore the rest)"
}}
"""


# Prompt for refining harness command
VAA_harness_refine_prompt = """You are refining a harness command to accurately run target program and reproduce a vulnerability.

Project: {project_name}
Repository path: {actual_repo_path}

Current harness command: 
(May contain absolute path prefix not existing in the local machine, need to be refined)
```
{harness_command}
```

Your tasks:

1. **Locate the binary**: Find the actual executable binary in the repository
   - You can refer to harness command to infer the path. Or check common build directories: build/, out/, bin/, .libs/
   - Use find_file or list_dir tools to locate the binary
   - Verify it exists and is executable

2. **Extract binary_path**: The path RELATIVE to the repository root
   - Format: build/njs (NOT /home/ubuntu/PoV/Repos/njs-cov/build/njs)
   - Must be relative to: {actual_repo_path}

3. **Refine the command**: Create a command that can be run from any directory
   - The command should be executable when run from arbitrary directories, so try to use absolute path for the binary program
   - Remain all the flags and command line arguments as in the original harness command!!!
   - For the input file paths in the command, replace them with placeholders like "<path/to/testcase>"
   - Example: /absolute/path/to/build/njs <path/to/testcase>

IMPORTANT PATH REQUIREMENTS:
- binary_path must be RELATIVE to repository root: {actual_repo_path}
- refined_harness_command must be runnable from any directory (i.e., the binary program in the command should use absolute path)
- Verify the program file exists in the repository using tools if needed!!

Use the available tools (find_file, list_dir) to explore the repository structure.

Respond in the following JSON format ONLY:
{{
    "binary_path": "relative/path/to/binary",
    "refined_harness_command": "/absolute/path/to/binary [flags] [<path/to/testcase>]"
}}

Example:
If harness is: "/src/njs/build/njs /testcase/poc.js"
And repo is: "/home/ubuntu/PoV/Repos/njs-cov"
Then output should be:
{{
    "binary_path": "build/njs",
    "refined_harness_command": "/home/ubuntu/PoV/Repos/njs-cov/build/njs <path/to/testcase>"
}}

Be thorough. Verify paths exist before responding.
"""

# Follow-up prompt after tool execution for harness refinement
# 2025.12.09: Fixed a tricky bug: {{tool_results}} -> {tool_results}
VAA_harness_followup_prompt = """You are refining a harness command to accurately run target program and reproduce a vulnerability.

Project: {project_name}
Repository path: {actual_repo_path}

Current harness command: 
(May contain absolute path prefix not existing in the local machine, need to be refined)
```
{harness_command}
```

Your tasks:

1. **Locate the binary**: Find the actual executable binary in the repository
   - You can refer to harness command to infer the path. Or check common build directories: build/, out/, bin/, .libs/
   - Use find_file or list_dir tools to locate the binary
   - Verify it exists and is executable

2. **Extract binary_path**: The path RELATIVE to the repository root
   - Format: build/njs (NOT /home/ubuntu/PoV/Repos/njs-cov/build/njs)
   - Must be relative to: {actual_repo_path}

3. **Refine the command**: Create a command that can be run from any directory
   - The command should be executable when run from arbitrary directories, so try to use absolute path for the binary program
   - Remain all the flags and command line arguments as in the original harness command!!!
   - For the input file paths in the command, replace them with placeholders like "<path/to/testcase>"
   - Example: /absolute/path/to/build/njs <path/to/testcase>

IMPORTANT PATH REQUIREMENTS:
- binary_path must be RELATIVE to repository root: {actual_repo_path}
- refined_harness_command must be runnable from any directory (i.e., the binary program in the command should use absolute path)
- Verify the program file exists in the repository using tools if needed!!

Previous tool results:
{tool_results}

Now provide the final refined harness information in JSON format:
{{
    "binary_path": "relative/path/to/binary",
    "refined_harness_command": "executable command (from any directory) with arguments and testcase placeholder (if any)"
}}
"""


# Prompt for root cause analysis
VAA_root_cause_analysis_prompt = """You are performing root cause analysis for a vulnerability.

Project: {project_name}
Repository path: {actual_repo_path}

Vulnerability Information:
- Vuln Type: {vuln_type}
- Crash Location: {crash_location}
- Crash Function: {crash_function}
- Entry Location: {entry_location}
- Entry Function: {entry_function}

Command to trigger the vulnerability crash:
```
{refined_harness_command}
```

Call trace to trigger the vulnerability crash (from a sanitizer report):
```
{refined_call_trace}
```

Your task is to explain the ROOT CAUSE of this vulnerability:

1. Examine the source code at the crash location.
2. Follow the above call trace to retrieve the source code around the corresponding locations, and analyze the data flow along the function calls, with particular attention to the call sites at each layer.
3. Identify WHY the vulnerability occurs during analysis. (e.g., missing bounds check, use-after-free due to dangling pointer)

Use the provided tools (mainly read_file) to examine relevant source files.
- All the relative file paths are based on the repository root: {actual_repo_path}
- Some source file line numbers may be inaccurate (i.e., target source line doesn't contain a callsite to next stack frame) due to compiler preprocessing or macro expansion.
- You may need to read a few more lines further down, and use the callee functionn name in the next stack frame to pinpoint the correct call-site code snippet!!

Provide a clear, technical explanation starting with "## VULNERABILITY ROOT CAUSE ANALYSIS" and covering:
- What the vulnerability is
- Why it occurs (the root cause)
- What code pattern or logic flaw enables it
- Explain what conditions trigger it!

"""


# Prompt for transforming raw call trace to structured format
VAA_call_trace_transform_prompt = """You are transforming a raw call trace from a sanitizer report into a structured format.

Project: {project_name}
Repository path: {actual_repo_path}

Raw Call Trace:
```
{raw_call_trace}
```

Your task is to parse this call trace and extract structured information for each frame.

For each line starting with '#' in the call trace:
1. Extract the sequence number (the number after #)
2. Extract the function name (the text after "in" if present, otherwise use empty string)
3. Extract the file path and convert it to a RELATIVE path based on the repository root: {actual_repo_path}
4. Extract the line number (the number after the colon in file:line format)

IMPORTANT PATH CONVERSION RULES:
- If the path contains the project name (e.g., "/home/b/asan/libplist/tools/plistutil.c"), extract the relative part (e.g., "tools/plistutil.c")
- If the path is a system library (e.g., "/lib/i386-linux-gnu/libc.so.6" or contains libasan, libstdc++, libc), keep it as-is but mark it as external
- The relative path should start from the repository root
- Remove any absolute path prefix that includes the repository path

SKIP THE FOLLOWING:
- Lines that are NOT actual stack frames (like allocation information, summary lines, etc.)
- System library frames (libc, libasan, etc.) - these should still be included but marked appropriately

Respond in the following JSON format ONLY:
{{
    "call_trace": [
        {{
            "sequence_num": 0,
            "function_name": "main",
            "file_path": "tools/plistutil.c",
            "line_number": 137,
            "is_external": false
        }},
        {{
            "sequence_num": 1,
            "function_name": "",
            "file_path": "/lib/i386-linux-gnu/libc.so.6",
            "line_number": 0,
            "is_external": true
        }}
    ]
}}

IMPORTANT:
- For frames without line numbers, use 0
- For frames without function names, use empty string ""
- Mark system library frames with `"is_external": true`
"""

