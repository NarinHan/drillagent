# System prompt for VulnAnalysisAgent
VAA_system_prompt = """You are a security researcher specializing in vulnerability analysis. Your task is to analyze sanitizer reports and corresponding vulnerable source code to extract accurate vulnerability information.

When using tools and generating paths, please adhere to the following guidelines:
- For source code files within the target code repository: Use RELATIVE paths (e.g., src/vm.c NOT /home/user/project/src/vm.c).
- For files outside the repository or system-level operations: Absolute paths are also supported.
- The repository root is the base directory for all relative paths.
- When using `execute_bash` tool: working_dir can be relative (to repo root) or absolute.
- Be precise and extract information directly from the provided data.
- Do not make assumptions without evidence!

When exploring the codebase, use efficient commands like ls, find, grep, etc. with appropriate filters to minimize unnecessary operations.

EFFICIENCY TIP: You can call multiple tools in a single response. When you need to read several related source files (e.g., to understand a call chain), call `read_file` multiple times (<= 5) in one turn rather than reading them one by one across multiple turns. This saves iterations and gives you more context at once.
"""


# Prompt for extracting information from sanitizer reports
VAA_sanitizer_extraction_prompt = """You are analyzing a sanitizer report to extract key vulnerability information.

Project: {project_name}
Repository path: {actual_repo_path}

# SANITIZER REPORT

```
{sanitizer_report}
```

# YOUR TASK

Your task is to extract the following information from the sanitizer report:

1. **Vulnerability Type**: Identify the type (e.g., heap-buffer-overflow, stack-buffer-overflow, heap-use-after-free, double-free, null pointer dereference, and so on)

2. **Crash Function**: From the crash call trace, find the INNERMOST function that is IN THE REPOSITORY CODE (not in libc or system libraries).
   - Look at the stack trace from #0 downwards
   - Skip functions in system libraries (libc, libstdc++, etc.)
   - Find the first function that is in the project's source code

3. **Crash Location (crash_location)**: Must be in format "file_relative_path:line_number"
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

6. **Call Traces**: Extract ALL call traces from the sanitizer report. Different vulnerability types have different traces:

   For **heap-buffer-overflow**:
   - `crash_trace` (REQUIRED): The main error trace showing where the overflow READ/WRITE occurred (starts with "ERROR: AddressSanitizer:")
   - `allocation_trace` (OPTIONAL): Shows where the overflowed buffer was allocated (starts with "allocated by thread")

   For **heap-use-after-free** and **double-free**:
   - `crash_trace` (REQUIRED): The main error trace showing where the freed memory was accessed (starts with "ERROR: AddressSanitizer:")
   - `free_trace` (OPTIONAL): Shows where the memory was freed (starts with "freed by thread")
   - `allocation_trace` (OPTIONAL): Shows where the memory was originally allocated (starts with "previously allocated by thread")

   For **other vulnerability types**:
   - `crash_trace` (REQUIRED): The main error trace
   - `allocation_trace` and `free_trace`: Leave as empty strings if not present

   IMPORTANT: Each trace should include ALL lines starting with # (the full stack frames).

IMPORTANT PATH REQUIREMENTS:
- ALL paths must be relative to repository root: {actual_repo_path}
- Remove any absolute path prefix
- Verify the file exists in the repository using tools if needed!!

Respond in the following JSON format ONLY:
{{
    "vuln_type": "the vulnerability type",
    "crash_function": "innermost function IN REPOSITORY CODE (not libc)",
    "crash_location": "relative/path/file.c:line_number",
    "entry_function": "main or other entry function",
    "entry_location": "relative/path/file.c:line_number",
    "crash_trace": "full stack trace of the crash point starting with #0... #1... etc.",
    "allocation_trace": "full stack trace showing where memory was allocated (or empty string if not present)",
    "free_trace": "full stack trace showing where memory was freed (or empty string if not present, only for use-after-free and double-free)"
}}

Be precise. Extract information directly from the report.
"""


# Prompt for transforming raw call trace to structured format
VAA_call_trace_transform_prompt = """You are transforming a raw call trace from a sanitizer report into a structured format.

Project: {project_name}
Repository path: {actual_repo_path}

# RAW CALL TRACE

```
{raw_call_trace}
```

# YOUR TASK

Your task is to parse this call trace and extract structured information for each frame.

For each line starting with '#' in the call trace:
1. Extract the sequence number (the number after #).
2. Extract the function name (the text after "in" if present, otherwise use empty string).
3. Extract the file path and convert it to a RELATIVE path based on the repository root: {actual_repo_path}.
4. Extract the line number (the number after the colon in file:line format).

IMPORTANT PATH CONVERSION RULES:
- If the path contains the project name (e.g., "/home/b/asan/libplist/tools/plistutil.c"), extract the relative part (e.g., "tools/plistutil.c").
- If the path is a system library (e.g., "/lib/i386-linux-gnu/libc.so.6" or contains libasan, libstdc++, libc), keep it as-is but mark it as external.
- If there is only a file name without path (e.g., "main.c"), you MUST use the provided tools (e.g., `execute_bash`) to locate the file in the repository and determine its correct relative path.
- The relative path should start from the repository root.
- Remove any absolute path prefix that includes the repository path.

TOOL USAGE:
- You have access to `execute_bash` tool to help locate files when needed.
  - Example command: `ls src/` to list files in a directory.
  - Example command: `find . -name "main.c"` to find the relative path of "main.c" in the repository.
- Use these tools when a file name appears without a full path to find its correct relative location.
- **CRITICAL:** For all files, call `execute_bash` to use `find` command to verify the file exists in the repository and get its relative path. 

SKIP THE FOLLOWING:
- Lines that are NOT actual stack frames (like allocation information, summary lines, etc.)
- System library frames (libc, libasan, etc.) - these should still be included but marked appropriately

Respond in the following JSON format ONLY:
{{
    "call_trace": [
         {{
         ...
         }},
         {{
            "sequence_num": 16,
            "function_name": "njs_function",
            "file_path": "src/njs_function.c",
            "line_number": 574,
            "is_external": false
        }},
        {{
            "sequence_num": 17,
            "function_name": "main",
            "file_path": "tools/plistutil.c",
            "line_number": 137,
            "is_external": false
        }},
        {{
            "sequence_num": 18,
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

VAA_call_trace_linenum_refine_prompt = """You are refining the line number for a single stack frame to ensure accuracy.

Project: {project_name}
Repository path: {actual_repo_path}

# CURRENT STACK FRAME INFO
Function call-site location: (with potentially inaccurate line number)
```json
{current_frame_json}
```

Callee function name: {callee_function_name}

# YOUR TASK

Your task is to verify and adjust the line number for this frame by examining the actual source code.

CRITICAL: You MUST use the `read_file` tool to verify and adjust the line number for accuracy!

Line Number Verification Requirements:
- The `file:line` in this frame should indicate the call site to the **callee function** `{callee_function_name}`.
- Because of compiler preprocessing or macro expansion, the line number may be inaccurate (i.e., the target code line doesn't contain a call site to the callee function). Such inaccurate line numbers usually require subtracting an offset to be precise.
- Example: If this frame is `main @ tools/plistutil.c:137` and the callee function is `njs_function`, then tools/plistutil.c:137 should contain a function call site to `njs_function`.

Verification Steps:
1. You MUST use provided code browsing tools to examine the source code at and around the provided line number.
2. Check if the target line contains a call site to the callee function `{callee_function_name}`:
   - If YES and it's a **direct function call** (e.g., `njs_function(...);`), keep the original non-zero line number and set `"is_original_linenum": true` and `"is_verified": true`.
   - If YES and it's an **indirect function call** (e.g., `(*callback)(arg);` or `func_ptr();` or `handler->process();`), keep the original non-zero line number and set `"is_original_linenum": true` and `"is_verified": true`.
   - If NO (the line doesn't contain a call to `{callee_function_name}`), read a few lines above (typically 1-20 lines) to find the correct call-site code snippet:
     * If you find the correct call site, update the line number accordingly and set `"is_original_linenum": false` and `"is_verified": true`.
     * If you cannot find the correct line number after thorough checking, keep the original non-zero line number and set `"is_original_linenum": true` and `"is_verified": false`.
3. CRITICAL RULE: The final `line_number` must NEVER be 0. Always use the original non-zero line number if you cannot determine a better value.

IMPORTANT:
- All file paths are RELATIVE to repository root: {actual_repo_path}
- The file_path field in the frame should NOT be changed!
- Only update the `line_number` and `is_original_linenum` and `is_verified` fields

VALIDATION RULE: The frame's `line_number` MUST be > 0 (NEVER 0)!!!

Respond in the following JSON format ONLY (return the updated frame):
{{
    "sequence_num": <original_sequence_num>,
    "function_name": "<original_function_name>",
    "file_path": "<original_file_path>",
    "line_number": <refined_line_number>,
    "is_external": <original_is_external_value>,
    "is_original_linenum": <true_or_false>,
    "is_verified": <true_or_false>
}}

Note: Set `"is_original_linenum": true` when you keep the original line number because:
- The call site is an indirect function call, OR
- You cannot find the correct call site line after thorough checking
Also set `"is_verified": false` if you cannot find the correct line number after thorough checking.

Make sure the line number has been verified and adjusted as needed using the code browsing tools.
Before finalizing your answer, re-verify that the line_number is > 0 (NEVER 0)!!!
"""


# Prompt for refining harness command (Even if the binary may not be compiled yet, this refinement should still work)
VAA_harness_refine_prompt = """You are refining a harness command to accurately run target program and reproduce a vulnerability.

Project: {project_name}
Repository path: {actual_repo_path}

# RAW HARNESS COMMAND

```
{harness_command}
```
(may contain absolute path prefix not existing in the local machine, need to be refined)

# YOUR TASK

1. **Extract and infer the binary_path**: The path RELATIVE to the repository root
   - You can refer to the provided harness command to infer the path. Or read README doc to find the built binary program location.
   - Note that the repository path may not be compiled yet, so the binary may not exist currently! You can still infer the expected binary path based on harness command.
   - Format example: build/njs (NOT /home/ubuntu/PoV/Repos/njs/build/njs)
   - Must be relative to: {actual_repo_path}

2. **Refine the command**: Create a command that can be run from any directory
   - The command should be executable when run from arbitrary directories, so try to construct absolute path for the binary program
   - Remain all the flags and command line arguments as in the original harness command!!!
   - For the input file path in the command, replace it with placeholders like "<path/to/testcase>"
     - Example: /absolute/path/to/build/njs <path/to/testcase>
     - Never use "<path/to/testcase>.js"! The file suffix should be indicated by the "input_file_suffix" field in your returned JSON object!
     - Avoid using angle-bracket placeholders for non-input files. Just use a random path in the current directory, like ./tmp1.xx or ./tmp2.yy.

3. **Extract input file suffix (if any)**: Identify if the program expects a specific file extension for input files
   - Examine the harness command to see if the input file has an extension (e.g., .js, .xml, .rb, .json, .pattern)
   - If the input file in the harness command has an extension, extract it (e.g., ".js", ".xml")
   - If no specific extension is present or required, leave it as an empty string ""
   - Examples:
     * If harness has "/path/to/njs input.js" → input_file_suffix: ".js"
     * If harness has "/path/to/xmlparser poc.xml" → input_file_suffix: ".xml"
     * If harness has "/path/to/program poc" → input_file_suffix: ""

IMPORTANT PATH REQUIREMENTS:
- binary_path must be RELATIVE to repository root: {actual_repo_path}
- refined_harness_command must be runnable from any directory (i.e., the binary program in the command should use absolute path)
- For the binary_path, you don't have to verify its existence in the repository (it may not be compiled yet)! Just infer the expected path.

Use the available tools to explore the repository structure.

Respond in the following JSON format ONLY:
{{
    "binary_path": "relative/path/to/binary",
    "refined_harness_command": "/absolute/path/to/binary [flags] <path/to/testcase>",
    "input_file_suffix": ".ext or empty string"
}}

## EXAMPLES

Example 1 (with file suffix):
If harness is: "/src/njs/build/njs /testcase/poc.js"
And repo is: "/home/ubuntu/PoV/Repos/njs"
Then output should be:
{{
    "binary_path": "build/njs",
    "refined_harness_command": "/home/ubuntu/PoV/Repos/njs/build/njs <path/to/testcase>",
    "input_file_suffix": ".js"
}}

Example 2 (without file suffix):
If harness is: "/src/program/bin/parser /testcase/input -o /testcase/output/result.log"
And repo is: "/home/ubuntu/PoV/Repos/program"
Then output should be:
{{
    "binary_path": "bin/parser",
    "refined_harness_command": "/home/ubuntu/PoV/Repos/program/bin/parser <path/to/testcase> -o ./result.log",
    "input_file_suffix": ""
}}
"""

# Some of the prompt contents are removed to handle the code repo that has not been compiled yet, since VulnAnalysis may be earlier than Instrumentation check.
# 1. **Locate the binary**: Find the actual executable binary in the repository
#    - You can refer to harness command to infer the path. Or check common build directories: build/, out/, bin/, .libs/
#    - Use provided tools to locate the binary
#    - Verify it exists and is executable
# 2. **Extract binary_path**: The path RELATIVE to the repository root
#    - Format: build/njs (NOT /home/ubuntu/PoV/Repos/njs/build/njs)
#    - Must be relative to: {actual_repo_path}
# Verify the program file exists in the repository using tools if needed!!
# Be thorough. Verify paths exist before responding.


# Prompt for root cause analysis
VAA_root_cause_analysis_prompt = """You are performing root cause analysis for a vulnerability.

Project: {project_name}
Repository path: {actual_repo_path}

# VULNERABILITY INFORMATION

- Vuln Type: {vuln_type}
- Crash Location: {crash_location}
- Crash Function: {crash_function}
- Entry Location: {entry_location}
- Entry Function: {entry_function}

Command to trigger the vulnerability crash:
```
{refined_harness_command}
```

**Crash Call Trace** (where the vulnerability was triggered):
```
{refined_call_trace}
```

**Allocation Call Trace** (where the problematic memory was allocated, if available):
```
{allocation_trace}
```

**Free Call Trace** (where the memory was freed, for use-after-free and double-free, if available):
```
{free_trace}
```

# YOUR TASK

Your task is to explain the ROOT CAUSE of this vulnerability:

1. Examine the source code at the crash location.
2. Follow the crash call trace to retrieve the source code around the corresponding locations, and analyze the data flow along the function calls, with particular attention to the call sites at each layer.
3. For memory-related vulnerabilities (heap-buffer-overflow, heap-use-after-free, double-free):
   - Use the **allocation trace** to understand where and how the memory was allocated (size, context)
   - For use-after-free and double-free: Use the **free trace** to understand where the memory was freed and why it became a dangling pointer
4. Identify WHY the vulnerability occurs during analysis. (e.g., missing bounds check, use-after-free due to dangling pointer)

Use the provided tools (mainly `ast_grep_search_function`, supplemented by `read_file`) to examine relevant source files.
- All the relative file paths are based on the repository root: {actual_repo_path}
- Some source file line numbers may be inaccurate (i.e., target code line doesn't contain a callsite to next stack frame) due to compiler preprocessing or macro expansion. You may need to read a few lines above the provided line number, and use the callee function name in the next stack frame to pinpoint the correct call-site code snippet!!

Provide a clear, technical explanation starting with "## VULNERABILITY ROOT CAUSE" and covering:
- What the vulnerability is
- Why it occurs (the root cause)
- What code pattern or logic flaw enables it
- Explain what conditions trigger it!
"""


# Prompt for finding actual binary path from a wrapper script
VAA_find_actual_binary_prompt = """You are analyzing a wrapper script to find the actual ELF binary it executes.

Project: {project_name}
Repository path: {actual_repo_path}

# WRAPPER SCRIPT PATH

```
{script_path}
```

# WRAPPER SCRIPT CONTENT

```
{script_content}
```

# YOUR TASK

This script is a wrapper that invokes an actual ELF binary executable. Your task is to identify the path of that actual binary.

Analysis steps:
1. Read the script content carefully.
2. Identify the command(s) that execute the actual binary program.
   - Look for patterns like: `exec /path/to/binary`, `./binary`, `/path/to/binary "$@"`, etc.
   - The binary is typically called with `exec`, or directly invoked as the main command.
3. Determine the binary path:
   - If it's a relative path in the script (e.g., `./build/program`), convert it to be relative to the repository root.
   - If it's an absolute path, extract the portion relative to the repository root.
   - If the script uses variables like `$DIR` or `$(dirname $0)`, resolve them based on the script's location.

IMPORTANT:
- The binary path must be RELATIVE to the repository root: {actual_repo_path}
- Use provided tools to verify the binary file exists in the repository.
- The binary should be an actual ELF executable, not another script.

Respond in the following JSON format ONLY:
{{
    "actual_binary_path": "relative/path/to/binary",
    "reasoning": "brief explanation of how you identified this binary"
}}

Example:
If the script at `tools/run_parser.sh` contains:
```
#!/bin/bash
DIR="$(dirname "$0")/.."
exec "$DIR/build/parser" "$@"
```
And repository root is `/home/ubuntu/PoV/Repos/project`, then output:
{{
    "actual_binary_path": "build/parser",
    "reasoning": "Script uses exec to run $DIR/build/parser where DIR resolves to repository root"
}}
"""


# Useless for now
VAA_critical_step_identification_prompt = """You are analyzing a vulnerability call trace to identify critical function call steps that are essential for triggering the vulnerability.

Project: {project_name}
Repository path: {actual_repo_path}

Vulnerability Information:
- Vuln Type: {vuln_type}

Root Cause Analysis:
```
{root_cause}
```

Refined Call Trace (The highest sequence number is the entry point):
```
{refined_call_trace}
```

Your task is to identify which function calls in the above call trace are CRITICAL for triggering the vulnerability.

IMPORTANT CONCEPTS:
- **Critical steps**: Function calls that are essential to reach the vulnerability point. If these are not executed, the vulnerability cannot be triggered.
- **Non-critical steps**: Basic/common function calls that would be executed by almost any test case (e.g., initialization functions, basic parsing functions). These are less important for our further coverage tracking.

Analysis Steps:
1. Use the code browsing tools to examine the source code for each function in the call trace.
2. Identify which function calls implement key logic that leads to the vulnerability (e.g., specific branching conditions, data transformations, state changes).
3. For each frame in the call trace, determine if it is "critical" based on:
   - Does it perform security-relevant operations (bounds checks, type checks, etc.)?
   - Does it contain conditional branches that filter inputs?
   - Does it transform data in a way specific to triggering the vulnerability?
   - Would most test cases skip this function or take a different path?
   - Is it a function call within a specific case of a switch statement (critical to choose this `case` branch)?

IMPORTANT:
- All file paths are RELATIVE to repository root: {actual_repo_path}
- You MUST use the code browsing tools to examine the actual source code before making judgments
- Be selective: typically only 20-40 percent of frames should be marked as critical

Respond in the following JSON format ONLY:
{{
    "critical_frames": [
        {{
            "sequence_num": <frame_sequence_number>,
            "function_name": "<function_name>",
            "file_path": "<relative_file_path>",
            "line_number": <line_number>,
            "reasoning": "<brief explanation of why this step is critical>"
        }},
        ...
    ],
    "non_critical_frames": [
        {{
            "sequence_num": <frame_sequence_number>,
            "function_name": "<function_name>",
            "reasoning": "<brief explanation of why this step is not critical>"
        }},
        ...
    ]
}}

Be thorough. Use provided tools to examine the code before making your assessment.
"""
