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
1. Extract the sequence number (the number after #).
2. Extract the function name (the text after "in" if present, otherwise use empty string).
3. Extract the file path and convert it to a RELATIVE path based on the repository root: {actual_repo_path}.
4. Extract the line number (the number after the colon in file:line format). 

IMPORTANT PATH CONVERSION RULES:
- If the path contains the project name (e.g., "/home/b/asan/libplist/tools/plistutil.c"), extract the relative part (e.g., "tools/plistutil.c").
- If the path is a system library (e.g., "/lib/i386-linux-gnu/libc.so.6" or contains libasan, libstdc++, libc), keep it as-is but mark it as external.
- The relative path should start from the repository root.
- Remove any absolute path prefix that includes the repository path.

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

VAA_call_trace_linenum_refine_prompt = """You are refining line numbers in a structured call trace to ensure accuracy.

Project: {project_name}
Repository path: {actual_repo_path}

Current Call Trace (with potentially inaccurate line numbers):
```
{current_call_trace}
```

Your task is to verify and adjust line numbers for accuracy by examining the actual source code.

CRITICAL: You MUST use the `read_file` tool to verify and adjust line numbers for accuracy!

Line Number Verification Requirements: In each stack frame, the `file:line` should indicate the call site to the **next** stack frame's **callee function**.
- Because of compiler preprocessing or macro expansion, some line numbers may be inaccurate (i.e., target code line doesn't contain a callsite to next stack frame). Such inaccurate line numbers usually require subtracting an offset to be precise.
- Correct example: If frame #17 is `main @ tools/plistutil.c:137` and frame #16 is `njs_function @ src/njs_function.c:574`, then tools/plistutil.c:137 should contain a call site to njs_function.

For all stack frames:
- You MUST use `read_file` to examine the source code around the provided line number.
- Check the target line for a call site to the next frame's callee function:
  * If the call site is an indirect function call (e.g., (*callback)(arg); or func_ptr(); or handler->process();), keep the original non-zero line number and mark this frame with `"is_original_linenum": true`.
  * If the target line does not contain a call to the next frame's callee function, read a few lines above (typically 1-15 lines) to find the correct call-site code snippet. Use the callee function name from the next stack frame to pinpoint the correct call site:
    - If you find the correct call site, update the line number accordingly.
    - If you cannot find the correct line number after thorough checking, keep the original non-zero line number and mark this frame with `"is_original_linenum": true`.
- CRITICAL RULE: The final line_number must NEVER be 0. Always use the original non-zero line number if you cannot determine a better value.
- After verifying all frames, provide the adjusted line numbers in your final JSON output.

IMPORTANT:
- Process frames from innermost (lowest sequence_num) to outermost (highest sequence_num)
- For each frame (sequence_num=N), look at the NEXT frame (sequence_num = N-1) to find the callee function name
- All file paths are RELATIVE to repository root: {actual_repo_path}

VALIDATION RULE: EVERY frame's line_number MUST be > 0 (NEVER 0) !!!

Respond in the following JSON format ONLY:
{{
    "call_trace": [
        {{
            "sequence_num": 16,
            "function_name": "njs_function",
            "file_path": "src/njs_function.c",
            "line_number": 574,
            "is_external": false,
            "is_original_linenum": false
        }},
        {{
            "sequence_num": 17,
            "function_name": "main",
            "file_path": "tools/plistutil.c",
            "line_number": 137,
            "is_external": false,
            "is_original_linenum": true
        }}
    ]
}}

Note: Set `"is_original_linenum": true` when you keep the original line number because:
- The call site is an indirect function call, OR
- You cannot find the correct call site line after thorough checking

Make sure all line numbers have been verified and adjusted as needed using the read_file tool.
After you generate the first JSON formatted response, re-verify that all line numbers are correct before finalizing your answer. EVERY frame's line_number MUST be > 0 (NEVER 0) !!!
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
- Some source file line numbers may be inaccurate (i.e., target code line doesn't contain a callsite to next stack frame) due to compiler preprocessing or macro expansion. You may need to read a few lines above the provided line number, and use the callee function name in the next stack frame to pinpoint the correct call-site code snippet!!

Provide a clear, technical explanation starting with "## VULNERABILITY ROOT CAUSE ANALYSIS" and covering:
- What the vulnerability is
- Why it occurs (the root cause)
- What code pattern or logic flaw enables it
- Explain what conditions trigger it!

"""

