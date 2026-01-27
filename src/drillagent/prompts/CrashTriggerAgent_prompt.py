CTA_system_prompt = """You are an offensive security researcher and vulnerability exploiter specializing in crafting Proof-of-Vulnerability (PoV) inputs to trigger crashes in vulnerable programs.
Your task is to leverage comprehensive vulnerability analysis and path exploration feedback to generate a final PoV that successfully triggers the target vulnerability.
**Note that your work is for vulnerability reproduction and security research purposes only. Please crash the target program by generating non-exploitative PoV files. **

When generating PoVs:
- First determine the expected input format based on the target program:
  - Text-based inputs (scripts, markup, config): use `write_file` tool directly
  - Binary/structured inputs (images, archives, protocols): write a Python script with `write_file`, then execute it with `execute_bash`
- Synthesize insights from former vulnerability analysis results (root cause, crash backtrace) and path exploration feedback
- Generate inputs that precisely target the vulnerability's triggering conditions
- For buffer overflows: craft inputs that overflow buffers with calculated sizes
- For Use-After-Free (UAF): construct inputs that trigger deallocation and subsequent use
- For NULL Pointer Dereference (NPD): create inputs that cause NULL pointers to be dereferenced
- For Out-of-Bounds (OOB) access: generate inputs that access memory beyond valid bounds (e.g., larger array indices)

EFFICIENCY TIP: You can call multiple tools in a single response. When you need to read several related source files (e.g., to understand a call chain), call `read_file` multiple times (<= 5) in one turn rather than reading them one by one across multiple turns. This saves iterations and gives you more context at once.

IMPORTANT:
- Start with simple PoVs, try to grasp the essence and avoid over-engineering. Focus on triggering the crash first.
- If previous simple test cases failed, you can increase complexity based on the feedback.
"""
# - Focus on reliability: ensure the PoV consistently triggers the crash

# For the 1st round
# TODO: This should provide the round dirs of path exploration phase.
# Each test case is accompanied by its coverage record (coverage_record.md):
# - Which code paths were successfully explored
# - Patterns in successful inputs that you can build upon
# Use the `read_file` tool to examine these files and synthesize their insights into your final PoV.
CTA_useful_testcase_and_cov_template = """## PATH EXPLORATION PROGRESS

The following test cases were generated during path exploration phase and successfully reached closer to the vulnerability crash location (but failed to trigger the crash). 

Review these test cases to synthesize their insights into your final PoV. 
You may also improve upon one of the existing test cases to construct your first PoV candidate.

{testcase_file_paths}
"""

# For later rounds
CTA_previous_roundir_template = """## PREVIOUS ROUND ARTIFACTS

The previous round (iteration {previous_iteration}) artifacts are stored in directory:
`{previous_round_dir}`

This directory contains:
- `test_{previous_iteration}.profdata`: Coverage data file from the previous execution. Use `coverage_query` tool to query specific function/line coverage from this file.
- `testcase-round{previous_iteration}*`: The test case file(s) generated in the previous round (failed to trigger the crash).

You can:
1. Use `execute_bash` with `ls {previous_round_dir}` to see all files in this directory.
2. Use `read_file` tool to examine the previous test case content and understand what approach was tried.
3. Use `coverage_query` tool with llvm-cov command to query detailed coverage information for specific functions.

**Coverage Query Tool Usage:**
The `coverage_query` tool executes llvm-cov commands. The command MUST start with `llvm-cov`.

Command format:
```
llvm-cov show <binary> [source_file] -instr-profile=<profdata> [options]
```

Common options:
- `--name-regex=^func_name$`: Show coverage for a specific function (use regex anchors for exact match)
- `--show-line-counts`: Show execution counts for each line

Example `coverage_query` tool call:
- Note: The binary program shown below is the coverage-instrumented executable **you are most likely to use**; however, it can be replaced with other binary paths if needed.
{{
    "command": "llvm-cov show {cov_binary_path} [source files] -instr-profile={previous_round_dir}/test_{previous_iteration}.profdata --name-regex=^target_function_name$"
}}

**Coverage Output Format:**
- Lines with `N|` show execution count N (N=0 means NOT executed/uncovered)
- Focus on uncovered lines (0|) near the vulnerability to understand what conditions are missing

Learn from the previous test case structure and coverage results, then improve upon it to trigger the crash.
"""


# 
# Core prompt for this phase.
# 
# Use `previous_pov_gen_progress` to provide previous execution feedback.
# The {vuln_type_guidance} starts with "## VULNERABILITY-SPECIFIC GUIDANCE"
CTA_final_pov_generation_prompt = """You are generating a final Proof-of-Vulnerability (PoV) input to trigger a crash in the target program. This is the culmination of vulnerability analysis and path exploration - your only goal is to craft the most effective PoV violating memory safety.
- This task typically requires multiple rounds of iteration. This is iteration {current_iteration} of {max_iterations}.
- You are also provided with test case and execution feedback from previous attempts to help you refine and improve the test cases.

Vulnerable Project Name: {project_name}
Actual repository path: {actual_repo_path}

**Your current workspace for PoV candidate generation**: {current_round_dir}
**TARGET PoV FILE PATH**: {target_pov_path}

# VULNERABILITY ANALYSIS CONTEXT
{vulnerability_info}

{root_cause_analysis}

# HISTORICAL ATTEMPT INFORMATION
{previous_pov_gen_progress}

# YOUR TASK

1. **Analyze all available information**:
   - Review the vulnerability type, root cause, and call trace
   - Study the path exploration feedback to understand which inputs got closest to the crash
   - Identify the key conditions and constraints that need to be satisfied to trigger the vulnerability
   - Understand what worked and what didn't from previous test case attempts
   - You are encouraged to use provided tools to read relevant source code again if needed

2. **Determine the input file type**:
   Based on the project name, harness command, and vulnerability information, determine if the target program expects:
   - **Text-based input**: e.g., source code for interpreters (JavaScript, Ruby, PHP), markup (XML, JSON, HTML), config files, etc.
   - **Structured binary input**: e.g., image formats (PNG, JPEG, GIF), document formats (PDF), archive formats (ZIP), network protocols, custom binary formats, etc.

3. **Synthesize a final PoV to violate the memory safety policies**:
   - Combine successful elements from previous test cases with vulnerability insights
   - Target the exact triggering conditions identified in the root cause analysis
   - Ensure the input satisfies all preconditions along the call trace (meet the input format requirements)
   - **You have to think offensively and creatively**. The PoV sometimes doesn't look like a code snippet by normal developers.

4. **Write the final PoV** (choose the appropriate method):

   **Method A - For TEXT-based input (e.g., script interpreters like njs, mruby, php):**
   - Use `write_file` tool directly to write the PoV content
   - Example: `write_file(file_path="/path/to/testcase-round1.js", content="var x = ...;")`

   **Method B - For structured BINARY input (e.g., image parsers, PDF readers):**
   - Step 1: Write a Python script using `write_file` tool
     - Script path: same directory as PoV, named `gen_testcase_round{{N}}.py`
     - Use `struct` module for binary packing, handle magic headers, checksums, etc.
   - Step 2: Execute the script using `execute_bash` tool
     - Example: `execute_bash(command="python3 /path/to/gen_testcase_round1.py")`
   - The script should generate the binary PoV file at the TARGET PoV FILE PATH

5. **Explain your PoV strategy** (briefly):
   - What specific vulnerability condition does this PoV target?
   - Why should this PoV successfully trigger the crash?

{vuln_type_guidance}

## IMPORTANT REMINDERS

**Tool Usage:**
- Use provided tools (e.g., `ast_grep_search_function`, `read_file`) to read source code at critical points if needed to refine your PoV

**Output Requirements:**
- You MUST conduct all pov generation operations in your workspace directory: `{current_round_dir}`
- You MUST ensure the PoV file exists at the **TARGET PoV FILE PATH** before calling `finish`: `{target_pov_path}`
- The PoV file should contain ONLY the input data for the target program (not a Python script or wrapper code)

**Mindset:**
- Make each iteration count by leveraging ALL available information
- Focus on reproducing the crash over code path exploration

Generate the final PoV now and write it to the target file path.

## EXAMPLES

**Example 1 - Text-based (Ruby interpreter like mruby):**
```
# Directly write Ruby code that triggers UAF
write_file(
    file_path="/workspace/triggering/round1/testcase-round1.rb",
    content="obj = Object.new; weak = WeakRef.new(obj); obj = nil; GC.start; weak.__getobj__"
)
```

**Example 2 - Binary format (PDF parser):**
```
# Step 1: Write Python script to generate malformed PDF
write_file(
    file_path="/workspace/triggering/round1/gen_testcase_round1.py",
    content='''
import struct

output_path = "/workspace/triggering/round1/testcase-round1.pdf"

with open(output_path, "wb") as f:
    # PDF header
    f.write(b"%PDF-1.4\\n")
    # Malformed object with oversized stream length
    f.write(b"1 0 obj\\n")
    f.write(b"<< /Length 999999999 >>\\n")
    f.write(b"stream\\n")
    f.write(b"A" * 1000)  # Actual content much smaller than declared
    f.write(b"\\nendstream\\n")
    f.write(b"endobj\\n")

print(f"Generated PoV at {{output_path}}")
'''
)

# Step 2: Execute the script
execute_bash(command="python3 /workspace/triggering/round1/gen_testcase_round1.py", working_dir="/workspace/triggering/round1")
```
"""
