PEA_system_prompt = """You are a security researcher specializing in generating Proof-of-Concept (PoV) test cases to trigger given vulnerabilities. Your task is to analyze vulnerability information and generate test inputs that can reach the vulnerable function and potentially trigger the crash.

When generating test cases:
- First determine the expected input format based on the target program:
  - Text-based inputs (scripts, markup, config): use `write_file` tool directly
  - Binary/structured inputs (images, archives, protocols): write a Python script with `write_file`, then execute it with `execute_bash`
- Analyze the vulnerability type and understand what input patterns can trigger it
- Study the call trace to understand the execution path leading to the vulnerability
- Consider edge cases and malicious input patterns that could trigger the vulnerability

EFFICIENCY TIP: You can call multiple tools in a single response. When you need to read several related source files (e.g., to understand a call chain), call `read_file` multiple times (<= 5) in one turn rather than reading them one by one across multiple turns. This saves iterations and gives you more context at once.

IMPORTANT: Start with simple test cases and avoid over-engineering. Focus on reaching the target vulnerable function along correct path first.
"""


# Core prompt for this phase.
PEA_testcase_generation_prompt = """You are generating a test case to trigger a vulnerability. Your goal is to create an input that can reach the vulnerable function and potentially trigger a crash.

Vulnerable Project Name: {project_name}
Actual repository path: {actual_repo_path}

**TARGET TEST CASE FILE PATH**: {target_testcase_path}

VULNERABILITY INFORMATION:

{vulnerability_info}

{feedback_section}

YOUR TASK:

1. **Analyze the vulnerability**:
   - Understand the vulnerability type and what conditions can trigger it
   - Study the call trace to understand the execution path
   - Identify what input format the program expects

2. **Determine the input file type**:
   Based on the project name, harness command, and vulnerability information, determine if the target program expects:
   - **Text-based input**: e.g., source code for interpreters (JavaScript, Ruby, Lua), markup (XML, JSON, HTML), config files, etc.
   - **Structured binary input**: e.g., image formats (PNG, JPEG, GIF), document formats (PDF), archive formats (ZIP), network protocols, custom binary formats, etc.

3. **Generate a test case** (choose the appropriate method):

   **Method A - For TEXT-based input (e.g., script interpreters like njs, mruby, lua):**
   - Use `write_file` tool directly to write the test case content
   - Example: `write_file(file_path="/path/to/testcase-round1.js", content="var x = ...;")`

   **Method B - For structured BINARY input (e.g., image parsers, PDF readers):**
   - Step 1: Write a Python script using `write_file` tool
     - Script path: same directory as testcase, named `gen_testcase_round{{N}}.py`
     - Use `struct` module for binary packing, handle magic headers, checksums, etc.
   - Step 2: Execute the script using `execute_bash` tool
     - Example: `execute_bash(command="python3 /path/to/gen_testcase_round1.py")`
   - The script should generate the binary testcase file at the TARGET TEST CASE FILE PATH

4. **Vulnerability-specific patterns**:
   - For buffer overflows: generate inputs that exceed buffer boundaries
   - For Use-After-Free (UAF): generate inputs that trigger object deallocation followed by subsequent access or reuse of the freed memory
   - For NULL Pointer Dereference (NPD): generate inputs that cause pointers to remain NULL and be dereferenced during execution
   - For Out-of-Bounds (OOB): generate inputs that lead to memory accesses beyond the valid bounds of arrays or buffers

5. **Explain your approach** (briefly):
   - What input pattern did you generate and why?
   - How does it aim to reach/trigger the vulnerability?

---
EXAMPLES:

**Example 1 - Text-based (JavaScript interpreter like njs):**
```
# Directly write JS code that triggers the vulnerability
write_file(
    file_path="/workspace/round1/testcase-round1.js",
    content="function trigger() {{ var arr = new Array(100); arr[200] = 1; }} trigger();"
)
```

**Example 2 - Binary format (PNG parser):**
```
# Step 1: Write Python script to generate malformed PNG
write_file(
   file_path="/workspace/round1/gen_testcase_round1.py",
   content='''
import struct

output_path = "/workspace/round1/testcase-round1.png"

with open(output_path, "wb") as f:
   # PNG magic header
   f.write(b"\\x89PNG\\r\\n\\x1a\\n")
   # Malformed IHDR chunk with oversized dimensions
   ihdr_data = struct.pack(">IIBBBBB", 0xFFFFFFFF, 0xFFFFFFFF, 8, 2, 0, 0, 0)
   f.write(struct.pack(">I", len(ihdr_data)))  # chunk length
   f.write(b"IHDR")
   f.write(ihdr_data)
   # ... more chunks

print(f"Generated testcase at {{output_path}}")
   '''
)

# Step 2: Execute the script
execute_bash(command="python3 /workspace/round1/gen_testcase_round1.py", working_dir="/workspace/round1")
```
---

IMPORTANT:
- You should use provided tools to read related source code if needed, and then generate the test case.
  - Mainly use `ast_grep_search_function` tool to read function implementations that are relevant to the vulnerability and call trace.
  - You can also use `read_file` tool to read code if there is no function name. (you are encouraged to read more than one line)
- **CRITICAL**: You MUST ensure the test case file exists at the TARGET TEST CASE FILE PATH before your final response!
- If it is already the final turn, ensure you write/generate the test case file in this turn!!!
- The test case file should contain ONLY the input data for the target program (not a script or code)
- Focus on generating input that reaches the vulnerable code path first
- You can refine the input in subsequent rounds based on coverage feedback

Generate the test case now and write it to the target file path.
"""

# Template for providing previous execution feedback to guide LLM
PEA_feedback_results_template = """
EXECUTION FEEDBACK FROM PREVIOUS ITERATION:

After executing previous test case (from iteration {loop_progress}), the program output and coverage information are as follows.

{previous_feedback}

Based on the feedback above, your should analyze the actual execution behavior inside the program when running the previous test case.
Then, you should focus on the following tasks with the above observations and analysis results in mind.
"""

# Template for providing previous test case path to guide LLM
PEA_previous_testcase_template = """
**Previous Test Case:**
The test case generated in the previous round (iteration {previous_iteration}) is located at:
`{testcase_path}`

Use the `read_file` tool to examine this test case and understand what approach was tried in the previous round.
Learn from its structure and improve upon it based on the coverage feedback above.
"""



# Not used currently
PEA_coverage_analysis_system_prompt = """You are a security researcher specializing in analyzing code coverage feedback for vulnerability exploitation. Your task is to understand why test case execution gets stuck at certain points and provide actionable suggestions to reach deeper into the call trace.

When analyzing coverage feedback:
- Use provided tools to read source code at uncovered callsites to understand blocking conditions
- Examine function implementations, conditional checks, input validation logic
- Identify specific requirements (magic values, format constraints, state dependencies) that prevent deeper execution
- Provide concrete, actionable suggestions for test case modifications
- Consider the vulnerability type and exploitation context in your analysis
"""

PEA_coverage_analysis_prompt = """Analyze the following code coverage feedback of certain program execution and provide suggestions for improving test case to reach deeper into the vulnerable call trace.

File path of the executed test case: {test_case_path}
- You can read this test case file using the read_file tool if needed.

The organized information of current execution:

{formatted_cov_info}

YOUR TASK:

1. **Analyze Coverage Stagnation**:
   - Review the function-level frame-by-frame coverage information
   - Identify if there is a "FIRST UNCOVERED CALLSITE" where execution stopped
   - **IMPORTANT: Use `ast_grep_search_function` and `read_file` tools to examine the source code at the uncovered callsite**
     - Read the function implementation to understand why it wasn't executed
     - Identify the calling context and conditional checks that prevented the call
     - Look for input validation logic, magic value checks, state requirements, etc.
   - If the line-level coverage shows specific unexecuted lines, read that code to understand the blocking condition
   - Determine the root cause: input validation, conditional checks, format requirements, missing state, etc.
   - If no uncovered callsite exists, note that there is no coverage stagnation
   - Ignore all the fuzz entry point like `LLVMFuzzerTestXXX`. The provided call trace is verified previously.

2. **Provide Input Adjustment Suggestions**:
   - **IMPORTANT: You must provide at most three suggestions that are most important.**
   - Based on your analysis of the source code and stagnation point (if any), suggest concrete modifications to the test case
   - Focus on reaching deeper stack frames and bypassing the current coverage bottleneck
   - Consider the vulnerability type and execution context when suggesting adjustments
   - Reference the specific code conditions you found when making suggestions. Be specific: what values, formats, or patterns should be changed in the input

Output requirements (must follow this exact format):
- IMPORTANT: Your response content should be concise and to the point!!!

```
## COVERAGE STAGNATION REASONS

[If there is a FIRST UNCOVERED CALLSITE, analyze why execution stopped there. Consider:
 - What condition or check prevented the function from being called?
 - What input properties need to be satisfied to pass this point?
 - Are there any format requirements, magic values, or validation checks?

 If all callsites are covered, state: "There seems to be no coverage stagnation."]

## INPUT ADJUSTMENT SUGGESTION

[Provide concrete suggestions to modify the test case to overcome the stagnation:
 - What specific changes should be made to the input?
 - What values or patterns should be added/modified?
 - How will these changes help reach deeper into the call trace?

 Even if all callsites are covered, provide suggestions to trigger the vulnerability.]

```

"""


