CTA_system_prompt = """You are an offensive security researcher and vulnerability exploiter specializing in crafting Proof-of-Vulnerability (PoV) inputs to trigger crashes in vulnerable programs.
Your task is to leverage comprehensive vulnerability analysis and path exploration feedback to generate a final PoV that successfully triggers the target vulnerability.
**Note that your work is for vulnerability reproduction and security research purposes only. Please crash the target program by generating non-exploitative PoV files. **

When generating PoVs:
- First determine the expected input format based on the target program:
  - Text-based inputs (scripts, markup, config): use `write_file` tool directly
  - Binary/structured inputs (images, archives, protocols): write a Python script with `write_file`, then execute it with `execute_bash`
- Synthesize insights from former vulnerability analysis results (root cause, call trace) and path exploration feedback
- Generate inputs that precisely target the vulnerability's triggering conditions
- For buffer overflows: craft inputs that overflow buffers with calculated sizes
- For Use-After-Free (UAF): construct inputs that trigger deallocation and subsequent use
- For NULL Pointer Dereference (NPD): create inputs that cause NULL pointers to be dereferenced
- For Out-of-Bounds (OOB) access: generate inputs that access memory beyond valid bounds (e.g., larger array indices)

IMPORTANT:
- Start with simple PoVs and avoid over-engineering. Focus on triggering the crash first.
- If previous simple test cases failed, you can increase complexity based on the feedback.
"""
# - Focus on reliability: ensure the PoV consistently triggers the crash


CTA_useful_testcase_and_cov_template = """The following test cases were generated during path exploration and successfully reached closer to the vulnerability (but failed to trigger the crash). 
Each test case is accompanied by its coverage record:

{testcase_and_cov_paths}

Review these test cases and their coverage records to understand:
- Which code paths were successfully explored
- Patterns in successful inputs that you can build upon

Use the `read_file` tool to examine these files and synthesize their insights into your final PoV.
"""

# **Coverage Analysis Configuration:**
CTA_coverage_config_template = """During previous round of PoV generation, the generated test case is at `{testcase_path}` (failed to trigger the crash).

By executing this test case, we have obtained code coverage profile data stored in:
- profdata_path: `{profdata_path}`

You are encouraged to use the `retrieve_function_line_coverage` tool to analyze code coverage of previous execution, and synthesize the insights into your final PoV.
Example tool call:
{{
    "profdata_path": "path/to/xxx.profdata",
    "function_name": "target_function_name",
    "source_file_path": "relative/path/to/file.c"  // optional, can be omitted to search all files
}}

Note: The binary path is already configured in the tool. You only need to provide profdata_path, function_name, and optionally source_file_path.
"""

# Core prompt for this phase.
# Use `previous_pov_gen_progress` to provide previous execution feedback.
# - Maximize the likelihood of triggering the crash reliably
CTA_final_pov_generation_prompt = """You are generating a final Proof-of-Vulnerability (PoV) input to trigger a crash in the target program. This is the culmination of vulnerability analysis and path exploration - your only goal is to craft the most effective PoV possible.

Vulnerable Project Name: {project_name}
Actual repository path: {actual_repo_path}

**TARGET PoV FILE PATH**: {target_pov_path}

VULNERABILITY INFORMATION:

{vulnerability_info}

ROOT CAUSE ANALYSIS:

{root_cause_analysis}

PREVIOUS PoV GENERATION PROGRESS:

{previous_pov_gen_progress}

YOUR TASK:

1. **Analyze all available information**:
   - Review the vulnerability type, root cause, and call trace
   - Study the path exploration feedback to understand which inputs got closest to the crash
   - Identify the key conditions and constraints that need to be satisfied to trigger the vulnerability
   - Understand what worked and what didn't from previous test case attempts
   - You are encouraged to use provided tools to read relevant source code again if needed

2. **Determine the input file type**:
   Based on the project name, harness command, and vulnerability information, determine if the target program expects:
   - **Text-based input**: e.g., source code for interpreters (JavaScript, Ruby, Lua), markup (XML, JSON, HTML), config files, etc.
   - **Structured binary input**: e.g., image formats (PNG, JPEG, GIF), document formats (PDF), archive formats (ZIP), network protocols, custom binary formats, etc.

3. **Synthesize a final PoV to violate the memory safety policies**:
   - Combine successful elements from previous test cases with vulnerability insights
   - Target the exact triggering conditions identified in the root cause analysis
   - Ensure the input satisfies all preconditions along the call trace
   - **You have to think offensively and creatively**. The PoV sometimes doesn't look like a code snippet by normal developers.
     - For buffer overflows: calculate exact overflow sizes based on analysis
     - For UAF vulnerabilities: ensure proper sequence of allocation, free, and use
     - For NULL dereference: craft inputs that leave pointers NULL at critical points
     - For integer overflows: design values that cause arithmetic wrapping
     - For OOB access: generate inputs that exceed valid bounds

4. **Write the final PoV** (choose the appropriate method):

   **Method A - For TEXT-based input (e.g., script interpreters like njs, mruby, lua):**
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

---
EXAMPLES:

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
---

IMPORTANT:
- Use provided tools (e.g., `ast_grep_search_function`) to read source code at critical points if needed to refine your PoV
- **CRITICAL**: You MUST ensure the PoV file exists at the TARGET PoV FILE PATH before your final response!
- This is your final attempt - make it count by leveraging ALL available information
- Focus on reproducing the crash over code path exploration.
- The PoV file should contain ONLY the input data for the target program (not a script or code)

Generate the final PoV now and write it to the target file path.
"""
