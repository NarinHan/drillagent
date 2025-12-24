PEA_system_prompt = """You are a security researcher specializing in generating Proof-of-Concept (PoV) test cases to trigger given vulnerabilities. Your task is to analyze vulnerability information and generate test inputs that can reach the vulnerable function and potentially trigger the crash.

When generating test cases:
- Generate inputs that follow the expected format of the target program 
  - (e.g., if the program is a xml parser, generate pure xml content as input)
  - (e.g., if the program is a ruby interpreter, generate pure ruby code as input)
- Analyze the vulnerability type and understand what input patterns can trigger it
- Study the call trace to understand the execution path leading to the vulnerability
- Consider edge cases and malicious input patterns that could trigger the vulnerability
- Return the test case content directly in your response using a code block
"""


PEA_generate_testcase_prompt = """You are generating a test case to trigger a vulnerability. Your goal is to create an input that can reach the vulnerable function and potentially trigger a crash.

Vulnerable Project Name: {project_name}
Actual repository path: {actual_repo_path}

VULNERABILITY INFORMATION:

{vulnerability_info}

{feedback_section}

YOUR TASK:

1. **Analyze the vulnerability**:
   - Understand the vulnerability type and what conditions can trigger it
   - Study the call trace to understand the execution path
   - Identify what input format the program expects

2. **Generate a test case**:
   - Create an input that aims to reach the vulnerable function
   - Consider the program's input format (text file, binary data, specific protocol, etc.)
   - For buffer overflows: generate inputs that exceed buffer boundaries
	- For Use-After-Free (UAF): generate inputs that trigger object deallocation followed by subsequent access or reuse of the freed memory
	- For NULL Pointer Dereference (NPD): generate inputs that cause pointers to remain NULL and be dereferenced during execution
   - For Integer Overflow (IO): generate inputs that cause arithmetic operations to exceed the maximum or minimum representable integer bounds
	- For Out-of-Bounds (OOB): generate inputs that lead to memory accesses beyond the valid bounds of arrays or buffers
	- For Use-Before-Initialization (UBI): generate inputs that cause variables or data structures to be accessed before they are properly initialized

3. **Return the test case in your response**:
   - Include the test case content in a code block marked with ```testcase
   - The code block should contain ONLY the test input data (no analysis, no comments in the test case itself)
   - For text inputs: return as plain text
   - For binary-like inputs that can be represented as text: return as text (e.g., hex strings, escape sequences)
   - Example format:
     ```testcase
     [Your test case content here]
     ```

4. **Explain your approach** (briefly, outside the code block):
   - What input pattern did you generate and why?
   - How does it aim to reach/trigger the vulnerability?

IMPORTANT:
- You should use provided tools and generate the test case.
  - When using read_file tools, you are encouraged to read more than one line.
- If it is already the final turn, ensure you respond with a test case in this turn!!!
- The test case should be pure input data (not a script or code)
- Do NOT include any analysis text or comments inside the ```testcase code block
- Focus on generating input that reaches the vulnerable code path first
- You can refine the input in subsequent rounds based on coverage feedback
- Since we assume text/code-based test cases (not binary), ensure your test case can be represented as text

Generate the test case now and return it in a ```testcase code block.
"""

PEA_feedback_results_template = """
FEEDBACK FROM PREVIOUS ITERATION:

The previous test case (from iteration {loop_progress}) was executed. Here are the results:

{previous_feedback}

Based on the feedback above, your goal is to improve the test case to reach deeper into the call trace toward the vulnerable function.
"""