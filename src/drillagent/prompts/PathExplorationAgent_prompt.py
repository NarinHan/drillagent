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
GENERATION TURN: {generation_turn} / {max_generation_turns}

VULNERABILITY INFORMATION:

{vulnerability_info}

Your task:

1. **Analyze the vulnerability**:
   - Understand the vulnerability type and what conditions can trigger it
   - Study the call trace to understand the execution path
   - Identify what input format the program expects

2. **Generate a test case**:
   - Create an input that aims to reach the vulnerable function
   - For buffer overflows: generate inputs that exceed buffer boundaries
   - For use-after-free: generate inputs that trigger object deallocation and reuse
   - For NULL pointer dereferences: generate inputs that cause NULL pointer access
   - Consider the program's input format (text file, binary data, specific protocol, etc.)

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
- You have {max_generation_turns} turns to use tools and generate the test case
- If it is already the final turn, ensure you respond with a test case in this turn!!!
- The test case should be pure input data (not a script or code)
- Do NOT include any analysis text or comments inside the ```testcase code block
- Focus on generating input that reaches the vulnerable code path first
- You can refine the input in subsequent rounds based on coverage feedback
- Since we assume text/code-based test cases (not binary), ensure your test case can be represented as text

Generate the test case now and return it in a ```testcase code block.
"""

PEA_feedback_section_prompt = """

================================================================================
FEEDBACK FROM PREVIOUS ITERATION
================================================================================

The previous test case (from iteration {previous_iteration}) was executed. Here are the results:

{previous_feedback}

================================================================================
INSTRUCTIONS FOR THIS ITERATION (Iteration {current_iteration})
================================================================================

Based on the feedback above, your goal is to improve the test case to reach deeper into the call trace toward the vulnerable function.

**Analysis Guidelines:**

1. **Examine the coverage summary:**
   - Which functions in the call trace were executed?
   - Which functions were NOT executed?
   - What percentage of the call trace was covered?

2. **Identify the FIRST UNCOVERED CALLSITE:**
   - This is your primary target for this iteration
   - This function is the next step toward reaching the vulnerability
   - Understanding why it wasn't reached is critical

3. **Understand the execution results:**
   - Did the previous test case cause a crash? (check exit code)
   - Were there any error messages in the execution output?
   - Did the program accept the input format?

**Test Case Generation Strategy:**

Based on your analysis, generate a NEW test case that:

- **Fixes any errors** from the previous iteration (if any)
- **Reaches the first uncovered callsite** by adjusting the input to satisfy the conditions needed to enter that function
- **Goes deeper** into the call trace if some functions were already reached
- **Considers the program logic** - what input would cause the program to call the uncovered function?

**Key Principles:**

- Each iteration should make progress toward the vulnerable function
- Don't repeat the exact same test case - analyze what didn't work and adjust
- If you're stuck, try different input patterns or edge cases
- Use the coverage feedback to guide your input generation strategy

Now, generate an improved test case and return it in a ```testcase code block.
"""
