# Automated PoV Generation Workflow v1

## Inputs

- Code repository
- Target location of certain known vulnerability
- Sanitizer report (optional)
- Project build script (optional)
- Test harness commands (optional)

(Sometimes all above inputs can be included in a docker image)

## Pipeline

### 1. Vulnerability Analysis
- Extract and summarize basic vulnerability information from the sanitizer report (e.g., crash backtrace), with additional refinement.
- Analyze the harness command used to trigger the vulnerability and identify the required input file suffix, if any.
- Reason about the vulnerability root cause and the triggering conditions, including the critical steps required to reproduce it.

<!-- - The analysis results can be used as part of the context for the subsequent stages. -->

### 2. Code Instrumentation
- Instrument the program with LLVM coverage to track executed code (based on llvm-cov).
- Instrument the program with memory sanitizers to detect runtime crashes.
<!-- - Calculate code distance using static program analysis (distance from basic blocks to crash location). optional... -->

### 3. Path Exploration
- Generate test cases that aim to reach the crash location at the branch level, without necessarily triggering the crash.
- Execute the test case using the coverage-instrumented program.
- Collect and analyze branch-level coverage feedback data to generate better test cases.
<!-- - (Future) Use in-context reinforcement learning to guide test case generation. -->

### 4. Crash Triggering
<!-- - Reanalyze the vulnerability root cause based on the current test case. Collect condition constraints needed to cause the crash. -->
- Review previous test cases and analyze any additional constraints required to trigger the crash.
- Generate test cases that aim to trigger the crash, and employ a prompt sampler to provide tailored instructions for different vulnerability types.
- Validate the PoV candidates using the sanitizer-instrumented program. If failed, retry.

