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
- Extract and summarize the basic and structured vulnerability information from the sanitizer report.
- Reasoning about the vulnerability root cause and critical triggering conditions / steps.
- The analysis results can be used as part of the context for the subsequent stages.

### 2. Code Instrumentation
- Instrument with LLVM coverage (llvm-cov) to track code execution paths.
- Instrument with memory sanitizers to detect runtime issues/crashes. (useless for sec-bench, useful for real-world analysis settings)
- Calculate code distance using static program analysis (distance from basic blocks to crash location). optional...

### 3. Path Exploration
- Generate test cases that can reach the crash location at branch level (may not trigger crash).
- After execution, collect branch-level coverage feedback data and analyze it, to generate better test cases.
- (Future) Use in-context reinforcement learning to guide test case generation.

### 4. Crash Triggering
- Reanalyze the vulnerability root cause based on the current test case. Collect condition constraints needed to cause the crash.
- Generate and execute test cases to trigger the vulnerability based on the vulnerability understanding. Try several times.
- Validate findings using the sanitizer-instrumented program. Format and output the final PoV

