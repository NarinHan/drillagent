# Automated PoV Generation Workflow v0

## Inputs (mainly a Docker image)
- Code repository with certain known vulnerabilities
- Sanitizer report (crash/vulnerability location and call trace)
- Build script
- Test harness commands

## Pipeline

### 1. Preprocessing
- Calculate code distance (distance from basic blocks to crash location)
- Instrument with LLVM coverage (llvm-cov) to track code execution paths
- Instrument with sanitizers to detect runtime issues/crashes

### 2. Vulnerability Analysis
- Extract and summarize the root cause from the sanitizer report
- The analysis results can be used as part of the context for the subsequent stages

### 3. Reachability Exploration
- Generate test cases that can reach the crash location at branch level (may not trigger crash)
- Use in-context reinforcement learning to guide test case generation

### 4. Crash Trigger
- Reanalyze the vulnerability root cause based on the current test case. Collect condition constraints needed to cause the crash.
- Generate and execute test cases to trigger the vulnerability based on the vulnerability understanding. Try N times.

### 5. Result Validation & Formatting
- Re-validate findings using the sanitizer-instrumented program
- Format and output the final PoV
