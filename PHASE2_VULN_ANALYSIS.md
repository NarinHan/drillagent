# Phase 2: Vulnerability Analysis - Final Implementation

## Overview

The `VulnAnalysisAgent` performs **multi-round LLM-based root cause analysis** for vulnerabilities using sanitizer reports and code exploration tools.

## Key Features

### ✅ Generic Implementation
- **No hardcoded project names** - works with ANY C/C++ project
- Automatically extracts relative paths from sanitizer reports
- Adapts to different vulnerability types

### ✅ Multi-Round Analysis
- LLM explores code iteratively (up to 5 rounds)
- **LLM decides when done** - stops when no more tools needed
- Each round feeds tool results back for deeper understanding

### ✅ Guaranteed Output
- `call_trace` - Extracted from sanitizer report (stack frames)
- `vuln_type` - Detected from sanitizer (heap-use-after-free, etc.)
- `crash_function` - Parsed from #0 frame
- `entry_function` - Found from call trace (usually "main")
- `root_cause` - LLM's detailed analysis
- `refined_vuln_location` - File:line of crash

## Workflow

```
1. Load sanitizer report from CVE JSON file
   ↓
2. Extract basics: vuln_type, crash_function, call_trace
   ↓
3. Round 1: LLM reads sanitizer → Calls read_file on crash location
   ↓
4. Round 2: LLM analyzes code → Calls grep_code for related functions
   ↓
5. Round 3-N: LLM explores deeper OR provides final analysis
   ↓
6. Done: Returns all fields with root cause explanation
```

## Usage

### Command
```bash
python src/drillagent/scripts/main_test.py <repo_path> --cve <cve_id>
```

### Example
```bash
python src/drillagent/scripts/main_test.py \
  /home/shared_project/repos/mruby/ \
  --cve mruby.cve-2022-1934
```

### What Happens
1. **Loads CVE data** from `datasets/sec-bench/CVE-instances/mruby.cve-2022-1934.json`
2. **Extracts sanitizer report** 
3. **Runs Phase 2 analysis**:

```
[VulnAnalysisAgent] Sanitizer report: 5901 chars
[VulnAnalysisAgent] Extracted: heap-use-after-free @ src/vm.c:1167

============================================================
[Round 1/5] Calling LLM...
============================================================

[LLM Response]: I'll analyze this vulnerability...

[Executing 2 tools...]
  read_file({"file_path": "src/vm.c", "start_line": 1160, ...})
  Result: 
  1163 | hash_new_from_values(mrb_state *mrb, ...)
  1167 |     mrb_hash_set(mrb, hash, regs[0], regs[1]);
  ...
  
  grep_code({"pattern": "mrb_hash_set"})
  Found 15 matches...

============================================================
[Round 2/5] Calling LLM...
============================================================

[LLM Response]: The root cause is that the `regs` pointer 
becomes invalid after stack reallocation. When mrb_hash_set 
is called (line 1167), it may trigger stack extension via 
mrb_funcall, which reallocates the stack. This invalidates 
the `regs` pointer, causing use-after-free on subsequent 
iterations of the loop.

[Round 2] LLM finished - no more tools needed

============================================================
[ROOT CAUSE ANALYSIS]
============================================================
The root cause is that the `regs` pointer becomes invalid...
============================================================

[VulnAnalysisAgent] ✓ Complete
  Type: heap-use-after-free
  Crash: hash_new_from_values
  Entry: main
```

## Output Fields

```python
{
    'vuln_type': 'heap-use-after-free',
    'call_trace': '#0 in hash_new_from_values...\n#1 in mrb_vm_exec...',
    'crash_function': 'hash_new_from_values',
    'entry_function': 'main',
    'refined_vuln_location': 'src/vm.c:1167',
    'root_cause': 'The root cause is that the regs pointer...',
    'critical_branches': []
}
```

## Implementation Details

### Call Trace Extraction
```python
def _extract_call_trace(report):
    # Extract all #N frames from sanitizer output
    lines = []
    for line in report.split('\n'):
        if re.match(r'^\s*#\d+', line.strip()):
            lines.append(line.strip())
    return '\n'.join(lines)
```

### Vulnerability Type Detection
```python
def _extract_vuln_type(report):
    # Match known sanitizer error types
    if 'heap-use-after-free' in report.lower():
        return 'heap-use-after-free'
    elif 'heap-buffer-overflow' in report.lower():
        return 'heap-buffer-overflow'
    # etc...
```

### Crash Location Parsing
```python
def _extract_crash_info(report):
    # Parse #0 frame: #0 in function /path/file.c:line
    # Returns: {'function': 'hash_new_from_values', 
    #           'location': 'src/vm.c:1167'}
```

### Multi-Round Loop
```python
for round_num in range(max_rounds):
    response, tool_calls = llm.generate_with_tools(prompt)
    
    if not tool_calls:
        # LLM is done!
        root_cause = response
        break
    
    # Execute tools and continue
    tool_results = execute_tools(tool_calls)
    prompt = f"Tool results: {tool_results}. Continue or finish."
```

## Configuration

- **Max Rounds**: 5 (configurable in code)
- **Temperature**: 0.3 (deterministic analysis)
- **Max Tokens**: 4096 per LLM call
- **Tools**: read_file, grep_code, find_file, list_directory, tree

## Notes

- LLM **receives full sanitizer report** in first prompt
- Basic fields extracted immediately (don't wait for LLM)
- LLM focuses on explaining **root cause** via code exploration
- Clean, simple prompts without project-specific details
- HTTP debug logs suppressed for cleaner output

