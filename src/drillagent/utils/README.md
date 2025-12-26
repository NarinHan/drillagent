# Utils and Tools

Utility modules and LLM agent tools for DrillAgent.

## Modules

### tools.py
LLM agent tools for code repository exploration. All tools inherit from `AgentTool` and support both Claude and OpenAI schemas.

**Available tools:**
- `ReadFileTool` - Read source files with line numbers
- `GrepTool` - Search for patterns across codebase
- `FindFileTool` - Find files by name or pattern
- `ListDirTool` - List directory contents
- `TreeTool` - Display directory tree structure

**Usage:**
```python
from drillagent.utils.tools import ReadFileTool, GrepTool

tool = ReadFileTool(repo_path="/path/to/repo")
result = tool.execute(file_path="src/main.c", start_line=100, end_line=150)

# Convert to LLM schema
claude_schema = tool.to_claude_schema()
openai_schema = tool.to_openai_schema()
```

See [TOOLS_USAGE.md](TOOLS_USAGE.md) for detailed documentation.

### llvm_cov.py
LLVM coverage instrumentation and data extraction utilities.

**Key functions:**
- `instrument_code()` - Inject coverage instrumentation into source code
- `parse_coverage_data()` - Extract line/branch coverage from profdata files
- `merge_coverage()` - Combine coverage from multiple executions

### utils.py
General utility functions for file operations, command execution, and data processing.

### logging.py
Logging configuration and utilities for DrillAgent components.
