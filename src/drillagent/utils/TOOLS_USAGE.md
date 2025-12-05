# Agent Tools Usage Guide

## Overview

This module provides a set of tools that LLM-based agents can use to interact with code repositories. All tools inherit from the `AgentTool` base class and provide both Claude and OpenAI compatible schemas.

## Available Tools

### 1. ReadFileTool
Read source code files with line numbers.

**Use cases:**
- Examine code mentioned in sanitizer reports
- Read specific functions or code sections
- Understand implementation details

**Example:**
```python
from drillagent.utils.tools import ReadFileTool

tool = ReadFileTool(repo_path="/path/to/repo")

# Read entire file
result = tool.execute(file_path="src/parser.c")

# Read specific line range
result = tool.execute(
    file_path="src/parser.c",
    start_line=100,
    end_line=150
)
```

**Output format:**
```python
{
    "success": True,
    "file_path": "src/parser.c",
    "content": "  100 | void parse_buffer() {\n  101 |   ...",
    "total_lines": 500,
    "displayed_lines": 51,
    "display_range": "100-150"
}
```

---

### 2. GrepTool
Search for patterns across the codebase.

**Use cases:**
- Find function definitions
- Locate symbol usages
- Trace function calls from stack traces

**Example:**
```python
from drillagent.utils.tools import GrepTool

tool = GrepTool(repo_path="/path/to/repo")

# Simple search
result = tool.execute(pattern="malloc")

# Search in specific file type
result = tool.execute(
    pattern="void.*parse",
    file_extension="c",
    max_results=20
)

# Case-insensitive search
result = tool.execute(
    pattern="buffer",
    case_sensitive=False
)
```

**Output format:**
```python
{
    "success": True,
    "pattern": "malloc",
    "matches": [
        {
            "file": "src/memory.c",
            "line": 42,
            "content": "ptr = malloc(size);"
        },
        ...
    ],
    "count": 15,
    "truncated": False,
    "message": "Found 15 matches"
}
```

---

### 3. FindFileTool
Find files by name or pattern.

**Use cases:**
- Locate files mentioned in error messages
- Find header files for includes
- Search for test files

**Example:**
```python
from drillagent.utils.tools import FindFileTool

tool = FindFileTool(repo_path="/path/to/repo")

# Find by exact name
result = tool.execute(filename_pattern="parser.c")

# Find with wildcards
result = tool.execute(filename_pattern="*.h")
result = tool.execute(filename_pattern="test_*.cpp")
```

**Output format:**
```python
{
    "success": True,
    "pattern": "*.h",
    "matches": [
        "src/parser.h",
        "include/buffer.h",
        ...
    ],
    "count": 23,
    "truncated": False
}
```

---

### 4. ListDirTool
List directory contents.

**Use cases:**
- Explore repository structure
- Understand code organization
- Find relevant directories

**Example:**
```python
from drillagent.utils.tools import ListDirTool

tool = ListDirTool(repo_path="/path/to/repo")

# List root directory
result = tool.execute(path=".")

# List subdirectory
result = tool.execute(path="src/utils")
```

**Output format:**
```python
{
    "success": True,
    "path": "src",
    "entries": [
        "parser/",
        "utils/",
        "main.c (5.2KB)",
        "config.h (1.1KB)"
    ],
    "directory_count": 2,
    "file_count": 2,
    "total_count": 4
}
```

---

### 5. TreeTool
Display directory tree structure.

**Use cases:**
- Get overview of repository organization
- Understand project structure
- Navigate unfamiliar codebases

**Example:**
```python
from drillagent.utils.tools import TreeTool

tool = TreeTool(repo_path="/path/to/repo")

# Show full tree (depth 3)
result = tool.execute(path=".", max_depth=3)

# Show only directories
result = tool.execute(
    path="src",
    max_depth=2,
    show_files=False
)
```

**Output format:**
```python
{
    "success": True,
    "path": "src",
    "tree": """
src/
├── parser/
│   ├── lexer.c
│   └── parser.c
└── utils/
    └── helper.c
""",
    "directory_count": 2,
    "file_count": 3
}
```

---

## Integration with LLMs

All tools support conversion to both Claude and OpenAI function calling schemas:

```python
from drillagent.utils.tools import ReadFileTool

tool = ReadFileTool(repo_path="/path/to/repo")

# For Claude
claude_schema = tool.to_claude_schema()

# For OpenAI
openai_schema = tool.to_openai_schema()
```

### Example: Using with Claude

```python
import anthropic
from drillagent.utils.tools import ReadFileTool, GrepTool

# Initialize tools
tools = [
    ReadFileTool(repo_path="/path/to/repo"),
    GrepTool(repo_path="/path/to/repo")
]

# Convert to Claude schemas
tool_schemas = [tool.to_claude_schema() for tool in tools]

# Create Claude client
client = anthropic.Anthropic(api_key="your-key")

# Send message with tools
response = client.messages.create(
    model="claude-3-7-sonnet-20250219",
    messages=[{
        "role": "user",
        "content": "Find the parse_buffer function and read its implementation"
    }],
    tools=tool_schemas,
    max_tokens=4096
)

# Process tool calls
for content in response.content:
    if content.type == "tool_use":
        tool_name = content.name
        tool_args = content.input

        # Execute the tool
        tool = next(t for t in tools if t.name() == tool_name)
        result = tool.execute(**tool_args)

        print(f"Tool: {tool_name}")
        print(f"Result: {result}")
```

---

## Tool Registry Pattern

For easier tool management:

```python
class ToolRegistry:
    """Manage multiple tools"""

    def __init__(self, repo_path: str):
        self.tools = {
            "read_file": ReadFileTool(repo_path),
            "grep_code": GrepTool(repo_path),
            "find_file": FindFileTool(repo_path),
            "list_directory": ListDirTool(repo_path),
            "tree": TreeTool(repo_path)
        }

    def get_tool(self, name: str):
        return self.tools.get(name)

    def execute(self, name: str, **kwargs):
        tool = self.get_tool(name)
        if tool:
            return tool.execute(**kwargs)
        return {"success": False, "error": f"Unknown tool: {name}"}

    def get_all_schemas(self, provider: str = "claude"):
        if provider == "claude":
            return [tool.to_claude_schema() for tool in self.tools.values()]
        elif provider == "openai":
            return [tool.to_openai_schema() for tool in self.tools.values()]

# Usage
registry = ToolRegistry(repo_path="/path/to/repo")

# Execute tool by name
result = registry.execute("read_file", file_path="src/main.c")

# Get all schemas for LLM
schemas = registry.get_all_schemas(provider="claude")
```

---

## Error Handling

All tools return a consistent error format:

```python
{
    "success": False,
    "error": "Descriptive error message",
    "file_path": "context/path" # if applicable
}
```

**Common errors:**
- File/directory not found
- Permission denied
- Invalid regex pattern (GrepTool)
- Binary file encoding (ReadFileTool)

---

## Best Practices

1. **Always check success flag:**
   ```python
   result = tool.execute(...)
   if result["success"]:
       # Process result
   else:
       # Handle error
       print(f"Error: {result['error']}")
   ```

2. **Use appropriate line limits:**
   - ReadFileTool: Use start_line/end_line for large files
   - GrepTool: Set reasonable max_results (default 50)
   - FindFileTool: Limit results to avoid overwhelming output

3. **Provide clear tool descriptions to LLM:**
   - The description field is crucial for LLM to understand when to use each tool
   - Be specific about use cases

4. **Combine tools systematically:**
   ```
   1. FindFile → locate file
   2. ReadFile → examine specific code
   3. Grep → find related symbols
   4. ReadFile → read related code
   ```

---

## Testing

Run the test suite:

```bash
python tests/test_tools.py
```

This will test all tools with various scenarios and verify schema conversions.
