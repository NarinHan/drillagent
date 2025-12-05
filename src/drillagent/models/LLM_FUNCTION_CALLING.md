# LLM Function Calling Guide

## Overview

The enhanced `LLM` class now supports **function calling** (also known as tool use), allowing the LLM to autonomously decide when and how to use tools to complete tasks.

## Key Features

✅ **Native function calling** for both Claude and OpenAI
✅ **Multi-turn conversations** with history tracking
✅ **Flexible API key loading** (parameter, file, or environment variable)
✅ **Unified interface** - same code works for both providers

---

## Quick Start

### Basic Setup

```python
from drillagent.models.llm import LLM
from drillagent.utils.tools import ReadFileTool, GrepTool

# Initialize LLM (API key from file)
llm = LLM(
    provider="openai",
    model_name="gpt-4-turbo",
    api_key_file="/path/to/api.key"
)

# Initialize tools
tools = [
    ReadFileTool(repo_path="/path/to/repo"),
    GrepTool(repo_path="/path/to/repo")
]

# Call LLM with tools
text_response, tool_calls = llm.generate_with_tools(
    prompt="Find the main function in this repository",
    tools=tools,
    system_prompt="You are a code exploration assistant"
)

# Process results
print(f"LLM Response: {text_response}")
print(f"Tool Calls: {tool_calls}")
```

### Output Format

The `generate_with_tools()` method returns a tuple:

```python
(text_response, tool_calls)
```

Where:
- **text_response** (str): LLM's reasoning and analysis
- **tool_calls** (list): List of tool invocations

Each tool call has this format:
```python
{
    "id": "call_abc123",           # Unique call identifier
    "name": "read_file",            # Tool name
    "arguments": {                  # Tool arguments
        "file_path": "src/main.c",
        "start_line": 1,
        "end_line": 50
    }
}
```

---

## Complete Agent Loop Example

Here's a full agent that autonomously uses tools until task completion:

```python
from drillagent.models.llm import LLM
from drillagent.utils.tools import ReadFileTool, GrepTool, FindFileTool

# Setup
llm = LLM(provider="openai", api_key_file="/path/to/key")
tools = [
    ReadFileTool("/path/to/repo"),
    GrepTool("/path/to/repo"),
    FindFileTool("/path/to/repo")
]
tool_registry = {tool.name(): tool for tool in tools}

system_prompt = """You are a code analysis assistant.
Use the available tools to systematically explore and analyze code."""

task = "Find the buffer overflow vulnerability in this repository"

# Agent loop
conversation_history = []
max_iterations = 10

for iteration in range(max_iterations):
    print(f"\n--- Iteration {iteration + 1} ---")

    # Call LLM with tools
    text_response, tool_calls = llm.generate_with_tools(
        prompt=task if iteration == 0 else tool_results_message,
        tools=tools,
        system_prompt=system_prompt,
        conversation_history=conversation_history,
        temperature=0.3
    )

    # Update conversation history
    conversation_history.append({
        "role": "user",
        "content": task if iteration == 0 else tool_results_message
    })
    conversation_history.append({
        "role": "assistant",
        "content": text_response
    })

    # If no tool calls, LLM is done
    if not tool_calls:
        print("Task completed!")
        print(f"Final answer: {text_response}")
        break

    # Execute tools
    tool_results_message = "Tool results:\n"
    for tool_call in tool_calls:
        tool = tool_registry[tool_call["name"]]
        result = tool.execute(**tool_call["arguments"])
        tool_results_message += f"\n{tool_call['name']}: {result}\n"

    task = f"Based on these results, continue the analysis:\n{tool_results_message}"
```

---

## API Reference

### LLM Class

#### Constructor

```python
LLM(provider="claude", model_name=None, api_key=None, api_key_file=None)
```

**Parameters:**
- `provider` (str): "claude" or "openai"
- `model_name` (str, optional): Model to use
  - Claude default: "claude-3-7-sonnet-20250219"
  - OpenAI default: "gpt-4-turbo"
- `api_key` (str, optional): API key (takes precedence)
- `api_key_file` (str, optional): Path to file containing API key

**API Key Priority:**
1. `api_key` parameter
2. `api_key_file` parameter
3. Environment variable (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`)

#### Methods

##### generate() - Simple Text Generation

```python
def generate(
    prompt: str,
    system_prompt: Optional[str] = None,
    temperature: float = 0.7,
    max_tokens: int = 4096
) -> str
```

Returns plain text response (no tool calling).

##### generate_with_tools() - Function Calling

```python
def generate_with_tools(
    prompt: str,
    tools: List[AgentTool],
    system_prompt: Optional[str] = None,
    conversation_history: Optional[List[Dict]] = None,
    temperature: float = 0.7,
    max_tokens: int = 4096
) -> Tuple[str, List[Dict[str, Any]]]
```

**Parameters:**
- `prompt`: User's task or question
- `tools`: List of AgentTool instances
- `system_prompt`: Instructions for the LLM
- `conversation_history`: Previous messages for context
- `temperature`: Sampling temperature (0.0-1.0)
- `max_tokens`: Maximum tokens to generate

**Returns:**
- `(text_response, tool_calls)` tuple

---

## Multi-Turn Conversations

Track conversation history for context-aware interactions:

```python
conversation_history = []

# Turn 1
text, calls = llm.generate_with_tools(
    prompt="Find all C files",
    tools=tools,
    conversation_history=conversation_history
)

conversation_history.append({"role": "user", "content": "Find all C files"})
conversation_history.append({"role": "assistant", "content": text})

# Turn 2 - references previous context
text, calls = llm.generate_with_tools(
    prompt="Now read the first file you found",
    tools=tools,
    conversation_history=conversation_history
)
```

---

## Provider-Specific Notes

### Claude (Anthropic)
- Uses Claude's native `tools` parameter
- Tool calls returned as `tool_use` content blocks
- Supports streaming (not yet implemented)

### OpenAI
- Uses OpenAI's `functions` API
- Tool calls returned in `message.tool_calls`
- `tool_choice="auto"` lets LLM decide

Both providers support the same interface through our abstraction layer!

---

## Best Practices

### 1. Write Clear System Prompts

```python
system_prompt = """You are a security analyst finding vulnerabilities.

Your approach:
1. First, explore the repository structure
2. Search for dangerous functions (malloc, strcpy, etc.)
3. Read and analyze suspicious code
4. Provide detailed vulnerability report

Available tools: read_file, grep_code, find_file"""
```

### 2. Set Appropriate Temperature

- **0.0-0.3**: Focused, deterministic (recommended for code analysis)
- **0.5-0.7**: Balanced creativity and focus
- **0.8-1.0**: More creative, less predictable

### 3. Limit Iterations

Always set a maximum iteration count to prevent infinite loops:

```python
max_iterations = 15  # Prevent runaway agents
for i in range(max_iterations):
    # ... agent logic
```

### 4. Handle Tool Execution Errors

```python
for tool_call in tool_calls:
    try:
        tool = tool_registry[tool_call["name"]]
        result = tool.execute(**tool_call["arguments"])

        if not result.get("success"):
            # Inform LLM of error
            error_msg = f"Tool {tool_call['name']} failed: {result['error']}"
    except Exception as e:
        error_msg = f"Tool execution error: {str(e)}"
```

### 5. Provide Feedback to LLM

After tool execution, give results back to LLM:

```python
tool_results_text = ""
for tool_call in tool_calls:
    result = execute_tool(tool_call)
    tool_results_text += f"\nTool '{tool_call['name']}': {result}\n"

# Next iteration prompt
next_prompt = f"Based on these tool results, continue:\n{tool_results_text}"
```

---

## Example: Sanitizer Report Analysis

```python
from drillagent.models.llm import LLM
from drillagent.utils.tools import ReadFileTool, GrepTool

# Setup
llm = LLM(provider="openai", api_key_file="openai.key")
tools = [
    ReadFileTool("/path/to/vulnerable/repo"),
    GrepTool("/path/to/vulnerable/repo")
]

# Sanitizer report
sanitizer_report = """
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x60300000eff4 thread T0
    #0 0x4a8f12 in parse_buffer /src/parser.c:142:5
    #1 0x4a7c3d in process_input /src/main.c:78:9
    #2 0x4a7890 in main /src/main.c:120:5
"""

system_prompt = """You are a vulnerability analyst. Use tools to:
1. Read code at crash locations
2. Trace back through call stack
3. Identify root cause
4. Suggest fix"""

task = f"""Analyze this sanitizer report and find the root cause:

{sanitizer_report}

Use the tools to examine the code."""

# Run agent
conversation_history = []
for i in range(10):
    text, tool_calls = llm.generate_with_tools(
        prompt=task,
        tools=tools,
        system_prompt=system_prompt,
        conversation_history=conversation_history
    )

    if not tool_calls:
        print(f"Analysis: {text}")
        break

    # Execute tools and continue...
```

---

## Testing

Run the test suites:

```bash
# Basic function calling test
python tests/test_llm_function_calling.py

# Complete agent task test
python tests/test_llm_complete_task.py
```

---

## Troubleshooting

### API Key Issues

```python
# Check if API key is loaded
llm = LLM(provider="openai", api_key_file="/path/to/key")
print(f"API key loaded: {llm.api_key[:10]}...")  # First 10 chars
```

### Tool Not Being Called

- Check tool description clarity
- Lower temperature (< 0.5) for more focused tool use
- Verify system prompt mentions available tools
- Ensure task is specific enough

### Too Many Tool Calls

- Add iteration limit
- Improve system prompt to be more efficient
- Use higher temperature for more decisive choices

---

## Performance Tips

1. **Batch tool calls**: Some tasks allow multiple tools in one turn
2. **Cache results**: Store frequently accessed files
3. **Limit context**: Don't send entire file contents if unnecessary
4. **Use appropriate max_tokens**: Balance between cost and completeness

---

## Next Steps

After mastering function calling, consider:
1. Implementing specialized tools (SanitizerParser, StackTraceAnalyzer)
2. Adding error recovery and retry logic
3. Implementing streaming for real-time feedback
4. Creating a full AgentExecutor class
