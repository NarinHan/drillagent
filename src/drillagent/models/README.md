# LLM Models

Enhanced LLM interface with provider abstraction and automatic agent loop.

## Core Components

### LLMInterface
Main interface supporting Claude and OpenAI with unified API.

**Key features:**
- Provider abstraction (Claude/OpenAI)
- Automatic conversation management
- Built-in agent loop for tool calling
- Token usage tracking
- Error handling with automatic retries

**Usage modes:**

1. **Simple text generation:**
```python
llm = LLMInterface(provider="claude", model_name="claude-3-7-sonnet-20250219")
response = llm.generate(prompt="Explain Python decorators")
```

2. **Manual tool calling** (backward compatible):
```python
text, tool_calls, msg, stop_reason = llm.generate_with_tools(
    prompt="Analyze this code",
    tools=[ReadFileTool(), BashTool()],
    conversation_history=history
)
```

3. **Automatic agent loop** (recommended):
```python
result = llm.run_agent_loop(
    task="Find all Python files and read main.py",
    tools=[BashTool(), ReadFileTool()],
    max_iterations=10
)
print(result['final_response'])
```

### ConversationManager
Manages conversation history with automatic provider-specific formatting.

**Methods:**
- `add_user_message(content)` - Add user message
- `add_assistant_message(message)` - Add assistant response
- `add_tool_results(tool_calls, results)` - Add tool results (handles provider differences)
- `get_messages()` - Get conversation history

### UsageStats
Tracks API usage statistics.

**Tracked metrics:**
- Total tokens
- Prompt/completion tokens
- API call count

**Usage:**
```python
stats = llm.get_usage_stats()
# {'total_tokens': 1250, 'prompt_tokens': 800, 'completion_tokens': 450, 'api_calls': 3}
```

## Error Handling

Custom exceptions for better error recovery:
- `LLMError` - Base exception
- `RateLimitError` - Rate limit exceeded (auto-retry)
- `TimeoutError` - Request timeout (auto-retry)
- `ToolExecutionError` - Tool execution failed (non-fatal)
- `InvalidResponseError` - Invalid LLM response

## Configuration

**API key priority:**
1. `api_key` parameter
2. `api_key_file` parameter
3. Environment variable (`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`)

**Example:**
```python
llm = LLMInterface(
    provider="openai",
    model_name="gpt-4-turbo",
    api_key_file="/path/to/openai.key"
)
``` 
