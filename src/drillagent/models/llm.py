"""
LLM interface for DrillAgent
Supports Claude and OpenAI with both simple text generation and tool calling.
"""

import os
import json
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path

"""
Usage:
1. generate(): Simple text generation without tools
2. generate_with_tools(): Tool calling support with conversation history
3. create_tool_result_message(): Create tool result messages in official API format
"""
class LLM:
    """Enhanced LLM interface with function calling support"""

    def __init__(self, provider: str = "claude", model_name: Optional[str] = None,
                 api_key: Optional[str] = None, api_key_file: Optional[str] = None):
        """
        Args:
            provider: "claude" or "openai"
            model_name: Model name (default: claude-3-7-sonnet-20250219 or gpt-4-turbo)
            api_key: API key string (takes precedence)
            api_key_file: Path to file containing API key
        """
        self.provider = provider.lower()

        # Set default model names
        if model_name is None:
            if self.provider == "claude":
                model_name = "claude-3-7-sonnet-20250219"
            elif self.provider == "openai":
                model_name = "gpt-4-turbo"
            else:
                raise ValueError(f"Unsupported provider: {provider}")

        self.model_name = model_name

        # Get API key (priority: parameter > file > environment)
        if api_key is None:
            if api_key_file and Path(api_key_file).exists():
                with open(api_key_file, 'r') as f:
                    api_key = f.read().strip()
            else:
                if self.provider == "claude":
                    api_key = os.environ.get("ANTHROPIC_API_KEY")
                elif self.provider == "openai":
                    api_key = os.environ.get("OPENAI_API_KEY")

        if not api_key:
            raise ValueError(
                f"API key not found for {provider}. "
                f"Provide via api_key parameter, api_key_file, or environment variable."
            )

        self.api_key = api_key

        # Initialize client
        if self.provider == "claude":
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError("anthropic package not found. Install it with: pip install anthropic")
        elif self.provider == "openai":
            try:
                import openai
                self.client = openai.OpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError("openai package not found. Install it with: pip install openai")

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 temperature: float = 0.7, max_tokens: int = 4096) -> str:
        """
        Generate text from prompt (simple text generation without tools)
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            temperature: Sampling temperature (0.0 to 1.0)
            max_tokens: Maximum tokens to generate
        Returns:
            Generated text
        """
        if self.provider == "claude":
            return self._generate_claude(prompt, system_prompt, temperature, max_tokens)
        elif self.provider == "openai":
            return self._generate_openai(prompt, system_prompt, temperature, max_tokens)

    def generate_with_tools(self,
                           prompt: str,
                           tools: List,  # List of AgentTool instances
                           system_prompt: Optional[str] = None,
                           conversation_history: Optional[List[Dict]] = None,
                           temperature: float = 0.7,
                           max_tokens: int = 4096) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
        """
        Generate response with tool calling support
        Args:
            prompt: User prompt
            tools: List of AgentTool instances available for the LLM
            system_prompt: Optional system instruction
            conversation_history: Previous messages for multi-turn conversation
            temperature: Sampling temperature
            max_tokens: Max tokens to generate
        Returns:
            Tuple of (text_response, tool_calls, assistant_message)
            - text_response: LLM's textual reasoning/response
            - tool_calls: List of tool calls, each with format:
              [{"id": "call_id", "name": "tool_name", "arguments": {...}}, ...]
            - assistant_message: Complete assistant message in official API format
              (ready to be added to conversation_history)
        """
        if self.provider == "claude":
            return self._generate_with_tools_claude(
                prompt, tools, system_prompt, conversation_history, temperature, max_tokens
            )
        elif self.provider == "openai":
            return self._generate_with_tools_openai(
                prompt, tools, system_prompt, conversation_history, temperature, max_tokens
            )

    def _generate_claude(self, prompt: str, system_prompt: Optional[str],
                        temperature: float, max_tokens: int) -> str:
        """Generate using Claude API (simple text generation)"""
        messages = [{"role": "user", "content": prompt}]

        kwargs = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if system_prompt:
            kwargs["system"] = system_prompt

        response = self.client.messages.create(**kwargs)
        return response.content[0].text

    def _generate_openai(self, prompt: str, system_prompt: Optional[str],
                        temperature: float, max_tokens: int) -> str:
        """Generate using OpenAI API (simple text generation)"""
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        return response.choices[0].message.content

    def _generate_with_tools_claude(self,
                                    prompt: str,
                                    tools: List,
                                    system_prompt: Optional[str],
                                    conversation_history: Optional[List[Dict]],
                                    temperature: float,
                                    max_tokens: int) -> Tuple[str, List[Dict], Dict]:
        """Claude-specific tool calling implementation"""

        # Convert tools to Claude's schema
        tool_schemas = [tool.to_claude_schema() for tool in tools]

        # Build messages
        messages = conversation_history.copy() if conversation_history else []
        messages.append({"role": "user", "content": prompt})

        # Call Claude API with tools
        kwargs = {
            "model": self.model_name,
            "messages": messages,
            "tools": tool_schemas,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        if system_prompt:
            kwargs["system"] = system_prompt

        response = self.client.messages.create(**kwargs)

        # Parse response
        text_response = ""
        tool_calls = []
        content_blocks = []

        for content_block in response.content:
            if content_block.type == "text":
                text_response += content_block.text
                content_blocks.append({
                    "type": "text",
                    "text": content_block.text
                })
            elif content_block.type == "tool_use":
                tool_calls.append({
                    "id": content_block.id,
                    "name": content_block.name,
                    "arguments": content_block.input
                })
                content_blocks.append({
                    "type": "tool_use",
                    "id": content_block.id,
                    "name": content_block.name,
                    "input": content_block.input
                })

        # Build complete assistant message in Claude's official format
        assistant_message = {
            "role": "assistant",
            "content": content_blocks
        }

        return text_response, tool_calls, assistant_message

    def _generate_with_tools_openai(self,
                                    prompt: str,
                                    tools: List,
                                    system_prompt: Optional[str],
                                    conversation_history: Optional[List[Dict]],
                                    temperature: float,
                                    max_tokens: int) -> Tuple[str, List[Dict], Dict]:
        """OpenAI-specific tool calling implementation"""

        # Convert tools to OpenAI's schema
        tool_schemas = [tool.to_openai_schema() for tool in tools]

        # Build messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        if conversation_history:
            messages.extend(conversation_history)

        messages.append({"role": "user", "content": prompt})

        # Call OpenAI API with tools
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            tools=tool_schemas,
            tool_choice="auto",  # LLM decides whether to use tools
            temperature=temperature,
            max_tokens=max_tokens
        )

        # Parse response
        message = response.choices[0].message
        text_response = message.content or ""

        tool_calls = []
        tool_calls_for_api = []
        if message.tool_calls:
            for tool_call in message.tool_calls:
                tool_calls.append({
                    "id": tool_call.id,
                    "name": tool_call.function.name,
                    "arguments": json.loads(tool_call.function.arguments)
                })
                tool_calls_for_api.append({
                    "id": tool_call.id,
                    "type": "function",
                    "function": {
                        "name": tool_call.function.name,
                        "arguments": tool_call.function.arguments
                    }
                })

        # Build complete assistant message in OpenAI's official format
        assistant_message = {
            "role": "assistant",
            "content": text_response
        }
        if tool_calls_for_api:
            assistant_message["tool_calls"] = tool_calls_for_api

        return text_response, tool_calls, assistant_message

    def create_tool_result_message(self, tool_calls: List[Dict[str, Any]],
                                   tool_results: List[Any]) -> Dict[str, Any]:
        """
        Create tool result message(s) in official API format
        Args:
            tool_calls: List of tool calls from generate_with_tools
                       Each item: {"id": "call_id", "name": "tool_name", "arguments": {...}}
            tool_results: List of tool execution results (same order as tool_calls)
        Returns:
            For Claude: Single user message with tool_result content blocks
            For OpenAI: Dict with "_openai_tool_messages" key containing list of tool messages
        """
        if self.provider == "claude":
            return self._create_tool_result_message_claude(tool_calls, tool_results)
        elif self.provider == "openai":
            return self._create_tool_result_message_openai(tool_calls, tool_results)

    def _create_tool_result_message_claude(self, tool_calls: List[Dict],
                                           tool_results: List[Any]) -> Dict:
        """Create tool result message for Claude (single user message with multiple tool_result blocks)"""
        content_blocks = []

        for tool_call, result in zip(tool_calls, tool_results):
            # Convert result to string if needed
            result_str = str(result) if not isinstance(result, str) else result

            content_blocks.append({
                "type": "tool_result",
                "tool_use_id": tool_call["id"],
                "content": result_str
            })

        return {
            "role": "user",
            "content": content_blocks
        }

    def _create_tool_result_message_openai(self, tool_calls: List[Dict],
                                           tool_results: List[Any]) -> Dict:
        """Create tool result messages for OpenAI

        Note: OpenAI requires separate messages for each tool result.
        We return a dict with a special marker "_openai_tool_messages" containing the list.
        """
        tool_messages = []

        for tool_call, result in zip(tool_calls, tool_results):
            # Convert result to string if needed
            result_str = str(result) if not isinstance(result, str) else result

            tool_messages.append({
                "role": "tool",
                "tool_call_id": tool_call["id"],
                "name": tool_call["name"],
                "content": result_str
            })

        # Return wrapper dict with special marker for OpenAI
        return {
            "_openai_tool_messages": tool_messages
        }
