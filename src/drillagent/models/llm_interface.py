"""
Enhanced LLM Interface for DrillAgent

Key features:
1. Automatic agent loop - no manual conversation management needed
2. Conversation manager - automatic handling of message history
3. Provider abstraction - no provider-specific code in application layer
4. Usage tracking - monitor token usage and costs
5. Better error handling and type safety

Usage patterns:
1. Simple text generation:
   llm = LLMInterface(provider="claude", model_name="claude-3-7-sonnet-20250219")
   response = llm.generate(prompt="What is Python?")

2. Manual tool calling (backward compatible):
   text, tool_calls, assistant_msg = llm.generate_with_tools(
       prompt="Analyze this code",
       tools=tools,
       conversation_history=history
   )

3. Automatic agent loop (NEW - recommended):
   result = llm.run_agent_loop(
       task="Find all Python files and read the main.py",
       tools=tools,
       max_iterations=10
   )
   print(result['final_response'])
"""

import os
import json
import logging
import time
from typing import Optional, List, Dict, Any, Tuple, Callable
from pathlib import Path
from dataclasses import dataclass, field

# Import LLM logging utilities
from drillagent.utils.logging import (
    log_llm_interaction,
    log_agent_loop_start,
    log_agent_loop_end,
    log_tool_results
)


# ==================== Custom Exceptions ====================

class LLMError(Exception):
    """Base exception for LLM-related errors"""
    pass


class RateLimitError(LLMError):
    """Rate limit exceeded - can be retried after waiting"""
    pass


class TimeoutError(LLMError):
    """Request timed out - can be retried"""
    pass


class ToolExecutionError(LLMError):
    """Tool execution failed - non-fatal, can continue with error message"""
    pass


class InvalidResponseError(LLMError):
    """LLM returned invalid response - may be retried"""
    pass


@dataclass
class UsageStats:
    """Track LLM API usage statistics"""
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    api_calls: int = 0

    def update(self, usage_data: Optional[Dict] = None):
        """Update stats from API response usage data"""
        if not usage_data:
            return

        self.api_calls += 1
        self.total_tokens += usage_data.get('total_tokens', 0)
        self.prompt_tokens += usage_data.get('input_tokens', 0) or usage_data.get('prompt_tokens', 0)
        self.completion_tokens += usage_data.get('output_tokens', 0) or usage_data.get('completion_tokens', 0)

    def to_dict(self) -> Dict[str, int]:
        return {
            'total_tokens': self.total_tokens,
            'prompt_tokens': self.prompt_tokens,
            'completion_tokens': self.completion_tokens,
            'api_calls': self.api_calls
        }


class ConversationManager:
    """
    Manages conversation history with automatic provider-specific formatting.

    This class encapsulates all provider differences so application code
    doesn't need to know about Claude vs OpenAI message formats.
    """

    def __init__(self, provider: str):
        """
        Args:
            provider: "claude" or "openai"
        """
        self.provider = provider.lower()
        self.messages: List[Dict[str, Any]] = []

    def add_user_message(self, content: str) -> None:
        """Add a user message to history"""
        self.messages.append({
            "role": "user",
            "content": content
        })

    def add_assistant_message(self, message: Dict[str, Any]) -> None:
        """
        Add assistant message in official API format.

        Args:
            message: Complete assistant message from generate_with_tools
                    (already in provider-specific format)
        """
        self.messages.append(message)

    def add_tool_results(
        self,
        tool_calls: List[Dict[str, Any]],
        tool_results: List[Any]
    ) -> None:
        """
        Add tool results to conversation history.
        Automatically handles provider differences internally.

        Args:
            tool_calls: List of tool calls from generate_with_tools
            tool_results: List of tool execution results (same order)
        """
        if self.provider == "claude":
            self._add_tool_results_claude(tool_calls, tool_results)
        elif self.provider == "openai":
            self._add_tool_results_openai(tool_calls, tool_results)

    def _add_tool_results_claude(
        self,
        tool_calls: List[Dict],
        tool_results: List[Any]
    ) -> None:
        """Claude: single user message with multiple tool_result blocks"""
        content_blocks = []

        for tool_call, result in zip(tool_calls, tool_results):
            result_str = str(result) if not isinstance(result, str) else result
            content_blocks.append({
                "type": "tool_result",
                "tool_use_id": tool_call["id"],
                "content": result_str
            })

        self.messages.append({
            "role": "user",
            "content": content_blocks
        })

    def _add_tool_results_openai(
        self,
        tool_calls: List[Dict],
        tool_results: List[Any]
    ) -> None:
        """OpenAI: separate tool message for each result"""
        for tool_call, result in zip(tool_calls, tool_results):
            result_str = str(result) if not isinstance(result, str) else result
            self.messages.append({
                "role": "tool",
                "tool_call_id": tool_call["id"],
                "name": tool_call["name"],
                "content": result_str
            })

    def get_messages(self) -> List[Dict[str, Any]]:
        """Get a copy of the conversation history"""
        return self.messages.copy()

    def clear(self) -> None:
        """Clear conversation history"""
        self.messages.clear()

    def __len__(self) -> int:
        """Return number of messages in history"""
        return len(self.messages)


class LLMInterface:
    """
    Enhanced LLM interface with automatic agent loop and conversation management.

    Features:
    - Supports Claude and OpenAI with unified interface
    - Automatic conversation history management
    - Built-in agent loop for tool calling
    - Usage statistics tracking
    - Provider differences fully encapsulated

    Example:
        # Create instance (supports multiple instances with different models)
        llm = LLMInterface(provider="claude", model_name="claude-3-7-sonnet-20250219")

        # Automatic agent loop (recommended)
        result = llm.run_agent_loop(
            task="Find and analyze main.py",
            tools=[ReadFileTool(), BashTool()],
            max_iterations=5
        )

        # Or manual control (backward compatible)
        text, tool_calls, msg = llm.generate_with_tools(
            prompt="Analyze this code",
            tools=tools
        )
    """

    def __init__(
        self,
        provider: str = "claude",
        model_name: Optional[str] = None,
        api_key: Optional[str] = None,
        api_key_file: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
        output_dir: Optional[str] = None
    ):
        """
        Initialize LLM interface.

        Args:
            provider: "claude" or "openai"
            model_name: Model name (default: claude-3-7-sonnet-20250219 or gpt-4-turbo)
            api_key: API key string (takes precedence)
            api_key_file: Path to file containing API key
            logger: Optional logger instance
            output_dir: Optional output directory for logging LLM interactions
        """
        self.provider = provider.lower()
        self.logger = logger or logging.getLogger(__name__)
        self.output_dir = output_dir  # For LLM interaction logging

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
                raise ImportError(
                    "anthropic package not found. Install it with: pip install anthropic"
                )
        elif self.provider == "openai":
            try:
                import openai
                self.client = openai.OpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError(
                    "openai package not found. Install it with: pip install openai"
                )

        # Usage tracking
        self.usage_stats = UsageStats()

    def get_usage_stats(self) -> Dict[str, int]:
        """Get API usage statistics"""
        return self.usage_stats.to_dict()

    def reset_usage_stats(self) -> None:
        """Reset usage statistics"""
        self.usage_stats = UsageStats()

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> str:
        """
        Simple text generation without tools.

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

    def generate_with_tools(
        self,
        prompt: str,
        tools: List,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[Dict]] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any], str]:
        """
        Generate response with tool calling support (manual mode).

        This is the backward-compatible interface for manual conversation management.
        For automatic agent loop, use run_agent_loop() instead.

        Args:
            prompt: User prompt
            tools: List of AgentTool instances
            system_prompt: Optional system instruction
            conversation_history: Previous messages for multi-turn conversation
            temperature: Sampling temperature
            max_tokens: Max tokens to generate

        Returns:
            Tuple of (text_response, tool_calls, assistant_message, stop_reason)
            - text_response: LLM's textual reasoning/response
            - tool_calls: List of tool calls [{"id": "...", "name": "...", "arguments": {...}}, ...]
            - assistant_message: Complete assistant message in official API format
            - stop_reason: Why the generation stopped (e.g., "end_turn", "max_tokens", "tool_use", "stop")
        """
        if self.provider == "claude":
            return self._generate_with_tools_claude(
                prompt, tools, system_prompt, conversation_history, temperature, max_tokens
            )
        elif self.provider == "openai":
            return self._generate_with_tools_openai(
                prompt, tools, system_prompt, conversation_history, temperature, max_tokens
            )

    def run_agent_loop(
        self,
        task: str,
        tools: List,
        system_prompt: Optional[str] = None,
        max_iterations: int = 10,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_executor: Optional[Callable] = None,
        continuation_prompt: str = "Continue based on the tool results.",
        on_iteration: Optional[Callable[[int, str, List[Dict]], None]] = None,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """
        Automatic agent loop with tool calling - NO MANUAL CONVERSATION MANAGEMENT NEEDED.

        This method handles everything automatically:
        - Conversation history management
        - Tool execution
        - Provider-specific message formatting
        - Iteration control
        - Error handling with automatic retries

        Args:
            task: The task description for the agent
            tools: List of AgentTool instances
            system_prompt: Optional system instruction
            max_iterations: Maximum number of iterations
            temperature: Sampling temperature
            max_tokens: Max tokens **per LLM generation**
            tool_executor: Optional custom tool executor function(tool_calls, tools) -> List[results]
                          If None, uses default executor that calls tool.execute()
            continuation_prompt: Prompt to send after tool results
            on_iteration: Optional callback(iteration, response, tool_calls) called each iteration
            max_retries: Maximum retries for rate limit/timeout errors (default: 3)

        Returns:
            Dict containing:
            - success: bool - whether task completed successfully
            - final_response: str - final text response from LLM
            - iterations: int - number of iterations used
            - conversation: ConversationManager - full conversation history
            - stop_reason: str - why the agent stopped
            - error: Optional[str] - error message if failed
            - usage_stats: Dict - token usage statistics for this call only
        """
        # Save old stats and create fresh stats for this call to ensure isolation
        old_stats = self.usage_stats
        self.usage_stats = UsageStats()

        # Log agent loop start if output_dir is configured
        if self.output_dir:
            try:
                log_agent_loop_start(
                    output_dir=self.output_dir,
                    task=task,
                    system_prompt=system_prompt,
                    provider=self.provider,
                    model_name=self.model_name
                )
            except Exception as e:
                self.logger.warning(f"Failed to log agent loop start: {e}")

        try:
            # Create conversation manager to handle history automatically
            conversation = ConversationManager(self.provider)

            text_response = ""
            stop_reason = "unknown"

            # Prepare initial prompt based on whether this is the last iteration
            if max_iterations == 1:
                # Only one iteration allowed - must provide final answer immediately
                current_prompt = (
                    "CRITICAL: You have ONLY ONE iteration to complete this task. "
                    "You can NO LONGER call any tools. "
                    "You must provide your final answer based on all available context and knowledge. "
                    "Analyze thoroughly and give your complete response as required. The task is as below.\n\n"
                    f"{task}"
                )
            else:
                current_prompt = task

            for iteration in range(1, max_iterations + 1): # 1 ~ max_iterations 
                # Determine tools availability based on iteration
                # On the last iteration, disable tools to force final answer
                current_tools = [] if iteration == max_iterations else tools

                # Retry logic for rate limits and timeouts
                retry_count = 0
                while retry_count <= max_retries:
                    try:
                        # Call LLM with tools
                        text_response, tool_calls, assistant_message, stop_reason = self.generate_with_tools(
                            prompt=current_prompt, # prepared before for-loop or at the end of for-loop
                            tools=current_tools,
                            system_prompt=system_prompt,
                            conversation_history=conversation.get_messages(),
                            temperature=temperature,
                            max_tokens=max_tokens
                        )

                        # Success - break retry loop
                        break

                    except RateLimitError as e:
                        retry_count += 1
                        if retry_count > max_retries:
                            self.logger.error(f"Rate limit exceeded after {max_retries} retries")
                            result = {
                                'success': False,
                                'final_response': text_response,
                                'iterations': iteration,
                                'conversation': conversation,
                                'stop_reason': 'rate_limit_error',
                                'error': f"Rate limit exceeded: {e}",
                                'usage_stats': self.usage_stats.to_dict()
                            }
                            # Log agent loop end
                            if self.output_dir:
                                try:
                                    log_agent_loop_end(
                                        output_dir=self.output_dir,
                                        success=False,
                                        final_response=text_response,
                                        iterations=iteration,
                                        stop_reason='rate_limit_error',
                                        error=f"Rate limit exceeded: {e}"
                                    )
                                except Exception as log_err:
                                    self.logger.warning(f"Failed to log agent loop end: {log_err}")
                            return result

                        # Exponential backoff
                        wait_time = min(2 ** retry_count, 60)  # Cap at 60 seconds
                        self.logger.warning(f"Rate limit hit, waiting {wait_time}s before retry {retry_count}/{max_retries}")
                        time.sleep(wait_time)
                        continue

                    except TimeoutError as e:
                        retry_count += 1
                        if retry_count > max_retries:
                            self.logger.error(f"Timeout after {max_retries} retries")
                            result = {
                                'success': False,
                                'final_response': text_response,
                                'iterations': iteration,
                                'conversation': conversation,
                                'stop_reason': 'timeout_error',
                                'error': f"Request timed out: {e}",
                                'usage_stats': self.usage_stats.to_dict()
                            }
                            # Log agent loop end
                            if self.output_dir:
                                try:
                                    log_agent_loop_end(
                                        output_dir=self.output_dir,
                                        success=False,
                                        final_response=text_response,
                                        iterations=iteration,
                                        stop_reason='timeout_error',
                                        error=f"Request timed out: {e}"
                                    )
                                except Exception as log_err:
                                    self.logger.warning(f"Failed to log agent loop end: {log_err}")
                            return result

                        self.logger.warning(f"Request timed out, retrying {retry_count}/{max_retries}")
                        time.sleep(2 ** retry_count)  # Exponential backoff
                        continue

                    except LLMError as e:
                        # Fatal LLM error - don't retry
                        self.logger.error(f"LLM error at iteration {iteration}: {e}")
                        result = {
                            'success': False,
                            'final_response': text_response,
                            'iterations': iteration,
                            'conversation': conversation,
                            'stop_reason': 'llm_error',
                            'error': str(e),
                            'usage_stats': self.usage_stats.to_dict()
                        }
                        # Log agent loop end
                        if self.output_dir:
                            try:
                                log_agent_loop_end(
                                    output_dir=self.output_dir,
                                    success=False,
                                    final_response=text_response,
                                    iterations=iteration,
                                    stop_reason='llm_error',
                                    error=str(e)
                                )
                            except Exception as log_err:
                                self.logger.warning(f"Failed to log agent loop end: {log_err}")
                        return result

                    except Exception as e:
                        # Unexpected error - don't retry
                        self.logger.error(f"Unexpected error at iteration {iteration}: {e}", exc_info=True)
                        result = {
                            'success': False,
                            'final_response': text_response,
                            'iterations': iteration,
                            'conversation': conversation,
                            'stop_reason': 'unexpected_error',
                            'error': str(e),
                            'usage_stats': self.usage_stats.to_dict()
                        }
                        # Log agent loop end
                        if self.output_dir:
                            try:
                                log_agent_loop_end(
                                    output_dir=self.output_dir,
                                    success=False,
                                    final_response=text_response,
                                    iterations=iteration,
                                    stop_reason='unexpected_error',
                                    error=str(e)
                                )
                            except Exception as log_err:
                                self.logger.warning(f"Failed to log agent loop end: {log_err}")
                        return result

                # Automatically add messages to history
                conversation.add_user_message(current_prompt)
                conversation.add_assistant_message(assistant_message)

                # Optional callback
                if on_iteration:
                    on_iteration(iteration, text_response, tool_calls)

                # Check stop_reason for proper completion
                if stop_reason in ["max_tokens", "length"]:
                    self.logger.warning(f"Response truncated at iteration {iteration} (stop_reason: {stop_reason})")
                    # Continue to next iteration with warning, might still succeed

                # If no tool calls, check if task is genuinely complete
                if not tool_calls or len(tool_calls) == 0:
                    if stop_reason in ["end_turn", "stop"]:
                        # Genuine completion
                        result = {
                            'success': True,
                            'final_response': text_response,
                            'iterations': iteration,
                            'conversation': conversation,
                            'stop_reason': stop_reason,
                            'usage_stats': self.usage_stats.to_dict()
                        }
                        # Log agent loop end
                        if self.output_dir:
                            try:
                                log_agent_loop_end(
                                    output_dir=self.output_dir,
                                    success=True,
                                    final_response=text_response,
                                    iterations=iteration,
                                    stop_reason=stop_reason
                                )
                            except Exception as log_err:
                                self.logger.warning(f"Failed to log agent loop end: {log_err}")
                        return result
                    elif stop_reason in ["max_tokens", "length"]:
                        # Response was truncated but no tool calls
                        self.logger.warning(f"Response truncated without tool calls - treating as incomplete")
                        result = {
                            'success': False,
                            'final_response': text_response,
                            'iterations': iteration,
                            'conversation': conversation,
                            'stop_reason': stop_reason,
                            'error': "Response truncated (max_tokens reached)",
                            'usage_stats': self.usage_stats.to_dict()
                        }
                        # Log agent loop end
                        if self.output_dir:
                            try:
                                log_agent_loop_end(
                                    output_dir=self.output_dir,
                                    success=False,
                                    final_response=text_response,
                                    iterations=iteration,
                                    stop_reason=stop_reason,
                                    error="Response truncated (max_tokens reached)"
                                )
                            except Exception as log_err:
                                self.logger.warning(f"Failed to log agent loop end: {log_err}")
                        # TODO: Do we make use of the incomplete response? Could be useful 🤔
                        return result
                    else:
                        # Unknown stop reason, assume complete
                        result = {
                            'success': True,
                            'final_response': text_response,
                            'iterations': iteration,
                            'conversation': conversation,
                            'stop_reason': stop_reason,
                            'usage_stats': self.usage_stats.to_dict()
                        }
                        # Log agent loop end
                        if self.output_dir:
                            try:
                                log_agent_loop_end(
                                    output_dir=self.output_dir,
                                    success=True,
                                    final_response=text_response,
                                    iterations=iteration,
                                    stop_reason=stop_reason
                                )
                            except Exception as log_err:
                                self.logger.warning(f"Failed to log agent loop end: {log_err}")
                        return result

                # Execute tools with error handling
                try:
                    if tool_executor:
                        tool_results = tool_executor(tool_calls, tools)
                    else:
                        tool_results = self._default_tool_executor(tool_calls, tools)
                except ToolExecutionError as e:
                    # Tool execution failed but not fatal - let LLM see the error
                    self.logger.warning(f"Tool execution failed: {e}")
                    tool_results = [f"Error: {e}"] * len(tool_calls)
                except Exception as e:
                    # Unexpected tool error - also not fatal
                    self.logger.error(f"Unexpected tool error: {e}", exc_info=True)
                    tool_results = [f"Unexpected error: {e}"] * len(tool_calls)

                # Log tool results to update the last interaction
                if self.output_dir:
                    try:
                        log_tool_results(self.output_dir, tool_results)
                    except Exception as e:
                        self.logger.warning(f"Failed to log tool results: {e}")

                # Automatically add tool results to history (handles provider differences)
                conversation.add_tool_results(tool_calls, tool_results)

                # Prepare next iteration prompt based on remaining iterations
                # In the second-to-last round, tools can still be called one final time, and in the final round (the last round), tool calls are disabled.
                next_iteration = iteration + 1
                if next_iteration == max_iterations:
                    # Next iteration is the last one: it will have no tools, must provide final answer
                    current_prompt = (
                        "CRITICAL: You can NO LONGER call any tools. "
                        "You must provide your final answer based on all the context and information gathered so far. "
                        "Analyze the available information thoroughly and give your complete response as required by the task."
                    )
                elif next_iteration == max_iterations - 1:
                    # Next iteration is second-to-last: warn this is the last chance to use tools
                    current_prompt = (
                        "IMPORTANT: This is your LAST chance to call tools. "
                        "After this iteration, you will need to provide your final answer based on all available context. "
                        "Use tools wisely if needed, or provide your final answer now if you have enough information.\n\n"
                        f"{continuation_prompt}"
                    )
                else:
                    # Normal continuation
                    current_prompt = continuation_prompt

            # Max iterations reached
            result = {
                'success': False,
                'final_response': text_response,
                'iterations': max_iterations,
                'conversation': conversation,
                'stop_reason': 'max_iterations',
                'error': f"Max iterations ({max_iterations}) reached without completion",
                'usage_stats': self.usage_stats.to_dict()
            }
            # Log agent loop end
            if self.output_dir:
                try:
                    log_agent_loop_end(
                        output_dir=self.output_dir,
                        success=False,
                        final_response=text_response,
                        iterations=max_iterations,
                        stop_reason='max_iterations',
                        error=f"Max iterations ({max_iterations}) reached without completion"
                    )
                except Exception as log_err:
                    self.logger.warning(f"Failed to log agent loop end: {log_err}")
            return result

        finally:
            # Restore and merge stats - accumulate usage from this call into the global stats
            old_stats.total_tokens += self.usage_stats.total_tokens
            old_stats.prompt_tokens += self.usage_stats.prompt_tokens
            old_stats.completion_tokens += self.usage_stats.completion_tokens
            old_stats.api_calls += self.usage_stats.api_calls
            self.usage_stats = old_stats

    def _default_tool_executor(
        self,
        tool_calls: List[Dict[str, Any]],
        tools: List
    ) -> List[Any]:
        """
        Default tool executor - calls tool.execute() for each tool call.

        Args:
            tool_calls: List of tool calls from LLM
            tools: List of available tool instances

        Returns:
            List of tool execution results
        """
        tool_registry = {tool.name(): tool for tool in tools}
        results = []

        for tool_call in tool_calls:
            tool_name = tool_call.get('name')
            tool_args = tool_call.get('arguments', {})

            if tool_name in tool_registry:
                try:
                    tool = tool_registry[tool_name]
                    result = tool.execute(**tool_args)
                    results.append(result)
                except Exception as e:
                    error_msg = f"Tool execution error: {str(e)}"
                    self.logger.error(f"{tool_name} failed: {error_msg}")
                    results.append(error_msg)
            else:
                error_msg = f"Unknown tool: {tool_name}"
                self.logger.error(error_msg)
                results.append(error_msg)

        return results

    # ==================== Private Implementation Methods ====================

    def _is_temperature_unsupported_model(self) -> bool:
        """
        Check if the current model doesn't support temperature parameter.

        Returns:
            True if the model doesn't support temperature, False otherwise
        """
        # List of models that don't support temperature
        unsupported_models = [
            "gpt-5-mini",
            "gpt-5-mini-2025-08-07",
            "o3-2025-04-16",
            "o4-mini-2025-04-16",
            # Add more models here as needed
        ]

        # Check if the current model is in the unsupported list
        for unsupported_model in unsupported_models:
            if unsupported_model.lower() in self.model_name.lower():
                return True

        return False

    def _generate_claude(
        self,
        prompt: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> str:
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

        # Track usage
        if hasattr(response, 'usage'):
            self.usage_stats.update({
                'input_tokens': response.usage.input_tokens,
                'output_tokens': response.usage.output_tokens,
                'total_tokens': response.usage.input_tokens + response.usage.output_tokens
            })

        # Get response text and stop reason
        text_response = response.content[0].text
        stop_reason = response.stop_reason if hasattr(response, 'stop_reason') else "unknown"

        # Log the interaction if output_dir is configured
        if self.output_dir:
            try:
                log_llm_interaction(
                    output_dir=self.output_dir,
                    interaction_data={
                        "provider": self.provider,
                        "model_name": self.model_name,
                        "system_prompt": system_prompt,
                        "user_prompt": prompt,
                        "assistant_response": text_response,
                        "tool_calls": [],  # No tool calls for simple generation
                        "stop_reason": stop_reason,
                        "usage_stats": self.usage_stats.to_dict() if hasattr(self, 'usage_stats') else None
                    }
                )
            except Exception as e:
                self.logger.warning(f"Failed to log LLM interaction: {e}")

        return text_response

    def _generate_openai(
        self,
        prompt: str,
        system_prompt: Optional[str],
        temperature: float,
        max_tokens: int
    ) -> str:
        """Generate using OpenAI API (simple text generation)"""
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        # Build kwargs for API call
        kwargs = {
            "model": self.model_name,
            "messages": messages,
            "max_completion_tokens": max_tokens,
        }

        # Only add temperature if the model supports it
        # gpt-5-mini and similar models don't support temperature
        if not self._is_temperature_unsupported_model():
            kwargs["temperature"] = temperature

        response = self.client.chat.completions.create(**kwargs)

        # Track usage
        if hasattr(response, 'usage') and response.usage:
            self.usage_stats.update({
                'prompt_tokens': response.usage.prompt_tokens,
                'completion_tokens': response.usage.completion_tokens,
                'total_tokens': response.usage.total_tokens
            })

        # Get response text and stop reason
        text_response = response.choices[0].message.content
        stop_reason = response.choices[0].finish_reason if response.choices else "unknown"

        # Log the interaction if output_dir is configured
        if self.output_dir:
            try:
                log_llm_interaction(
                    output_dir=self.output_dir,
                    interaction_data={
                        "provider": self.provider,
                        "model_name": self.model_name,
                        "system_prompt": system_prompt,
                        "user_prompt": prompt,
                        "assistant_response": text_response,
                        "tool_calls": [],  # No tool calls for simple generation
                        "stop_reason": stop_reason,
                        "usage_stats": self.usage_stats.to_dict() if hasattr(self, 'usage_stats') else None
                    }
                )
            except Exception as e:
                self.logger.warning(f"Failed to log LLM interaction: {e}")

        return text_response

    def _generate_with_tools_claude(
        self,
        prompt: str,
        tools: List,
        system_prompt: Optional[str],
        conversation_history: Optional[List[Dict]],
        temperature: float,
        max_tokens: int
    ) -> Tuple[str, List[Dict], Dict, str]:
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

        try:
            response = self.client.messages.create(**kwargs)
        except Exception as e:
            # Convert API errors to our custom exceptions
            error_msg = str(e).lower()
            if 'rate' in error_msg or 'quota' in error_msg or '429' in error_msg:
                raise RateLimitError(f"Rate limit exceeded: {e}")
            elif 'timeout' in error_msg:
                raise TimeoutError(f"Request timed out: {e}")
            else:
                raise LLMError(f"Claude API error: {e}")

        # Track usage
        if hasattr(response, 'usage'):
            self.usage_stats.update({
                'input_tokens': response.usage.input_tokens,
                'output_tokens': response.usage.output_tokens,
                'total_tokens': response.usage.input_tokens + response.usage.output_tokens
            })

        # Get stop_reason from response
        stop_reason = response.stop_reason if hasattr(response, 'stop_reason') else "unknown"

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

        # Log the interaction if output_dir is configured
        if self.output_dir:
            try:
                log_llm_interaction(
                    output_dir=self.output_dir,
                    interaction_data={
                        "provider": self.provider,
                        "model_name": self.model_name,
                        "system_prompt": system_prompt,
                        "user_prompt": prompt,
                        "assistant_response": text_response,
                        "tool_calls": tool_calls,
                        "stop_reason": stop_reason,
                        "usage_stats": self.usage_stats.to_dict() if hasattr(self, 'usage_stats') else None
                    }
                )
            except Exception as e:
                self.logger.warning(f"Failed to log LLM interaction: {e}")

        return text_response, tool_calls, assistant_message, stop_reason

    def _generate_with_tools_openai(
        self,
        prompt: str,
        tools: List,
        system_prompt: Optional[str],
        conversation_history: Optional[List[Dict]],
        temperature: float,
        max_tokens: int
    ) -> Tuple[str, List[Dict], Dict, str]:
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

        # Build kwargs for API call
        kwargs = {
            "model": self.model_name,
            "messages": messages,
            "tools": tool_schemas,
            "tool_choice": "auto",
            "max_completion_tokens": max_tokens
        }

        # Only add temperature if the model supports it
        # gpt-5-mini and similar models don't support temperature
        if not self._is_temperature_unsupported_model():
            kwargs["temperature"] = temperature

        # Call OpenAI API with tools
        try:
            response = self.client.chat.completions.create(**kwargs)
        except Exception as e:
            # Convert API errors to our custom exceptions
            error_msg = str(e).lower()
            if 'rate' in error_msg or 'quota' in error_msg or '429' in error_msg:
                raise RateLimitError(f"Rate limit exceeded: {e}")
            elif 'timeout' in error_msg:
                raise TimeoutError(f"Request timed out: {e}")
            else:
                raise LLMError(f"OpenAI API error: {e}")

        # Track usage
        if hasattr(response, 'usage') and response.usage:
            self.usage_stats.update({
                'prompt_tokens': response.usage.prompt_tokens,
                'completion_tokens': response.usage.completion_tokens,
                'total_tokens': response.usage.total_tokens
            })

        # Get stop_reason from response (OpenAI calls it finish_reason)
        stop_reason = response.choices[0].finish_reason if response.choices else "unknown"

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

        # Log the interaction if output_dir is configured
        if self.output_dir:
            try:
                log_llm_interaction(
                    output_dir=self.output_dir,
                    interaction_data={
                        "provider": self.provider,
                        "model_name": self.model_name,
                        "system_prompt": system_prompt,
                        "user_prompt": prompt,
                        "assistant_response": text_response,
                        "tool_calls": tool_calls,
                        "stop_reason": stop_reason,
                        "usage_stats": self.usage_stats.to_dict() if hasattr(self, 'usage_stats') else None
                    }
                )
            except Exception as e:
                self.logger.warning(f"Failed to log LLM interaction: {e}")

        return text_response, tool_calls, assistant_message, stop_reason
