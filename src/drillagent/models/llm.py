"""
Minimal LLM interface for DrillAgent

Supports Claude and OpenAI with simple text generation.
"""

import os
from typing import Optional


class LLM:
    """Base LLM interface for text generation"""
    
    def __init__(self, provider: str = "claude", model_name: Optional[str] = None, api_key: Optional[str] = None):
        """
        Initialize LLM
        
        Args:
            provider: "claude" or "openai"
            model_name: Model name (default: claude-3-7-sonnet-20250219 or gpt-4-turbo)
            api_key: API key (or use environment variable)
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
        
        # Get API key
        if api_key is None:
            if self.provider == "claude":
                api_key = os.environ.get("ANTHROPIC_API_KEY")
            elif self.provider == "openai":
                api_key = os.environ.get("OPENAI_API_KEY")
        
        if not api_key:
            raise ValueError(f"API key not found for {provider}. Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable.")
        
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
        Generate text from prompt
        
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
    
    def _generate_claude(self, prompt: str, system_prompt: Optional[str], 
                        temperature: float, max_tokens: int) -> str:
        """Generate using Claude API"""
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
        """Generate using OpenAI API"""
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

