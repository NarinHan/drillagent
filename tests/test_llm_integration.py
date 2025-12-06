"""
Test LLM Integration

Tests for Claude and OpenAI LLM integration.
Run with: PYTHONPATH=src pytest tests/test_llm_integration.py -v
"""

import os
import sys
import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from drillagent.models import LLM


# Fixtures
@pytest.fixture
def claude_api_key():
    """Get Claude API key from environment"""
    return os.environ.get("ANTHROPIC_API_KEY")


@pytest.fixture
def openai_api_key():
    """Get OpenAI API key from environment"""
    return os.environ.get("OPENAI_API_KEY")


@pytest.fixture
def skip_if_no_claude_key(claude_api_key):
    """Skip test if Claude API key not available"""
    if not claude_api_key:
        pytest.skip("ANTHROPIC_API_KEY not set")


@pytest.fixture
def skip_if_no_openai_key(openai_api_key):
    """Skip test if OpenAI API key not available"""
    if not openai_api_key:
        pytest.skip("OPENAI_API_KEY not set")


# Test initialization
class TestLLMInitialization:
    """Test LLM initialization for both providers"""
    
    def test_claude_init_with_default_model(self, skip_if_no_claude_key):
        """Test Claude initialization with default model"""
        llm = LLM(provider="claude")
        assert llm.provider == "claude"
        assert llm.model_name == "claude-3-7-sonnet-20250219"
        assert llm.client is not None
    
    def test_claude_init_with_custom_model(self, skip_if_no_claude_key):
        """Test Claude initialization with custom model"""
        llm = LLM(provider="claude", model_name="claude-3-5-sonnet-20241022")
        assert llm.model_name == "claude-3-5-sonnet-20241022"
    
    def test_openai_init_with_default_model(self, skip_if_no_openai_key):
        """Test OpenAI initialization with default model"""
        llm = LLM(provider="openai")
        assert llm.provider == "openai"
        assert llm.model_name == "gpt-4o-mini-2024-07-18"
        assert llm.client is not None
    
    def test_openai_init_with_custom_model(self, skip_if_no_openai_key):
        """Test OpenAI initialization with custom model"""
        llm = LLM(provider="openai", model_name="gpt-3.5-turbo")
        assert llm.model_name == "gpt-3.5-turbo"
    
    def test_invalid_provider(self):
        """Test that invalid provider raises error"""
        with pytest.raises(ValueError, match="Unsupported provider"):
            LLM(provider="invalid")
    
    def test_missing_api_key(self):
        """Test that missing API key raises error"""
        # Temporarily clear environment variables
        original_claude = os.environ.pop("ANTHROPIC_API_KEY", None)
        
        try:
            with pytest.raises(ValueError, match="API key not found"):
                LLM(provider="claude")
        finally:
            # Restore original value
            if original_claude:
                os.environ["ANTHROPIC_API_KEY"] = original_claude


# Test text generation
class TestLLMGeneration:
    """Test text generation for both providers"""
    
    def test_claude_simple_generation(self, skip_if_no_claude_key):
        """Test Claude simple text generation"""
        llm = LLM(provider="claude")
        
        response = llm.generate(
            prompt="Say 'Hello' and nothing else.",
            temperature=0.0,
            max_tokens=50
        )
        
        assert isinstance(response, str)
        assert len(response) > 0
        assert "hello" in response.lower()
    
    def test_claude_with_system_prompt(self, skip_if_no_claude_key):
        """Test Claude generation with system prompt"""
        llm = LLM(provider="claude")
        
        response = llm.generate(
            prompt="What is 2+2?",
            system_prompt="You are a helpful math assistant. Answer briefly.",
            temperature=0.0,
            max_tokens=50
        )
        
        assert isinstance(response, str)
        assert "4" in response
    
    def test_openai_simple_generation(self, skip_if_no_openai_key):
        """Test OpenAI simple text generation"""
        llm = LLM(provider="openai")
        
        response = llm.generate(
            prompt="Say 'Hello' and nothing else.",
            temperature=0.0,
            max_tokens=50
        )
        
        assert isinstance(response, str)
        assert len(response) > 0
        assert "hello" in response.lower()
    
    def test_openai_with_system_prompt(self, skip_if_no_openai_key):
        """Test OpenAI generation with system prompt"""
        llm = LLM(provider="openai")
        
        response = llm.generate(
            prompt="What is 2+2?",
            system_prompt="You are a helpful math assistant. Answer briefly.",
            temperature=0.0,
            max_tokens=50
        )
        
        assert isinstance(response, str)
        assert "4" in response


# Test security analysis use case
class TestSecurityAnalysis:
    """Test LLM for security vulnerability analysis"""
    
    def test_claude_vulnerability_analysis(self, skip_if_no_claude_key):
        """Test Claude analyzing a simple vulnerability"""
        llm = LLM(provider="claude")
        
        code = """
void process(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerability here
}
"""
        
        response = llm.generate(
            prompt=f"What vulnerability exists in this code? Answer in one sentence.\n\n{code}",
            system_prompt="You are a security expert.",
            temperature=0.3,
            max_tokens=200
        )
        
        assert isinstance(response, str)
        # Check for common vulnerability keywords
        response_lower = response.lower()
        assert any(keyword in response_lower for keyword in ["buffer overflow", "overflow", "strcpy", "unsafe"])
    
    def test_openai_vulnerability_analysis(self, skip_if_no_openai_key):
        """Test OpenAI analyzing a simple vulnerability"""
        llm = LLM(provider="openai")
        
        code = """
void process(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerability here
}
"""
        
        response = llm.generate(
            prompt=f"What vulnerability exists in this code? Answer in one sentence.\n\n{code}",
            system_prompt="You are a security expert.",
            temperature=0.3,
            max_tokens=200
        )
        
        assert isinstance(response, str)
        # Check for common vulnerability keywords
        response_lower = response.lower()
        assert any(keyword in response_lower for keyword in ["buffer overflow", "overflow", "strcpy", "unsafe"])


# Test temperature and max_tokens parameters
class TestParameters:
    """Test generation parameters"""
    
    def test_claude_temperature_zero(self, skip_if_no_claude_key):
        """Test that temperature=0 produces consistent results"""
        llm = LLM(provider="claude")
        
        prompt = "Count from 1 to 5."
        
        response1 = llm.generate(prompt, temperature=0.0, max_tokens=50)
        response2 = llm.generate(prompt, temperature=0.0, max_tokens=50)
        
        # With temperature=0, responses should be very similar or identical
        assert isinstance(response1, str)
        assert isinstance(response2, str)
    
    def test_claude_max_tokens(self, skip_if_no_claude_key):
        """Test max_tokens limits response length"""
        llm = LLM(provider="claude")
        
        response = llm.generate(
            prompt="Write a very long story.",
            temperature=0.5,
            max_tokens=20
        )
        
        # Response should be relatively short due to token limit
        assert isinstance(response, str)
        assert len(response) < 200  # Approximate check


# Integration test with DrillAgent config
class TestDrillAgentIntegration:
    """Test LLM integration with DrillAgent config"""
    
    def test_llm_with_config(self, skip_if_no_claude_key):
        """Test creating LLM with DrillAgent-style config"""
        from drillagent.config import AgentConfig
        
        config = AgentConfig(
            target_repo_path="/tmp/test",
            model_provider="claude",
            model_name="claude-3-7-sonnet-20250219"
        )
        
        llm = LLM(
            provider=config.model_provider,
            model_name=config.model_name,
            api_key=config.api_key
        )
        
        assert llm.provider == "claude"
        assert llm.model_name == "claude-3-7-sonnet-20250219"
        
        # Test it can generate
        response = llm.generate("Hello", max_tokens=10)
        assert isinstance(response, str)


# Run all tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

