# LLM Integration Tests

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set API keys:
```bash
# For Claude (recommended)
export ANTHROPIC_API_KEY="your_anthropic_api_key_here"

# For OpenAI
export OPENAI_API_KEY="your_openai_api_key_here"
```

## Run Tests

Run all LLM integration tests:
```bash
PYTHONPATH=src pytest tests/test_llm_integration.py -v
```

Run specific test class:
```bash
PYTHONPATH=src pytest tests/test_llm_integration.py::TestLLMInitialization -v
```

Run with output:
```bash
PYTHONPATH=src pytest tests/test_llm_integration.py -v -s
```

Quick verification (no pytest needed):
```bash
python3 verify_llm.py
```

## Test Coverage

The test file includes:
- ✓ LLM initialization (Claude & OpenAI)
- ✓ Text generation with/without system prompts
- ✓ Security vulnerability analysis
- ✓ Parameter testing (temperature, max_tokens)
- ✓ Integration with DrillAgent config

Tests automatically skip if API keys are not available.

