"""
LLM pricing configuration.

All prices are in USD per 1,000,000 tokens (MTok).
"""

MODEL_PRICE_PER_MTOK_USD = {
    # Claude Sonnet series (4.5 / 4.0 / 3.7 share the same pricing tier).
    "claude-sonnet-4-5-20250929": {"input": 3.0, "output": 15.0},

    # Claude Haiku 4.5
    "claude-haiku-4-5-20251001": {"input": 1.0, "output": 5.0},

    # Claude Opus 4.5
    "claude-opus-4-5-20251101": {"input": 5.0, "output": 25.0},

    # OpenAI GPT-5 series
    "gpt-5.2-codex": {"input": 1.75, "output": 14.0},
    "gpt-5.2-2025-12-11": {"input": 1.75, "output": 14.0},
    "gpt-5.1-2025-11-13": {"input": 1.25, "output": 10.0},
    "gpt-5-mini-2025-08-07": {"input": 0.25, "output": 2.0},

    # OpenAI GPT-4 series
    "gpt-4.1": {"input": 2.0, "output": 8.0},
    "gpt-4o": {"input": 2.5, "output": 10.0},
}
