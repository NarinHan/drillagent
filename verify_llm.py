#!/usr/bin/env python3
"""
Quick verification script for LLM integration

"""

import sys
import os

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from drillagent.models import LLM


def main():
    print("=" * 60)
    print("DrillAgent LLM Integration Verification")
    print("=" * 60)
    
    # Check API keys
    claude_key = os.environ.get("ANTHROPIC_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")
    
    print("\n1. Checking API Keys:")
    print(f"   Claude (ANTHROPIC_API_KEY): {'✓ Set' if claude_key else '✗ Not set'}")
    print(f"   OpenAI (OPENAI_API_KEY): {'✓ Set' if openai_key else '✗ Not set'}")
    
    if not claude_key and not openai_key:
        print("\n⚠️  No API keys found!")
        print("Set at least one: export ANTHROPIC_API_KEY=your_key")
        return 1
    
    # Test Claude if key available
    if claude_key:
        print("\n2. Testing Claude:")
        try:
            llm = LLM(provider="claude")
            print(f"   ✓ Initialized: {llm.model_name}")
            
            response = llm.generate(
                prompt="Say 'Hello from Claude' and nothing else.",
                temperature=0.0,
                max_tokens=20
            )
            print(f"   ✓ Response: {response[:50]}")
        except Exception as e:
            print(f"   ✗ Error: {e}")
            return 1
    
    # Test OpenAI if key available
    if openai_key:
        print("\n3. Testing OpenAI:")
        try:
            llm = LLM(provider="openai")
            print(f"   ✓ Initialized: {llm.model_name}")
            
            response = llm.generate(
                prompt="Say 'Hello from OpenAI' and nothing else.",
                temperature=0.0,
                max_tokens=20
            )
            print(f"   ✓ Response: {response[:50]}")
        except Exception as e:
            print(f"   ✗ Error: {e}")
            return 1
    
    print("\n" + "=" * 60)
    print("✓ All checks passed! LLM integration is working.")
    print("=" * 60)
    print("\nNext steps:")
    print("  - Run tests: PYTHONPATH=src pytest tests/test_llm_integration.py -v")
    print("  - See: LLM_INTEGRATION.md for usage examples\n")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

