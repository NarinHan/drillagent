#!/usr/bin/env python3
"""
Test script to verify ConfigGeneratorAgent integration with DrillAgent
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from drillagent.drill_agent import DrillAgent
from drillagent.config import AgentConfig


def test_config_generator_integration():
    """Test that ConfigGeneratorAgent is properly integrated"""
    
    print("=" * 60)
    print("Testing ConfigGeneratorAgent Integration")
    print("=" * 60)
    
    # Create a test configuration
    config = AgentConfig(
        target_repo="repos/jq",
        cve_id="jq.cve-2023-50246",  # Example CVE from SEC-bench
        model_provider="openai",
        model_name="gpt-4-turbo",
        api_key=os.getenv("OPENAI_API_KEY"),
        enable_coverage=False,  # Disable for this test
        enable_distance=True,   # Enable distance calculation
        enable_sanitizer=False,  # Disable for this test
        output_dir="./test_output",
        verbose=True
    )
    
    print(f"\nTest Configuration:")
    print(f"  Target: {config.target_repo}")
    print(f"  CVE ID: {config.cve_id}")
    print(f"  Distance calculation: {config.enable_distance}")
    
    # Initialize DrillAgent
    print("\nInitializing DrillAgent...")
    agent = DrillAgent(config)
    
    # Check if ConfigGeneratorAgent was initialized
    if hasattr(agent, 'config_generator') and agent.config_generator is not None:
        print("✓ ConfigGeneratorAgent successfully initialized")
        print(f"  Provider: {agent.config_generator.llm.provider}")
        print(f"  Model: {agent.config_generator.llm.model_name}")
        print(f"  SEC-bench dir: {agent.config_generator.secbench_dir}")
    else:
        print("✗ ConfigGeneratorAgent not initialized")
        return False
    
    # Test the instrumentation phase (just that phase, not full run)
    print("\nTesting instrumentation phase...")
    try:
        agent._phase_instrumentation()
        
        # Check if config was generated
        if agent.state.aflgo_config_path:
            print(f"✓ AFLGo config generated: {agent.state.aflgo_config_path}")
            
            # Verify the file exists
            if Path(agent.state.aflgo_config_path).exists():
                print("✓ Config file exists")
                
                # Show a preview
                with open(agent.state.aflgo_config_path) as f:
                    preview = f.read(500)
                print("\nConfig preview:")
                print("-" * 60)
                print(preview)
                if len(preview) >= 500:
                    print("...")
                print("-" * 60)
                
                return True
            else:
                print("✗ Config file does not exist")
                return False
        else:
            print("✗ No config path in state")
            return False
            
    except Exception as e:
        print(f"✗ Error during instrumentation phase: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_config_generator_integration()
    sys.exit(0 if success else 1)
