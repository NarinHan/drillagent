#!/usr/bin/env python3
"""
Test script to verify ConfigGeneratorAgent integration with DrillAgent
"""

import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(Path(__file__).resolve().parent.parent / '.env')

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
        target_repo_path="/home/shared_project/repos-llvm-cov/jq",
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
    print(f"  Target: {config.target_repo_path}")
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


def test_batch_config_generation():
    """Test batch config generation for one project (liblouis)"""
    
    print("\n" + "=" * 60)
    print("Testing Batch Config Generation for liblouis Project")
    print("=" * 60)
    
    # Import ConfigGeneratorAgent directly since it's no longer in DrillAgent.__init__
    from drillagent.instrumentation import ConfigGeneratorAgent
    from pathlib import Path
    
    # Create a minimal config just to initialize DrillAgent
    config = AgentConfig(
        target_repo_path="/home/shared_project/repos-llvm-cov/liblouis",
        model_provider="openai",
        model_name="gpt-4-turbo",
        api_key=os.getenv("OPENAI_API_KEY"),
        enable_distance=True,
        output_dir="./test_output",
        verbose=False
    )
    
    print("\nInitializing DrillAgent...")
    agent = DrillAgent(config)
    
    # Initialize ConfigGeneratorAgent directly
    print("Initializing ConfigGeneratorAgent...")
    config_generator = ConfigGeneratorAgent(agent)
    
    print("✓ ConfigGeneratorAgent initialized")
    
    # Generate configs for liblouis CVEs only
    output_dir = Path("./test_output/batch_configs")
    project_filter = "liblouis"
    
    print(f"\nGenerating configs for {project_filter} CVEs in SEC-bench...")
    print(f"SEC-bench directory: {config_generator.secbench_dir}")
    print(f"Output directory: {output_dir}")
    
    try:
        # Filter to only liblouis CVEs
        config_generator.generate_batch(output_dir, filter_pattern=project_filter)
        
        # Check how many configs were generated
        generated_configs = list(output_dir.glob("*.yaml"))
        print(f"\n✓ Batch generation complete!")
        print(f"  Generated {len(generated_configs)} config files")
        
        # Show sample of generated configs
        print(f"\n  Sample of generated configs:")
        for config_file in sorted(generated_configs)[:10]:  # Show first 10
            print(f"    - {config_file.name}")
        
        if len(generated_configs) > 10:
            print(f"    ... and {len(generated_configs) - 10} more")
        
        if len(generated_configs) > 0:
            # Verify one of the configs
            sample_config = generated_configs[0]
            print(f"\n✓ Sample config verification: {sample_config.name}")
            
            import yaml
            with open(sample_config) as f:
                config_data = yaml.safe_load(f)
            
            required_fields = ['repo_url', 'commit_id', 'cve_id', 'binary_name', 
                             'binary_path', 'sanitizer_report', 'build_config']
            
            missing_fields = [field for field in required_fields if field not in config_data]
            
            if missing_fields:
                print(f"✗ Missing required fields: {missing_fields}")
                return False
            else:
                print(f"  ✓ All required fields present")
                print(f"  ✓ CVE ID: {config_data.get('cve_id')}")
                print(f"  ✓ Binary: {config_data.get('binary_name')}")
                print(f"  ✓ Repo: {config_data.get('repo_url')}")
            
            return True
        else:
            print("✗ No configs were generated")
            return False
            
    except Exception as e:
        print(f"✗ Error during batch generation: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Run both tests
    # test1_success = test_config_generator_integration()
    test2_success = test_batch_config_generation()
    
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    # print(f"Single config generation: {'✓ PASS' if test1_success else '✗ FAIL'}")
    print(f"Batch config generation:  {'✓ PASS' if test2_success else '✗ FAIL'}")
    print("=" * 60)
    
    # sys.exit(0 if (test1_success and test2_success) else 1)
