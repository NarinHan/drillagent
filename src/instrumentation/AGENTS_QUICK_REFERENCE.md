# AFLGo LLM Agents - Quick Reference

Two LLM-driven agents for automated directed fuzzing with AFLGo from SEC-bench CVE data.

## Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    SEC-bench CVE Data                       │
│              (CVE-instances/*.json)                         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
         ╔═══════════════════════════════════╗
         ║  1. Config Generator Agent        ║
         ║     (config_generator_agent.py)   ║
         ╚═══════════════════════════════════╝
                         │
                         │ Analyzes CVE data
                         │ Extracts build info
                         │ Uses LLM to generate
                         │
                         ▼
         ┌───────────────────────────────────┐
         │   AFLGo Config YAML Files         │
         │   (configs/*.yaml)                │
         └────────────────────────────────────┘
                         │
                         ▼
         ╔═══════════════════════════════════╗
         ║  2. AFLGo LLM Agent               ║
         ║     (aflgo_llm_agent.py)          ║
         ╚═══════════════════════════════════╝
                         │
                         │ Clones repo
                         │ Extracts targets
                         │ Instruments code
                         │ Uses LLM for build decisions
                         │
                         ▼
         ┌───────────────────────────────────┐
         │  Instrumented Binary Ready        │
         │  for Directed Fuzzing             │
         └───────────────────────────────────┘
```

## Quick Start

```bash
# 1. Generate config from SEC-bench
./gen_config.sh jq.cve-2023-50246

# 2. Instrument with AFLGo
./aflgo_llm_agent.py --config configs/jq.cve-2023-50246.yaml

# 3. Binary ready at repos/jq/jq
```

## Agent 1: Config Generator

Generates YAML configs from SEC-bench CVE instances.

**Usage:**
```bash
./gen_config.sh <cve-id>              # Single CVE
./gen_config.sh <project>             # All CVEs for project
./gen_config.sh all                   # All CVEs
```

**Output:** `configs/<project>.cve-<id>.yaml`

## Agent 2: AFLGo Instrumentation

Instruments binaries for directed fuzzing.

**Usage:**
```bash
./aflgo_llm_agent.py --config configs/<file>.yaml
```

**Output:** Instrumented binary in `repos/<project>/`

## Setup

```bash
# Required: Build AFLGo
cd fuzzing/aflgo && ./build.sh

# Optional: For LLM features (recommended)
export OPENAI_API_KEY='your-key'
# or create /home/ray/cs562/.env

# Install Python packages
pip install openai python-dotenv pyyaml
```

## Examples

```bash
# jq
./gen_config.sh jq.cve-2023-50246
./aflgo_llm_agent.py --config configs/jq.cve-2023-50246.yaml

# md4c
./gen_config.sh md4c.cve-2021-30027
./aflgo_llm_agent.py --config configs/md4c.cve-2021-30027.yaml

# All gpac CVEs
./gen_config.sh gpac
for cfg in configs/gpac.*.yaml; do
    ./aflgo_llm_agent.py --config "$cfg"
done
```

## File Structure

```
fuzzing/
├── config_generator_agent.py    # Config generator
├── aflgo_llm_agent.py           # AFLGo agent
├── gen_config.sh                # Wrapper script
├── configs/                     # Generated configs
├── logs/                        # Execution logs
└── temps/                       # AFLGo temp files
```

## Troubleshooting

**Build failures:** LLM retries up to 10 times. Check logs under `temps/` for details.

**Wrong binary name:** Edit the YAML config's `binary_name` field.

## Success Indicators

✓ Config generated in `configs/`  
✓ `BBtargets.txt` created  
✓ `distance.cfg.txt` generated  
✓ Instrumented binary exists in `repos/`
