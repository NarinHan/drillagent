#!/bin/bash
# Convenience wrapper for config_generator_agent.py

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT="$SCRIPT_DIR/config_generator_agent.py"

# Default output directory
OUTPUT_DIR="$SCRIPT_DIR/configs"

# Check if agent exists
if [ ! -f "$AGENT" ]; then
    echo "Error: config_generator_agent.py not found at $AGENT"
    exit 1
fi

# Make sure it's executable
chmod +x "$AGENT"

# Show usage if no arguments
if [ $# -eq 0 ]; then
    cat << EOF
AFLGo Config Generator - Convenience Wrapper

Usage:
  $(basename $0) <cve-id>                    # Generate single config
  $(basename $0) all                         # Generate all configs
  $(basename $0) <project-name>              # Generate configs for a project (e.g., gpac, jq)

Examples:
  $(basename $0) jq.cve-2023-50246          # Generate jq config
  $(basename $0) md4c.cve-2021-30027        # Generate md4c config
  $(basename $0) all                         # Generate all configs
  $(basename $0) gpac                        # Generate all GPAC configs
  $(basename $0) mruby                       # Generate all mruby configs

The generated configs will be saved to: $OUTPUT_DIR/

For advanced options, use the agent directly:
  $AGENT --help
EOF
    exit 0
fi

# Handle different invocations
case "$1" in
    all)
        echo "Generating configs for ALL CVE instances..."
        "$AGENT" --batch --output-dir "$OUTPUT_DIR"
        ;;
    *.cve-*)
        # Looks like a specific CVE ID
        echo "Generating config for $1..."
        "$AGENT" --cve-id "$1" --output-dir "$OUTPUT_DIR"
        ;;
    *)
        # Assume it's a project name filter
        echo "Generating configs for all $1 CVEs..."
        "$AGENT" --batch --filter "$1" --output-dir "$OUTPUT_DIR"
        ;;
esac

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo ""
    echo "Success! Configs saved to: $OUTPUT_DIR/"
    echo ""
    echo "To use with AFLGo agent:"
    echo "  ./aflgo_llm_agent.py --config $OUTPUT_DIR/<config-file>.yaml"
fi

exit $exit_code
