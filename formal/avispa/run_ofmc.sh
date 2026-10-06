#!/usr/bin/env bash
# P11.6: detects a local AVISPA/SPAN installation; if present, runs OFMC and diffs its
# output against expected_output.txt (RP9 Fig. 9). If absent, prints instructions plus RP9's
# published result and marks NOT RUN -- TOOL ABSENT. Never fabricates verification output.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HLPSL_FILE="$SCRIPT_DIR/maka.hlpsl"
EXPECTED_FILE="$SCRIPT_DIR/expected_output.txt"

if command -v ofmc >/dev/null 2>&1; then
    echo "OFMC found on PATH -- running against $HLPSL_FILE"
    ofmc "$HLPSL_FILE" | tee /tmp/maka_ofmc_actual.txt
    echo "--- diff against RP9's published result (expected_output.txt) ---"
    diff "$EXPECTED_FILE" /tmp/maka_ofmc_actual.txt && echo "MATCH" || echo "DIFFERS (see above)"
else
    echo "NOT RUN -- TOOL ABSENT (this script runs the legacy maka.hlpsl; the real AVISPA runs are run_avispa.sh, see TOOLING.md)"
    echo
    echo "AVISPA/SPAN (providing the 'ofmc' command) was not found on PATH."
    echo "To install: see http://www.avispa-project.org/ or the SPAN toolset."
    echo "Once installed, re-run this script: formal/avispa/run_ofmc.sh"
    echo
    echo "RP9's published result (Fig. 9), quoted rather than reproduced:"
    cat "$EXPECTED_FILE"
    exit 0
fi
