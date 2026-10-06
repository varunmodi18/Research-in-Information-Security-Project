#!/usr/bin/env bash
# Runs OFMC on every AnB model and writes the raw outputs to results/ (IMPLEMENTATION_PLAN.md M7).
# OFMC 2024 (Moedersheim et al., BSD): http://people.compute.dtu.dk/samo/ofmc2024.zip
#   unzip, then:  OFMC=/path/to/ofmc2024/executables/linux/ofmc formal/avispa/run_all.sh
# Never fabricates output: if OFMC is not available it says so and exits non-zero.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OFMC="${OFMC:-$(command -v ofmc || true)}"
if [ -z "$OFMC" ] || [ ! -x "$OFMC" ]; then
  echo "NOT RUN -- OFMC not found (set OFMC=/path/to/ofmc). See formal/avispa/TOOLING.md." >&2
  exit 2
fi
mkdir -p "$HERE/results"
run() {  # model, sessions
  local out="$HERE/results/$(basename "$1" .AnB).sessions$2.txt"
  { echo "# command: ofmc --numSess $2 anb/$(basename "$1")"; echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    "$OFMC" --version 2>/dev/null | head -1 | sed 's/^/# /'
    timeout 1800 "$OFMC" --numSess "$2" "$1" 2>&1; } > "$out"
  echo "$(basename "$1") sessions=$2: $(grep -A1 SUMMARY "$out" | tail -1 | tr -d ' ')"
}
run "$HERE/anb/maka_e_ake.AnB" 1
run "$HERE/anb/maka_e_ake.AnB" 2
run "$HERE/anb/maka_e_ake.AnB" 3
run "$HERE/anb/maka_e_ake_nopsk_control.AnB" 1
run "$HERE/anb/rp9_auth.AnB" 1
run "$HERE/anb/rp9_auth_honest_ch.AnB" 1
run "$HERE/anb/rp9_auth_outsider.AnB" 1
run "$HERE/anb/rp9_auth_outsider.AnB" 2
run "$HERE/anb/maka_e_ake_fs.AnB" 1
run "$HERE/anb/maka_e_ake_fs.AnB" 2
run "$HERE/anb/maka_e_ake_fs_nodh_control.AnB" 1
run "$HERE/anb/maka_e_ake_fs_nodh_control.AnB" 2
rm -f "$HERE/attracktrace.svg" "$HERE/anb/attracktrace.svg"  # OFMC 2024 writes an (empty) attack-trace SVG
python3 "$HERE/summarize_avispa.py"
