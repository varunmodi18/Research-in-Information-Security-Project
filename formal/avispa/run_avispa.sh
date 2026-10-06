#!/usr/bin/env bash
# Runs every HLPSL model through the AVISPA tool chain fetched by fetch_avispa.sh and writes the raw
# outputs to formal/avispa/results/avispa/ (follow-up Part C2). Never fabricates output: a tool error,
# crash or timeout is recorded verbatim with its exit code.
#   AVISPA_TOOLS=~/avispa_tools formal/avispa/run_avispa.sh [--calibration | MODEL...]
# With MODEL names, only those models are run (models are independent, so they can run in parallel);
# SUMMARY.json is rebuilt from whatever outputs exist after every invocation.
#
# Tool chain (see TOOLING.md for why):
#   translator   hlpsl2if of the 64-bit SPAN 1.6 package (accepts `hash_func`, RP9's dialect); every
#                model is ALSO given to the original 32-bit hlpsl2if and its verbatim output recorded
#   back-ends    OFMC "version of 2006/02/13" and CL-AtSe 2.2-5 from the original 32-bit SPAN 1.6
#                package (calibrated on SPAN's own test suite: 32 of 34 models agree), plus CL-AtSe 2.3-4
#                of the 64-bit package as a second CL-AtSe build. Default options = SPAN's defaults
#                (typed model). Untyped runs are recorded separately for the MAKA-E models.
#   timeout      1800 s per run.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="${AVISPA_TOOLS:?set AVISPA_TOOLS to the directory prepared by fetch_avispa.sh}"
L=$T/sysroot_i386/usr/lib/i386-linux-gnu
S32=$T/x_span16_linux32/span/bin
S64=$T/x_span16_linux64/span/bin
TO=1800
OUT=results/avispa
cd "$HERE"
mkdir -p $OUT/if $OUT/split $OUT/translate $OUT/runs $OUT/probes

stamp() { echo "# date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"; }
# run LABEL OUTFILE CMD...   (LABEL is the human-readable command written into the header)
run() {
  local label=$1 out=$2; shift 2
  { echo "# command: $label"; stamp; timeout $TO "$@" 2>&1; echo "# exit: $?"; } > "$out"
}
# command prefixes (arrays, so that `timeout` can run them)
T64=(env LD_LIBRARY_PATH=$T/compat_lib $S64/translator/hlpsl2if)
T32=($L/ld-linux.so.2 --library-path $L $S32/translator/hlpsl2if $S32/translator/hlpsl2if)  # OCaml custom
OFMC=($L/ld-linux.so.2 --library-path $L $S32/backends/ofmc/ofmc)                          #  runtime: the binary
CL225=($L/ld-linux.so.2 --library-path $L $S32/backends/cl/cl-atse)                        #  is passed as its own
CL234=(env LD_LIBRARY_PATH=$T/compat_lib $S64/backends/cl/cl-atse)                         #  bytecode file

OFMC12=(env LD_LIBRARY_PATH=$T/compat_lib $S64/backends/ofmc/ofmc --classic)      # 2012c; hangs without --classic

if [ "${1:-}" = "--calibration" ]; then
  # SPAN's own test suite through three chains (default options, 120 s per run):
  #   all-32  original translator -> OFMC 2006, CL-AtSe 2.2-5
  #   mixed   64-bit translator   -> OFMC 2006, CL-AtSe 2.2-5   (the chain used for our models)
  #   all-64  64-bit translator   -> OFMC 2012c, CL-AtSe 2.3-4
  verdict() { timeout 120 "$@" 2>&1 | awk '/^SUMMARY/{getline; print $1; exit}'; }
  W=$(mktemp -d); W64=$(mktemp -d); cp $S32/../testsuite/hlpsl/*.hlpsl $W/; cp $W/*.hlpsl $W64/
  { echo "# SPAN 1.6 test suite ($(ls $W/*.hlpsl | wc -l) models), default options, 120 s per run; '-' = no IF produced"
    stamp
    printf "%-26s | %-9s %-9s | %-9s %-9s | %-9s %-9s\n" model "32:ofmc06" "32:cl225" "mx:ofmc06" "mx:cl225" "64:ofmc12" "64:cl234"
    for f in $W/*.hlpsl; do m=$(basename $f .hlpsl)
      (cd $W && "${T32[@]}" $m.hlpsl > /dev/null 2>&1)
      (cd $W64 && "${T64[@]}" --output $W64 $m.hlpsl > /dev/null 2>&1)
      a=- b=- c=- d=- e=- g=-
      if [ -f $W/$m.if ]; then a=$(verdict "${OFMC[@]}" $W/$m.if); b=$(verdict "${CL225[@]}" $W/$m.if); fi
      if [ -f $W64/$m.if ]; then c=$(verdict "${OFMC[@]}" $W64/$m.if); d=$(verdict "${CL225[@]}" $W64/$m.if)
                                 e=$(verdict "${OFMC12[@]}" $W64/$m.if); g=$(verdict "${CL234[@]}" $W64/$m.if); fi
      printf "%-26s | %-9s %-9s | %-9s %-9s | %-9s %-9s\n" $m "${a:-ERR/TO}" "${b:-ERR/TO}" "${c:-ERR/TO}" "${d:-ERR/TO}" "${e:-ERR/TO}" "${g:-ERR/TO}"
    done; } > $OUT/calibration_span_testsuite.txt
  rm -rf $W $W64; exit 0
fi

MODELS="${*:-rp9_transcribed rp9_fixed rp9_executable rp9_insider maka_e maka_e_nopsk_control}"
for m in $MODELS; do
  kind=rp9; case $m in maka_e*) kind=maka_e;; esac
  # translation, by both translators (verbatim output; only the 64-bit one's IF is used)
  run "hlpsl2if(64-bit SPAN 1.6) $m.hlpsl" $OUT/translate/$m.hlpsl2if-64.txt "${T64[@]}" --output $OUT/if $m.hlpsl
  W=$(mktemp -d); cp $m.hlpsl $W/
  run "hlpsl2if(32-bit SPAN 1.6, original) $m.hlpsl" $OUT/translate/$m.hlpsl2if-32.txt bash -c "cd $W && ${T32[*]} $m.hlpsl"
  rm -rf $W
  [ -f $OUT/if/$m.if ] || continue
  "${T64[@]}" --split --output $OUT/split $m.hlpsl > /dev/null 2>&1
  # all goals together, each back-end
  run "ofmc(2006/02/13) if/$m.if" $OUT/runs/$m.ofmc2006.txt "${OFMC[@]}" $OUT/if/$m.if
  run "cl-atse(2.2-5) if/$m.if" $OUT/runs/$m.clatse225.txt "${CL225[@]}" $OUT/if/$m.if
  run "cl-atse(2.3-4) if/$m.if" $OUT/runs/$m.clatse234.txt "${CL234[@]}" $OUT/if/$m.if
  # one goal at a time (hlpsl2if --split): a back-end stops at the first attack it finds
  for g in $OUT/split/$m-*.if; do b=$(basename $g .if)
    run "ofmc(2006/02/13) split/$b.if" $OUT/runs/$b.ofmc2006.txt "${OFMC[@]}" $g
    run "cl-atse(2.2-5) split/$b.if" $OUT/runs/$b.clatse225.txt "${CL225[@]}" $g
  done
  if [ $kind = maka_e ]; then  # the untyped model (not AVISPA's default) for the MAKA-E models
    run "ofmc(2006/02/13) if/$m.if -untyped" $OUT/runs/$m.ofmc2006-untyped.txt "${OFMC[@]}" $OUT/if/$m.if -untyped
    run "cl-atse(2.2-5) if/$m.if -notype" $OUT/runs/$m.clatse225-untyped.txt "${CL225[@]}" $OUT/if/$m.if -notype
  fi
  # executability: one probe per transition
  P=$OUT/probes/$m; mkdir -p $P
  python3 probes.py $m.hlpsl $P/${m}_probes.hlpsl $kind > /dev/null
  "${T64[@]}" --split --output $P $P/${m}_probes.hlpsl > /dev/null 2>&1
  for g in $P/${m}_probes-secrecy-probe_*.if; do b=$(basename $g .if)
    run "ofmc(2006/02/13) probes/$m/$b.if" $P/$b.ofmc2006.txt "${OFMC[@]}" $g
  done
  rm -f $P/${m}_probes-auth-*.if $P/${m}_probes-secrecy-sec*.if $P/${m}_probes-secrecy-k_*.if
done
python3 summarize_avispa.py
