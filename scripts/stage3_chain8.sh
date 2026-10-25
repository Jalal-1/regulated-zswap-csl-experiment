#!/bin/bash
# Archived run script; container-specific paths were replaced by $SCRATCH.
# Chain 8: rerun after the forged-state option for T13(a).
set -u
S=${SCRATCH:?set SCRATCH to the scratch directory}
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"
echo "chain8 start $(date -u +%FT%TZ)" > "$L/stage3_chain8.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer --no-run 2>&1; echo "EXIT=$?"; } > "$L/stage3_scenarios_build3.log" 2>&1
echo "build done $(date -u +%FT%TZ)" >> "$L/stage3_chain8.log"
if grep -q '^EXIT=0' "$L/stage3_scenarios_build3.log"; then
  { cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer -- --nocapture --test-threads=1 2>&1; echo "EXIT=$?"; } > "$L/stage3_scenarios_run3.log" 2>&1
fi
echo "chain8 end $(date -u +%FT%TZ)" >> "$L/stage3_chain8.log"
