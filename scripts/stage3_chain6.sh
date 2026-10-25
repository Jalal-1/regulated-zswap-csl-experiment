#!/bin/bash
# Archived run script; container-specific paths were replaced by $SCRATCH.
set -u
S=${SCRATCH:?set SCRATCH to the scratch directory}
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"
while ! grep -q 'chain5 end' "$L/stage3_chain5.log" 2>/dev/null; do sleep 15; done
echo "chain6 start $(date -u +%FT%TZ)" > "$L/stage3_chain6.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer --no-run 2>&1; echo "EXIT=$?"; } > "$L/stage3_scenarios_build.log" 2>&1
echo "build done $(date -u +%FT%TZ)" >> "$L/stage3_chain6.log"
if grep -q '^EXIT=0' "$L/stage3_scenarios_build.log"; then
  { cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer -- --nocapture --test-threads=1 2>&1; echo "EXIT=$?"; } > "$L/stage3_scenarios_run.log" 2>&1
fi
echo "chain6 end $(date -u +%FT%TZ)" >> "$L/stage3_chain6.log"
