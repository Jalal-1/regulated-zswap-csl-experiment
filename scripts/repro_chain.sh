#!/bin/bash
# Archived run script; container-specific paths were replaced by $SCRATCH.
set -u
S=${SCRATCH:?set SCRATCH to the scratch directory}
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"
echo "repro start $(date -u +%FT%TZ)" > "$L/repro_chain.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_regression --no-run 2>&1; echo "EXIT=$?"; } > "$L/repro_build.log" 2>&1
echo "build done $(date -u +%FT%TZ)" >> "$L/repro_chain.log"
if grep -q '^EXIT=0' "$L/repro_build.log"; then
  { cargo test --release -p midnight-ledger-v10 --features proving --test csl_regression -- --nocapture --test-threads=1 2>&1; echo "EXIT=$?"; } > "$L/repro_run.log" 2>&1
fi
echo "repro end $(date -u +%FT%TZ)" >> "$L/repro_chain.log"
