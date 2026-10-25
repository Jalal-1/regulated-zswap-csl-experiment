#!/bin/bash
# Archived run script; container-specific paths were replaced by $SCRATCH.
set -u
S=${SCRATCH:?set SCRATCH to the scratch directory}
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"
echo "chain2 start $(date -u +%FT%TZ)" > "$L/stage2_chain2.log"
{ cargo test --release -p midnight-zswap 2>&1; echo "EXIT=$?"; } > "$L/stage2_zswap_tests.log" 2>&1
echo "zswap tests done $(date -u +%FT%TZ)" >> "$L/stage2_chain2.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_baseline -- --nocapture 2>&1; echo "EXIT=$?"; } > "$L/stage2_ledger_csl_baseline.log" 2>&1
echo "baseline done $(date -u +%FT%TZ)" >> "$L/stage2_chain2.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_gate_layout -- --nocapture 2>&1; echo "EXIT=$?"; } > "$L/stage2_gate_layout.log" 2>&1
echo "chain2 end $(date -u +%FT%TZ)" >> "$L/stage2_chain2.log"
