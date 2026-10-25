#!/bin/bash
# Archived run script; container-specific paths were replaced by $SCRATCH.
# Chain 10: the complete ledger package test suite (lib, every integration test, doc tests) under real proving, no fail-fast.
set -u
S=${SCRATCH:?set SCRATCH to the scratch directory}
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"
echo "chain10 start $(date -u +%FT%TZ)" > "$L/stage4_chain10.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --no-fail-fast -- --test-threads=1 2>&1; echo "EXIT=$?"; } > "$L/stage4_full_ledger_tests.log" 2>&1
echo "chain10 end $(date -u +%FT%TZ)" >> "$L/stage4_chain10.log"
