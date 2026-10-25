#!/bin/bash
# Archived run script; container-specific paths were replaced by $SCRATCH.
set -u
S=${SCRATCH:?set SCRATCH to the scratch directory}
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"; echo "full start $(date -u +%FT%TZ)" > "$L/full_marker.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --no-fail-fast -- --test-threads=1 2>&1; echo "FULL_EXIT=$?"; } > "$L/full_suite.log" 2>&1
echo "full end $(date -u +%FT%TZ)" >> "$L/full_marker.log"
