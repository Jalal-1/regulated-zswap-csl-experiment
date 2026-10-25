#!/bin/bash
set -u
S=/tmp/claude-0/-home-user-wea-japan-pos-poc/8fb10d81-7d79-5e0b-88f5-274972519579/scratchpad
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"; echo "full start $(date -u +%FT%TZ)" > "$L/full_marker.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --no-fail-fast -- --test-threads=1 2>&1; echo "FULL_EXIT=$?"; } > "$L/full_suite.log" 2>&1
echo "full end $(date -u +%FT%TZ)" >> "$L/full_marker.log"
