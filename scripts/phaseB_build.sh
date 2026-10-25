#!/bin/bash
set -u
S=/tmp/claude-0/-home-user-wea-japan-pos-poc/8fb10d81-7d79-5e0b-88f5-274972519579/scratchpad
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"; echo "phaseB build start $(date -u +%FT%TZ)" > "$L/phaseB_build_marker.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_regression --test csl_regulated_transfer --test csl_baseline --no-run 2>&1; echo "LEDGER_EXIT=$?"; } > "$L/phaseB_build_ledger.log" 2>&1
{ cargo test --release -p midnight-zkir --test zswap_spend_csl --no-run 2>&1; echo "ZKIR_EXIT=$?"; } > "$L/phaseB_build_zkir.log" 2>&1
echo "phaseB build done $(date -u +%FT%TZ)" >> "$L/phaseB_build_marker.log"
