#!/bin/bash
set -u
S=/tmp/claude-0/-home-user-wea-japan-pos-poc/8fb10d81-7d79-5e0b-88f5-274972519579/scratchpad
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"
echo "chain3 start $(date -u +%FT%TZ)" > "$L/stage2_chain3.log"
{ cargo test --release -p midnight-onchain-runtime 2>&1; echo "EXIT=$?"; } > "$L/stage2_onchain_runtime_tests.log" 2>&1
echo "onchain-runtime done $(date -u +%FT%TZ)" >> "$L/stage2_chain3.log"
{ cargo test --release -p midnight-zkir --lib 2>&1; echo "EXIT=$?"; } > "$L/stage2_zkir_lib_tests.log" 2>&1
echo "zkir lib done $(date -u +%FT%TZ)" >> "$L/stage2_chain3.log"
{ cargo test --release -p midnight-ledger-v10 --lib 2>&1; echo "EXIT=$?"; } > "$L/stage2_ledger_lib_tests.log" 2>&1
echo "ledger lib done $(date -u +%FT%TZ)" >> "$L/stage2_chain3.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_baseline -- --nocapture 2>&1; echo "EXIT=$?"; } > "$L/stage2_ledger_csl_baseline.log" 2>&1
echo "chain3 end $(date -u +%FT%TZ)" >> "$L/stage2_chain3.log"
