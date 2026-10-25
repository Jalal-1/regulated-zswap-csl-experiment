#!/bin/bash
set -u
S=/tmp/claude-0/-home-user-wea-japan-pos-poc/8fb10d81-7d79-5e0b-88f5-274972519579/scratchpad
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"
# wait for chain3 to finish (cargo lock would serialize anyway, but keep logs clean)
while ! grep -q 'chain3 end' "$L/stage2_chain3.log" 2>/dev/null; do sleep 15; done
echo "chain4 start $(date -u +%FT%TZ)" > "$L/stage3_chain4.log"
{ cargo test --release -p midnight-zswap --lib embedded_spend_verifier_key 2>&1; echo "EXIT=$?"; } > "$L/stage3_zswap_embedded_key.log" 2>&1
{ cargo test --release -p midnight-ledger-v10 --lib test_resolver_resolves 2>&1; echo "EXIT=$?"; } > "$L/stage3_ledger_resolver_test.log" 2>&1
echo "sidecar checks done $(date -u +%FT%TZ)" >> "$L/stage3_chain4.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer --no-run 2>&1; echo "EXIT=$?"; } > "$L/stage3_scenarios_build.log" 2>&1
echo "scenario build done $(date -u +%FT%TZ)" >> "$L/stage3_chain4.log"
if grep -q '^EXIT=0' "$L/stage3_scenarios_build.log"; then
  { cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer -- --nocapture --test-threads=1 2>&1; echo "EXIT=$?"; } > "$L/stage3_scenarios_run.log" 2>&1
fi
echo "chain4 end $(date -u +%FT%TZ)" >> "$L/stage3_chain4.log"
