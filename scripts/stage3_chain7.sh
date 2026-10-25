#!/bin/bash
# Chain 7: rebuild and rerun the Stage 3 scenarios after the rejection-helper rework.
set -u
S=/tmp/claude-0/-home-user-wea-japan-pos-poc/8fb10d81-7d79-5e0b-88f5-274972519579/scratchpad
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"
echo "chain7 start $(date -u +%FT%TZ)" > "$L/stage3_chain7.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer --no-run 2>&1; echo "EXIT=$?"; } > "$L/stage3_scenarios_build2.log" 2>&1
echo "build done $(date -u +%FT%TZ)" >> "$L/stage3_chain7.log"
if grep -q '^EXIT=0' "$L/stage3_scenarios_build2.log"; then
  { cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer -- --nocapture --test-threads=1 2>&1; echo "EXIT=$?"; } > "$L/stage3_scenarios_run2.log" 2>&1
fi
echo "chain7 end $(date -u +%FT%TZ)" >> "$L/stage3_chain7.log"
