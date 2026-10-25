#!/bin/bash
# Archived run script; container-specific paths were replaced by $SCRATCH.
set -u
S=${SCRATCH:?set SCRATCH to the scratch directory}
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"
echo "chain start $(date -u +%FT%TZ)" > "$L/stage2_chain1.log"
{ cargo test --release -p midnight-zkir --test zswap_spend_csl write_csl_spend_verifier_key -- --ignored --nocapture 2>&1; echo "EXIT=$?"; } > "$L/stage2_write_vk.log" 2>&1
{ cargo test --release -p midnight-zkir --test zswap_spend_csl legacy_relation 2>&1; echo "EXIT=$?"; } > "$L/stage2_legacy_rejected.log" 2>&1
echo "vk written $(date -u +%FT%TZ)" >> "$L/stage2_chain1.log"
{ cargo test --release -p midnight-zswap 2>&1; echo "EXIT=$?"; } > "$L/stage2_zswap_tests.log" 2>&1
echo "zswap tests done $(date -u +%FT%TZ)" >> "$L/stage2_chain1.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_baseline -- --nocapture 2>&1; echo "EXIT=$?"; } > "$L/stage2_ledger_csl_baseline.log" 2>&1
echo "baseline done $(date -u +%FT%TZ)" >> "$L/stage2_chain1.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_gate_layout -- --nocapture 2>&1; echo "EXIT=$?"; } > "$L/stage2_gate_layout.log" 2>&1
echo "chain end $(date -u +%FT%TZ)" >> "$L/stage2_chain1.log"
