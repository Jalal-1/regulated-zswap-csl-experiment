#!/bin/bash
# Regenerate the embedded CSL spend verifier key, rebuild, and run the full CSL suite.
set -u
S=/tmp/claude-0/-home-user-wea-japan-pos-poc/8fb10d81-7d79-5e0b-88f5-274972519579/scratchpad
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"; echo "phaseB run start $(date -u +%FT%TZ)" > "$L/phaseB_run_marker.log"

# 1. Regenerate the embedded spend verifier key from the v2 relation.
{ cargo test --release -p midnight-zkir --test zswap_spend_csl write_csl_spend_verifier_key -- --ignored --nocapture 2>&1; echo "KEYGEN_EXIT=$?"; } > "$L/phaseB_keygen.log" 2>&1
echo "keygen done $(date -u +%FT%TZ)" >> "$L/phaseB_run_marker.log"
sha256sum zswap/static/spend.verifier >> "$L/phaseB_run_marker.log"
cat zswap/static/spend.verifier.csl.sha256 >> "$L/phaseB_run_marker.log"

# 2. zkir relation tests (equivalence, negatives, historical rejection) under the regenerated key.
{ cargo test --release -p midnight-zkir --test zswap_spend_csl -- --nocapture 2>&1; echo "ZKIR_EXIT=$?"; } > "$L/phaseB_zkir_tests.log" 2>&1
{ cargo test --release -p midnight-zkir --test zswap_spend 2>&1; echo "ZKIR_LEGACY_EXIT=$?"; } > "$L/phaseB_zkir_legacy.log" 2>&1
{ cargo test --release -p midnight-zkir --lib 2>&1; echo "ZKIR_LIB_EXIT=$?"; } > "$L/phaseB_zkir_lib.log" 2>&1
{ cargo test -p midnight-coin-structure custom_spend 2>&1; echo "CS_EXIT=$?"; } > "$L/phaseB_coin_structure.log" 2>&1
echo "zkir/cs done $(date -u +%FT%TZ)" >> "$L/phaseB_run_marker.log"

# 3. zswap + onchain-runtime (embedded key pin lives in zswap).
{ cargo test --release -p midnight-zswap 2>&1; echo "ZSWAP_EXIT=$?"; } > "$L/phaseB_zswap.log" 2>&1
{ cargo test --release -p midnight-onchain-runtime 2>&1; echo "ORT_EXIT=$?"; } > "$L/phaseB_onchain_runtime.log" 2>&1
{ cargo test --release -p midnight-ledger-v10 --lib 2>&1; echo "LEDGERLIB_EXIT=$?"; } > "$L/phaseB_ledger_lib.log" 2>&1
echo "zswap/ort/ledgerlib done $(date -u +%FT%TZ)" >> "$L/phaseB_run_marker.log"

# 4. Ledger proving suites: controls, scenarios, regression.
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_baseline -- --nocapture 2>&1; echo "BASELINE_EXIT=$?"; } > "$L/phaseB_csl_baseline.log" 2>&1
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer -- --nocapture --test-threads=1 2>&1; echo "SCENARIOS_EXIT=$?"; } > "$L/phaseB_csl_scenarios.log" 2>&1
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_regression -- --nocapture --test-threads=1 2>&1; echo "REGRESSION_EXIT=$?"; } > "$L/phaseB_csl_regression.log" 2>&1
echo "phaseB run done $(date -u +%FT%TZ)" >> "$L/phaseB_run_marker.log"
