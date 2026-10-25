#!/bin/bash
# Stage 0 chain, part 2: zkir CLIs -> test artifacts -> ledger proving controls.
set -u
S=/tmp/claude-0/-home-user-wea-japan-pos-poc/8fb10d81-7d79-5e0b-88f5-274972519579/scratchpad
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never
export MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864
ART="$S/test-artifacts"
export MIDNIGHT_LEDGER_TEST_STATIC_DIR="$ART"
LOGS="$S/logs"
# 1. wait for the zkir equivalence job to release the cargo lock
while ! grep -q '^EXIT=' "$LOGS/stage0_zkir_zswap_spend.log" 2>/dev/null; do sleep 20; done
echo "chain2 start $(date -u +%FT%TZ)" > "$LOGS/stage0_chain2.log"
# 2. zkir CLIs (v2 and v3)
{ cargo build --release -p midnight-zkir --features binary --bin zkir 2>&1; echo "EXIT=$?"; } > "$LOGS/stage0_build_zkir_v2_cli.log" 2>&1
cp target/release/zkir "$S/bin/zkir-v2"
{ cargo build --release -p midnight-zkir-v3 --features binary --bin zkir 2>&1; echo "EXIT=$?"; } > "$LOGS/stage0_build_zkir_v3_cli.log" 2>&1
cp target/release/zkir "$S/bin/zkir-v3"
echo "clis built $(date -u +%FT%TZ)" >> "$LOGS/stage0_chain2.log"
# 3. test artifacts (reproduces flake.nix packages.test-artifacts)
rm -rf "$ART"; mkdir -p "$ART"
for c in zkir-precompiles/*/; do
  name=$(basename "$c"); mkdir -p "$ART/$name/zkir" "$ART/$name/keys"
  cp "$c"/* "$ART/$name/zkir/"
  ver=$(jq -s '.[0].version.major' "$ART/$name/zkir"/*.zkir)
  if [ "$ver" = "2" ]; then bin="$S/bin/zkir-v2"; else bin="$S/bin/zkir-v3"; fi
  { echo "== $name (zkir v$ver)"; "$bin" compile-many "$ART/$name/zkir" "$ART/$name/keys" 2>&1; echo "EXIT=$?"; } >> "$LOGS/stage0_test_artifacts.log" 2>&1
done
echo "artifacts done $(date -u +%FT%TZ)" >> "$LOGS/stage0_chain2.log"
# 4. ledger proving controls: existing negative control, then the new baseline file if present
{ echo "# $(date -u +%FT%TZ)"; cargo test --release -p midnight-ledger-v10 --features proving --test malicious_imbalance -- --nocapture 2>&1; echo "EXIT=$?"; echo "# end $(date -u +%FT%TZ)"; } > "$LOGS/stage0_ledger_malicious_imbalance.log" 2>&1
if [ -f ledger/tests/csl_baseline.rs ]; then
  { echo "# $(date -u +%FT%TZ)"; cargo test --release -p midnight-ledger-v10 --features proving --test csl_baseline -- --nocapture 2>&1; echo "EXIT=$?"; echo "# end $(date -u +%FT%TZ)"; } > "$LOGS/stage0_ledger_csl_baseline.log" 2>&1
fi
echo "chain2 end $(date -u +%FT%TZ)" >> "$LOGS/stage0_chain2.log"
