#!/bin/bash
# Archived run script; container-specific paths were replaced by $SCRATCH.
set -u
S=${SCRATCH:?set SCRATCH to the scratch directory}
cd /home/user/midnightntwrk/midnight-ledger
export CARGO_NET_GIT_FETCH_WITH_CLI=true CARGO_TERM_COLOR=never MIDNIGHT_PP="$S/params" RUST_MIN_STACK=67108864 MIDNIGHT_LEDGER_TEST_STATIC_DIR="$S/test-artifacts"
L="$S/logs"; echo "regr start $(date -u +%FT%TZ)" > "$L/regr_marker.log"
{ cargo test --release -p midnight-ledger-v10 --features proving --test csl_regression --no-run 2>&1; echo "BUILD_EXIT=$?"; } > "$L/regr_build.log" 2>&1
if grep -q '^BUILD_EXIT=0' "$L/regr_build.log"; then
  { cargo test --release -p midnight-ledger-v10 --features proving --test csl_regression -- --nocapture --test-threads=1 2>&1; echo "RUN_EXIT=$?"; } > "$L/regr_run.log" 2>&1
fi
echo "regr end $(date -u +%FT%TZ)" >> "$L/regr_marker.log"
