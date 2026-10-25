#!/usr/bin/env bash
# Portable, pinned reproduction of the regulated ZSwap CSL experiment.
#
# Usage:  scripts/reproduce.sh [stage ...]
# Stages: clone      fetch this repository's ledger branch and check out the PINNED commit from MANIFEST.json
#         verify     check that $LEDGER is at the pinned commit and has no local modifications (never resets)
#         params     download and verify (SHA-256) the public parameters bls_midnight_2p0..18 into $MIDNIGHT_PP
#         clis       build the zkir CLIs (v2 and v3) into $BIN
#         artifacts  compile zkir-precompiles/* into $MIDNIGHT_LEDGER_TEST_STATIC_DIR and place the zswap and
#                    dust keys into $MIDNIGHT_PP/<component>/<version> (as flake.nix and its local-params do)
#         features   assert `mock-verify` is absent from the resolved feature graph of every tested crate
#         metadata   write $LOGS/run-metadata.json (revision, toolchain, features, parameter and artifact hashes)
#         unit       the non-proving suites touched by the change
#         controls   the strict ledger controls (plain transfer accepted; corrupted proof and altered statement rejected)
#         scenarios  the Stage 3 scenarios (real proofs, about four minutes on four cores)
#         regression the regression suite (malicious gate, hiding binding, protected-token configuration)
#         full       the complete midnight-ledger-v10 proving suite (about forty minutes on four cores)
#         quick      clone verify params clis artifacts features metadata unit controls scenarios regression
#         all        quick + full   (default)
#
# Environment (all optional):
#   LEDGER                           ledger checkout            (default: ./midnight-ledger)
#   MIDNIGHT_PP                      public parameters          (default: ./params)
#   MIDNIGHT_LEDGER_TEST_STATIC_DIR  compiled test artifacts    (default: ./test-artifacts)
#   BIN                              zkir CLI binaries          (default: ./bin)
#   LOGS                             log directory              (default: ./logs)
#   MANIFEST                         pin file                   (default: MANIFEST.json next to this script's parent)
#   REPO_URL                         where `clone` fetches from (default: manifest.repository)
#   ALLOW_REVISION_MISMATCH=1        proceed on a different commit (recorded in run-metadata.json as a deviation)
#   ALLOW_DIRTY=1                    proceed with local modifications (recorded; the diff summary is logged)
#
# Requirements: rust stable (rustc 1.97.0 was used), git, curl, jq, sha256sum. No Nix needed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${MANIFEST:-$HERE/../MANIFEST.json}"
[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

LEDGER="${LEDGER:-$PWD/midnight-ledger}"
export MIDNIGHT_PP="${MIDNIGHT_PP:-$PWD/params}"
export MIDNIGHT_LEDGER_TEST_STATIC_DIR="${MIDNIGHT_LEDGER_TEST_STATIC_DIR:-$PWD/test-artifacts}"
BIN="${BIN:-$PWD/bin}"
LOGS="${LOGS:-$PWD/logs}"
export RUST_MIN_STACK="${RUST_MIN_STACK:-67108864}"
export CARGO_TERM_COLOR=never
mkdir -p "$LOGS"

PIN_COMMIT="$(jq -r .implementation_commit "$MANIFEST")"
PIN_BRANCH="$(jq -r .implementation_branch "$MANIFEST")"
REPO_URL="${REPO_URL:-$(jq -r .repository "$MANIFEST")}"
PARAM_URL="$(jq -r .parameters.url "$MANIFEST")"
PIN_SPEND_VK="$(jq -r .artifacts.embedded_spend_verifier_sha256 "$MANIFEST")"
DEVIATIONS=()

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
run() { # run <logname> <command...>: tee to a log, keep the exit code
  local name="$1"; shift
  log "$name: $*"
  set +e; "$@" 2>&1 | tee "$LOGS/$name.log"; local rc=${PIPESTATUS[0]}; set -e
  echo "EXIT=$rc" >> "$LOGS/$name.log"
  [ "$rc" -eq 0 ] || { log "$name FAILED (exit $rc); see $LOGS/$name.log"; exit "$rc"; }
}

stage_clone() {
  if [ -d "$LEDGER/.git" ]; then log "ledger checkout present at $LEDGER (not touching it; see 'verify')"; return; fi
  log "cloning $REPO_URL branch $PIN_BRANCH into $LEDGER"
  git clone --branch "$PIN_BRANCH" "$REPO_URL" "$LEDGER"
  log "checking out the pinned commit $PIN_COMMIT (detached)"
  git -C "$LEDGER" checkout --quiet --detach "$PIN_COMMIT"
}

stage_verify() {
  [ -d "$LEDGER/.git" ] || { log "no ledger checkout at $LEDGER; run the clone stage"; exit 3; }
  local head; head="$(git -C "$LEDGER" rev-parse HEAD)"
  if [ "$head" != "$PIN_COMMIT" ]; then
    log "REVISION MISMATCH: checkout is at $head, manifest pins $PIN_COMMIT"
    if [ "${ALLOW_REVISION_MISMATCH:-0}" = "1" ]; then
      DEVIATIONS+=("revision mismatch: $head != $PIN_COMMIT"); log "continuing because ALLOW_REVISION_MISMATCH=1"
    else
      log "refusing to continue: results would not describe the pinned implementation."
      log "Either check out $PIN_COMMIT yourself, or set ALLOW_REVISION_MISMATCH=1 to record the deviation. Nothing was reset."
      exit 3
    fi
  else
    log "revision verified: $head"
  fi
  local dirty; dirty="$(git -C "$LEDGER" status --porcelain --untracked-files=normal)"
  if [ -n "$dirty" ]; then
    log "LOCAL MODIFICATIONS in $LEDGER:"; printf '%s\n' "$dirty" | head -40
    git -C "$LEDGER" diff --stat | tail -3 | tee "$LOGS/local-modifications.txt" >/dev/null || true
    if [ "${ALLOW_DIRTY:-0}" = "1" ]; then
      DEVIATIONS+=("local modifications present (see local-modifications.txt)"); log "continuing because ALLOW_DIRTY=1"
    else
      log "refusing to continue with local modifications; commit or stash them, or set ALLOW_DIRTY=1 to record the deviation. Nothing was reset or deleted."
      exit 3
    fi
  else
    log "working tree clean"
  fi
}

stage_params() {
  mkdir -p "$MIDNIGHT_PP"
  jq -r '.parameters.files | to_entries[] | "\(.value) \(.key)"' "$MANIFEST" | while read -r hash name; do
    local f="$MIDNIGHT_PP/$name"
    if [ -f "$f" ] && [ "$(sha256sum "$f" | cut -d' ' -f1)" = "$hash" ]; then log "$name: present, hash verified"; continue; fi
    log "$name: downloading"
    curl -fsSL --retry 3 -o "$f.part" "$PARAM_URL/$name"
    local got; got="$(sha256sum "$f.part" | cut -d' ' -f1)"
    if [ "$got" != "$hash" ]; then log "$name: HASH MISMATCH (got $got)"; rm -f "$f.part"; exit 1; fi
    mv "$f.part" "$f"; log "$name: downloaded, hash verified"
  done
}

stage_clis() {
  mkdir -p "$BIN"
  (cd "$LEDGER" && run build_zkir_v2 cargo build --release -p midnight-zkir --features binary --bin zkir && cp target/release/zkir "$BIN/zkir-v2")
  (cd "$LEDGER" && run build_zkir_v3 cargo build --release -p midnight-zkir-v3 --features binary --bin zkir && cp target/release/zkir "$BIN/zkir-v3")
}

stage_artifacts() {
  local art="$MIDNIGHT_LEDGER_TEST_STATIC_DIR"
  rm -rf "$art"; mkdir -p "$art"
  for c in "$LEDGER"/zkir-precompiles/*/; do
    local name; name="$(basename "$c")"
    mkdir -p "$art/$name/zkir" "$art/$name/keys"; cp "$c"/* "$art/$name/zkir/"
    local ver; ver="$(jq -s '.[0].version.major' "$art/$name/zkir"/*.zkir)"
    local bin; if [ "$ver" = "2" ]; then bin="$BIN/zkir-v2"; else bin="$BIN/zkir-v3"; fi
    log "compiling $name (zkir v$ver)"
    "$bin" compile-many "$art/$name/zkir" "$art/$name/keys" >> "$LOGS/test_artifacts.log" 2>&1
  done
  log "artifacts in $art"
  # Published zswap and dust keys into the parameter cache, as flake.nix's local-params does: the
  # zswap unit tests read them from $MIDNIGHT_PP/<component>/<version>/ and never download them.
  local ver; ver="$(tr -d '\n' < "$LEDGER/static/version")"
  for c in zswap dust; do
    mkdir -p "$MIDNIGHT_PP/$c/$ver"
    cp -a "$art/$c/zkir/." "$MIDNIGHT_PP/$c/$ver/"
    cp -a "$art/$c/keys/." "$MIDNIGHT_PP/$c/$ver/"
  done
  # The data provider serves a cached file only if its SHA-256 matches the sidecar compiled into
  # midnight-zswap; check here so a compiled key that differs from the published one fails loudly.
  local f exp got
  for f in spend.prover spend.verifier spend.bzkir output.prover output.verifier output.bzkir sign.prover sign.verifier sign.bzkir; do
    exp="$(cut -c1-64 "$LEDGER/zswap/static/$f.sha256")"; got="$(sha256sum "$MIDNIGHT_PP/zswap/$ver/$f" | cut -c1-64)"
    [ "$exp" = "$got" ] || { log "zswap/$ver/$f: compiled key differs from the pinned hash ($got != $exp)"; exit 4; }
  done
  log "zswap/$ver and dust/$ver keys placed in $MIDNIGHT_PP (the nine zswap files match the pinned hashes)"
}

stage_features() {
  cd "$LEDGER"
  local bad=0
  for pkg in midnight-ledger-v10 midnight-zswap midnight-zkir midnight-onchain-runtime midnight-coin-structure; do
    local out n
    if out="$(cargo tree -p "$pkg" --features proving -e features 2>/dev/null)"; then :; else out="$(cargo tree -p "$pkg" -e features)"; fi
    n="$(printf '%s\n' "$out" | grep -c 'mock-verify' || true)"
    log "$pkg: mock-verify occurrences in the resolved feature graph = $n"
    [ "$n" = "0" ] || bad=1
  done
  [ "$bad" = "0" ] || { log "mock-verify is enabled somewhere; refusing to count these runs as real-proof evidence"; exit 4; }
}

stage_metadata() {
  local head dirty spend_vk
  head="$(git -C "$LEDGER" rev-parse HEAD 2>/dev/null || echo unknown)"
  dirty="$(git -C "$LEDGER" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
  spend_vk="$(sha256sum "$LEDGER/zswap/static/spend.verifier" | cut -d' ' -f1)"
  [ "$spend_vk" = "$PIN_SPEND_VK" ] || DEVIATIONS+=("embedded spend verifier sha256 $spend_vk differs from the manifest's $PIN_SPEND_VK")
  {
    echo "{"
    echo "  \"manifest\": \"$MANIFEST\","
    echo "  \"pinned_commit\": \"$PIN_COMMIT\","
    echo "  \"checked_out_commit\": \"$head\","
    echo "  \"local_modifications\": $dirty,"
    echo "  \"rustc\": \"$(rustc -V)\","
    echo "  \"cargo\": \"$(cargo -V)\","
    echo "  \"host\": \"$(uname -srm)\","
    echo "  \"features\": \"--features proving on midnight-ledger-v10 (default proof-verifying); mock-verify asserted absent by the features stage\","
    echo "  \"embedded_spend_verifier_sha256\": \"$spend_vk\","
    echo "  \"embedded_spend_verifier_pin\": \"$(cut -d' ' -f1 "$LEDGER/zswap/static/spend.verifier.csl.sha256")\","
    echo "  \"parameters_sha256\": $(cd "$MIDNIGHT_PP" && sha256sum bls_midnight_2p* | jq -R -s 'split("\n") | map(select(length>0))'),"
    if [ -d "$MIDNIGHT_LEDGER_TEST_STATIC_DIR" ]; then
      echo "  \"test_artifact_keys_sha256\": $(cd "$MIDNIGHT_LEDGER_TEST_STATIC_DIR" && { find . -name '*.verifier' -o -name '*.prover' | sort | xargs sha256sum; } | jq -R -s 'split("\n") | map(select(length>0))'),"
    fi
    echo "  \"deviations\": $(printf '%s\n' "${DEVIATIONS[@]:-}" | jq -R -s 'split("\n") | map(select(length>0))'),"
    echo "  \"written\": \"$(date -u +%FT%TZ)\""
    echo "}"
  } > "$LOGS/run-metadata.json"
  log "run metadata written to $LOGS/run-metadata.json"; cat "$LOGS/run-metadata.json"
}

stage_unit() {
  cd "$LEDGER"
  run coin_structure       cargo test -p midnight-coin-structure custom_spend
  run zkir_lib             cargo test --release -p midnight-zkir --lib
  run zkir_zswap_spend     cargo test --release -p midnight-zkir --test zswap_spend
  run zkir_zswap_spend_csl cargo test --release -p midnight-zkir --test zswap_spend_csl
  run zswap                cargo test --release -p midnight-zswap
  run onchain_runtime      cargo test --release -p midnight-onchain-runtime
  run ledger_lib           cargo test --release -p midnight-ledger-v10 --lib
}

stage_controls()   { cd "$LEDGER"; run ledger_malicious_imbalance cargo test --release -p midnight-ledger-v10 --features proving --test malicious_imbalance; run ledger_csl_baseline cargo test --release -p midnight-ledger-v10 --features proving --test csl_baseline -- --nocapture; }
stage_scenarios()  { cd "$LEDGER"; run ledger_csl_regulated_transfer cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer -- --nocapture --test-threads=1; }
stage_regression() { cd "$LEDGER"; run ledger_csl_regression cargo test --release -p midnight-ledger-v10 --features proving --test csl_regression -- --nocapture --test-threads=1; }
stage_full()       { cd "$LEDGER"; run ledger_full_proving_suite cargo test --release -p midnight-ledger-v10 --features proving --no-fail-fast -- --test-threads=1; }

stage_quick() { stage_clone; stage_verify; stage_params; stage_clis; stage_artifacts; stage_features; stage_metadata; stage_unit; stage_controls; stage_scenarios; stage_regression; }

stages=("$@"); [ ${#stages[@]} -gt 0 ] || stages=(all)
for s in "${stages[@]}"; do
  case "$s" in
    all) stage_quick; stage_full ;;
    quick) stage_quick ;;
    clone|verify|params|clis|artifacts|features|metadata|unit|controls|scenarios|regression|full) "stage_$s" ;;
    *) echo "unknown stage: $s" >&2; exit 2 ;;
  esac
done
log "done"
