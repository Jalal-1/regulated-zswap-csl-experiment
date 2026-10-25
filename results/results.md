# Regulated ZSwap CSL experiment: results log

Base: `fa995fa5791bc19112e97334a2d9265751c35fad`; toolchain rustc 1.97.0 stable; 4 vCPU, 15 GB RAM,
public parameters `bls_midnight_2p0..18` (hashes verified against `flake.nix`). All proving
tests run in `--release` with the `proving` feature; mock verification is never enabled.

| Stage | Evidence | Result |
| --- | --- | --- |
| 0 | `cargo test -p midnight-coin-structure custom_spend` | 3 passed (plus `descriptor_hash_matches_fixed_layout` added in Stage 2) |
| 0 | `cargo test --release -p midnight-zkir --test zswap_spend` (legacy relation vs shipped key, real proofs) | 2 passed, 17.9 s |
| 0 | `cargo test --release -p midnight-ledger-v10 --features proving --test malicious_imbalance` | 2 passed, 29.2 s (negative control through the real verifier) |
| 0 | `ledger/tests/csl_baseline.rs` (plain transfer accepted; corrupted proof rejected; altered statement rejected) | 3 passed, 39.1 s. The first run of the positive control exposed a 1e11 Speck DUST underpayment by the shared balancing helper (it prices against mock proofs); fixed by exact fee payment with a pay-prove-measure fixed point, after which all three controls pass |
| 0 | `cargo test --release -p midnight-zkir --test zswap_spend_csl` (CSL relation, real proofs, k = 15) | 4 passed: derivation matches coin-structure; guarded spend proves with non-zero binding and tampering fails; Empty-for-guarded, wrong-gate and underivable-type witnesses do not verify; legacy-relation proofs do not verify under the CSL key |
| 2 | `cargo test --release -p midnight-zswap` after the wire change and key switch | 19 + 2 passed (spend proofs now produced by the CSL relation through the prover hook) |
| 2 | `cargo test --release -p midnight-onchain-runtime` with effects indices 9 and 10 | 23 passed (tag `contract-effects[v5]` registered) |
| 2 | `cargo test --release -p midnight-zkir --lib` | 10 passed (whitelist path helper included) |
| 2 | `cargo test --release -p midnight-ledger-v10 --lib` with the matching rule and tag bumps | 90 passed, 1 failed (`test_resolver_resolves`: the download sidecar had been changed to the CSL hash); restored to the legacy hash, after which the test passes (1 passed) and `zswap::verify::embedded_spend_verifier_key_is_the_csl_key` pins the embedded key |
| 3 | `ledger/tests/csl_regulated_transfer.rs` (T01, T02/T12, T04, T06, T07, T08, T13a, T13b, T24), real proofs, strict `well_formed`, state application | 9 passed, 236 s (third run; the first two runs are explained below) |

## Stage 3 scenarios in detail

Each scenario builds a real transaction (CSL spend proof, gate proof, DUST fee), proves it with the
production prover, and submits it to `TestState::apply` under the default (strict) strictness. The
"disposal" column is the ledger's actual error, copied from the run log.

| Id | Scenario | Disposal |
| --- | --- | --- |
| T01 | approved Alice to approved Bob | accepted and applied: Alice's nullifier recorded, Bob's commitment inserted |
| T02/T12 (stale) | proof made before Alice's removal, submitted after the new root is published | `Failure(Transcript(Execution(ReadMismatch { expected: <old root>, actual: <new root> })))` at application; the coin is not consumed and no output is created |
| T02/T12 (fresh) | Alice tries again under the new root | `InvalidProof(v1 verification: Invalid proof)` at verification: the only proof she can make does not verify |
| T04 | approved Alice to unapproved Carol | `InvalidProof` at verification (Carol has no membership path) |
| T06 | the regulated coin is spent with no gate call | `EffectsCheckFailure(SpendAuthorizationsNEClaimed)` at verification, before any state change |
| T07 | the gate is shown Bob as the sender while Alice's coin is spent | `EffectsCheckFailure(SpendAuthorizationsNEClaimed)`: the spend proof binds Alice's key, the gate claims Bob's binding |
| T08 | the gate checks Bob, the offer pays Carol | `EffectsCheckFailure(OutputCoverageNESegmentCommitments)`: the claimed commitment is not the segment's output |
| T13a | membership under an attacker-chosen root, with the transcript claiming that root (program run against a forged state copy) | `Failure(Transcript(Execution(ReadMismatch { expected: <forged root>, actual: <real root> })))` at application: the proof verifies for its own statement, the root claim does not replay |
| T13b | membership under an attacker-chosen root, with the transcript claiming the real root | `InvalidProof` at verification: statement and witness disagree |
| T24 | `update_root` with the wrong administrator secret | `InvalidProof` at verification; nothing applied |

Observations recorded during the runs:

- The first run asserted that unsatisfiable witnesses fail *at proving*. They do not: `create_proof`
  emits a proof for any witness and the proof fails verification. The scenarios were reworked to
  assert on the ledger's disposal (`Rejection` in `csl_common.rs`), which is also the property that
  matters.
- The first run's stale-proof case was rejected for `IntentTtlExpired` rather than for the root:
  the fee intent's TTL equalled its creation time and the harness advances block time by ten
  seconds per block. Fee intents now carry a ten-minute TTL, and the stale case is decided by the
  root replay.
- The transcript builder (`partition_transcripts`) executes the program against a contract state
  and itself fails with `ReadMismatch` on a forged root claim, so T13a runs the program against a
  forged copy of the state, which is what an attacker would do. A forged tree also changes the
  recipient's sibling path, so both membership paths must come from the forged tree for the
  attacker's proof to be self-consistent (the first T13a attempt mixed trees and was rejected as
  an invalid proof instead).

Known consequences of the mandatory design, observed while building:

- Every shielded spend now needs the token-type derivation inputs. No existing ledger test spends a
  contract-minted shielded coin without them: the two tests that spend contract-owned coins
  (`micro-dao`, `token_vault_shielded`) use the native all-zero type, which the relation accepts
  under `Empty` without derivation inputs, and both pass in the full suite below. The fail-closed
  behaviour for a coin of underivable type is shown by the zkir relation test only. The migration
  cost for wallets (resolving the preimage of every contract-minted coin) stands.
- The data provider still serves the legacy spend artifacts under `zswap/9/`; the ledger no
  longer uses them for spends, but their download verification keeps the legacy hash.

## Full ledger suite

`cargo test --release -p midnight-ledger-v10 --features proving --no-fail-fast -- --test-threads=1`,
the complete package (library unit tests, every integration test binary, doc tests), run after the
scenarios passed. Wall clock 39 minutes including compilation; log `stage4_full_ledger_tests`.

| Target | Result |
| --- | --- |
| `src/lib.rs` unit tests | 98 passed |
| `composable` | 3 passed, 31.5 s |
| `contract_deployment` | 2 passed |
| `csl_baseline` | 3 passed, 36.9 s |
| `csl_gate_layout` | 1 passed |
| `csl_regulated_transfer` | 9 passed, 226.7 s |
| `dust` | 4 passed, 15.5 s |
| `fallible` | 1 passed |
| `intent` | 16 passed, 10.6 s |
| `maintenance` | 2 passed |
| `malicious_imbalance` | 2 passed, 38.6 s |
| `micro-dao` | 1 passed, 2 ignored (ignored upstream), 122.7 s |
| `noop-dos` | 1 passed |
| `simple-merkle-tree` | 1 passed, 6.3 s |
| `system_tx` | 5 passed, 1 ignored (ignored upstream) |
| `token_vault_shielded` | 2 passed, 93.3 s |
| `token_vault_unshielded` | 2 passed, 5.0 s |
| `verify-proof` | 1 passed, 198.6 s |
| `zkir-artifacts` | 1 passed |
| doc tests | 0 |

Every target passes; the expectation recorded earlier in this log that `micro-dao` and
`token_vault_shielded` would fail was wrong, for the reason given above.

## Revision 2: security fixes

Base for the fixes: `8285f69` (reviewed implementation). Same toolchain, parameters and feature
discipline as above; `mock-verify` is absent from the resolved graph for every run here.

### Malicious-gate attack, reproduced against the reviewed implementation

Before fixing, the gate-substitution attack was run against `8285f69` with real proofs. A sender
removed from the whitelist, keeping her coin and keys, deploys a permissive gate `H` and repoints
her genuine spend's public routing fields to it; `H` rubber-stamps the authorization. The ledger
ACCEPTED it:

```
test attack_gate_substitution_is_rejected ... 
thread '...' panicked at ledger/tests/csl_common.rs: the transaction was accepted and applied
test result: FAILED. 0 passed; 1 failed
```

Full logs: `attack_reproduction_approved_alice_8285f69.txt` (first form) and
`attack_reproduction_revoked_alice_8285f69.txt` (the decisive revoked-sender form).

### Regression suite under the fixed implementation

`cargo test --release -p midnight-ledger-v10 --features proving --test csl_regression -- --test-threads=1`

| Id | Test | What it shows | Disposal |
| --- | --- | --- | --- |
| 1a | `attack_gate_substitution_is_rejected` | revoked sender routes to a permissive gate | InvalidProof (native spend) at verification |
| 1b | `route_entry_point_substitution_is_rejected` | route to a different entry point on the real gate | InvalidProof (native spend) at verification |
| 1c | `attack_cloned_gate_is_rejected` | clone gate with attacker whitelist | InvalidProof (native spend) at verification |
| 1d | `omitted_policy_is_rejected` | guarded coin presented as unguarded | InvalidProof (native spend) at verification |
| 1e | `omitted_gate_call_is_rejected` | policy kept, no gate call | EffectsCheckFailure(SpendAuthorizationsNEClaimed) at verification |
| 1f | `approved_transfer_still_succeeds` | correctly routed approved transfer | accepted and applied |
| 2a | `mismatched_blinding_is_rejected` | gate proof uses a different `rho` than the spend | EffectsCheckFailure(SpendAuthorizationsNEClaimed) at verification |
| 2b | `tampered_binding_is_rejected` | public binding value altered after proving | InvalidProof (native spend) at verification |
| 3a | `transfer_before_initialization_is_rejected` | gate not initialized | EffectsCheckFailure(SpendAuthorizationsNEClaimed) at verification |
| 3b | `second_initialization_cannot_retarget` | second `init`, honest and forged-state | Failure(Transcript ReadMismatch) at application (one-time init) |
| 3c | `init_with_wrong_admin_is_rejected` | wrong administrator secret | InvalidProof (gate proof) at verification |
| 3d | `second_asset_at_same_gate_gets_no_authorization` | a second asset pointed at the gate | EffectsCheckFailure(SpendAuthorizationsNEClaimed) at verification |
| 3e | `protected_asset_survives_root_update` | approved works and approved->unapproved fails after an update | approved->approved accepted; approved->unapproved InvalidProof (gate proof) |
| 5 | `historical_v1_spend_proof_is_rejected_by_the_ledger` | a v1-layout spend proof spliced into a valid transfer | InvalidProof (native spend) at verification |

Result: 14 passed, 0 failed, 329 s.

### zkir relation tests under the regenerated key

`cargo test --release -p midnight-zkir --test zswap_spend_csl`: 5 passed, 1 ignored (the key-writing test), 58 s. Includes the appended
route authenticators (tampering with any of the five fails verification), the hiding binding, and
`historical_v1_csl_proofs_do_not_verify_under_v2_key` (a v1-layout proof is rejected by the current
embedded key at the relation level).

### Embedded key

The embedded spend verifier key was regenerated from the fixed relation:
`zswap/static/spend.verifier` persistent-hash `bb6033fb0cccf70eec4328dca6d61d5e95d336266e629c340bd0eaefbf39e932` (pinned in
`spend.verifier.csl.sha256`). `zswap::verify::embedded_spend_verifier_key_is_the_csl_key` passes, so
the key the ledger embeds is the one the production prover generates.

### Full ledger suite under the fixed implementation

`cargo test --release -p midnight-ledger-v10 --features proving --no-fail-fast -- --test-threads=1`
on the fixed code (ledger commit `7f40a1a4`; the commit that adds this section changes documentation
only). Wall clock 42 minutes including compilation; log `full_suite_revision2`. Every one of the 22
targets passes, with the new embedded key in place:

| Target | Result |
| --- | --- |
| `src/lib.rs` unit tests | 98 passed |
| `composable` | 3 passed, 31.5 s |
| `contract_deployment` | 2 passed |
| `csl_baseline` | 3 passed, 33.9 s |
| `csl_gate_layout` | 1 passed |
| `csl_regression` (revision 2) | 14 passed, 303.2 s |
| `csl_regulated_transfer` | 9 passed, 206.3 s |
| `dust` | 4 passed, 14.1 s |
| `fallible` | 1 passed |
| `intent` | 16 passed, 10.3 s |
| `maintenance` | 2 passed |
| `malicious_imbalance` | 2 passed, 35.2 s |
| `micro-dao` | 1 passed, 2 ignored (ignored upstream), 116.3 s |
| `noop-dos` | 1 passed |
| `simple-merkle-tree` | 1 passed, 5.8 s |
| `system_tx` | 5 passed, 1 ignored (ignored upstream) |
| `token_vault_shielded` | 2 passed, 85.9 s |
| `token_vault_unshielded` | 2 passed, 4.9 s |
| `verify-proof` | 1 passed, 185.0 s |
| `zkir-artifacts` | 1 passed |
| doc tests | 0 |

The two existing tests that spend contract-owned coins (`micro-dao`, `token_vault_shielded`) still
pass: their coins are of the native type, which the relation accepts under `Empty` with all five
route authenticators zero.

### Continuous integration under revision 2

Four ledger commits follow the fix commit `7f40a1a4` and its documentation commit `b5575a56`. None
of them changes the relations, the gate, the verifier or the embedded key; they exist because the
CI evidence could not be produced without them, or to keep the repository's own test suites
consistent with the change:

| Commit | Change | Why |
| --- | --- | --- |
| `6ff98056` | `.github/workflows/csl-proving.yml`: a step name containing `: ` is quoted; the coin-structure unit test builds in release like the other steps. | The YAML did not parse, so the real-proving workflow at `7f40a1a4` and `b5575a56` failed before any job started. |
| `6ff98056` | `ledger-wasm/src/zswap_wasm.rs`: `Input::new_contract_owned` is called with the `derivation` argument (`None`). | The first experiment commit (`850fb602`) added the parameter; the upstream `build-wasm` and `integration-tests` jobs had failed since (observed on `8285f69`, `7f40a1a4`, `b5575a56`). |
| `6ff98056` | `zkir/src/csl_whitelist.rs`, `ledger/tests/csl_*.rs`: six clippy lints (`manual_is_multiple_of`, `useless_conversion`, `err_expect`, `needless_late_init`). | The upstream `check` job runs clippy with `-D warnings`; the whole-workspace command of that job passes locally on rustc 1.97.0 after the change. |
| `03d51e59` | Both workflow jobs place the compiled zswap and dust keys into `$MIDNIGHT_PP/<component>/<version>/` after compiling the test artifacts, and check the nine zswap files against the SHA-256 sidecars compiled into `midnight-zswap` (`zswap/static/*.sha256`). `scripts/reproduce.sh` does the same in its `artifacts` stage (docs commit `2f787aa0`). | The zswap unit test `prove::tests::test_proof_sizes` reads the published keys from the parameter cache in `FetchMode::Synchronous`, which never downloads. `flake.nix`'s `local-params` fills the cache this way for the Nix-based jobs; the first run of the workflow on `6ff98056` failed at exactly this point, with every earlier step green (run metadata, mock-verify assertion, parameter download, CLI and artifact builds, the zkir and coin-structure suites). A fresh cache built by the new stage passes the whole `midnight-zswap` suite locally (20 tests); each of the nine files matches its pinned hash, so the compiled keys are byte-identical to the published ones. |
| `b047cf77` | `onchain-runtime/src/context.rs`: one doc-comment link loses its redundant explicit target. | `cargo doc --all-features --no-deps` (the step after clippy in the upstream `check` job) rejects it under `#![deny(warnings)]`; the workspace doc build passes afterwards. |
| `8b3571f4` | `onchain-runtime-wasm/onchain-runtime-v5.d.ts`: the TypeScript `Effects` type declares `claimedSpendAuthorizations: Fr[]` and `claimedOutputCoverage: CoinCommitment[]`; the seven `Effects` literals in `integration-tests/` carry the two fields. No Rust change. | The experiment's `Effects` has had the two fields since `850fb602` and the wasm serializes them, so three `no-proving` JavaScript tests that compared whole `Effects` objects failed (see "The six JavaScript integration-test failures" below). |

Outcome of the real-proving workflow. The run on `03d51e59` is the first complete one (the cache
step was introduced there); `b047cf77` differs from it by one doc comment. The pinned commit
`8b3571f4` adds only TypeScript declarations and JavaScript test literals on top of `b047cf77`: its
Rust sources, keys and workflow are byte-identical. Trimmed logs:
`results/ci_csl_real_proving_03d51e59.txt`, `results/ci_csl_real_proving_b047cf77.txt`.

| Run | Result |
| --- | --- |
| `csl-real-proving` on `03d51e59`, job "CSL scenarios and regressions (real proofs)" ([run 40239225403](https://github.com/Jalal-1/regulated-zswap-csl-experiment/actions/runs/40239225403)) | **passed**, 32 minutes on a GitHub-hosted 4-vCPU runner, rustc 1.99.1. `mock-verify` occurrences in the resolved feature graph: 0 for all five crates. All nine compiled zswap files matched the pinned hashes. Suites: coin-structure 5; zkir library 10; `zswap_spend` 2; `zswap_spend_csl` 5 (1 ignored); zswap 20 + 2; onchain-runtime 12 + 11; ledger library 91; `csl_baseline` 3 (42.5 s); `csl_regulated_transfer` 9 (231.0 s); `csl_regression` 14 (344.4 s). Embedded spend verifier hash `bb6033fb…e932`, equal to its pin. |
| `csl-real-proving` on `b047cf77` ([run 40239592300](https://github.com/Jalal-1/regulated-zswap-csl-experiment/actions/runs/40239592300)) | **passed**, 32 minutes, same runner class and toolchain. Same zero `mock-verify` count, same nine hash matches, same suite counts: coin-structure 5; zkir library 10; `zswap_spend` 2; `zswap_spend_csl` 5 (1 ignored); zswap 20 + 2 (including `embedded_spend_verifier_key_is_the_csl_key`); onchain-runtime 12 + 11; ledger library 91; `csl_baseline` 3 (43.7 s); `csl_regulated_transfer` 9 (230.4 s); `csl_regression` 14 (345.1 s). Embedded spend verifier hash `bb6033fb…e932`, equal to its pin. Run metadata uploaded as the `csl-run-metadata` artifact. |
| `csl-real-proving` on `8b3571f4` (the pinned commit) | in progress at the time of writing ([run 40243311037](https://github.com/Jalal-1/regulated-zswap-csl-experiment/actions/runs/40243311037)); its outcome is recorded in the next revision of this file |

Outcome of the upstream `ci.yml` on `b047cf77` ([run 40239592295](https://github.com/Jalal-1/regulated-zswap-csl-experiment/actions/runs/40239592295)):

| Job | Result |
| --- | --- |
| build-ledger (ubuntu, ubuntu-arm, macos) | passed on all three (the Nix-based `cargo test --release` of the default members, as at every experiment revision) |
| build-proof-server (ubuntu, ubuntu-arm) | passed |
| build-wasm | passed (it had failed at every experiment revision before `6ff98056`) |
| integration-tests | failed: 6 of 791 JavaScript tests ([job](https://github.com/Jalal-1/regulated-zswap-csl-experiment/actions/runs/40239592295/job/121308476517)); the job reached the tests for the first time since the wasm build was fixed. Two causes, below. |
| check | failed at the clippy step, on the pre-existing storage deprecation only (five identical errors, none in the experiment's files; see below) |

**The six JavaScript integration-test failures.**

- *Three `no-proving` tests* (`QueryContext > effects - set and get effects`, `QueryContext > runTranscript`,
  `functions > should return 2 transcripts from partition transcripts`) compare an `Effects` object
  against a literal written for the nine upstream fields. The experiment's `Effects` has two more,
  `claimedSpendAuthorizations` (effects index 9) and `claimedOutputCoverage` (index 10), and the
  wasm serializes them as two further (empty) arrays, so deep equality fails. Fixed in `8b3571f4` (TypeScript type and test literals); outcome of that commit's `integration-tests` job: in progress at the time of writing ([run 40243311125](https://github.com/Jalal-1/regulated-zswap-csl-experiment/actions/runs/40243311125)).
- *Three `proving` tests* (`Transient` ×2, `TransactionBig`) prove zswap inputs through the
  **proof server** (`proof-server` crate, started by the test harness; `MN_AXIOS=true`). The proof
  server proves a `midnight/zswap/spend` preimage by interpreting the shipped zswap IR with the
  published key (`versioned_ir::prove` in `proof-server/src/endpoints.rs`); the CSL spend preimage
  carries 87 inputs where that IR expects 77, so the server answers HTTP 400
  (`BadInput("Expected 77 inputs, received 87")`) and the client reports `'prove' returned an
  error`. This is a path the experiment never switched: the hand-written CSL relation is dispatched
  only by the in-process prover (`zkir::LocalProvingProvider`, used by the ledger, the wallet-side
  Rust code and every test in this record). **Proving a guarded or unguarded zswap spend through the
  proof server is unsupported on this branch**; the server would need the same `is_native_relation`
  dispatch to `zswap_spend_csl::prove_from_preimage` / `csl_gate::prove_from_preimage` in `/prove`
  and `/prove-tx`, with its parameter provider. Recorded as a next step, not done here (the user's
  decision for this experiment was to leave node and service integration for later, and the fix
  prompt asked not to broaden scope).

The full-suite job of `csl-real-proving` is skipped on pushes by design; it runs on the weekly schedule or on manual dispatch with `full_suite`. Pre-existing failures that the experiment does not touch and that are left as they are:

- `check` fails at its clippy step inside `storage/` (`use of deprecated method
  AtomicU64::fetch_update`), because that job runs on the GitHub runner's current stable toolchain
  rather than the toolchain pinned by `flake.nix` (rustc 1.97.0, where the deprecation does not
  exist). The failure is identical at the reviewed revision `8285f69`, and `storage/` is unchanged
  from the upstream base. The job's spellcheck step reports pre-existing dictionary misses and does
  not fail the job.
- `nightly.yml` ("Ledger Build and Test All") triggers on every `ledger-*` branch and requests the
  `ubuntu-latest-8-core-x64` runner, which this repository does not have; its runs stay queued until
  the next push cancels them.

Local re-run at `6ff98056` (the last commit that changed Rust sources other than one doc comment;
same environment as the earlier results; log `final_verification_6ff98056`): zkir library 10
passed; `zswap_spend_csl` 5 passed, 1 ignored; `csl_gate_layout` 1 passed; `csl_baseline` 3 passed;
`csl_regulated_transfer` 9 passed (201 s); `csl_regression` 14 passed (308 s). Workspace clippy with
the upstream flags and `cargo doc --all-features --no-deps` (after `b047cf77`) both pass.
