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

- Every shielded spend now needs the token-type derivation inputs; coins of random
  (underivable) types used by some existing ledger tests (`micro-dao`, `token_vault_shielded`)
  can no longer be spent, which is the intended closure of the unguarded route and a
  migration cost for wallets.
- The data provider still serves the legacy spend artifacts under `zswap/9/`; the ledger no
  longer uses them for spends, but their download verification keeps the legacy hash.
