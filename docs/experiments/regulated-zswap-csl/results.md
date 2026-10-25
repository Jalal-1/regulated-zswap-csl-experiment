# Regulated ZSwap CSL experiment: results log

Base: `fa995fa5791bc19112e97334a2d9265751c35fad`; toolchain rustc 1.97.0 stable; 4 vCPU, 15 GB RAM,
public parameters `bls_midnight_2p0..18` (hashes verified against `flake.nix`). All proving
tests run in `--release` with the `proving` feature; mock verification is never enabled.

| Stage | Evidence | Result |
| --- | --- | --- |
| 0 | `cargo test -p midnight-coin-structure custom_spend` | 3 passed (plus `descriptor_hash_matches_fixed_layout` added in Stage 2) |
| 0 | `cargo test --release -p midnight-zkir --test zswap_spend` (legacy relation vs shipped key, real proofs) | 2 passed, 17.9 s |
| 0 | `cargo test --release -p midnight-ledger-v10 --features proving --test malicious_imbalance` | 2 passed, 29.2 s (negative control through the real verifier) |
| 0 | `ledger/tests/csl_baseline.rs` (plain transfer accepted; corrupted proof rejected; altered statement rejected) | corrupted-proof and altered-statement controls passed on the first run; the positive control exposed a 1e11 Speck DUST underpayment by the shared balancing helper, fixed by exact two-pass fee payment; rerun pending in this log |
| 0 | `cargo test --release -p midnight-zkir --test zswap_spend_csl` (CSL relation, real proofs, k = 15) | 4 passed: derivation matches coin-structure; guarded spend proves with non-zero binding and tampering fails; Empty-for-guarded, wrong-gate and underivable-type witnesses do not verify; legacy-relation proofs do not verify under the CSL key |
| 2 | `cargo test --release -p midnight-zswap` after the wire change and key switch | 19 + 2 passed (spend proofs now produced by the CSL relation through the prover hook) |
| 2 | `cargo test --release -p midnight-onchain-runtime` with effects indices 9 and 10 | 23 passed (tag `contract-effects[v5]` registered) |
| 2 | `cargo test --release -p midnight-zkir --lib` | 10 passed (whitelist path helper included) |
| 2 | `cargo test --release -p midnight-ledger-v10 --lib` with the matching rule and tag bumps | 90 passed, 1 failed (`test_resolver_resolves`: download sidecar had been changed to the CSL hash; restored to the legacy hash, rerun pending) |
| 3 | `ledger/tests/csl_regulated_transfer.rs` (T01, T02/T12, T04, T06, T07, T08, T13, T24) | pending |

Known consequences of the mandatory design, observed while building:

- Every shielded spend now needs the token-type derivation inputs; coins of random
  (underivable) types used by some existing ledger tests (`micro-dao`, `token_vault_shielded`)
  can no longer be spent, which is the intended closure of the unguarded route and a
  migration cost for wallets.
- The data provider still serves the legacy spend artifacts under `zswap/9/`; the ledger no
  longer uses them for spends, but their download verification keeps the legacy hash.
