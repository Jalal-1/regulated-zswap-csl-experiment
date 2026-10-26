# Regulated ZSwap via Custom Spend Logic: high-level summary

This page is the short version of the record. The long version is `README.md`; the reviewer's
guide is `REVIEWING.md`; what Compact would need is `design/compact-support.md`.

## The question

Can a shielded ZSwap token carry a transfer rule that stays mandatory after the token leaves the
issuer, so that holding the spending key is necessary but no longer sufficient to move it? The rule
tested is the simplest useful one: **the actual sender and the actual recipient must both be on the
issuer's current whitelist**, checked by one call to a gate contract in the same transaction.

## The answer

Yes, on Midnight ledger 10 built on the custom-spend-logic base (`midnightntwrk/midnight-ledger`
commit `fa995fa`). The mechanism has three parts:

1. **The token type commits to the rule.** A regulated token's type is derived from the minting
   contract's address, a domain separator, and a *spend rule* naming the gate contract and its
   `authorize` entry point. Nobody can mint a coin of that type without that rule, and nobody can
   present the coin as an ordinary one: the type is different.
2. **The spend proof re-derives the type and names the gate.** The ZSwap spend circuit was replaced
   by a hand-written relation that re-derives the token type from the witnessed derivation and
   exposes, as public inputs, whether the coin is guarded, which gate and which entry point must
   authorize it, and a hiding binding value that only the real sender can produce.
3. **The gate call authorizes, and the ledger matches.** The gate contract proves that the sender
   and every recipient of the segment are in the whitelist, and claims two things in its effects:
   the spend it authorizes and every output commitment of the segment. The ledger requires the
   claims to match the guarded inputs one-to-one and to cover all outputs; a transaction missing the
   gate call, pointing at another gate, or paying someone else is rejected before any state changes.

The headline scenario passes with real proofs: **a revoked holder cannot move her coin** (the gate
refuses to authorize her, and no other contract can authorize for her), while an approved holder's
transfer to an approved recipient succeeds, and the whitelist can be updated by the administrator.

## What was built

| Layer | What |
| --- | --- |
| Circuits | The CSL spend relation (`zkir/src/zswap_spend_csl.rs`, embedded as the ledger's spend verifier key) and the gate's three relations `authorize`, `update_root`, `init` (`zkir/src/csl_gate.rs`), all hand-written against the zk-stdlib circuit API. |
| Ledger | A `policy` field on shielded inputs, two new effects maps (spend authorizations, output coverage), the one-to-one matching and full-coverage rules with their own error variants, a mint-effect key that carries the spend rule, and the token-type derivation that folds the rule in. |
| Wallet side | The input builders take the coin's derivation and draw the per-spend randomness `rho`. |
| Harness | A fixture with an issuer, a whitelist (depth-8 Poseidon tree), parties Alice and Bob, a raw transfer builder with adversarial knobs, nine scenarios, three strict controls and fourteen regression tests. |
| Reproducibility | A real-proving GitHub Actions workflow with mock verification asserted absent, a manifest pinning the commit and every hash, a portable reproduction script, and archived logs and run metadata. |

## Revision 2: what the security review found and how it was fixed

| # | Defect | Fix |
| --- | --- | --- |
| 1, critical | The spend proof authenticated only an opaque binding. An attacker's own contract could repeat it and "authorize" a revoked holder's spend. Reproduced with real proofs against the reviewed commit. | The spend statement now exposes and constrains the mode, the gate address and the entry point; the verifier fills them from the input's public policy. |
| 2, high | The binding was recomputable from public data plus a candidate sender key, a recognition oracle. | The binding is now a hiding commitment with fresh private randomness shared only between the spend and gate proofs. |
| 3 | The administrator's root update could rewrite the protected token type; a second asset at the same gate got sender-only checks. | A one-time `init` fixes the type, `update_root` touches only the root, and the gate binds its own type cell, so it authorizes only its own asset. |
| 4 | Real-proof coverage was not reproducible in CI. | Dedicated workflow, manifest, reproduction script, run metadata. |
| 5 | Artifacts drifted. | Verifier key regenerated; the old relation kept only as never-dispatched test evidence; old-layout proofs rejected through the full ledger path. |

## Evidence

- 14 regression tests, 9 scenarios and 3 controls pass with real proofs, locally and in three
  GitHub Actions runs (`results/ci_csl_real_proving_*.txt`), each run asserting that mock
  verification is absent and that the embedded key equals its pin.
- The complete `midnight-ledger-v10` suite (22 targets) passes under the fixed implementation.
- The attack is reproduced against the reviewed commit and rejected after the fix
  (`results/attack_reproduction_*_8285f69.txt`, `results/csl_regression_run.txt`).
- `MANIFEST.json` pins the implementation commit, the parameter hashes and the key hash;
  `scripts/reproduce.sh` reproduces every run from a clean machine.

## What is not covered, and known limits

- **Shape**: one regulated input, one equal-value regulated output, one gate call. No change
  outputs, splits, merges, transients, contract-owned coins or multi-input transfers yet (Stage 4).
- **Issuance**: the tests create regulated coins by harness state injection. Minting a regulated
  coin through a contract call is supported by the ledger's balance logic but has no test, and
  mints, claims and burns of a guarded type are not themselves gated (T27).
- **Proof server**: proving any ZSwap spend through the proof server is unsupported on this branch;
  only the in-process prover dispatches the new relations. Three upstream JavaScript integration
  tests fail for this reason.
- **Toolchain**: nothing in Compact yet. The issuer, the gate and the wallet plumbing are Rust and
  hand-written VM programs. `design/compact-support.md` lists what the Compact compiler, runtime
  and SDK would need.
- **Harness simplifications**: gate transcript templates were taken from measured encodings, the
  new effects maps are priced by copying an existing entry, and the storable tag bumps are
  experiment-local.
- **Node integration and measurements** were not started.

## Where to look

- The design and its decisions: `design/stage1-design-decision.md` (section 7 for revision 2).
- The code, as a patch series: `patches/`; as a branch: `ledger-experiment`.
- Every run and its outcome: `results/results.md`.
- How to verify and extend: `REVIEWING.md`, `design/next-steps.md`.
