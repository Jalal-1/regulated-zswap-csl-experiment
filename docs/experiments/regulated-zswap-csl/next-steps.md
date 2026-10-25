# Regulated ZSwap CSL experiment: state of play and next steps

## What is in place

- A production spend circuit that re-derives the token type and binds guarded spends to a gate
  (`zkir/src/zswap_spend_csl.rs`), embedded as the ledger's spend verifier key; the legacy key is
  rejected (`zkir/tests/zswap_spend_csl.rs`).
- The wire and effects plumbing: `Input.policy`, effects maps 9 and 10, kernel claim fragments, and
  the ledger's two-way matching rule in `effects_check` with its own error variants.
- The whitelist gate contract as two hand-written relations (`zkir/src/csl_gate.rs`), a depth-8
  Poseidon whitelist (`zkir/src/csl_whitelist.rs`), and a fixture with a raw transfer builder whose
  knobs reproduce the adversarial cases (`ledger/tests/csl_common.rs`).
- Stage 3 scenarios (`ledger/tests/csl_regulated_transfer.rs`): T01, T02/T12, T04, T06, T07, T08,
  T13 (a: forged root claimed, b: forged root in the witness only), T24. See `results.md` for
  outcomes.

## Open items the coding agent should take next, in order

1. **Proof-free matching tests.** `effects_check` is exercised end-to-end by the scenarios; add
   in-crate tests that build `StandardTransaction<Signature, (), Pedersen, _>` values with an input
   carrying `policy` and calls claiming (or not) the binding and coverage, so the rule is tested
   without proving (fast, exhaustive over the duplicate and segment cases of T14 to T16).
2. **Stage 4, first expansions.** `N_OUTPUTS = 2` in the gate (Bob plus change to the sender) is the
   first real-wallet shape; then transients (a `policy` field on `Transient`, or an explicit
   ledger rejection of guarded transients), contract-owned senders and recipients (`owner_kind`),
   and the mint route: a `shielded_mints` entry whose `ShieldedMintKey` carries a non-Empty rule must
   require full output coverage in its segment; and `AuthorizedClaim` of a guarded type must be
   rejected (the type is public there).
3. **Stage 4, coverage register.** Zero-value outputs of the guarded type, merged offers (T18:
   rejected by construction, add the test), fallible-segment placement (T16, T20), and the
   same-block ordering tests (T25) with the admin update and the transfer in both orders.
4. **Stage 5, node.** The pinned node (`ad8f2802`, current `main`) consumes ledger 9.1.0.0-rc.6 by git
   tag and has `ledger_8`/`ledger_9` host modules plus a v8-to-v9 state translation. Ledger 10
   integration needs a `ledger_10` module, a v9-to-v10 translation, host-API bridging for the new
   `Proof` wire format and the `zswap-input[v3]`/`contract-effects[v5]` tags, and a fresh genesis.
   Start with block import of the negative fixture through the host API in a node unit test.
5. **Stage 6, measurements.** Proving-time and size comparison of a guarded transfer (spend proof
   plus gate proof) against an unguarded one; the gate relation's `k`; verification cost of the two
   extra effects maps. Record the governance trust finding (an authorized `update_root` changes the
   rule without changing the token type) and the preimage-resolution migration cost.

## Findings worth carrying into the design discussion

- **Every spend needs derivation inputs.** With unconditional re-derivation, coins of random or
  unknown-preimage types cannot be spent; no existing ledger test spends such a coin (the
  two tests that spend contract-owned coins, `micro-dao` and `token_vault_shielded`, use the native
  type, which is accepted under `Empty`), so the full ledger suite passes unchanged; see `results.md`. Wallets and indexers must
  resolve `(domain separator, minting address, rule)` for every contract-minted shielded coin.
- **Native type.** The all-zero native type is special-cased under `Empty`; any other fixed types
  (if introduced) need the same treatment or a published derivation.
- **"Cannot be proven" means "no accepted proof exists".** `create_proof` does not check
  satisfiability: for an unsatisfiable witness (a removed sender, an unapproved recipient, a
  wrong administrator secret, a forged root with the real root claimed) the prover still emits
  a proof, and that proof fails under the embedded verifier key (`InvalidProof`). The scenarios
  therefore assert on the ledger's disposal of the transaction, not on a prover error. A proof
  that is self-consistent but made against a root the contract does not hold (a stale or
  attacker-chosen root) verifies and is rejected when the ledger replays the transcript's
  root claim against the contract state (`TransactionInvalid::Transcript`), so the two layers
  are: the circuit binds the statement, the ledger binds the statement to current state.
- **Retained transactions and TTLs.** The test harness advances block time by ten seconds per
  applied block; an intent whose TTL equals its creation time (the fee intent in the first
  version of the fixture) expires as soon as the administrator's update lands, which hides the
  root check behind `IntentTtlExpired`. The fixture now gives fee intents a ten-minute TTL so
  the retained-proof case is decided by the gate, not by expiry.
- **Fee pricing.** The ledger prices by proven size, and the DUST spend's encoded value is part of
  that size: an exact fee is a fixed point of pay-prove-measure, not a single estimate. The shared
  balancing helper underpays real proofs by a constant and needed replacing in the fixture.
- **Gate privacy.** Per guarded input the chain learns the gate address, entry point and a Poseidon
  binding; per gate call, the claimed binding and output commitments (already public). The
  whitelist contents and both parties' keys stay off chain. The asset family of a guarded input is
  therefore public, as the plan anticipated.
- **ECDSA inside the gate.** zk-stdlib v1 exposes a secp256k1 chip (`ZkStdLibArch::secp256k1`), so a
  k-of-n ECDSA authorization predicate can be added to the gate relation without new primitives;
  the spending key still has to reach the spend prover, so this makes the key insufficient rather
  than removing it from custody.

## Revision 2 security fixes (done)

The three protocol defects a source review found in `8285f69`, and the reproducibility gap, are
fixed on this branch and covered by `ledger/tests/csl_regression.rs` under real proofs. See
`design/stage1-design-decision.md` section 7 and `results.md` for details and outcomes.

- **Authenticated gate route** (critical): the spend statement now exposes and constrains the mode,
  gate address and entry point; `Input::well_formed` fills them from the input's policy. The
  malicious-gate redirection was reproduced against `8285f69` (accepted) and is now rejected.
- **Hiding binding** (high): `Poseidon(DOM[v2], nullifier, sender, token_type, rho)` with fresh
  private `rho`, removing the known-key recognition oracle and binding the spent type across the
  spend and gate proofs.
- **One-time protected-type init**: `init` sets the type once; `update_root` is root-only; the gate
  authorizes only its own asset.
- **Real-proof CI, pinned reproduction**: `.github/workflows/csl-proving.yml` (mock-verify asserted
  absent), `MANIFEST.json`, and a revision-checking `scripts/reproduce.sh`.

## Still open after revision 2 (unchanged scope boundaries)

- Change outputs, transients, contract owners, merges, multi-input (Stage 4). The hiding binding and
  route authentication carry over unchanged to those shapes; `N_OUTPUTS` is still 1.
- Mint and `AuthorizedClaim` of a guarded type are still not gated (Stage 4), as before.
- Node integration (Stage 5) and measurements (Stage 6) remain untouched.
- `rho` transport in a real wallet: here the fixture draws `rho` and hands it to both proofs. A
  production wallet must do the same (draw once, use in the spend and the gate call); the experiment
  does not define a wire-level carrier for it because it is private to the spender.
- The permissive gate and the historical v1 relation are test-only; they are never dispatched or
  embedded. A production build would gate them behind a test feature.
