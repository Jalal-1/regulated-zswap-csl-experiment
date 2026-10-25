# Regulated ZSwap via Custom Spend Logic: experiment record

This repository is the complete record of an experiment on the Midnight ledger: can a shielded
ZSwap token carry a transfer rule that stays mandatory after the token leaves the issuer, so that
possession of the spending key is necessary but no longer sufficient to move it? The rule tested
is the simplest useful one: the actual sender and the actual recipient must both be on the
issuer's current whitelist, checked by one Custom Spend Logic (CSL) gate contract call.

It contains the plan, the design decision, the ledger changes as a reviewable patch series and as
a real git branch, every test log, and this document, which states exactly what was done, what was
not done, and which parts are harness conveniences rather than protocol behaviour.

**Headline result.** For the one transaction shape that was implemented (one regulated input, one
regulated output of equal value, one gate call, fees in DUST), the ledger enforces the rule with
real proofs and strict verification. The decisive scenario passes: Alice is funded while approved,
removed, and then cannot move the coin with a retained proof, a fresh proof, or a raw transaction
that omits or misstates the gate call. Approved transfers still work. Everything beyond that shape
(change outputs, transients, contract owners, mint and burn routes, node integration, measurements)
was **not** done; see "What was not done".

**Revision 2 (security review).** A later source review found that the first implementation, while it
enforced the rule for honest callers, had three protocol defects: the spend proof did not
authenticate which gate the ledger routed to (so a malicious contract could rubber-stamp a revoked
holder's spend), the public binding let anyone holding a candidate key recognise a sender's spends,
and the gate's protected token type was freely retargetable. All three are fixed on this branch and
demonstrated with real proofs; the malicious-gate attack was first reproduced accepting against the
reviewed commit. See "Revision 2: security fixes" below.

**Start here.** `REVIEWING.md` is the reviewer's guide: reading order, the plan's validation
properties mapped to code and tests, a file-by-file map of the diff with what to check, the open
questions, and how to run and extend the work. `scripts/reproduce.sh` reproduces every run from a
clean machine against the commit pinned in `MANIFEST.json` (no Nix needed). The ledger code itself is
on the `ledger-experiment` branch.

---

## Contents

1. [Repository layout](#repository-layout)
2. [The question and the design in brief](#the-question-and-the-design-in-brief)
3. [What was done](#what-was-done)
4. [Evidence](#evidence)
5. [What was not done](#what-was-not-done)
6. [Deviations from the plan and the design document](#deviations-from-the-plan-and-the-design-document)
7. [Harness mechanisms, simplifications and anything that could be mistaken for a mock](#harness-mechanisms-simplifications-and-anything-that-could-be-mistaken-for-a-mock)
8. [Findings](#findings)
9. [Known issues in the implementation](#known-issues-in-the-implementation)
10. [How to reproduce](#how-to-reproduce)
11. [Process notes](#process-notes)

---

## Repository layout

Branch `main` (this branch):

| Path | What it is |
| --- | --- |
| `plan/regulated_zswap_csl_experiment_plan_v2.md` | The experiment plan, revision 2, which this work implements. |
| `plan/review-of-v1.md`, `plan/plan_v1_to_v2.diff` | The source-verification review of revision 1 and the diff it produced. |
| `design/stage1-design-decision.md` | The Stage 1 design decision (decisions D1 to D12, movement-path inventory P1 to P12) with section 6 "as built" notes. |
| `design/next-steps.md` | Handoff for the next person: open items in order, and findings. |
| `patches/000*-*.patch` | The ledger changes as a patch series (seven commits) against `midnightntwrk/midnight-ledger` commit `fa995fa5791bc19112e97334a2d9265751c35fad` (branch `alexshielded/custom-spend-logic`, the Custom Spend Logic draft). Apply with `git am`. |
| `results/results.md` | The results log: every test run with its command, outcome and timing, and the disposal of every scenario. |
| `results/*.txt` | Trimmed logs of every build and test run, including the failed iterations. |
| `scripts/reproduce.sh` | Portable reproduction: clone, parameters (downloaded and hash-verified), zkir CLIs, test artifacts, unit suites, strict controls, scenarios. Stages can be run individually. |
| `scripts/stage*_chain*.sh`, `scripts/*.py`, `scripts/publish.sh` | The scripts that actually ran each stage in the experiment's container, and the Python scripts that applied the larger edits. They contain absolute paths from that container and are kept as a record. |
| `REVIEWING.md` | Reviewer's and pickup guide. |
| `MANIFEST.json` | Pins the implementation commit, parameter hashes and embedded verifier hash; `scripts/reproduce.sh` reads it. |
| `results/attack_reproduction_*_8285f69.txt` | The malicious-gate attack accepted against the reviewed commit (revision 2 evidence). |
| `results/csl_regression_run.txt` | The revision-2 regression suite (14 tests) under real proofs. |

Branch `ledger-experiment`: the actual ledger branch, that is, the full history of
`midnightntwrk/midnight-ledger` up to `fa995fa` plus the four experiment commits. It is the same
content as the patch series; it exists so the branch can be checked out and built directly.

---

## The question and the design in brief

The plan's central question: *can Alice produce any transaction accepted by the active ledger that
moves this regulated token while her actual spending owner is absent from the current approval
set?*

The design (full text in `design/stage1-design-decision.md`) answers it in three layers:

1. **The token names its rule.** A regulated token's type is derived from
   `(domain separator, minting address, SpendRule::GateContract(gate address, entry point hash))`,
   as the Custom Spend Logic draft already defines. The spend circuit re-derives the type from
   these witnessed inputs on every spend, so a coin of a guarded type cannot be presented as
   unguarded.
2. **The spend proof binds the spend to the gate.** For a guarded coin the spend statement's first
   public input (constant zero today) becomes a Poseidon binding over the nullifier, the sender's
   real public key (derived in-circuit from the spending key), the gate address and the entry
   point. It travels on the wire as `Input.policy`.
3. **The ledger makes the gate call mandatory.** The gate's transcript claims the binding it
   authorizes and the output commitments it checked, into two new `Effects` maps. The ledger's
   `effects_check` requires the multiset of claimed authorizations to equal the multiset of
   guarded inputs (both directions, keyed by logical segment), and requires any claiming call to
   have claimed exactly the output and transient commitments of its segment. The gate reads the
   whitelist root from its own contract state, and the ledger replays that read against current
   state at application, so a proof made against a superseded root fails there.

The gate contract is a whitelist: a depth-8 Poseidon Merkle tree whose root is published by an
administrator; membership is proven inside the gate's `authorize` relation for the sender and for
the recipient of every output of the regulated type.

---

## What was done

### Stage 0: reproducible baseline and pipeline switch

- Toolchain: rustc 1.97.0 stable; the public parameters `bls_midnight_2p0..18` fetched from the
  S3 bucket named in the ledger's `flake.nix`, all SHA-256 hashes verified against the flake.
  The Compact compiler is commented out of the flake, so test artifacts were compiled from the
  checked-in ZKIR in `zkir-precompiles/` with `zkir compile-many`, as the flake does.
- Baseline tests: coin-structure derivation tests; the existing hand-written zk-stdlib spend
  relation shown byte-identical in verifier key to the shipped one and producing verifying proofs;
  the ledger's existing negative control (`malicious_imbalance`) through the real verifier.
- New strict controls (`ledger/tests/csl_baseline.rs`): a plain shielded transfer accepted under
  `WellFormedStrictness::default()`; the same transaction with a corrupted proof rejected; the
  same transaction with an altered statement rejected.
- Pipeline switch: the hand-written relation (with the CSL constraints added in Stage 2) is now
  the production spend prover for key location `midnight/zswap/spend`, through a hook in
  `zkir::LocalProvingProvider` (and the ledger test harness's `CombinedProofProvider`). Its
  verifier key is embedded as `zswap/static/spend.verifier`; the shipped key and IR were moved to
  `zswap/static/legacy/`. A test pins the embedded key's hash and another shows that proofs from
  the legacy relation do not verify under the new key.

### Stage 1: inventory and design decision

- `design/stage1-design-decision.md`: the movement-path inventory (P1 user spend, P2 contract
  spend, P3 user output, P4 contract output, P5 transient, P6 offer merge, P7 segments, P8
  shielded mint, P9 authorized claim, P10 unshielded, P11 DUST, P12 system transactions) with the
  first shape's treatment of each, and decisions D1 to D12.
- The user's standing decisions were applied: the design is derived from the pinned sources and
  the CSL draft only (no other proposal is an input); ledger 10 is the base; the hand-written
  relation is promoted to production; output coverage shape and whitelist details were decided in
  Stage 1 (segment-wide coverage claimed by the gate; depth-8 Poseidon tree, one cell read for the
  root); node integration deferred.

### Stage 2: native enforcement and the gate

Ledger-side changes (all in the patch series, by crate):

- `coin-structure/src/custom_spend.rs`: `TokenDerivation`, `csl_policy_binding` (the off-circuit
  mirror of the in-circuit binding), `fr_pair`, and a unit test that pins the descriptor byte
  layout the circuit hashes.
- `zkir/src/zswap_spend_csl.rs`: the CSL spend relation. Nine witness elements (rule kind, domain
  separator, minting address, gate address, entry point hash, each 32-byte value split into two
  field elements) prepended to the legacy 77-element witness; three in-circuit SHA-256s re-derive
  the token type; the native all-zero type is accepted only under the `Empty` rule; the binding is
  computed with the standard library's Poseidon over nine inputs; `GateCircuit` cannot be
  witnessed because the rule kind is a bit. Parameter size `k = 15`, unchanged.
- `zkir/src/csl_gate.rs`: the gate's two relations, `authorize` and `update_root`, as hand-written
  zk-stdlib v1 relations registered as `v2` contract operations. Their public transcripts are
  emitted from templates whose op encodings were measured by a probe test
  (`ledger/tests/csl_gate_layout.rs`) rather than assumed.
- `zkir/src/csl_whitelist.rs`: the depth-8 Poseidon whitelist (leaf, root, path) with a unit test.
- `zkir/src/lib.rs`: `is_native_relation`, and the `check`/`prove` hooks that route the spend and
  gate key locations to the hand-written relations before any ZKIR resolution.
- `zswap`: `SpendPolicyBinding` and `Input.policy` (tags `zswap-input[v3]`, `zswap-offer[v6]`);
  `Input::well_formed` puts the binding in the statement slot; the constructors take an optional
  `TokenDerivation`; `local::State::spend_with_derivation`; `UnsupportedSpendRule` error.
- `onchain-runtime`: `Effects.claimed_spend_authorizations` (VM effects index 9) and
  `Effects.claimed_output_coverage` (index 10), appended so indices 0 to 8 are unchanged; VM
  encode/decode, serde, distribution; kernel fragment macros for the two claims; tags
  `contract-effects[v5]`, `contract-transcript[v6]`.
- `ledger/src/verify.rs`: the matching rule in `effects_check`, before the existing
  `claimed_calls` rule, with two new `EffectsCheckError` variants; `ledger/src/structure.rs`:
  containing tags bumped (`contract-call[v5]`, `contract-action[v11]`, the `intent[v11]` family,
  `standard-transaction[v14]`, `transaction[v14]`) and cost-model entries for the two maps (priced
  like `claimed_shielded_receives`); the `.tag-decompositions/` files that the tag enforcement
  tests require.
- `ledger/src/test_utilities.rs`: the harness's `CombinedProofProvider` routes native relations
  to the `zkir` hook (otherwise it tries to resolve a key through the data provider).

### Stage 3: the revoked-Alice scenario and its controls

- `ledger/tests/csl_common.rs`: the fixture. Deploys the gate, publishes the administrator's root
  (which also writes the token-type cell), issues one regulated coin to Alice, and provides a raw
  transfer builder (`regulated_transfer_tx`) whose knobs omit the gate call, misstate the sender,
  pay a different recipient than the gate checked, prove against a forged whitelist, or claim a
  forged root in the transcript. Fees are paid exactly in DUST by a pay-prove-measure fixed point.
  `Rejection`/`attempt` report how the ledger disposed of a transaction that must not succeed.
- `ledger/tests/csl_regulated_transfer.rs`: nine scenarios, listed under Evidence. Each uses real
  proofs, `WellFormedStrictness::default()`, and `TestState::apply`, and asserts the intended
  rejection reason plus the state invariants (Alice's nullifier absent, no new commitment).

---

## Evidence

All runs: `--release`, feature `proving`, real public parameters, mock verification never enabled.
Container: 4 vCPU, 15 GB RAM. Exact commands and timings are in `results/results.md`; raw logs are
in `results/*.txt`.

| Stage | Run | Result |
| --- | --- | --- |
| 0 | `cargo test -p midnight-coin-structure custom_spend` | 3 passed (4 after the layout test was added) |
| 0 | `cargo test --release -p midnight-zkir --test zswap_spend` (legacy relation vs shipped key) | 2 passed, 17.9 s |
| 0 | `cargo test --release -p midnight-ledger-v10 --features proving --test malicious_imbalance` | 2 passed, 29.2 s |
| 0 | `cargo test --release -p midnight-ledger-v10 --features proving --test csl_baseline` | 3 passed, 39.1 s |
| 0/2 | `cargo test --release -p midnight-zkir --test zswap_spend_csl` (CSL relation, real proofs) | 4 passed |
| 2 | `cargo test --release -p midnight-zswap` | 19 + 2 passed |
| 2 | `cargo test --release -p midnight-onchain-runtime` | 23 passed |
| 2 | `cargo test --release -p midnight-zkir --lib` | 10 passed |
| 2 | `cargo test --release -p midnight-ledger-v10 --lib` | 91 passed (one failure found and fixed on the way; see Known issues) |
| 3 | `cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer -- --test-threads=1` | 9 passed, 236 s |
| 3 | `cargo test --release -p midnight-ledger-v10 --features proving --no-fail-fast -- --test-threads=1` (the complete package: library and every integration test) | all 22 targets pass: library 98, scenarios 9 again (226.7 s), baseline 3, `micro-dao` 1 (+2 ignored upstream), `token_vault_shielded` 2, `verify-proof` 1, the rest as upstream; 39 min wall clock |

Scenario disposals (the ledger's actual error, copied from the log):

| Id | Scenario | Disposal |
| --- | --- | --- |
| T01 | approved Alice to approved Bob | accepted and applied; Alice's nullifier recorded, Bob's commitment inserted |
| T02/T12 (stale) | proof made before Alice's removal, submitted after the new root is published | rejected at application: `Failure(Transcript(Execution(ReadMismatch { expected: <old root>, actual: <new root> })))`; coin not consumed, no output created |
| T02/T12 (fresh) | Alice tries again under the new root | rejected at verification: `InvalidProof` (the only proof she can make does not verify) |
| T04 | approved Alice to unapproved Carol | rejected at verification: `InvalidProof` |
| T06 | regulated coin spent with no gate call | rejected at verification: `EffectsCheckFailure(SpendAuthorizationsNEClaimed)`, before any state change |
| T07 | gate shown Bob as sender while Alice's coin is spent | rejected at verification: `EffectsCheckFailure(SpendAuthorizationsNEClaimed)` |
| T08 | gate checks Bob, offer pays Carol | rejected at verification: `EffectsCheckFailure(OutputCoverageNESegmentCommitments)` |
| T13a | membership under an attacker-chosen root, transcript claims that root (program run against a forged state copy) | rejected at application: `Failure(Transcript(Execution(ReadMismatch ...)))` |
| T13b | membership under an attacker-chosen root, transcript claims the real root | rejected at verification: `InvalidProof` |
| T24 | `update_root` with the wrong administrator secret | rejected at verification: `InvalidProof`; nothing applied |

What this evidence does and does not establish, in the plan's own terms:

- **Native enforcement demonstrated** for the first supported shape: positive, negative and bypass
  tests pass with real proofs and strict ledger validation. Yes, for that shape.
- **Node enforcement demonstrated.** No. Nothing was run through a node.
- **Movement coverage demonstrated.** No. Only the first shape has tests; the other inventoried
  paths are either rejected by construction without a test, or untouched (see below).
- **Privacy demonstrated within a stated boundary.** Partially: the disclosures are documented
  (D12) but no test reads the public artifacts to check for leakage (T28).
- **General programmable CSL demonstrated.** Partially. The ledger authenticates and enforces a
  designated gate contract named by the token's descriptor, which is the general mechanism; but
  only one gate, with a hard-coded whitelist relation, was written, and the `GateCircuit` rule
  variant is rejected rather than supported.

---

## What was not done

This section records the status **as of revision 1**. Revision 2 (the security fixes, see the
section at the end) additionally closed several acceptance items that were open or only
relation-level before: gate and entry-point substitution (T10), old-relation proofs through the full
ledger path (T21), a wrong/lookalike contract (T17), and the attacker-root family (T13), plus new
checks on the binding's hiding property and the protected-token configuration. The stage-level scope
below (Stage 4 shapes, mint/claim gating, Stage 5 node, Stage 6 measurements) is unchanged.

### Plan stages

| Stage | Status |
| --- | --- |
| 0 | Done, except the "written node compatibility decision": there is a note in `design/next-steps.md` on the pinned node's `ledger_8`/`ledger_9` host modules and what a `ledger_10` module would need, not a decision document. |
| 1 | Done. The "proof-free prototype of the matching rule" became the real rule; it has no proof-free unit tests (see below). |
| 2 | Done for the first shape. Not done: the "approved recipient who can receive asynchronously using public receiving information plus private membership evidence" is only exercised in the sense that the sender's wallet supplies Bob's membership path to the gate; there is no separate recipient-side flow or protocol for handing out membership material. |
| 3 | Done for nine scenarios. Not done from the stage text: the "old spend-proof path" attempt at the ledger level (legacy-key rejection is shown at the `zkir` level and by the embedded-key pin, not by a ledger transaction carrying a legacy proof); the "deterministic replay script" is the seeded test file run single-threaded, not a standalone script. |
| 4 | Not started. No change outputs (`N_OUTPUTS = 1` in the gate: a transfer must spend the whole coin), no splits, merges, multiple inputs, multiple owners, batches, contract owners, contract recipients, transient coins or composable offers. No coverage register beyond the inventory table in the design document. No audit of mint, burn, redemption, wrapping or conversion routes; in particular, the shielded mint route (`Effects.shielded_mints` with a non-Empty rule) is **not** gated, and `AuthorizedClaim` of a guarded type is **not** prohibited. Both are listed in the design as Stage 4 rules and neither is implemented. |
| 5 | Not started. No node changes, no genesis, no RPC submission, no block-import test. |
| 6 | Not started. No proving-time, verification-time, size or memory measurements (the only timings are whole-test durations). No CSL interface proposal document. The two standing findings the plan asks to record are noted in `design/next-steps.md` but not elaborated. |

### Acceptance and adversarial tests (plan table T01 to T32)

| Id | Status | Notes |
| --- | --- | --- |
| T01 | Done | |
| T02 | Done | Both the retained-proof and the fresh-proof cases. |
| T03 | Not done | A never-approved holder fixture was not built. The fresh-proof half of T02 is the same mechanism (no membership path), but the fixture differs. |
| T04 | Done | |
| T05 | Not done | Both parties unapproved. |
| T06 | Done | |
| T07 | Done | |
| T08 | Done | |
| T09 | Not done | Change, second or transient recipient. Transients fail closed by design (no `policy` field, so a guarded transient's statement slot is zero and its proof cannot verify) but this was not tested. |
| T10 | Partially | Presenting a guarded coin as `Empty` or with another gate is shown not to verify at the `zkir` relation level; no ledger-level transaction test. Another entry point: not tested. |
| T11 | Partially | `GateCircuit` is rejected at construction and cannot be witnessed; a malformed or non-canonical descriptor encoding is not tested (the encoding is fixed-width and pinned by a unit test, which is a different thing). |
| T12 | Done | The stale-root case of T02. |
| T13 | Done | Two variants (a and b). |
| T14 | Not done | Replaying gate evidence for another coin, output set, network or segment. The binding includes the nullifier and the match is keyed by segment, so this should fail by construction; untested. |
| T15 | Not done | Multi-input authorization; the gate only authorizes one input. |
| T16 | Not done | Gate in a failing section with the spend in a successful one. Matching is keyed by logical segment and application is per segment, so this should fail; untested. |
| T17 | Not done | Wrong contract, lookalike event, unrelated valid call. |
| T18 | Not done | Offer merge after authorization. Rejected by construction (the coverage claim no longer equals the segment's commitments); untested. |
| T19 | Not done | Contract owner, escrow, DEX. The constructors accept a derivation for contract-owned coins and bind the contract address as sender, and the gate's leaves only encode user keys, so a contract-owned guarded spend cannot obtain a matching claim from this gate; untested. |
| T20 | Not done | Transients and alternate guaranteed/fallible paths. |
| T21 | Partially | Legacy-relation proofs do not verify under the embedded key (`zkir` test) and the embedded key is pinned; no ledger transaction carrying an old-key proof was submitted. |
| T22 | Partially | Corrupt proof and altered statement are rejected for a plain transfer (Stage 0 controls); not repeated on a regulated transfer. |
| T23 | Existing | The ledger's own `malicious_imbalance` tests pass; nullifier reuse was not separately tested. |
| T24 | Done | |
| T25 | Not done | Removal and transfer in the same block, both orders. |
| T26 | Done in effect | The plain transfer control and the zswap test suite pass with the native (Empty) type under the new relation. |
| T27 | Not done | Mint, burn, redemption, conversion and wrapping routes. |
| T28 | Not done | No test reads public inputs, events and effects across transfers; disclosures are documented only. |
| T29, T30 | Not done | Node. |
| T31 | Not done | Gate contract missing at the descriptor's address. Expected: the required claim cannot exist, so the asset is frozen; untested. |
| T32 | Not done | Zero-value guarded output to an unapproved party. |

### Deliverables checklist (plan, "Deliverables and completion decision")

| Deliverable | Status |
| --- | --- |
| Isolated ledger experiment branch | Done (`ledger-experiment` branch, patch series). |
| Matching node changes or pinned compatible node baseline | Not done. |
| Design decision document | Done. |
| Whitelist contract, issuer-update mechanism, synthetic fixture | Done (hand-written relations, not a Compact contract). |
| Versioned circuit artifacts and reproducible generation | Partially: the CSL spend verifier key is embedded with its hash pinned; the gate's keys are generated at test time from the public parameters and not checked in; `static/version` was not bumped (see Deviations). |
| Direct transaction builder and automated scenario runner | Done (`csl_common.rs`, `csl_regulated_transfer.rs`). |
| Coverage register linking every shape to a test | Not done beyond the inventory table and the T-table above. |
| Pipeline-switch evidence (new key embedded, old key rejected) | Done. |
| Real-proof test results and before/after state assertions | Done for the nine scenarios. Node/block-validation evidence: not done. |
| Performance measurements, privacy findings, missing-primitive list | Measurements: not done. Privacy: documented, not measured. Missing primitives: listed in `design/next-steps.md`. |
| Final CSL interface proposal | Not done. |

---

## Deviations from the plan and the design document

- **Native spend proofs stay on the v1 verification pipeline.** The plan's Stage 0 text speaks of
  routing through the production verifier; `Input::well_formed` uses the legacy pipeline
  (`transient_crypto_old`) with the built-in key, and that is the only path it has. What changed
  is the embedded key. Contract proofs (`ProofVersioned`) are untouched. (Design D10.)
- **`static/version` was not bumped** and the `spend.verifier.sha256` download sidecar keeps the
  legacy hash. The version only names data-provider download paths, and the data provider still
  serves the legacy IR artifacts, which the ledger no longer uses for spends. A separate
  `spend.verifier.csl.sha256` pins the embedded key. The design (D10) said to bump the version;
  the as-built section records why it was not.
- **Transcript templates were measured, not derived.** The gate relations emit public-transcript
  field representations from constants whose op encodings were read off a probe test. If the VM's
  `field_repr` encoding changes, the templates break and the probe must be rerun.
- **T13 was split in two** (claimed forged root vs forged witness only) because the two cases are
  rejected by different layers.
- **"Cannot be proven" is asserted as "no accepted proof exists".** The first version of the
  scenarios asserted that unsatisfiable witnesses fail at proving; they do not (see Findings), and
  the plan's Stage 3 text anticipates exactly this ("a negative circuit test may fail during proof
  creation; supplement it with ... otherwise-valid proofs that the real verifier rejects").
- **MIP-0017 was deliberately not used** as an input, per the user's instruction.
- **ECDSA multisig in the gate** (the user's stated interest) was not attempted; its feasibility
  note is in Findings.

---

## Harness mechanisms, simplifications and anything that could be mistaken for a mock

Nothing in the evidence path is mocked: proofs are real, verification is the production
`Transaction::well_formed` under default strictness, and state application is the production
`LedgerState::apply`. The following are the places where the test harness, rather than the
protocol, does the work, or where the implementation is narrower than a production one would be.
Each is stated so it is not mistaken for something it is not.

| Item | What it is | What it means for the evidence |
| --- | --- | --- |
| Issuance by state injection | The regulated coin is created with `TestState::rewards_shielded`, which applies an unbalanced offer with balancing disabled, exactly as the ledger's own tests fund wallets. No minting contract is deployed; the "minting address" is a constant. | The issuance route is not tested or gated. Only movement after issuance is. |
| `check` hook returns "all ops active" | `ProvingProvider::check` normally interprets the ZKIR to find untaken transcript branches. The hand-written relations have no ZKIR, and their transcripts are fixed, so the hook returns a vector marking every op active. | Not a bypass of verification; it only affects which transcript ops are kept before proving. Nothing is skipped in `well_formed`. |
| `CombinedProofProvider` short-circuit | The ledger test harness's prover tried to resolve the spend key through the data provider; native relations are now routed to the hand-written prover first. | Test-harness plumbing. The production `LocalProvingProvider` has the same routing in `zkir/src/lib.rs`. |
| Alice is the test wallet | Alice's keys are the harness's own zswap wallet keys; Bob and Carol are synthetic parties with fresh keys. | Cosmetic; the harness replays Alice's events so her local state tracks the chain. |
| Exact-fee loop | The shared balancing helper prices against mock proofs and underpaid real ones by a constant, so the fixture pays DUST by iterating pay, prove, measure to a fixed point. | The transaction is fully fee-paid and balanced under strict verification; the loop is a construction convenience. |
| Fee intent TTL of ten minutes | The harness advances block time by ten seconds per applied block; the first fixture gave the fee intent a TTL equal to its creation time and the retained-proof case expired before the root check could run. | The stale case is now decided by the gate's root replay, not by expiry; the first run's TTL failure is recorded in `results/`. |
| Hand-written relations instead of Compact | The gate's `authorize` and `update_root` and the CSL spend circuit are zk-stdlib v1 relations written in Rust. The Compact compiler is not in the pinned flake. | The gate is a real contract (state, entry points, verifier keys, transcripts) but not one a dApp developer would write today. |
| One output per gate call | `N_OUTPUTS = 1`: the gate authorizes one input and checks one output. | A real wallet needs change; this is the first Stage 4 item. |
| Depth-8 whitelist | 256 slots, Poseidon leaves `(owner kind, pk, enrollment randomness)`, maintained off chain; only the root is on chain. | Adequate for the fixture; a production list needs a larger tree and a membership-material distribution protocol. |
| Single-secret administrator | `update_root` proves knowledge of a Poseidon preimage of the admin cell. | Not a multisig; governance of the root is a single key. |
| Gate's own token type written after deployment | The token type names the gate's address and the gate's state names the token type, so the type cell is written by the first `update_root`. | Breaks a circularity; it also means the gate's state is incomplete between deployment and the first root publication (no transfer can succeed then, which is the safe direction). |
| Test-time key generation for the gate | The gate's proving and verifier keys are generated from the public parameters when the tests run and served by a test resolver; they are not checked in. | Deterministic for given parameters and relation; not a versioned artifact. |
| Scripts with absolute paths | `scripts/` ran in one container and reference its scratch directory. | Records of what ran, not a portable reproduction tool; the reproduction steps below are the portable form. |
| Existing tests updated to compile | `ledger/tests/micro-dao.rs` and `ledger/tests/token_vault_shielded.rs` gained a `None` derivation argument so the workspace compiles. | Both pass in the full suite: their coins are of the native type. |

---

## Findings

- **The prover does not check satisfiability.** `create_proof` emits a proof for any witness. For
  a removed sender, an unapproved recipient, a wrong administrator secret, or a forged root with
  the real root claimed, the resulting proof fails under the embedded verifier key
  (`InvalidProof`). The security property is therefore "no accepted proof exists", and the tests
  assert on the ledger's disposal rather than on a prover error.
- **Two layers, two rejections.** The circuit binds the statement (witness and public transcript
  must agree); the ledger binds the statement to current state (the transcript's root read is
  replayed at application). A self-consistent proof against a stale or forged root passes
  verification and fails at application with `ReadMismatch`; a proof whose witness disagrees with
  its statement fails at verification. Both are needed; neither alone would do.
- **Every spend now needs derivation inputs.** With unconditional re-derivation, a coin whose type
  preimage `(domain separator, minting address, rule)` is unknown cannot be spent. This closes the
  unguarded route for guarded coins, and it is a real migration cost: wallets and indexers must
  resolve the preimage for every contract-minted shielded coin. The native all-zero type is
  special-cased under `Empty`, which is why the existing ledger tests, which only spend native
  coins, pass unchanged; the closure for an underivable type is shown by the zkir relation test.
- **Public disclosures.** Per guarded input the chain learns that it is guarded, by which gate and
  entry point, and a Poseidon binding value. Per gate call: the gate address, the claimed binding
  and the claimed output commitments (already public in the offer). The whitelist contents, both
  parties' keys and the membership paths stay off chain. The asset family of a guarded input is
  therefore public, as the plan anticipated.
- **Governance trust.** An authorized `update_root` changes who may transact without changing the
  token type; holders trust the gate's administrator as well as its code. (Plan Stage 6 standing
  finding; recorded, not elaborated.)
- **Fee pricing is a fixed point.** The ledger prices by proven size and the DUST spend's encoded
  value is part of that size.
- **ECDSA in the gate.** zk-stdlib 1.3.0 (the `v1` pipeline the relations use) has a secp256k1
  foreign-field and curve chip (`ZkStdLibArch::secp256k1`). A k-of-n ECDSA predicate in the gate
  is therefore buildable without new primitives, but was not attempted. It would make the spending
  key insufficient on its own; the spending key still has to reach the spend prover, so this does
  not remove it from custody.

---

## Known issues in the implementation

- **The full ledger suite passes.** The complete `midnight-ledger-v10` package (library, every
  integration test) passes under real proving; the table is in `results/results.md`, "Full ledger
  suite". An earlier note in this work expected `micro-dao` and `token_vault_shielded` to fail
  because they spend contract-owned coins; they use the native token type, which the relation
  accepts under `Empty` without derivation inputs, so they pass. The consequence is that **no
  existing ledger test spends a contract-minted shielded coin without its derivation**, and the
  fail-closed behaviour for an underivable type rests on the zkir relation test alone.
- **`test_resolver_resolves` was broken and fixed.** Replacing the embedded spend verifier key
  initially changed the download sidecar's hash as well, which broke verification of the legacy
  artifacts still served by the data provider. The sidecar was restored to the legacy hash and a
  separate `.csl.sha256` pins the embedded key.
- **Cost model entries are copied, not measured.** The two new effects maps are priced like
  `claimed_shielded_receives`.
- **Tag bumps are experiment-local.** Every containing type's storable tag was bumped and the
  `.tag-decompositions/` files regenerated so the enforcement tests pass; these are not reviewed
  or coordinated with upstream.
- **Gate templates depend on measured encodings** (see Deviations).
- **No proof-free unit tests of the matching rule.** The design called for in-crate tests of
  `effects_check` with proof-erased transactions; the rule is exercised only end to end by T06,
  T07 and T08. This is the first item in `design/next-steps.md`.
- **No negative test for a guarded transient, contract owner, mint, claim or merge** even where
  the design argues they fail by construction.

---

## How to reproduce

1. Clone `midnightntwrk/midnight-ledger` and check out `fa995fa5791bc19112e97334a2d9265751c35fad`,
   or check out this repository's `ledger-experiment` branch, which is that commit plus the two
   experiment commits. To use the patches instead: `git am patches/*.patch` on `fa995fa`.
2. Rust stable (the flake pins fenix stable of 2026-04-23; rustc 1.97.0 was used).
3. Fetch the public parameters `bls_midnight_2p0` through `bls_midnight_2p18` from the S3 bucket
   named in the ledger's `flake.nix` into a directory, verify their SHA-256 against the flake, and
   export `MIDNIGHT_PP=<that directory>`.
4. Build the `zkir` CLIs with `--features binary` (both the `zkir` and `zkir_v2` crates are needed
   by the flake's artifact step) and compile `zkir-precompiles/*` into a directory with
   `zkir compile-many`; export `MIDNIGHT_LEDGER_TEST_STATIC_DIR=<that directory>`. The exact
   invocations are in `scripts/stage0_chain2.sh` and its log in `results/stage0_chain2.txt`.
5. Export `RUST_MIN_STACK=67108864` (the hand-written relations recurse deeply in debug builds and
   the harness threads need the headroom in release as well).
6. Run, in order:
   ```
   cargo test -p midnight-coin-structure custom_spend
   cargo test --release -p midnight-zkir --test zswap_spend
   cargo test --release -p midnight-zkir --test zswap_spend_csl
   cargo test --release -p midnight-zswap
   cargo test --release -p midnight-onchain-runtime
   cargo test --release -p midnight-ledger-v10 --lib
   cargo test --release -p midnight-ledger-v10 --features proving --test csl_baseline
   cargo test --release -p midnight-ledger-v10 --features proving --test csl_regulated_transfer -- --nocapture --test-threads=1
   ```
   The scenarios print each rejection as it happens; expect about four minutes on four cores.
   `scripts/reproduce.sh` runs steps 1 to 6 (it also downloads and verifies the parameters).

---

## Process notes

- The Stage 3 scenarios took three runs to reach their final form, all recorded in `results/`:
  run 1 (four failures: the "cannot be proven" assertions and the fee-intent TTL), run 2 (one
  failure: T13a could not construct its transcript because the builder executes the gate against
  the real state), run 3 (one failure: T13a's forged tree changed Bob's sibling path while his
  path was still taken from the real tree, so the proof was invalid rather than self-consistent),
  run 4 (nine passed). Each fix is described in `results/results.md`.
- The user's decisions during the review of the plan: ignore MIP-0017 and derive the design from
  the pinned sources; build on ledger 10; promote the hand-written relation; decide output shape
  and whitelist details in Stage 1; leave node integration for later.
- Commit authorship: the ledger commits and this repository's commits carry the experimenter as
  author with a co-author trailer for the coding assistant that produced them.

---

## Revision 2: security fixes

A source review of the first implementation (ledger commit `8285f69`) found three protocol defects
and a reproducibility gap. All are fixed on this branch and demonstrated with real proofs by
`ledger/tests/csl_regression.rs`. Details: `design/stage1-design-decision.md` section 7,
`results/results.md`.

| # | Defect | Fix | Demonstrated by |
| --- | --- | --- | --- |
| 1 (critical) | The spend proof authenticated only the opaque binding, not `policy.gate`/`policy.entry_point_hash`. An attacker-controlled contract could repeat the binding and rubber-stamp the authorization, so a revoked holder could move the coin through a gate she deployed. | The spend statement now exposes and constrains `[mode, gate, entry_point]`, filled by the verifier from the input's public policy; the token type binds to the real gate's address. | reproduced accepting against `8285f69` (`results/attack_reproduction_*`), rejected after the fix (`attack_gate_substitution`, `attack_cloned_gate`, `route_entry_point_substitution`, `omitted_policy`) |
| 2 (high) | The binding `Poseidon(dom, nullifier, sender, gate, ep)` was recomputable by anyone who knew a candidate sender key: a recognition oracle. | The binding is now `Poseidon(dom[v2], nullifier, sender, token_type, rho)` with fresh private `rho` shared only between the spend and gate proofs. | `mismatched_blinding`, `tampered_binding`, and the coin-structure unit test `policy_binding_is_blinded_and_type_bound` |
| 3 | `update_root` could rewrite the protected token type, silently disabling recipient checks; a second asset at the same gate got sender-only enforcement. | A one-time admin `init` sets the type; `update_root` is root-only; the gate folds its own type cell into the binding, so it authorizes only its own asset. | `transfer_before_initialization`, `second_initialization_cannot_retarget`, `init_with_wrong_admin`, `second_asset_at_same_gate`, `protected_asset_survives_root_update` |
| 4 | Real-proof coverage was not reliably reproducible in CI. | A dedicated real-proving CI job (mock-verify asserted absent), a pinned `MANIFEST.json`, and a revision-checking `scripts/reproduce.sh` that records run metadata. | `.github/workflows/csl-proving.yml` on the `ledger-experiment` branch |
| 5 | — | The embedded verifier key is regenerated from the fixed relation; the old relation is frozen as never-dispatched test evidence; old-layout proofs are rejected through the full ledger path. | `historical_v1_spend_proof_is_rejected_by_the_ledger`, `historical_v1_csl_proofs_do_not_verify_under_v2_key` |

**What still stands:** the first supported shape (one regulated input, one equal-value regulated
output, one gate call), the ledger's matching and coverage rules, the effects maps, and the privacy
boundary are unchanged. The nine original scenarios still pass. Scope not addressed here (change
outputs, transients, contract owners, mint/claim gating, node integration, measurements) is
unchanged from revision 1; see `design/next-steps.md`.
