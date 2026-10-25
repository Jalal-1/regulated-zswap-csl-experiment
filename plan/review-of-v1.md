# Review: Regulated ZSwap CSL Experiment Plan (25 October 2026)

Reviewer basis: the plan's pinned sources were fetched and read directly.

| Source | Revision checked |
| --- | --- |
| midnight-ledger, branch `alexshielded/custom-spend-logic` | `fa995fa5791bc19112e97334a2d9265751c35fad` ("zswap in zk-stdlib") |
| midnight-node | `ad8f2802c16594fb3c0a54c5976cab98bdeaab20` (node-1.0.400). This is also the current `main` head. |
| midnight-improvement-proposals PR 335 | head `41d3b15302b0a69cff62cafc19767c4c1be478fb` ("Early draft of custom spend logic MIP"), still absent from `main` |
| midnight-improvement-proposals `main` | MIP-0017 and MPS 0013/0014/0021/0024/0025/0029 present |

## 1. Verdict

The plan is a strong handoff. Its reading of the baseline is accurate in every detail I could check, its adversarial test set is the right shape, and its central insistence that evidence must come from strict ledger verification rather than UI or wallet refusals is exactly right.

Three findings would change what the coding agent does and should be folded in before handoff:

1. **MIP-0017 (Shielded Note V2) is missing from the design material**, and it already specifies most of the "movement commitment" the plan asks the agent to design from scratch.
2. **The pinned branch already carries proof recursion** (`verify_proof` / `inner_proof` in ZKIR). The route table's assessment of the recursive gate is stale, and the real reason to prefer the contract route is V4 (removal), which the plan should say outright.
3. **Stage 1 is larger than written**: the production circuit pipeline has no Compact compiler in the build, native proofs are verified through the legacy pipeline against built-in keys, and the existing effects matching reaches only contract-owned coins. Sender binding for a user-owned coin needs new wire fields, a new effect, and new two-way matching.

Everything else is a correction or an addition, not a change of direction.

## 2. Claims verified against the pinned sources

| Plan claim | Result | Evidence |
| --- | --- | --- |
| `SpendRule::Empty`, `GateCircuit(vk_hash)`, `GateContract(address, entrypoint_hash)` | Correct | `coin-structure/src/custom_spend.rs:47-57` |
| Descriptor is hashed (tagged serialization, `persistent_hash`) before entering type derivation; Empty keeps the legacy 96-byte preimage | Correct | `custom_spend.rs:71-78`; `coin-structure/src/contract.rs:60-70` uses `persistent_commit((domain_sep, address, descriptor_hash), "midnight:derive_token")` |
| `ShieldedMintKey(domain_sep, SpendRule)` | Correct | `onchain-runtime/src/context.rs:606` |
| Hand-written `ZswapSpend` reproduces the shipped verifier key and is not the production path | Correct | `zkir/src/zswap_spend.rs:14-24` module doc; `zkir/tests/zswap_spend.rs:115` asserts byte-identical VK. Production keys resolve via `zswap/src/prove.rs:32-44` (`zswap/<version>/spend`) from IR, not from this relation |
| Spend constructor sets `binding_input` to zero | Correct on the construction side | `zswap/src/construct.rs:213` (`0.into()`); outputs bind `transient_commit(coin, 0)` at `:74`; `ledger/src/construct.rs:562` |
| `whitelist` in `zswap/src/ledger.rs` is contract-state tracking, not eligibility | Correct | `zswap/src/ledger.rs:71-156`, `Option<Map<ContractAddress, ()>>` with `on_whitelist` |
| Crate names and features: `midnight-coin-structure`, `midnight-zkir`, `midnight-ledger-v10`; `proving`, `proof-verifying` default-on, `mock-verify` | Correct | `ledger/Cargo.toml` `[features]`; README confirms tests do not prove without `--release --features proving` |
| `--all-features` can enable mock verification | Correct | `mock-verify` is a plain feature of `midnight-ledger-v10` |
| Node exposes ledger 8 and 9 host modules, 9 as latest; CSL checkout is ledger v10 | Correct | node `ledger/src/lib.rs:34-37`; node `Cargo.toml:89,104,469` pins `midnight-ledger-v9` by git tag `crate-ledger-9.1.0.0-rc.6` |
| PR 335 is open and unmerged; its recipient argument is a declaration | Correct | Draft: "Nothing binds the declaration and nothing needs to ... A rule like *you may only pay X* is not enforced: the spender picks the witness." Not present on `main` |
| MIP requires Capsule Runtime | Correct | Draft front matter: `Requires: Capsule Runtime MIP` |
| Existing contract-call / native-effect matching | Correct but narrower than the plan implies | `ledger/src/verify.rs:1443-1530`: the `nullifiers` and `commitments` multisets include only inputs/outputs whose `contract_address` is `Some`. The MIP itself notes this: "reaches only inputs that carry a contract address" |

## 3. Findings that should change the plan

### 3.1 Add MIP-0017 to the primary design material

`mips/mip-0017-shielded-spend-auth/` on `main` (Status: Proposed, created 2026-08-28, Related-MPS includes MPS-0013) introduces shielded note version 2 with VRF nullifiers and, in its `specification.md`, a complete payment-binding design:

- §6 "Payment Scope and Digest": an `AuthScope` over input references, output references and intents, keyed by segment, with a canonical digest under `midnight:zswap-spend-auth[v2]` and digest binding under `midnight:zswap-auth-bind[v2]`.
- §6.1 coverage rules: every input covered exactly once, no repeats within a scope, transients as one record.
- §6.2 merge semantics, §8.2 branch-independent digest binding, §10 transaction-level validation.

This is the "canonical, domain-separated movement commitment" with "ordering, multiplicity, value/type linkage and freshness semantics" that the plan's V5 asks the agent to invent. Two consequences:

- The Stage 1 design decision should adopt or deliberately diverge from `AuthScope`, and record why. Two incompatible payment-binding formats in the same protocol family would be a bad outcome of this experiment.
- Note versioning becomes a design input. If v2 notes land, a regulated note format must either compose with v2 or be v3. The plan's "bind the rule to the token" section should state which note version the experiment builds on.

### 3.2 The route table understates what is on the branch

`CHANGELOG.md`, "Unreleased (Ledger 10)", on the pinned commit lists: ZKIR `verify_proof` and `inner_proof` instructions; `Proof` wire format `proof[v6]` carrying `DeferredAccumulator`s; `ProofVersioned::V4`; `IrSource` carrying `verify_proof_vks` (`IrMinorVersion::V1`). The implementation is in `zkir-v3/src/ir_instructions/verify_proof.rs` and is used by `zkir/src/ir_v1.rs`.

So recursive verification against a gate verifying key that is fixed in the outer circuit's IR is available now. What is not available is the "privately witnessed verifying key" the MIP wants for mode 2, and, more importantly for this experiment, a consensus-authenticated current whitelist root as a spend public input. Without that root, mode 2 cannot satisfy V4 (removal) at all: a holder removed from the list can keep proving against the old set.

Recommended wording: "The decisive scenario is removal. Only a gate that reads current chain state at execution can reject a revoked holder, so the contract route is primary. The branch's recursion instructions make a fixed-key recursive gate feasible for a privacy comparison, but it cannot pass T02 or T12 until a provable current-state root exists (MIP draft, 'Future: a provable state root for pure rules')."

### 3.3 Decide the production circuit pipeline in Stage 0, not Stage 1

Facts at the pinned commit:

- `flake.nix` has the Compact compiler commented out (lines 22-24, 35, 332, 338, 341-343). The `local-params` derivation copies the checked-in IR from `zkir-precompiles/zswap/*.zkir` and runs `zkir compile-many` to produce keys (lines 348-353, 369-384). `zswap/zswap.compact` is therefore documentation of the v1 circuits, not a build input.
- Native proof verification in `zswap/src/verify.rs` runs through `transient_crypto_old` with built-in verifier keys (for example `SIGN_VK` at line 141). `ledger/src/structure.rs:500-547` dispatches `ProofVersioned::V2/V3/V4` to the legacy or current pipeline.
- The hand-written relation is "written directly against zk-stdlib (v1)" and only lives in tests.

The agent has three ways to ship a changed spend relation: regenerate IR from a modified `zswap.compact` with a Compact compiler whose ZKIR output matches `midnight-zkir` 2.2.0 (not pinned anywhere in the repo); hand-write ZKIR; or promote the zk-stdlib relation to the production prover and embed its new verifier key, which is the direction the branch's latest commit message suggests. The plan's instruction "establish which circuit source actually feeds production artifacts" should become "the production source is the checked-in IR; choose one of these three paths and pin its toolchain before Stage 1".

### 3.4 Sender binding for user-owned coins is new infrastructure

Because `effects_check` only matches contract-owned coins, a regulated coin held under a user key has no existing channel through which a contract call can reference its nullifier. The MIP's mode 3 sketch describes what is needed: a new proved public field on `Input` committing to `(nullifier, coin, sender_pk, gate_address, ep_hash)`, a sibling `Effects` field claimed by the gate call, and two-way matching keyed by segment, nullifier and gate address. The MIP also lists the collateral cost of widening `Effects`: tag bump of `contract-effects[v3]`, VM encode/decode paths including the fixed-length effects array, kernel and standard-library mint changes, and a cost-model entry.

The plan's groundwork table row "Existing contract-call and native-effect matching" should say this explicitly, and the Stage 1 and Stage 2 effort estimates should assume wire-format changes to `Input`, `Output` and `Effects`, not just circuit constraints.

### 3.5 Universal re-derivation makes the type preimage a spending prerequisite

The MIP flags this as open: once the spend circuit re-derives the token type unconditionally, every spend of a contract-minted shielded coin, guarded or not, must witness `(domain separator, minting address, descriptor)`. The plan's phrase "including any newly required inputs for legacy spends" undersells a protocol-wide wallet and indexer change.

For the experiment it is manageable, and the plan should say why: fees are paid through DUST actions on the intent (`ledger/src/dust.rs`, `Intent.dust_actions` at `ledger/src/structure.rs:965`), so the regulated offer needs no fee coin and the builder only needs the regulated token's preimage. Record the general case as a production-migration finding for Stage 6.

### 3.6 Force the output-side choice in Stage 1

The plan wants one gate invocation to cover sender and recipient, and notes that output-circuit changes "may be necessary". There are two viable shapes and they differ in privacy and in witness burden:

- **Marked outputs.** The output circuit re-derives the type and, for a guarded descriptor, exposes a public binding field; the gate claims exactly the marked inputs and outputs. This is the MIP's receipt-guard principle. It reveals that each regulated output is regulated at creation.
- **Segment-wide coverage.** One gate call claims every output commitment in the segment and checks, per coin, "type equals the regulated type implies recipient is whitelisted". No output is marked, but the gate witnesses every output's opening, and any later merge invalidates the authorization. Minting must then be gated through the public `shielded_mints` effect, which already carries the `ShieldedMintKey` and therefore the rule, or a regulated output could appear in a segment with no regulated input.

Either is defensible for the first shape. The plan should make the agent choose and record the privacy delta under V9. In both shapes the MIP's observation about zero-value outputs applies: a zero-value coin of a guarded colour is Pedersen-neutral and needs no mint, so "no new regulated output" assertions and the coverage register must say how zero-value outputs are treated.

### 3.7 Freshness and read-pattern details for the contract route

V4 comes for free in the contract route only if the whitelist state is read in a way that fails on stale reads. In Compact, `HistoricMerkleTree.checkRoot` accepts a window of past roots, which is exactly what `zswap.compact` uses for the coin tree and exactly what the plan warns against for eligibility. The whitelist must use the non-historic `MerkleTree`, or a bounded set read in full. If a bounded set is read selectively, the transcript records which cell was read and leaks the matching index. Add "state-read access pattern in the gate transcript" to the V9 review list.

### 3.8 Node integration is a separate project

The pinned node revision is current `main`, so no newer node already consumes ledger 10. The node pins ledger 9.1.0.0-rc.6 by git tag and ships a `v8-to-v9-state-translation` crate. A ledger 10 host module implies a `ledger_10` module, a v9-to-v10 state translation, host API bridging and runtime dispatch, all against a ledger whose `Proof` wire format just changed. Keep Stage 5 as a separately reported outcome, as the plan does, and add an intermediate milestone: block import of the negative fixture through the node's ledger host API in a node unit test before full RPC and genesis work.

## 4. Smaller corrections

- **`static/` is the version crate** (`midnight-ledger-static`, consumed by `prove.rs` for key paths), not public parameters. Public parameters come from the flake's `public-params` derivation, which fetches k-indexed files from an S3 bucket (`flake.nix:482-492`). Stage 0 needs network access to that host or a pre-staged `MIDNIGHT_PP`.
- **`test-utilities` carries a warning** in `ledger/Cargo.toml`: "This *disables* a small amount of well-formedness checking for test setups!" The relaxation is not in `ledger/src/verify.rs`, so it lives in a dependency feature (`zkir_v3/test-utilities`). `ledger/tests` compile with it. The acceptance run should use `WellFormedStrictness` defaults (`ledger/src/verify.rs:452-466`, all three flags true) and the agent should pin down what the feature relaxes.
- **Where "close old proof routes" lives**: `ProofVersioned::V2/V3/V4` dispatch in `ledger/src/structure.rs:311-349, 500-547` and the legacy verification in `zswap/src/verify.rs`. `ledger/src/prior_versions.rs` is a 14-line stub.
- **Descriptor encoding and the circuit**: the Rust side hashes a tagged serialization. Reproducing tagged serialization in-circuit is awkward. Choose a fixed-width in-circuit encoding and make the Rust `descriptor_hash` match before the first mint, since changing it later changes asset identity.
- **Companion material**: PR 335 also carries `mips/custom-spend-logic/attribution-designs.md` (Designs A/B/C, ERC-3643 analogue, identity-provider mapping). It belongs in "Existing identity work to reuse later".
- **Fixture construction**: if minting is gated, the never-approved holder can only be created by direct state insertion or genesis, which the node stage cannot do through RPC. Say so, and say that T03 is a sanity check that is strictly easier than T02.
- **Second shape**: "one regulated input, one regulated output, one regulated change output to the sender" should be the first expansion in Stage 4. Change is the first thing a real wallet needs, and the sender is already whitelisted as a recipient.
- **Tests to add**: policy contract undeployed or missing at the descriptor's address (must fail closed, which freezes the asset); authorized gate upgrade that changes the rule (a governance trust finding to document, not a test); zero-value guarded outputs.
- **Capsule Runtime**: the plan scopes it out correctly. Add one sentence: the experiment's whitelist is public contract state, so the capsule's issuer-private-state motivation does not apply here.

## 5. Document hygiene

- "CSL" is never expanded. Say "Custom Spend Logic" once.
- "Monument" is never introduced. One clause identifying it as the issuer and administrator of the experimental asset would help a fresh agent.
- "EOA" is defined in the objective section and never used again.
- "The current workspace has Git but lacks Nix, Cargo and Rust" and the `/workspace/scratch/...` path describe a previous session's machine. Make them conditional or drop them.
- The `authorizeTransfer` pseudo-signature is useful. Consider adding, right under it, the three forks the agent must close in Stage 1: circuit pipeline (3.3), output-side shape (3.6), note version and binding format (3.1).

## 6. Suggested insertions, by section

- *Starting implementation and known gaps*, groundwork table: replace "Existing contract-call and native-effect matching" with "Effects matching for contract-owned coins only (`claimed_nullifiers`, `claimed_shielded_receives`); user-owned coins have no claim channel".
- *Starting implementation and known gaps*, after the node paragraph: "The pinned node revision is current `main`; no node revision consumes ledger 10."
- *Evaluate the contract route first*, recursive row: replace "Recursive verification with a privately witnessed verifying key" with "Fixed-key recursion exists on this branch (`verify_proof`); privately witnessed keys and a consensus-authenticated current whitelist root do not".
- *Bind the rule to the token*: add "State the note version this experiment targets relative to MIP-0017's note v2."
- *Authenticate one decision for both sides*: add "Start from MIP-0017 §6 `AuthScope` for the movement commitment; document any divergence."
- *Stage 0*: add "Record which of the three circuit pipelines (regenerated IR, hand-written IR, zk-stdlib relation) feeds production artifacts, and pin its toolchain."
- *Primary design material*: add MIP-0017 and `attribution-designs.md`.
