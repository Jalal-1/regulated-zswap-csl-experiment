# Regulated ZSwap CSL Experiment Plan

**Implementation plan and coding agent handoff — 25 October 2026, revision 2**

*Revision 2 incorporates a source-verification review of the pinned ledger, node and proposal revisions. Decisions taken after that review are marked **Decision**; items left to the coding agent are marked **Open**.*

We want to create an experimental regulated member of the native ZSwap token family whose transfer rules remain mandatory after the token leaves the issuer and enters a self-custody wallet. Possession of the spending key must remain necessary, but must no longer be sufficient to move this asset.

The first rule is deliberately simple: the actual sender and every actual recipient must be on the current whitelist maintained by Monument, the issuer and approval administrator of the experimental asset. One Custom Spend Logic (CSL) invocation may check both sides. The experiment should establish where that invocation belongs, how it is authenticated, and what changes Midnight’s circuits, ledger and node require.

This is a protocol experiment. Its result must be evidence from real proofs and ledger validation. The existing CSL work is a starting point; feasibility and end-to-end enforcement remain to be demonstrated.

**Standing decisions from the revision 2 review**

| Topic | Status |
| --- | --- |
| Design inputs | **Decision:** the binding and gate design is derived from first principles against the pinned sources. The CSL draft and the MPS documents listed under Reference material are the only external design inputs; no other proposal is a dependency. |
| Ledger base | **Decision:** the pinned ledger 10 branch is the base. Its recursion instructions are an available primitive, not a dependency. |
| Production circuit pipeline | **Decision (recommended; confirm or override):** promote the hand-written zk-stdlib spend relation to the production path in Stage 0. See Starting implementation and known gaps. |
| Recipient coverage shape | **Open:** marked outputs or segment-wide coverage, decided in Stage 1 with the privacy delta recorded. |
| Whitelist structure and freshness | **Open:** decided in Stage 1. The known traps are listed under Keep the whitelist simple. |
| Node integration | **Decision:** resolved in Stage 5 with an intermediate host-API milestone. It does not gate Stages 1 to 4. |

## Objective and decisive scenario

Alice holds a regulated ZSwap coin in her own wallet. She controls its spending and viewing keys. Alice is absent from the whitelist. Bob’s receiving wallet is approved and operated by an exchange. Alice constructs a native transfer herself and submits it without using Monument’s application.

**Required outcome: Midnight rejects the regulated transfer.** A modified wallet, direct transaction construction, omitted contract call, permissive exchange or alternative RPC endpoint must not make it valid.

Use this reproducible fixture:

1. Approve Alice and Bob and issue experimental regulated tokens.
2. Give Alice a coin while she is approved.
3. Remove Alice from the whitelist and commit that update.
4. Preserve Alice’s original coin, spending key and viewing key.
5. Attempt Alice → Bob through a raw transaction builder.
6. Verify rejection by the ledger, with no consumption of Alice’s regulated coin and no creation of Bob’s proposed output.
7. Run an approved sender → approved Bob transfer as the positive control in an independent/reset fixture, so it does not consume the negative test’s coin.

This lifecycle produces a valid coin held by a now-ineligible owner without weakening issuance. Also keep a synthetic never-approved-holder fixture for adversarial tests, clearly separated from normal issuance. If issuance is gated, that fixture can only be created by direct state insertion in the ledger harness or by genesis in the node; it is a sanity check that is strictly easier than the revoked-Alice case.

Alice’s wallet is a user-controlled shielded ZSwap wallet, not an Ethereum-style account. The ledger checks the exchange’s actual receiving key or contract owner. An exchange’s internal customer account is outside this initial proof. Bob need not reveal his spending or viewing key, or co-sign merely to receive. Alice’s viewing key is not an authorization credential.

## Scope and boundaries

The long-term requirement is universal enforcement for this regulated token across every native movement path. Wallet labels do not alter policy: personal wallet, exchange, custodian, contract, DEX and custom client all face the same rule.

The initial implementation may support fewer transaction shapes, provided every unsupported shape is rejected at the protocol boundary. A narrow demonstrator establishes feasibility for its supported shape; it does not establish full transfer coverage.

| Included in this experiment | Deferred |
| --- | --- |
| New guarded native token type and immutable binding to its policy descriptor | Retrofitting existing unguarded tokens without changing asset identity |
| Simple issuer-managed approval set, including removal | Real KYC decisions, sanctions screening and legal compliance determinations |
| Actual sender and actual recipient binding | DID issuance, identity registries and credential attestations |
| Real proof generation, verification and ledger rejection | Production deployment, public-network upgrade and operational rollout |
| Contract and proof mode evaluation, followed by one implemented route | Implementing both modes before demonstrating either |
| Exhaustive movement-path inventory and enforced restrictions | ECDSA multisig, force transfer, seizure and custody key redesign |
| Local node integration and adversarial submission | Exchange API integration or a polished wallet UI |

Eligibility in this POC means approval of a cryptographic owner identifier. It does not prove the human operating that key is Alice, prevent approved users sharing keys, or identify the source of funds. Monument’s approval administrator is trusted to manage the set; unauthorized updates must still be rejected.

Preserve a clean extension point for future identity predicates. The existing DID and VC projects are later integration resources, not prerequisites for this experiment. Preserve a second extension point for a future k-of-n ECDSA authorization predicate inside the gate: the gate interface must be able to accept additional authorization witnesses over the same movement binding, and in-circuit ECDSA will need its own primitive and cost model. Such a gate makes the spending key insufficient but still necessary; it does not remove the key from the prover.

## What the experiment must validate

| ID | Property | Evidence required |
| --- | --- | --- |
| V1 | Policy is mandatory for the asset | A valid native spend cannot omit its required gate or choose a weaker rule. |
| V2 | The policy identifies the actual spender | Substituting an approved participant for Alice fails, even when the caller supplies a plausible key or witness. |
| V3 | The policy identifies every actual recipient | Checking approved Bob while creating an output for unapproved Carol fails. This includes change and additional outputs. |
| V4 | Approval is current | A membership proof prepared before Alice’s removal cannot authorize a transfer applied after that removal. |
| V5 | Authorization belongs to this movement | A gate result cannot be replayed for another coin, output set, segment, policy or network. |
| V6 | Policy and movement are atomic | A failed or unmatched gate cannot leave its protected spend committed in another successful section. |
| V7 | There is no alternate accepted path | Legacy proof routes, transient coins, contract owners, merged offers and other supported forms cannot bypass enforcement. Unsupported forms fail closed. |
| V8 | Native token invariants survive | No inflation, value imbalance, double spend, token-type substitution or unintended loss of legacy functionality. |
| V9 | Participant data stays private | Public transfer data does not disclose the checked keys, identities, membership witnesses or a new stable participant identifier. Any policy-routing metadata is measured separately. |
| V10 | The result works in a node | Production verification and block validation enforce the same rule as the test harness. |

A UI refusal, a failed wallet preflight, an application allowlist or a stand-alone whitelist circuit is not sufficient evidence for V1. An inability to construct a proof is useful circuit evidence, but the acceptance suite must also show that adversarial serialized transactions cannot pass the ledger’s real verification path.

## Starting implementation and known gaps

The inspected ledger baseline is [alexshielded/custom-spend-logic](https://github.com/midnightntwrk/midnight-ledger/tree/fa995fa5791bc19112e97334a2d9265751c35fad), commit `fa995fa5791bc19112e97334a2d9265751c35fad`. The portable source of truth is the pinned Git commit; verify any local checkout against it before use.

| Existing groundwork | What still needs to be established |
| --- | --- |
| `SpendRule::Empty`, `GateCircuit(vk_hash)` and `GateContract(address, entrypoint_hash)` | A mandatory execution or verification route for the chosen rule |
| Nonempty descriptor hash contributes to shielded token-type derivation | The production spend circuit re-derives the type and cannot bypass the rule |
| `ShieldedMintKey(domain_sep, SpendRule)` and related encodings | Complete mint, discovery, construction and verification integration |
| Handwritten `ZswapSpend` relation and equivalence tests | New constraints, new proving artifacts and actual production use |
| Effects matching for contract-owned coins only: `claimed_nullifiers`, `claimed_shielded_receives` and `claimed_shielded_spends` in `ledger/src/verify.rs` match inputs and outputs whose `contract_address` is set | A claim channel for user-owned regulated inputs and outputs: new public binding fields, a new effects field and complete two-way matching |
| Checked-in ZKIR in `zkir-precompiles/zswap` compiled to keys by `zkir compile-many`; no Compact compiler in the flake; hand-written zk-stdlib relation used only in tests | A production proving and verification path for a changed relation (decision below) |
| Ledger 10 recursion instructions (`verify_proof`, `inner_proof`), `ProofVersioned::V4` and the `proof[v6]` format | Nothing required for the contract route; usable for a privacy comparison of the recursive gate |

The current handwritten spend relation is designed to reproduce the shipped verifier key. It is not already a CSL-enforcing circuit. Editing that relation alone will not necessarily alter the production proving path.

**Decision (recommended):** the experiment promotes that zk-stdlib relation to the production spend path. At the pinned commit, production keys are compiled from the checked-in ZKIR in `zkir-precompiles/zswap`; the Compact compiler is commented out of `flake.nix`, so `zswap/zswap.compact` documents the v1 circuits and is not a build input; native proofs are verified through the legacy pipeline against verifier keys built into the ledger. The agent therefore first routes the unchanged relation through the production prover and verifier, embeds its verifier key, bumps the static version and proves the switch works (Stage 0), then adds CSL constraints to that relation (Stage 2). New native proofs use the ledger 10 proof format and version. Fallbacks, only if the switch fails: hand-written ZKIR, or ZKIR regenerated by a Compact compiler pinned to the IR version that `midnight-zkir` 2.2.0 expects.

Three source details are particularly easy to misread:

- The implementation hashes a tagged rule descriptor with `persistent_hash` and then commits `(domain_sep, address, descriptor_hash)` under the `midnight:derive_token` separator. The draft MIP describes descriptor concatenation more abstractly. Reproducing tagged serialization in-circuit is awkward, so choose a fixed-width in-circuit encoding, make the Rust `descriptor_hash` match it before the first mint, and test the single byte encoding across all implementations.
- The current spend constructor sets `binding_input` to zero and the verifier expects zero. Its descriptive name/comment is not evidence of transaction or policy binding.
- The `whitelist` parameter in `zswap/src/ledger.rs` filters contract-state tracking. It is not the participant eligibility list.
- The `static/` directory is the `midnight-ledger-static` version crate that `zswap/src/prove.rs` uses for key paths, not the public parameters. Public parameters come from the flake’s `public-params` derivation, which fetches k-indexed files from an S3 bucket; Stage 0 needs network access to that host or a pre-staged `MIDNIGHT_PP`.
- `ledger/Cargo.toml` warns that the `test-utilities` feature disables a small amount of well-formedness checking, and `ledger/tests` compile with it. Final acceptance runs must use `WellFormedStrictness` defaults, and the agent must record what the feature relaxes.
- Old proof acceptance lives in the `ProofVersioned` dispatch in `ledger/src/structure.rs` and the legacy verification in `zswap/src/verify.rs`; `ledger/src/prior_versions.rs` is a stub.

Andrzej Kopeć’s [CSL proposal, PR 335](https://github.com/midnightntwrk/midnight-improvement-proposals/pull/335), is open and unmerged at the inspected revision. Its recipient argument is a declaration; it explicitly does not enforce that the actual output pays that recipient. **Our requirement extends that draft.** Preserve one policy invocation checking Alice and Bob, while adding whatever spend/output proof and ledger linkage makes those checks authoritative.

The inspected node revision `ad8f2802c16594fb3c0a54c5976cab98bdeaab20` exposes ledger 8 and ledger 9 host modules, with ledger 9 as latest. The CSL checkout uses `midnight-ledger-v10`. Node integration therefore needs an explicit compatibility decision, not merely a changed dependency URL. That revision is also the current `main` head, so no node revision consumes ledger 10. The node pins ledger crates by git tag and depends on a v8-to-v9 state translation crate, so a ledger 10 host module implies a `ledger_10` module, a v9-to-v10 state translation and dispatch for the new proof format. **Decision:** the experiment builds on ledger 10 and resolves node compatibility in Stage 5.

## Proposed first architecture

### Evaluate the contract route first

A stateful contract gate is the most direct starting candidate for a whitelist that can change. This is a proposed experiment direction, not a settled CSL API.

| Route | Why investigate it | Main unresolved work |
| --- | --- | --- |
| Contract gate | Can consult the current approval set and update policy state | Native spender authentication, output binding, mandatory call matching, atomicity, execution/discovery and visible routing metadata |
| Recursive proof gate | Could verify a policy inside the spend proof without exposing the chosen gate; fixed-key recursion (`verify_proof`, `inner_proof`) exists on the pinned branch | A consensus-authenticated current whitelist state input, without which revocation cannot be enforced; a privately witnessed verifying key; output binding and cost |
| Inline experimental predicate | Can isolate whether private membership and native enforcement are feasible | Does not by itself demonstrate programmable CSL; classify it as a temporary diagnostic, not completion |

The decisive scenario is removal. Only a gate that reads current chain state at execution can reject a revoked holder, so the contract route is primary; the feasibility spike confirms it rather than selects it. The recursion primitive may serve a privacy comparison but cannot pass T02 or T12 until a current-state root is available to the spend proof. Do not replace live whitelist checks with an unanchored root supplied by Alice. A pure proof against an old or attacker-chosen set does not satisfy removal.

The MIP includes Capsule Runtime as a dependency for its broader execution model. For this bounded experiment, assess whether an explicit locally installed gate executable and synthetic membership witnesses can exercise the consensus mechanism without implementing the full capsule/discovery system. Record that limitation. The experiment’s whitelist is public contract state, so the capsule runtime’s issuer-private-state motivation does not apply here. A capsule or runtime identity does not substitute for native coin-owner authentication.

### Keep the whitelist simple

Use a small issuer-controlled set of approved owner commitments. For a tiny fixture, a bounded collection checked in-circuit is adequate; use a Merkle root only when required by the available primitives or cost. **Open (Stage 1):** if a bounded collection is used, read every entry unconditionally, because a selective read records the matching cell in the public transcript and leaks the index; confirm the read pattern as part of the V9 review. This is a data structure, not a DID or KYC registry.

Proposed leaf semantics are a domain-separated commitment to the owner kind, owner identifier and enrollment randomness. The owner identifier is the ZSwap coin public key for a user, or the contract address for a contract. Use high-entropy randomness if hiding enrollment links is part of the privacy test; a public hash of a known key alone is not that guarantee.

The gate receives the owner and membership opening privately, proves membership in the current set, and binds the owner to the native transfer. Monument can supply Bob’s membership material alongside his receiving information for this fixture; Bob supplies no spending secret. Treat membership material as evidence of inclusion, not as spending authority.

The administrator can add or remove entries. Bind the active set or root to actual on-chain state at execution. A historical coin commitment-tree root may remain valid under normal ZSwap rules; an old eligibility root must not silently inherit that acceptance window. In Compact terms, `HistoricMerkleTree.checkRoot` is that window and is what `zswap.compact` uses for the coin tree; the whitelist must use the non-historic `MerkleTree` or an equivalent current-state read. **Open (Stage 1):** verify this when the gate is written.

### Bind the rule to the token

Mint a new synthetic asset, such as `MGBP-CSL-TEST`, using the selected rule descriptor. The display name is only a fixture label; the derived token type is the security boundary.

The native proof must establish that the committed coin’s type was derived from the issuer’s address, domain separator and exact descriptor. Then it must enforce the descriptor. A prover cannot choose `Empty`, a different gate or a more permissive entry point for the same regulated coin.

Because token type is shielded, avoid a design that first asks the ledger to look up a public token type to decide whether checking is necessary. The relation and version dispatch must close that bypass without disclosing the type.

Retain exact legacy derivation for `Empty`. Reject unsupported descriptor variants; do not treat an unimplemented `GateCircuit` as success. Before minting the experimental asset, decide whether the descriptor reserves future receipt-policy fields; changing a committed descriptor later changes asset identity. Rule discovery and derivation inputs must also be available to legitimate wallets. Unconditional re-derivation makes the `(domain separator, minting address, descriptor)` preimage a prerequisite for spending any contract-minted shielded coin, guarded or not. For this experiment that is contained: fees are paid through DUST actions on the intent, so the regulated offer carries no fee coin and the builder needs only the regulated token’s preimage. Record the general case as a production-migration finding in Stage 6.

### Authenticate one decision for both sides

The following describes required semantics, not an existing function signature:

```text
authorizeTransfer(
    authenticated native input owners,
    actual regulated input and output bindings,
    private membership witnesses,
    current policy state
) -> success or failure
```

For the first shape, this is one gate decision covering Alice and Bob. Alice’s key must derive from the same native ownership witness that authorizes the consumed coin. Bob’s checked key must open the exact output commitment that will enter the ledger.

Design a canonical, domain-separated movement commitment or equivalent proof linkage. It must bind the relevant inputs/nullifiers, output commitments, policy address and entry point, segment and network context. Specify ordering, multiplicity, value/type linkage and freshness semantics. Exclude proof bytes or other circular dependencies; do not casually use a final transaction hash that itself contains the proof.

The spend proof, output proof or authenticated output effect, and gate proof must agree on this movement. The ledger must establish complete matching in both directions. A free-form caller argument, witness-only `ownPublicKey()`, arbitrary output digest, or unrelated successful contract call is insufficient.

Additional output-circuit or native output-format changes may be necessary. That does not require two separate application-level CSL calls: one policy invocation can still validate both parties. For multiple inputs/outputs, define explicit coverage rather than assuming a one-to-one mapping between coins and payments.

**Open (Stage 1): recipient coverage shape.** Two shapes are viable and the design decision must choose one. Under *marked outputs*, the output circuit re-derives the type and exposes a public binding field for guarded descriptors, and the gate claims exactly the marked inputs and outputs; this reveals at creation that an output is regulated. Under *segment-wide coverage*, one gate call claims every output commitment in the segment and checks, per coin, that a regulated type implies an approved recipient; no output is marked, but the gate witnesses every output, any later merge invalidates the authorization, and minting must be gated through the public mint effect so that a regulated output cannot appear in a segment with no regulated input. In either shape, a zero-value output of a guarded type is Pedersen-neutral and needs no mint; the coverage register must state how zero-value outputs are treated.

### Specify application and privacy semantics

The gate and protected movement must share an execution outcome. Define how guaranteed and fallible sections interact; reject combinations where policy fails but the regulated spend survives. Authorizations cannot be copied across segments or reused for uncovered inputs.

Treat the current state immediately preceding execution in canonical transaction order as the whitelist authority. Test both orders when approval updates and transfers occur in one block, and reject or explicitly define an attempt to alter the policy within the same transaction.

Public transfers should carry only the proof and commitments/effects required by the chosen design, without participant keys, DIDs, membership indices or stable enrollment handles. Review public inputs, serialized transactions, effects, events, logs and prover boundaries.

A contract gate can reveal which policy contract authorized a public nullifier and narrow the asset family. That is a material privacy finding, even if Alice and Bob remain hidden. If the requirement becomes hiding policy association as well, the contract experiment is not a complete privacy solution; assess the pure-proof route or a different routing design. Do not claim that successful ZK verification means the entire transaction reveals nothing.

## Implementation stages and exit criteria

### Stage 0 Establish a reproducible baseline

Read repository instructions and the sources below. Preserve the pinned checkout and create an isolated experiment branch. The ledger base is the pinned ledger 10 branch. Before substantial Stage 5 work, confirm the node strategy: a `ledger_10` host module in the pinned node (default) or an experimental host adapter.

Provision the pinned Nix/Rust/proving environment. Run derivation tests, the existing real spend-proof baseline and one ordinary transfer through strict ledger verification. Record exact revisions, enabled features and artifact hashes.

Then perform the pipeline switch: route the unchanged hand-written zk-stdlib spend relation through the production prover and verifier, embed its verifier key, bump the static version, and show that a proof from it passes `Transaction<Proof>` verification under `WellFormedStrictness` defaults while a proof under the old key is rejected. Every later CSL constraint builds on this baseline.

**Exit:** a reproducible baseline with real proofs, an approved-transfer control, a corrupt-proof rejection control, a completed pipeline switch with old-key rejection, and a written node compatibility decision.

### Stage 1 Specify the native authorization boundary

Inventory all paths that consume or create this asset. Write a short design decision covering the selected gate mode, token encoding and in-circuit descriptor encoding, sender authentication, recipient coverage shape (marked outputs or segment-wide coverage), whitelist structure and read pattern, current-state rules, proof linkage, segment atomicity and public disclosures.

Prototype the smallest missing proof/call linkage. Establish which circuit source actually feeds production artifacts. Define the first supported shape as one regulated input and one regulated output of equal value, with no regulated change or transient leg. Pay fees through DUST, the ordinary fee mechanism at this ledger version, so the regulated offer contains no fee coin. Enforce these limits without trusting client labels: fee plumbing must not conceal additional regulated inputs or outputs. Budget for wire-format changes: a public binding field on `Input` (and on `Output` under the marked-outputs shape), a new `Effects` field with its storable tag bump, VM encode and decode paths, and a cost-model entry.

**Exit:** an implementable proof relation and ledger matching rule. Every other shape is either covered by that rule or explicitly rejected at consensus validation. If linkage cannot be made sound with the chosen route, report the precise blocker and evaluate the alternate route; do not downgrade to application enforcement.

### Stage 2 Implement native enforcement and the simple gate

Complete token derivation checks inside the production relation. Implement authenticated sender and output binding, the gate’s membership checks and the ledger’s mandatory matching. Version serialized fields, circuit artifacts and resolver paths together.

Add issuer-controlled set updates and removal. Include an approved recipient who can receive asynchronously using public receiving information plus private membership evidence, without surrendering keys.

**Exit:** approved → approved succeeds with real proofs; unapproved sender → approved recipient and approved sender → unapproved recipient cannot produce an accepted regulated transfer. Omitting the gate, substituting a participant or changing the output is rejected.

### Stage 3 Demonstrate the exact revoked Alice scenario

Run the lifecycle fixture through strict `Transaction<Proof>` verification with `WellFormedStrictness` defaults and state application. Submit through a raw builder that bypasses application policy checks. Attempt an old-root proof, omitted call, wrong call, old spend-proof path and substituted recipient.

A negative circuit test may fail during proof creation. Supplement it with deliberately malformed or mismatched serialized transactions and otherwise-valid proofs/effects that the real verifier rejects. Verify the intended rejection reason; an unrelated fee, expiry or balance error is not evidence of CSL enforcement.

**Exit:** a deterministic replay script and results showing the required rejection, an approved positive control, and no unauthorized regulated state transition.

### Stage 4 Expand and audit movement coverage

Add support incrementally, starting with one regulated input, one regulated output and one regulated change output to the sender, since change is the first thing a real wallet needs and the sender is already an approved recipient. Then add splits, merges, multiple inputs, multiple owners, batches, contract owners, contract recipients, transient coins and composable offers. Re-run the native bypass cases for each shape.

For merged/partial offers, decide whether authorization binds before or after composition and whether re-proving is required. A changed output set must never inherit an authorization for the original set. Maintain an explicit coverage register of supported, rejected and unresolved shapes, including zero-value outputs of the guarded type.

Audit mint, burn, redemption, wrapping and conversion routes that exist in the selected baseline. Initial issuance must not create an accidental unapproved-recipient route. Burn or redemption cannot become an unguarded spend escape. Deferred routes remain rejected for the regulated asset.

**Exit:** each identified path has a real positive/negative test or an explicit ledger-level prohibition. Only claim universal enforcement across the inventoried protocol surface; keep future protocol extensions within this requirement.

### Stage 5 Integrate the experimental node

Use a fresh local chain/genesis and an isolated chain identity. Wire the selected ledger version, verifier artifacts, host interface, serialization and runtime dispatch. Update only the client/indexer/prover components needed to submit and inspect the experiment. Before RPC and genesis work, reach an intermediate milestone: import a block containing the negative fixture through the node’s ledger host API in a node unit test.

Run the exact positive and negative scenarios through RPC. Then exercise block import/validation with an invalid transaction embedded in a proposed block, bypassing normal mempool admission. Reject old-version proof routes at the active experimental protocol boundary, while preserving any explicitly supported historical validation semantics.

**Exit:** validator execution enforces the same result as the ledger harness. Mempool rejection alone does not satisfy this stage.

### Stage 6 Record findings and define the CSL interface

Measure proving time, verification time, transaction/proof sizes, memory and gate/state-read costs against a comparable unguarded transfer. Include first-shape and expanded-shape results and the hardware/configuration used.

Produce the proposed CSL contract/proof interface from the implementation: authenticated inputs, private witnesses, public inputs/effects, authorization coverage, freshness, versioning and failure behavior. Explain which parts are general primitives and which are POC restrictions. Record two standing findings: an authorized upgrade of the gate contract changes the rule without changing the token type, so holders trust the gate’s governance as well as its code; and unconditional re-derivation requires every wallet to resolve the token-type preimage for any contract-minted shielded coin.

**Exit:** reproducible evidence, a concrete CSL interface proposal, known limitations, and a decision on whether the mechanism is ready for a DID/VC-backed eligibility predicate. Successful whitelist enforcement alone does not establish production readiness.

## Required acceptance and adversarial tests

Use synthetic keys, coins and approval data. Each negative test should start from a known-valid transaction where possible, alter one condition, and assert the CSL-specific failure plus regulated-state invariants.

| ID | Test | Expected result |
| --- | --- | --- |
| T01 | Approved Alice → approved Bob | Accepted; correct output and value conservation |
| T02 | Fund approved Alice, remove her, send to approved exchange Bob | Rejected despite retained spending/viewing keys |
| T03 | Never-approved holder fixture → approved Bob | Rejected |
| T04 | Approved Alice → unapproved Carol | Rejected |
| T05 | Both parties unapproved | Rejected |
| T06 | Direct raw spend with no policy call/evidence | Rejected by real ledger verification |
| T07 | Claim an approved key as sender while spending Alice’s coin | Rejected by ownership binding |
| T08 | Gate checks Bob; actual output pays Carol | Rejected by output binding |
| T09 | Add an unapproved change, second or hidden/transient recipient | Rejected, or explicitly unsupported at the current stage |
| T10 | Replace descriptor with Empty, another gate, or another entry point | Rejected for the original regulated token type |
| T11 | Submit an unimplemented/malformed descriptor or noncanonical encoding | Rejected; no default-success branch |
| T12 | Prove membership under the pre-removal root | Rejected after removal executes |
| T13 | Prove membership under an attacker-created set/root | Rejected |
| T14 | Replay gate evidence for another coin, output set, network or segment | Rejected |
| T15 | Duplicate, omit or overclaim coverage in a multi-input authorization | Rejected |
| T16 | Put gate in a failing section and spend in a successful section | No protected regulated movement commits |
| T17 | Use the wrong contract, a lookalike event, or an unrelated valid call | Rejected |
| T18 | Merge/retarget an offer after policy authorization | Rejected unless the final movement is fully reauthorized |
| T19 | Spend or receive through a contract owner, escrow or DEX | Same policy enforced, or ledger rejects unsupported shape |
| T20 | Use transient coins or alternate guaranteed/fallible paths | Same policy enforced, or ledger rejects unsupported shape |
| T21 | Spend a newly guarded coin using an old relation/proving key | Rejected under the active experimental protocol |
| T22 | Corrupt a proof or its public inputs | Rejected in every final harness and node build |
| T23 | Reuse a nullifier or create an imbalanced transfer | Rejected; existing security properties retained |
| T24 | Unauthorized whitelist update; invalid administrator authorization | Rejected |
| T25 | Removal before transfer versus transfer before removal in a block | Deterministic results according to canonical execution order |
| T26 | Legacy Empty asset and ordinary fee path | Supported legacy behavior preserved under the chosen fork design |
| T27 | Try mint, burn, redemption, conversion or wrapping escape routes | Correct policy or explicit native prohibition |
| T28 | Read public inputs, events, effects and logs across repeated transfers | No new stable participant identifier or witness leakage; policy metadata documented |
| T29 | Submit an invalid transaction inside a proposed block | Block validation rejects it even without mempool checks |
| T30 | Restart/replay the experimental chain | Same policy state and transfer validity; no runtime/version fallback |
| T31 | Policy contract missing or undeployed at the descriptor’s address | Rejected; the asset is frozen rather than spendable unguarded |
| T32 | Zero-value output of the guarded type to an unapproved party | Rejected, or explicitly permitted and documented as worthless and unspendable |

For rejected movement, assert no new regulated output and no consumed regulated input/nullifier. Account separately for fees or unrelated sections according to the selected transaction semantics; do not silently equate all transaction-level side effects with the protected transfer.

Add focused property/fuzz tests around canonical descriptor encoding, output coverage, duplicate evidence and segment matching. Unit tests and mocked execution can speed development, but final claims require real proofs, strict validation and the corresponding node tests.

## Code map for the coding agent

All ledger links below are pinned to the inspected CSL commit.

| Area | Files and entry points | Why they matter |
| --- | --- | --- |
| Rule identity | [custom_spend.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/coin-structure/src/custom_spend.rs), [contract.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/coin-structure/src/contract.rs), [fab.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/coin-structure/src/fab.rs) | Descriptor encoding, token derivation and aligned representations |
| Mint effects | [onchain-runtime/src/context.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/onchain-runtime/src/context.rs) | ShieldedMintKey, effect serialization and rule discovery data |
| Spend relation | [zkir/src/zswap_spend.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/zkir/src/zswap_spend.rs), [equivalence tests](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/zkir/tests/zswap_spend.rs) | Existing relation and real-proof baseline, not CSL enforcement |
| Production circuit artifacts | [zkir-precompiles/zswap](https://github.com/midnightntwrk/midnight-ledger/tree/fa995fa5791bc19112e97334a2d9265751c35fad/zkir-precompiles/zswap), [zswap/static](https://github.com/midnightntwrk/midnight-ledger/tree/fa995fa5791bc19112e97334a2d9265751c35fad/zswap/static), [zswap.compact](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/zswap/zswap.compact) | Establish the authoritative generation path; synchronize changed relations and shipped keys |
| Native data and construction | [structure.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/zswap/src/structure.rs), [construct.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/zswap/src/construct.rs) | Input/output/transient formats, witnesses and binding values |
| Proving and verification | [prove.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/zswap/src/prove.rs), [verify.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/zswap/src/verify.rs) | ZswapResolver, static versions, KeyLocation and actual proof verification |
| Transaction checks | [ledger/src/verify.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/ledger/src/verify.rs) | Transaction well_formed, effects_check, sequencing and balancing |
| State application | [ledger/src/semantics.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/ledger/src/semantics.rs), [zswap/src/ledger.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/zswap/src/ledger.rs) | apply_section, guaranteed/fallible outcomes, commitment/nullifier state |
| Integration tests | [ledger/tests](https://github.com/midnightntwrk/midnight-ledger/tree/fa995fa5791bc19112e97334a2d9265751c35fad/ledger/tests), [test_utilities.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/ledger/src/test_utilities.rs) | Start with intent, malicious_imbalance and verify-proof patterns; ensure strict final validation |
| Build and artifacts | [README](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/README.md), [flake.nix](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/flake.nix), [static](https://github.com/midnightntwrk/midnight-ledger/tree/fa995fa5791bc19112e97334a2d9265751c35fad/static) | Pinned environment, the `public-params` and `local-params` derivations, artifact hashes, and the `midnight-ledger-static` version crate |
| Node integration | [node Cargo.toml](https://github.com/midnightntwrk/midnight-node/blob/ad8f2802c16594fb3c0a54c5976cab98bdeaab20/Cargo.toml), [node ledger/src/lib.rs](https://github.com/midnightntwrk/midnight-node/blob/ad8f2802c16594fb3c0a54c5976cab98bdeaab20/ledger/src/lib.rs) | Versioned dependencies, host modules and active ledger dispatch |
| Proof versions | [ledger/src/structure.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/ledger/src/structure.rs) | `ProofVersioned` dispatch; where old proof routes are closed |
| Recursion primitives | [zkir-v3/src/ir_instructions/verify_proof.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/zkir-v3/src/ir_instructions/verify_proof.rs) | Available primitive for the recursive-gate comparison; not a dependency |

Do not validate the security claim by calling generic ZSwap state application alone: that layer accepts generic proof types and is not the complete transaction verifier. Enter through the real transaction verification path and then apply the verified result.

## Build and verification starting points

The following commands are grounded in the inspected repository and are starting points for the coding agent. No CSL implementation or build has been completed as part of this plan. Provisioning the toolchain is Stage 0; do not assume Nix, Cargo or Rust are present.

For a fresh checkout:

```bash
git clone --branch alexshielded/custom-spend-logic --single-branch \
  https://github.com/midnightntwrk/midnight-ledger.git midnight-ledger-csl
cd midnight-ledger-csl
git switch -c experiment/regulated-zswap-csl \
  fa995fa5791bc19112e97334a2d9265751c35fad
nix develop
```

For the existing clean checkout, create the experiment branch at the same pinned commit instead of recloning. Inspect local changes first and preserve unrelated work.

Baseline checks inside the configured development environment:

```bash
cargo test -p midnight-coin-structure custom_spend
cargo test --release -p midnight-zkir --test zswap_spend
```

The broader ledger proving suite is:

```bash
cargo test --release -p midnight-ledger-v10 --features proving
```

During implementation, add and run focused CSL integration targets before the broader suite. Recheck package names if the compatibility decision changes the ledger base.

The flake supplies the proving parameters and environment, including `MIDNIGHT_PP`, `MIDNIGHT_LEDGER_TEST_STATIC_DIR` in relevant test/dev configurations, and experimental flags. Its `public-params` derivation fetches the public parameters by k from an S3 bucket. Its `local-params` derivation copies the checked-in ZKIR from `zkir-precompiles/zswap`, compiles it with `zkir compile-many`, hashes the artifacts and installs versioned files; the Compact compiler is commented out, so `.compact` sources are not compiled in this pipeline. Follow that actual generation pipeline, or the zk-stdlib relation path chosen above; document how the new verifier key reaches the ledger binary.

Keep `proof-verifying` enabled and `mock-verify` disabled. Do not use `--all-features` indiscriminately: it can enable mock verification. Default Rust test runs do not necessarily perform proving; preserve the explicit real-proof checks. Require a deliberately corrupted proof to fail so feature mistakes cannot masquerade as successful enforcement. Note that `ledger/tests` compile with the `test-utilities` feature, which the manifest says disables some well-formedness checking; run final acceptance with `WellFormedStrictness` defaults and record what the feature relaxes.

Changing the relation requires coordinated prover/verifier/IR artifacts, hashes, static versioning and key-resolution updates. Preserve the old equivalence baseline as historical evidence; do not require a changed CSL relation to retain the old verifier key. Close all active old-proof acceptance routes, rather than giving the submitter a verifier-version choice. Those routes are the `ProofVersioned` dispatch in `ledger/src/structure.rs` and the legacy verification in `zswap/src/verify.rs`.

## Reference material and later identity integration

### Primary design material

1. [CSL proposal PR 335](https://github.com/midnightntwrk/midnight-improvement-proposals/pull/335) and the [pinned draft](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/41d3b15302b0a69cff62cafc19767c4c1be478fb/mips/mip-xxxx-custom-spend-logic.md). Read binding without lookup, the authorization modes, what a gate is handed, discovery, current-state roots and receipt guards. The draft is a design input, not a completed specification.
2. [MPS 0013 ZSwap business logic](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/41d3b15302b0a69cff62cafc19767c4c1be478fb/mps/mps-0013-zswap-business-logic.md). Broader programmable-asset and counterparty-eligibility requirements.
3. Related requirements linked from the CSL draft: [MPS 0014 proof recursion](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/main/mps/mps-0014-proof-verification-recursion.md), [MPS 0024 custodian-safe spends](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/main/mps/mps-0024-custodian-safe-shielded-spends.md), [MPS 0025 shielded source of funds](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/main/mps/mps-0025-shielded-source-of-funds.md), [MPS 0029 caller identity](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/main/mps/mps-0029-compact-caller-identity.md) and [MPS 0021 contract-to-contract calls](https://github.com/midnightntwrk/midnight-improvement-proposals/blob/main/mps/mps-0021-phase2-contract-to-contract.md). These links track main; pin the versions used in implementation.
4. [Midnight ledger repository](https://github.com/midnightntwrk/midnight-ledger) and [Midnight node repository](https://github.com/midnightntwrk/midnight-node). Use the specific inspected revisions above as reproducible baselines, then record any deliberate updates.

### Existing identity work to reuse later

| Resource | Later use | Boundary for this experiment |
| --- | --- | --- |
| [midnight-vc-passport](https://github.com/midnightntwrk/midnight-vc-passport/tree/c9dcdce679d60ca9f47ffd9605d56af4e8afd94f) | Reference credential family, private committed claims, selective disclosure, explicit holder binding and predicate circuits | A passport/age credential is not the required bank approval policy; do not make it a prerequisite. |
| [midnight-verifiable-credentials](https://github.com/midnightntwrk/midnight-verifiable-credentials/tree/245e3a04860930b7289ff114237fc222dedd247e) | Generic VC/VP building blocks and bounded did:midnight binding extension | Does not supply issuer trust, current status authority or native ZSwap enforcement by itself. |
| [midnight-did](https://github.com/midnightntwrk/midnight-did/tree/4e7f6b0f69bf4e2c8506a9693f8d0c3dfe68e550) | DID contract, domain model, mapping and orchestration | DID integration must still bind the credential subject/controller to the actual native owner. |

For that later phase, use [W3C DID Core](https://www.w3.org/TR/did-core/) and [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) as standards references. Check actual package/toolchain compatibility and conformance at integration time. This whitelist experiment neither establishes nor requires W3C credential interoperability.

The future substitution should be localized: replace the approval-set predicate with the agreed bank identity/credential predicate while preserving the already-tested native ownership, output, freshness and anti-bypass bindings. Reassess token-type identity if adopting that predicate changes a descriptor or fixed verifying key.

## Deliverables and completion decision

The coding agent should leave:

- An isolated ledger experiment branch and the matching node changes or pinned compatible node baseline.
- A concise design decision specifying the proof relation, gate API, encoding, state freshness, ownership/output binding and public disclosures.
- The simple whitelist contract or selected proof gate, issuer-update mechanism and synthetic fixture data.
- Versioned circuit artifacts and a reproducible generation/build procedure.
- A direct transaction builder and automated scenario runner for the decisive Alice → Bob case and positive control.
- A coverage register linking every supported or prohibited movement shape to a test.
- Stage 0 pipeline-switch evidence: the new verifier key embedded and a proof under the old key rejected.
- Real-proof test results, node/block-validation evidence and before/after regulated-state assertions.
- Performance measurements, privacy findings and a clear list of missing primitives or unresolved semantics.
- A final CSL interface proposal, with the smallest next step toward identity-backed approval.

Report outcomes separately:

**Native enforcement demonstrated:** the first supported shape passes its positive, negative and bypass tests with real proofs and strict ledger validation.

**Node enforcement demonstrated:** the same behavior survives RPC submission, active-version dispatch and block validation.

**Movement coverage demonstrated:** every inventoried path either enforces the rule or is explicitly rejected. Rejected shapes remain functionality gaps even when they preserve safety.

**Privacy demonstrated within a stated boundary:** participant data is absent from public transfer artifacts, and all remaining metadata disclosures are documented.

**General programmable CSL demonstrated:** the implementation authenticates and enforces a designated policy circuit or contract, rather than only hard-coding a whitelist into a special native spend.

The first action for the coding agent is Stage 0, followed by the Stage 1 binding design. The central question throughout is: **Can Alice produce any transaction accepted by the active ledger that moves this regulated token while her actual spending owner is absent from the current approval set?** The experiment succeeds only when the supported protocol paths make the answer no, while approved transfers still work.

