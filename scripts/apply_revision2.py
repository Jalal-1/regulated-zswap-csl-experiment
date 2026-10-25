import sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()

R = []
def rep(old, new):
    R.append((old, new))

rep("**Implementation plan and coding agent handoff — 25 October 2026**",
"""**Implementation plan and coding agent handoff — 25 October 2026, revision 2**

*Revision 2 incorporates a source-verification review of the pinned ledger, node and proposal revisions. Decisions taken after that review are marked **Decision**; items left to the coding agent are marked **Open**.*""")

rep("The first rule is deliberately simple: the actual sender and every actual recipient must be on Monument’s current whitelist. One CSL invocation may check both sides.",
"The first rule is deliberately simple: the actual sender and every actual recipient must be on the current whitelist maintained by Monument, the issuer and approval administrator of the experimental asset. One Custom Spend Logic (CSL) invocation may check both sides.")

rep("This is a protocol experiment. Its result must be evidence from real proofs and ledger validation. The existing CSL work is a starting point; feasibility and end-to-end enforcement remain to be demonstrated.",
"""This is a protocol experiment. Its result must be evidence from real proofs and ledger validation. The existing CSL work is a starting point; feasibility and end-to-end enforcement remain to be demonstrated.

**Standing decisions from the revision 2 review**

| Topic | Status |
| --- | --- |
| Design inputs | **Decision:** the binding and gate design is derived from first principles against the pinned sources. The CSL draft and the MPS documents listed under Reference material are the only external design inputs; no other proposal is a dependency. |
| Ledger base | **Decision:** the pinned ledger 10 branch is the base. Its recursion instructions are an available primitive, not a dependency. |
| Production circuit pipeline | **Decision (recommended; confirm or override):** promote the hand-written zk-stdlib spend relation to the production path in Stage 0. See Starting implementation and known gaps. |
| Recipient coverage shape | **Open:** marked outputs or segment-wide coverage, decided in Stage 1 with the privacy delta recorded. |
| Whitelist structure and freshness | **Open:** decided in Stage 1. The known traps are listed under Keep the whitelist simple. |
| Node integration | **Decision:** resolved in Stage 5 with an intermediate host-API milestone. It does not gate Stages 1 to 4. |""")

rep("Also keep a synthetic never-approved-holder fixture for adversarial tests, clearly separated from normal issuance.",
"Also keep a synthetic never-approved-holder fixture for adversarial tests, clearly separated from normal issuance. If issuance is gated, that fixture can only be created by direct state insertion in the ledger harness or by genesis in the node; it is a sanity check that is strictly easier than the revoked-Alice case.")

rep("Here, “EOA” means a user-controlled shielded ZSwap wallet, not an Ethereum account model. The ledger checks",
"Alice’s wallet is a user-controlled shielded ZSwap wallet, not an Ethereum-style account. The ledger checks")

rep("Preserve a clean extension point for future identity predicates. The existing DID and VC projects are later integration resources, not prerequisites for this experiment.",
"Preserve a clean extension point for future identity predicates. The existing DID and VC projects are later integration resources, not prerequisites for this experiment. Preserve a second extension point for a future k-of-n ECDSA authorization predicate inside the gate: the gate interface must be able to accept additional authorization witnesses over the same movement binding, and in-circuit ECDSA will need its own primitive and cost model. Such a gate makes the spending key insufficient but still necessary; it does not remove the key from the prover.")

rep("The local checkout is `/workspace/scratch/89085fb2343e/midnight-ledger-csl`; the portable source of truth is the pinned Git commit.",
"The portable source of truth is the pinned Git commit; verify any local checkout against it before use.")

rep("| Existing contract-call and native-effect matching | Authenticated, complete matching of native spends, outputs and policy calls |",
"""| Effects matching for contract-owned coins only: `claimed_nullifiers`, `claimed_shielded_receives` and `claimed_shielded_spends` in `ledger/src/verify.rs` match inputs and outputs whose `contract_address` is set | A claim channel for user-owned regulated inputs and outputs: new public binding fields, a new effects field and complete two-way matching |
| Checked-in ZKIR in `zkir-precompiles/zswap` compiled to keys by `zkir compile-many`; no Compact compiler in the flake; hand-written zk-stdlib relation used only in tests | A production proving and verification path for a changed relation (decision below) |
| Ledger 10 recursion instructions (`verify_proof`, `inner_proof`), `ProofVersioned::V4` and the `proof[v6]` format | Nothing required for the contract route; usable for a privacy comparison of the recursive gate |""")

rep("The current handwritten spend relation is designed to reproduce the shipped verifier key. It is not already a CSL-enforcing circuit. Editing that relation alone will not necessarily alter the production proving path.",
"""The current handwritten spend relation is designed to reproduce the shipped verifier key. It is not already a CSL-enforcing circuit. Editing that relation alone will not necessarily alter the production proving path.

**Decision (recommended):** the experiment promotes that zk-stdlib relation to the production spend path. At the pinned commit, production keys are compiled from the checked-in ZKIR in `zkir-precompiles/zswap`; the Compact compiler is commented out of `flake.nix`, so `zswap/zswap.compact` documents the v1 circuits and is not a build input; native proofs are verified through the legacy pipeline against verifier keys built into the ledger. The agent therefore first routes the unchanged relation through the production prover and verifier, embeds its verifier key, bumps the static version and proves the switch works (Stage 0), then adds CSL constraints to that relation (Stage 2). New native proofs use the ledger 10 proof format and version. Fallbacks, only if the switch fails: hand-written ZKIR, or ZKIR regenerated by a Compact compiler pinned to the IR version that `midnight-zkir` 2.2.0 expects.""")

rep("- The implementation hashes a tagged rule descriptor before including that hash in token-type derivation. The draft MIP describes descriptor concatenation more abstractly. Specify one exact byte encoding and test it across all implementations.",
"- The implementation hashes a tagged rule descriptor with `persistent_hash` and then commits `(domain_sep, address, descriptor_hash)` under the `midnight:derive_token` separator. The draft MIP describes descriptor concatenation more abstractly. Reproducing tagged serialization in-circuit is awkward, so choose a fixed-width in-circuit encoding, make the Rust `descriptor_hash` match it before the first mint, and test the single byte encoding across all implementations.")

rep("- The `whitelist` parameter in `zswap/src/ledger.rs` filters contract-state tracking. It is not the participant eligibility list.",
"""- The `whitelist` parameter in `zswap/src/ledger.rs` filters contract-state tracking. It is not the participant eligibility list.
- The `static/` directory is the `midnight-ledger-static` version crate that `zswap/src/prove.rs` uses for key paths, not the public parameters. Public parameters come from the flake’s `public-params` derivation, which fetches k-indexed files from an S3 bucket; Stage 0 needs network access to that host or a pre-staged `MIDNIGHT_PP`.
- `ledger/Cargo.toml` warns that the `test-utilities` feature disables a small amount of well-formedness checking, and `ledger/tests` compile with it. Final acceptance runs must use `WellFormedStrictness` defaults, and the agent must record what the feature relaxes.
- Old proof acceptance lives in the `ProofVersioned` dispatch in `ledger/src/structure.rs` and the legacy verification in `zswap/src/verify.rs`; `ledger/src/prior_versions.rs` is a stub.""")

rep("The inspected node revision `ad8f2802c16594fb3c0a54c5976cab98bdeaab20` exposes ledger 8 and ledger 9 host modules, with ledger 9 as latest. The CSL checkout uses `midnight-ledger-v10`. Node integration therefore needs an explicit compatibility decision, not merely a changed dependency URL.",
"The inspected node revision `ad8f2802c16594fb3c0a54c5976cab98bdeaab20` exposes ledger 8 and ledger 9 host modules, with ledger 9 as latest. The CSL checkout uses `midnight-ledger-v10`. Node integration therefore needs an explicit compatibility decision, not merely a changed dependency URL. That revision is also the current `main` head, so no node revision consumes ledger 10. The node pins ledger crates by git tag and depends on a v8-to-v9 state translation crate, so a ledger 10 host module implies a `ledger_10` module, a v9-to-v10 state translation and dispatch for the new proof format. **Decision:** the experiment builds on ledger 10 and resolves node compatibility in Stage 5.")

rep("| Recursive proof gate | Could verify a policy inside the spend proof without exposing the chosen gate | Recursive verification with a privately witnessed verifying key, a consensus-authenticated current whitelist state input, output binding and cost |",
"| Recursive proof gate | Could verify a policy inside the spend proof without exposing the chosen gate; fixed-key recursion (`verify_proof`, `inner_proof`) exists on the pinned branch | A consensus-authenticated current whitelist state input, without which revocation cannot be enforced; a privately witnessed verifying key; output binding and cost |")

rep("Choose one primary route after a small feasibility spike. Do not replace live whitelist checks with an unanchored root supplied by Alice.",
"The decisive scenario is removal. Only a gate that reads current chain state at execution can reject a revoked holder, so the contract route is primary; the feasibility spike confirms it rather than selects it. The recursion primitive may serve a privacy comparison but cannot pass T02 or T12 until a current-state root is available to the spend proof. Do not replace live whitelist checks with an unanchored root supplied by Alice.")

rep("Record that limitation. A capsule or runtime identity does not substitute for native coin-owner authentication.",
"Record that limitation. The experiment’s whitelist is public contract state, so the capsule runtime’s issuer-private-state motivation does not apply here. A capsule or runtime identity does not substitute for native coin-owner authentication.")

rep("For a tiny fixture, a bounded collection checked in-circuit is adequate; use a Merkle root only when required by the available primitives or cost. This is a data structure, not a DID or KYC registry.",
"For a tiny fixture, a bounded collection checked in-circuit is adequate; use a Merkle root only when required by the available primitives or cost. **Open (Stage 1):** if a bounded collection is used, read every entry unconditionally, because a selective read records the matching cell in the public transcript and leaks the index; confirm the read pattern as part of the V9 review. This is a data structure, not a DID or KYC registry.")

rep("A historical coin commitment-tree root may remain valid under normal ZSwap rules; an old eligibility root must not silently inherit that acceptance window.",
"A historical coin commitment-tree root may remain valid under normal ZSwap rules; an old eligibility root must not silently inherit that acceptance window. In Compact terms, `HistoricMerkleTree.checkRoot` is that window and is what `zswap.compact` uses for the coin tree; the whitelist must use the non-historic `MerkleTree` or an equivalent current-state read. **Open (Stage 1):** verify this when the gate is written.")

rep("Rule discovery and derivation inputs must also be available to legitimate wallets, including any newly required inputs for legacy spends.",
"Rule discovery and derivation inputs must also be available to legitimate wallets. Unconditional re-derivation makes the `(domain separator, minting address, descriptor)` preimage a prerequisite for spending any contract-minted shielded coin, guarded or not. For this experiment that is contained: fees are paid through DUST actions on the intent, so the regulated offer carries no fee coin and the builder needs only the regulated token’s preimage. Record the general case as a production-migration finding in Stage 6.")

rep("Additional output-circuit or native output-format changes may be necessary. That does not require two separate application-level CSL calls: one policy invocation can still validate both parties. For multiple inputs/outputs, define explicit coverage rather than assuming a one-to-one mapping between coins and payments.",
"""Additional output-circuit or native output-format changes may be necessary. That does not require two separate application-level CSL calls: one policy invocation can still validate both parties. For multiple inputs/outputs, define explicit coverage rather than assuming a one-to-one mapping between coins and payments.

**Open (Stage 1): recipient coverage shape.** Two shapes are viable and the design decision must choose one. Under *marked outputs*, the output circuit re-derives the type and exposes a public binding field for guarded descriptors, and the gate claims exactly the marked inputs and outputs; this reveals at creation that an output is regulated. Under *segment-wide coverage*, one gate call claims every output commitment in the segment and checks, per coin, that a regulated type implies an approved recipient; no output is marked, but the gate witnesses every output, any later merge invalidates the authorization, and minting must be gated through the public mint effect so that a regulated output cannot appear in a segment with no regulated input. In either shape, a zero-value output of a guarded type is Pedersen-neutral and needs no mint; the coverage register must state how zero-value outputs are treated.""")

rep("Confirm the ledger/node compatibility strategy before substantial integration work: use a compatible node branch, add an experimental host adapter, or port the bounded CSL changes to an agreed ledger base.",
"The ledger base is the pinned ledger 10 branch. Before substantial Stage 5 work, confirm the node strategy: a `ledger_10` host module in the pinned node (default) or an experimental host adapter.")

rep("Provision the pinned Nix/Rust/proving environment. Run derivation tests, the existing real spend-proof baseline and one ordinary transfer through strict ledger verification. Record exact revisions, enabled features and artifact hashes.",
"""Provision the pinned Nix/Rust/proving environment. Run derivation tests, the existing real spend-proof baseline and one ordinary transfer through strict ledger verification. Record exact revisions, enabled features and artifact hashes.

Then perform the pipeline switch: route the unchanged hand-written zk-stdlib spend relation through the production prover and verifier, embed its verifier key, bump the static version, and show that a proof from it passes `Transaction<Proof>` verification under `WellFormedStrictness` defaults while a proof under the old key is rejected. Every later CSL constraint builds on this baseline.""")

rep("**Exit:** a reproducible baseline with real proofs, an approved-transfer control, a corrupt-proof rejection control and a written version compatibility decision.",
"**Exit:** a reproducible baseline with real proofs, an approved-transfer control, a corrupt-proof rejection control, a completed pipeline switch with old-key rejection, and a written node compatibility decision.")

rep("Write a short design decision covering the selected gate mode, token encoding, sender authentication, recipient coverage, current-state rules, proof linkage, segment atomicity and public disclosures.",
"Write a short design decision covering the selected gate mode, token encoding and in-circuit descriptor encoding, sender authentication, recipient coverage shape (marked outputs or segment-wide coverage), whitelist structure and read pattern, current-state rules, proof linkage, segment atomicity and public disclosures.")

rep("Pay fees separately using the ordinary supported fee mechanism. Enforce these limits without trusting client labels: fee plumbing must not conceal additional regulated inputs or outputs.",
"Pay fees through DUST, the ordinary fee mechanism at this ledger version, so the regulated offer contains no fee coin. Enforce these limits without trusting client labels: fee plumbing must not conceal additional regulated inputs or outputs. Budget for wire-format changes: a public binding field on `Input` (and on `Output` under the marked-outputs shape), a new `Effects` field with its storable tag bump, VM encode and decode paths, and a cost-model entry.")

rep("Run the lifecycle fixture through strict `Transaction<Proof>` verification and state application.",
"Run the lifecycle fixture through strict `Transaction<Proof>` verification with `WellFormedStrictness` defaults and state application.")

rep("Add support incrementally for splits, change, merges, multiple inputs, multiple owners, batches, contract owners, contract recipients, transient coins and composable offers. Re-run the native bypass cases for each shape.",
"Add support incrementally, starting with one regulated input, one regulated output and one regulated change output to the sender, since change is the first thing a real wallet needs and the sender is already an approved recipient. Then add splits, merges, multiple inputs, multiple owners, batches, contract owners, contract recipients, transient coins and composable offers. Re-run the native bypass cases for each shape.")

rep("Maintain an explicit coverage register of supported, rejected and unresolved shapes.",
"Maintain an explicit coverage register of supported, rejected and unresolved shapes, including zero-value outputs of the guarded type.")

rep("Update only the client/indexer/prover components needed to submit and inspect the experiment.",
"Update only the client/indexer/prover components needed to submit and inspect the experiment. Before RPC and genesis work, reach an intermediate milestone: import a block containing the negative fixture through the node’s ledger host API in a node unit test.")

rep("Explain which parts are general primitives and which are POC restrictions.",
"Explain which parts are general primitives and which are POC restrictions. Record two standing findings: an authorized upgrade of the gate contract changes the rule without changing the token type, so holders trust the gate’s governance as well as its code; and unconditional re-derivation requires every wallet to resolve the token-type preimage for any contract-minted shielded coin.")

rep("| T30 | Restart/replay the experimental chain | Same policy state and transfer validity; no runtime/version fallback |",
"""| T30 | Restart/replay the experimental chain | Same policy state and transfer validity; no runtime/version fallback |
| T31 | Policy contract missing or undeployed at the descriptor’s address | Rejected; the asset is frozen rather than spendable unguarded |
| T32 | Zero-value output of the guarded type to an unapproved party | Rejected, or explicitly permitted and documented as worthless and unspendable |""")

rep("| Pinned environment, public parameters, local-params generation, artifact hashes and version |",
"| Pinned environment, the `public-params` and `local-params` derivations, artifact hashes, and the `midnight-ledger-static` version crate |")

rep("| Versioned dependencies, host modules and active ledger dispatch |",
"""| Versioned dependencies, host modules and active ledger dispatch |
| Proof versions | [ledger/src/structure.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/ledger/src/structure.rs) | `ProofVersioned` dispatch; where old proof routes are closed |
| Recursion primitives | [zkir-v3/src/ir_instructions/verify_proof.rs](https://github.com/midnightntwrk/midnight-ledger/blob/fa995fa5791bc19112e97334a2d9265751c35fad/zkir-v3/src/ir_instructions/verify_proof.rs) | Available primitive for the recursive-gate comparison; not a dependency |""")

rep("The current workspace has Git but lacks Nix, Cargo and Rust; provisioning is Stage 0.",
"Provisioning the toolchain is Stage 0; do not assume Nix, Cargo or Rust are present.")

rep("Its `local-params` derivation compiles the ZSwap precompiles with `zkir compile-many`, hashes the artifacts and installs versioned files. Follow that actual generation pipeline; document how the regenerated verifier reaches the ledger binary.",
"Its `public-params` derivation fetches the public parameters by k from an S3 bucket. Its `local-params` derivation copies the checked-in ZKIR from `zkir-precompiles/zswap`, compiles it with `zkir compile-many`, hashes the artifacts and installs versioned files; the Compact compiler is commented out, so `.compact` sources are not compiled in this pipeline. Follow that actual generation pipeline, or the zk-stdlib relation path chosen above; document how the new verifier key reaches the ledger binary.")

rep("Require a deliberately corrupted proof to fail so feature mistakes cannot masquerade as successful enforcement.",
"Require a deliberately corrupted proof to fail so feature mistakes cannot masquerade as successful enforcement. Note that `ledger/tests` compile with the `test-utilities` feature, which the manifest says disables some well-formedness checking; run final acceptance with `WellFormedStrictness` defaults and record what the feature relaxes.")

rep("Close all active old-proof acceptance routes, rather than giving the submitter a verifier-version choice.",
"Close all active old-proof acceptance routes, rather than giving the submitter a verifier-version choice. Those routes are the `ProofVersioned` dispatch in `ledger/src/structure.rs` and the legacy verification in `zswap/src/verify.rs`.")

rep("- Real-proof test results, node/block-validation evidence and before/after regulated-state assertions.",
"""- Stage 0 pipeline-switch evidence: the new verifier key embedded and a proof under the old key rejected.
- Real-proof test results, node/block-validation evidence and before/after regulated-state assertions.""")

failed = []
for i, (old, new) in enumerate(R, 1):
    n = text.count(old)
    if n != 1:
        failed.append((i, n, old[:70]))
        continue
    text = text.replace(old, new)
if failed:
    for f in failed: print("FAILED edit", f)
    sys.exit(1)
open(dst, "w", encoding="utf-8").write(text)
print(f"applied {len(R)} edits")
