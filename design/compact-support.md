# Creating a regulated ZSwap token from Compact: what is required

This document answers one question: what has to exist for a developer to write, in Compact, an
**issuer contract that mints a regulated ZSwap token**, and, in a second step, the **gate contract**
that enforces the rule, with wallets and dapps able to spend the token. It is written against the
state of the `ledger-experiment` branch (commit pinned in `MANIFEST.json`) and the Compact toolchain
as it exists today. Everything marked *exists* is in that branch and tested unless stated otherwise;
everything marked *required* does not exist anywhere yet. Signatures given for new Compact builtins
are proposals, not decisions.

## 1. What a regulated token is, on this branch (exists)

A shielded token type is derived by the minting contract's address, a 32-byte domain separator and
a **spend rule** (`coin_structure::custom_spend::SpendRule`):

```text
Empty                              ordinary token; legacy derivation, unchanged bytes
GateCircuit(vk_hash)               reserved by the upstream base; not used here
GateContract(gate_address, ep_hash) regulated token: spends need an authorizing call to
                                    entry point ep_hash of gate_address in the same segment
```

```text
descriptor_hash = persistent_hash( tagged_serialize(rule) )          -- tag "spend-rule[v1]"
type            = SHA256( pad32("midnight:derive_token") || domain_sep || mint_address || descriptor_hash )
Empty           = SHA256( pad32("midnight:derive_token") || domain_sep || mint_address )   -- legacy
```

(`coin-structure/src/custom_spend.rs`, `ContractAddress::custom_shielded_token_type`.) For the
whitelist gate, `ep_hash` is the entry-point hash of `authorize`.

## 2. Minting: the ledger side (exists, one gap)

A contract mints by inserting into effects map 4 (`shielded_mints`). On this branch the key is a
`ShieldedMintKey(domain_sep, rule)` and the ledger derives the minted type from the key and the
calling contract's address (`ledger/src/verify.rs`, the `shielded_mints` loop in the balance check):

```text
type = call.address.custom_shielded_token_type(key.domain_sep, key.rule)
```

So a contract whose transcript records `ShieldedMintKey(domain_sep, GateContract(gate, ep_hash))`
mints coins of the regulated type. No new ledger rule is needed for that.

**Encoding the compiler must emit.** The key is a five-atom aligned value: the domain separator
followed by the rule's four atoms (`coin-structure/src/fab.rs`):

```text
Empty                 : [0, (), (), ()]
GateCircuit(vk_hash)  : [1, vk_hash, (), ()]
GateContract(addr, ep): [2, (), addr, ep_hash]
```

The program fragment the Compact compiler emits for a mint is vendored at
`onchain-runtime/vendored/program_fragments.rs` (`kernel_mint`). On this branch it already builds
the key as `concat(domain_sep, SpendRule::Empty)`; it hard-codes `Empty`. A regulated mint needs the
same fragment with the `GateContract` atoms in place of the `Empty` ones. Nothing else in the
fragment changes (index 4, member test, add-or-insert).

**Gap, ledger side.** No test on this branch mints through a contract call with a non-`Empty` rule:
the fixture issues regulated coins by harness state injection (`TestState::rewards_shielded`,
README "Harness mechanisms"). Mints of a guarded type are also not themselves gated (plan item T27,
not done): the ledger will accept a regulated mint to any recipient. The first thing to do before any
compiler work is a Rust harness test that mints a `GateContract`-typed coin through a hand-written
program and then spends it through the gate; it costs an afternoon and settles the encoding.

## 3. Minting from Compact: requirements for the issuer contract

What a Compact issuer looks like, functionally: it stores the gate address (constructor argument or
constant), optionally checks the recipient against a whitelist, and mints `value` coins of the
regulated type to `recipient`. Today's Compact cannot express the mint itself:

| Id | Requirement | Where | Why |
| --- | --- | --- | --- |
| C1 | A mint builtin that carries a spend rule. Proposal: `mintToken(domainSep: Bytes<32>, value: Uint<64>, nonce: Bytes<32>, recipient: Either<ZswapCoinPublicKey, ContractAddress>, rule: SpendRule): CoinInfo` with `struct SpendRule { gate: ContractAddress; entryPoint: Bytes<32>; }` and the existing four-argument form meaning `Empty`. | Compact standard library + compiler | Today's `mintToken` emits the `kernel_mint` fragment with the `Empty` atoms; the rule must reach the effects key. |
| C2 | The emitted program fragment writes the five-atom key with `[2, (), gate, ep_hash]`. | Compiler (fragment table) and `compact-runtime` (its JavaScript mirror of the fragments and of `Effects`) | Section 2. |
| C3 | A token-type helper that takes the rule. Proposal: `tokenType(domainSep: Bytes<32>, contract: ContractAddress, rule: SpendRule): Bytes<32>`, computing `descriptor_hash` as the ledger does (SHA-256 of the tagged serialization `midnight:spend-rule[v1]:` + canonical encoding). | Standard library / runtime | The contract needs the type of the coins it mints (to construct `CoinInfo`, to check balances, to compare with the gate's protected type). The tagged serialization is not expressible in Compact source; it belongs in the runtime next to today's `tokenType`. |
| C4 | `Effects` in the runtime and in the wasm API model the key as `(domainSep, rule)`. The JSON form on this branch is the bare hex domain separator for `Empty` and `hex:hexOfTaggedRule` otherwise (`onchain-runtime/src/context.rs`, `shielded_mint_key_to_hex`). | `compact-runtime`, `onchain-runtime-wasm` TypeScript (`shieldedMints: Map<string, bigint>` today) | Dapps read effects back; the key must round-trip. |
| C5 | Build against this branch's wasm packages. The branch bumped the storable tags of every containing type (`zswap-input[v3]`, `contract-effects[v5]`, `transaction[v14]`, ...) and the effects array has eleven entries. | `compactc` output pinned to the `ledger-experiment` wasm builds | A contract compiled against released packages will not deserialize or execute against this ledger. |
| C6 | Optional, policy: the issuer checks the recipient's whitelist membership before minting (a `MerkleTree` ledger ADT with the recipient's enrollment leaf, or a signed admin approval). | Contract source only; expressible in Compact today | The ledger does not gate mints (section 2); if "only whitelisted parties may ever hold the token" is part of the policy, the issuer must enforce it at mint. |

Nothing in C1 to C5 is large. C1 and C3 are a standard-library addition plus one new fragment; C4
is a type and a codec; C5 is build plumbing. Acceptance: a Compact issuer deployed in the Rust
harness mints a coin whose type equals `gate.derivation` of the fixture, and `csl_regulated_transfer`
moves that coin from Alice to Bob with the existing gate.

## 4. The gate in Compact: requirements

The gate's contract shape is free as long as its call makes the two claims and proves what the
ledger relies on. Translating the hand-written gate (`zkir/src/csl_gate.rs`) into Compact needs:

| Id | Requirement | Why |
| --- | --- | --- |
| G1 | Builtins that write effects maps 9 and 10. Proposal: `claimSpendAuthorization(binding: Field)` and `claimOutputCoverage(commitment: Bytes<32>)`, emitting exactly `kernel_claim_spend_authorization` and `kernel_claim_output_coverage` from `onchain-runtime/src/csl_fragments.rs` (an `Idx` into index 9 or 10, a `Push` of the value, `Ins`). | These two maps are what the ledger matches and covers (`ledger/src/verify.rs`, `effects_check`). Without them a Compact contract cannot authorize anything. |
| G2 | The binding computed in-circuit as `transientHash([DOM, nf_hi, nf_lo, sender_hi, sender_lo, type_hi, type_lo, rho])` with `DOM = "midnight:csl-bind[v2]"` as a field element and each 32-byte value split as the ledger's `fr_pair` does (`hi` = last byte, `lo` = first 31 bytes, little-endian). | The ledger compares this value with the one inside the spend proof; any encoding difference is a silent mismatch and the transfer is rejected. **Compatibility to verify first**: check how Compact encodes a `Bytes<32>` into field elements for `transientHash` against `fr_pair`. If it differs, either Compact gains a way to split bytes as the ledger does, or the ledger-side binding (spend relation and `csl_policy_binding`) adopts Compact's encoding, which changes the relation and the embedded key. Decide this before writing the gate. |
| G3 | Witness inputs the dapp supplies privately: the input's nullifier and sender key, `rho`, and for every output of the segment its commitment opening (recipient key, value, type, nonce) and, for regulated outputs, the recipient's whitelist membership. The circuit recomputes each commitment and asserts the recomputed set is what it claims under G1. | The output-coverage claim is only meaningful if the circuit opened the commitments it claims; this is what stops paying a non-whitelisted recipient (scenario T08). |
| G4 | Whitelist membership in-circuit. Either keep the branch's off-chain tree (leaf `transientHash([DOM_LEAF, 1, pk_hi, pk_lo, r])`, depth 8, root in a ledger cell, paths as witnesses) or use Compact's `MerkleTree` ledger ADT with the issuer inserting leaves on chain. | The ledger does not care how the gate proves membership; the on-chain ADT is simpler to write in Compact and removes the off-chain tree, at the cost of public membership changes. |
| G5 | Protected-type binding and one-time `init`: a `tokenType: Bytes<32>` ledger cell asserted non-zero in `authorize` and folded into the binding; `init` asserts it is still zero before writing it; `update_root` must not touch it. | These are the revision-2 fixes (regression tests `transfer_before_initialization`, `second_initialization_cannot_retarget`, `second_asset_at_same_gate`, `protected_asset_survives_root_update`). Compact's ledger reads produce the same "read claiming the value" transcript, so the replay protection carries over. |
| G6 | One output in the first supported shape (`N_OUTPUTS = 1`); growing it is Stage 4 work in the gate circuit, not in the ledger. | Same boundary as the hand-written gate. |

What Compact already gives for free: the contract call's public inputs (transaction binding input,
communication commitment, field representation of the transcript program) are produced by the
compiler for every Compact contract, which is exactly what the hand-written relations emulate; the
circuit for `authorize` becomes an ordinary exported circuit; `update_root` and `init` are
ordinary admin circuits with a secret-key witness.

## 5. Wallet, dapp and SDK requirements

| Id | Requirement | State |
| --- | --- | --- |
| W1 | Spending needs the coin's derivation `(domain_sep, mint_address, rule)`. On the Rust side `LocalState::spend_with_derivation` and `Input::new_contract_owned(.., derivation)` take it (`zswap/src/local.rs`, `zswap/src/construct.rs`); the wasm API `ZswapInput.newContractOwned` passes `None` today. Wallets must store the derivation with each coin and the wasm builders must accept it. | Rust exists; wasm/TypeScript surface required. |
| W2 | `rho` transport: the wallet draws `rho` for the spend proof and the same value must reach the gate circuit's witness in the same transaction (G3). This needs a dapp-to-wallet protocol step; `rho` is private and must never be serialized into the transaction. | Design decision required (recorded in `next-steps.md`). |
| W3 | `Input.policy` (`gate`, `entry_point_hash`, `binding`, tag `zswap-spend-policy-binding[v1]`) must be surfaced in the TypeScript `ZswapInput` type for dapps that assemble transactions. | Required (wasm serializes it already). |
| W4 | Proving through the **proof server** is unsupported on this branch: it interprets the shipped zswap IR and rejects the CSL preimage (`Expected 77 inputs, received 87`). `proof-server/src/endpoints.rs` must dispatch `zkir::is_native_relation` key locations to the hand-written relations as `zkir::LocalProvingProvider` does. Any Compact dapp proves through the server, so this blocks Compact end to end. | Required; first open item in `next-steps.md`. |

## 6. Suggested order of work, with acceptance tests

1. **Ledger-only mint test** (Rust, this branch): a hand-written issuer program writes
   `ShieldedMintKey(domain_sep, GateContract(gate, ep))`; the minted coin is spent through the
   existing gate. Settles section 2 and gives C2 its exact bytes.
2. **Proof-server dispatch** (W4). Acceptance: the three failing upstream JavaScript proving tests
   (`Transient` x2, `TransactionBig`) pass.
3. **Issuer from Compact** (C1 to C5, C6 optional). Acceptance: the step-1 test with the issuer
   replaced by the compiled Compact contract.
4. **Encoding decision for the binding** (G2), then **the gate from Compact** (G1 to G6).
   Acceptance: `csl_regulated_transfer` and `csl_regression` pass with the Compact gate in place of
   the hand-written one, including every negative case.
5. **Wallet and dapp surface** (W1 to W3), then node integration (`next-steps.md`, Stage 5).

## 7. What does not change

The ledger rules (one-to-one matching of spend authorizations, full output coverage, the
protected-type binding), the spend relation and the embedded verifier key stay as they are through
steps 1 to 3; only step 4's encoding decision may touch them. The privacy boundary is unchanged: the
nullifier, the gate and entry point and the fact that an input is guarded are public; the sender,
the recipient, the amount and `rho` are not.
