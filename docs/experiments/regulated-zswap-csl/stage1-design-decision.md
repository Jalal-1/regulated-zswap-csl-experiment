# Regulated ZSwap CSL experiment: Stage 1 design decision

Status: draft for implementation, 25 October 2026. Base: `alexshielded/custom-spend-logic` at
`fa995fa5791bc19112e97334a2d9265751c35fad`, branch `experiment/regulated-zswap-csl`.

This document fixes the native authorization boundary for the first supported shape and records
what the baseline measurements established. It is derived from the pinned sources only; the CSL
draft (PR 335) and the MPS documents it cites are the only external design inputs.

## 1. Baseline established in Stage 0

| Check | Result | Evidence |
| --- | --- | --- |
| Toolchain | rustc 1.97.0 stable compiles the workspace; the flake pins fenix stable of 2026-04-23 | `cargo test -p midnight-coin-structure custom_spend`: 3 passed |
| Public parameters | 19 files `bls_midnight_2p0..18` fetched from the S3 bucket named in `flake.nix`; all SHA-256 hashes match the flake | scratchpad `params/` |
| Hand-written spend relation | `vk_is_byte_identical_to_shipped_spend_verifier` and `proofs_verify_against_shipped_verifier_key` pass with real parameters (release, 17.9 s) | `cargo test --release -p midnight-zkir --test zswap_spend` |
| Production proving path | `ZswapResolver` resolves `zswap/9/{spend,output,sign}.{prover,verifier,bzkir}` from the data provider (`https://srs.midnight.network/`, cache `$MIDNIGHT_PP`); proofs are produced by interpreting the IR, not by the hand-written relation | `zswap/src/prove.rs:32-83`, `zkir/src/zswap_spend.rs:14-24` |
| Production verification path | `Input::well_formed` builds the statement `[0, ops...]` and verifies with the built-in `SPEND_VK` through the legacy pipeline (`transient_crypto_old`) | `zswap/src/verify.rs:154-207` |
| Compact compiler | commented out of `flake.nix`; keys are compiled from checked-in ZKIR in `zkir-precompiles/` with `zkir compile-many`, which also writes `.bzkir` next to each `.zkir` | `flake.nix:22-24,332-353,369-384`; `zkir/src/main.rs:84-96` |
| Strict verification entry | `Transaction::well_formed(ref_state, WellFormedStrictness::default(), tblock)`: native proofs, contract proofs, balancing, limits all on | `ledger/src/verify.rs:452-466,620-704` |
| Fees | DUST actions on the intent (`Intent.dust_actions`); the test balancer adds a dust intent at segment `0xFEED`. The zswap offer of a transfer carries no fee coin | `ledger/src/test_utilities.rs:573-633` |

The ledger controls (`ledger/tests/csl_baseline.rs`: plain transfer accepted, corrupted proof
rejected, altered statement rejected) run in the Stage 0 chain and are reported with the Stage 0 results.

## 2. Movement-path inventory at the pinned commit

Every path that consumes or creates a shielded coin, and how the first shape treats it.

| # | Path | Where | Public data today | First-shape treatment |
| --- | --- | --- | --- | --- |
| P1 | User-owned spend | `zswap::Input` with `contract_address: None`; built by `local::State::spend` / `construct.rs`; verified by `Input::well_formed` against `SPEND_VK`; statement `[0, check_root, Set_insert(nullifier), Noop, Cell_read(segment), Cell_write(value_commitment)]` | nullifier, Merkle root, value commitment | **Supported.** The regulated spend exposes a policy binding in the statement slot that is constant 0 today (section 3). |
| P2 | Contract-owned spend | `Input` with `contract_address: Some`; ledger requires `claimed_nullifiers` from the owning contract (`verify.rs:1529-1547`) | as P1 plus owner address | **Rejected by the gate** (owner kind must be user). Stage 4 extends to contract owners. |
| P3 | User-owned output | `zswap::Output`, `contract_address: None`; statement `[ciphertext_field or 0, insert_hash(cm), Noop, Cell_read(segment), Cell_write(vc)]` | commitment, value commitment, ciphertext | **Covered by the gate's segment-wide output claim** (section 3.4). No output-circuit change in the first shape. |
| P4 | Contract-owned output | `Output` with `contract_address: Some`; ledger requires `claimed_shielded_receives` from the contract | as P3 plus address | **Rejected by the gate** for the regulated type (recipient must be a whitelisted user key). |
| P5 | Transient coin | `zswap::Transient`: one spend proof and one output proof over a coin created and spent in the same offer; `as_input()` reconstructs a one-leaf tree root | nullifier, commitment, two value commitments | **Fails closed.** `Transient` carries no policy binding field, so a regulated transient's spend proof cannot be verified (its statement slot is forced to 0); explicitly unsupported in Stage 2, revisited in Stage 4. |
| P6 | Offer merge | `Offer::merge`: disjoint union of inputs, outputs, transients, deltas; renormalized | n/a | **Rejected unless reauthorized.** A merge changes the segment's commitment set, so the gate's output claim no longer equals it (T18 by construction). |
| P7 | Guaranteed vs fallible offers | `StandardTransaction.guaranteed_coins` (segment 0) and `fallible_coins[seg]`; contract transcripts match offers by *logical* segment (guaranteed transcript to 0, fallible transcript to its intent segment) | segment ids | **Matching keyed by logical segment**; application is per segment (`apply_section`), so gate and regulated offer succeed or fail together (V6). |
| P8 | Shielded mint | `Effects.shielded_mints: HashMap<ShieldedMintKey(domain_sep, SpendRule), u64>`; the ledger derives the token type from the key and the calling contract's address at validation | domain separator, rule, amount | **Stage 2 fixture issues by harness state injection** (unbalanced offer under `enforce_balancing = false`, as `rewards_shielded` does). A real mint route is gated in Stage 4: a mint whose rule is non-Empty requires the gate's full output claim in that segment. |
| P9 | Authorized claim | `zswap::AuthorizedClaim { coin, recipient, proof }` verified against `SIGN_VK` (`zswap_claim_well_formed`) | the coin itself, including its type | **Prohibited for guarded types** at the ledger: the type is public here, so a claim of a type whose descriptor is non-Empty is rejected outright (Stage 4 rule). |
| P10 | Unshielded tokens | separate `UnshieldedTokenType` and UTXO set; `custom_unshielded_token_type` is always the Empty derivation | public | Out of scope; conversion to shielded form is a mint (P8). |
| P11 | DUST | `DustActions` on intents, own proofs and state | public | Never carries regulated value. |
| P12 | System transactions, rewards | `SystemTransaction::*`, `Transaction::ClaimRewards` | public | Unshielded only. |

Additional fact for the coverage register: a zero-value output of any colour is Pedersen-neutral and
needs no mint (Offer balancing is per type and value). The segment-wide output claim covers it when
a regulated input is present; otherwise it is a worthless, unspendable coin and is recorded as such.

## 3. Decisions

### D1 Gate mode: contract gate, one call per segment

The regulated asset's descriptor is `SpendRule::GateContract(gate_address, ep_hash)`. A transaction
that spends a regulated coin in logical segment `s` must carry, in an intent whose transcript for
segment `s` is present, exactly one call to `(gate_address, ep)` whose effects claim (a) the policy
binding of every regulated input in `s` and (b) every output and transient commitment in `s`.

Why not the recursive gate: the pinned branch already has fixed-key recursion (`verify_proof`,
`inner_proof`, `IrSource.verify_proof_vks`), but a pure gate cannot see the current whitelist. The
decisive scenario is removal, so the gate must read chain state at execution. The recursive route is
kept only as a privacy comparison in Stage 6.

### D2 Token encoding and in-circuit re-derivation

Ledger side (unchanged, `coin-structure`): `descriptor_hash = SHA256(tagged_serialize(rule))` for
non-Empty rules, and
`type = SHA256(pad32("midnight:derive_token") || domain_sep || mint_address || descriptor_hash)`
(`persistent_commit` writes the opening first, then the tuple). Empty keeps the 96-byte preimage.

Circuit side: the spend circuit takes `(domain_sep, mint_address, rule_kind, gate_address, ep_hash)`
as private witnesses and asserts, unconditionally on every spend:

- `rule_kind == Empty` implies `type == SHA256(sep32 || domain_sep || mint_address)`;
- `rule_kind == GateContract` implies
  `type == SHA256(sep32 || domain_sep || mint_address || SHA256(descriptor_bytes))` where
  `descriptor_bytes` is the tagged serialization of `GateContract(gate_address, ep_hash)`: a constant
  prefix (the `spend-rule[v1]` tag framing and the variant discriminant) followed by the two 32-byte
  payloads. Fixed width, so it is one SHA-256 over constant plus witnessed bytes;
- `rule_kind == GateCircuit` is rejected (unsupported, fail closed; T10/T11).

The exact `descriptor_bytes` layout is pinned by a new unit test in `coin-structure`
(`descriptor_hash_matches_fixed_layout`) so the circuit constant and the Rust side cannot drift.
The native token type (constant) is handled as an Empty derivation special case if it is ever
spent in these tests; the fixture uses only contract-derived types.

### D3 Sender authentication

For a user-owned coin the spend circuit already derives `sender_pk = SHA256("midnight:zswap-pk[v1]" || sk)`
from the witnessed secret key (`target()` in `zkir/src/zswap_spend.rs`). The binding commits to that
value, so the gate checks the key that actually authorizes the spend, not a caller-supplied one (V2, T07).

### D4 The policy binding

The spend circuit's first public input is the "binding input", constant 0 in every spend today
(`construct.rs:213`, `verify.rs:193`). It becomes:

```
binding = 0                                            if rule_kind == Empty
binding = Poseidon(DOM_BIND, nullifier_hi, nullifier_lo,
                   sender_hi, sender_lo,
                   gate_hi, gate_lo, ep_hi, ep_lo)     if rule_kind == GateContract
```

`DOM_BIND` is a fixed field constant; `*_hi/_lo` are the existing 1-byte/31-byte field splits of
32-byte values (`split_bytes32`). The number of public inputs stays 68. A regulated coin cannot
produce `binding = 0` except with negligible probability, and cannot witness `Empty` because of D2,
so omitting the binding on the wire (D5) fails verification (V1, T06).

### D5 Wire format

`zswap::Input` gains `policy: Option<Sp<SpendPolicyBinding, D>>` with
`SpendPolicyBinding { gate: ContractAddress, entry_point_hash: HashOutput, binding: Fr }`; tag
`zswap-input[v2]` becomes `zswap-input[v3]`, `Offer` tag bumps accordingly. `Input::well_formed`
puts `policy.map(|p| p.binding).unwrap_or(0)` in the statement slot. `Transient` is unchanged in the
first shape (P5 fails closed). Outputs are unchanged.

### D6 Gate claims and the ledger matching rule

`onchain_runtime::context::Effects` gains two fields (tag `contract-effects[v4]` to `[v5]`, VM array
of 9 becomes 11, `SerdeEffects` and the cost model follow):

- `claimed_spend_authorizations: HashSet<Fr>`: the bindings this call authorizes;
- `claimed_output_coverage: HashSet<CoinCommitment>`: the commitments this call has checked.

`StandardTransaction::effects_check` adds, with the same multiset style as
`nullifiers == claimed_nullifiers`:

1. `A == B` where `A = {(logical_seg, call.address, call.ep_hash(), b)}` over every claimed
   authorization of every transcript, and `B = {(seg, p.gate, p.entry_point_hash, p.binding)}` over
   every input with `policy: Some`, inputs and transients alike. Equality gives both directions:
   no uncovered regulated input, no dangling claim (V1, V5, T14, T15).
2. For every transcript that claims at least one authorization or one coverage entry, its coverage
   multiset equals the full multiset of output and transient commitments of its logical segment.
   A claim is always a complete statement about its segment (V3, T08, T09, T18).
3. Duplicate bindings within a segment fail rule 1 (a duplicated input already fails the nullifier
   set); duplicate coverage entries fail rule 2.

Why the `claimed_contract_calls` subset model is not reused: that rule only requires claims to be a
subset of real calls, which is the wrong direction for a mandatory check.

### D7 Freshness and read pattern

The gate contract state holds `root: Cell<Fr>` (Poseidon Merkle root of the whitelist, depth 8 for
the fixture) and `admin: Cell<Fr>` (Poseidon hash of the administrator secret). The gate entry point
reads `root` through a `Cell_read` whose result is a public input of the gate proof; the ledger
replays the transcript against current state in `apply_actions` and fails the call on any mismatch
of effects (`EffectsMismatch`) or program result. A proof made against a superseded root therefore
fails at application, which is V4 and T12. `HistoricMerkleTree` is not used anywhere in the gate.
Reading one cell for the root means the transcript has no data-dependent access pattern (V9).

### D8 Whitelist structure and witnesses

Leaf `= Poseidon(DOM_LEAF, owner_kind, pk_hi, pk_lo, r)` with `owner_kind = 1` for user coin public
keys (contracts reserved), and `r` enrollment randomness. The administrator maintains the tree off
chain and publishes the root through the `update_root` entry point, whose circuit checks knowledge of
the admin secret against `admin` (T24). Removal is publishing a root without the leaf. Membership
material for a party is `(r, path)`; Monument hands Bob's material out with Bob's address, and it
carries no spending authority (T07 and section 3.3 of the plan). The gate circuit reuses the
spend circuit's Poseidon path logic (`SpendWitness::merkle_root`).

### D9 Gate circuit statement (first shape)

Private witnesses: `nullifier, sender_pk, sender_r, sender_path`, and for every output `i` in the
segment `(nonce_i, type_i, value_i, recipient_i, recipient_r_i, recipient_path_i)`.
Public inputs, in the fixed order the ledger expects for any contract call
(`ContractCall::public_inputs`): `binding_input(binding_com)`, `communication_commitment`, then the
transcript ops in field representation. The transcript program: `Cell_read(root)` (result public),
then inserts into the two new effects maps: the authorization binding
`Poseidon(DOM_BIND, nullifier, sender_pk, self_address, ep_hash)` and each output commitment
`SHA256("midnight:zswap-cc[v1]" || coin_i || 1 || recipient_i)`.
Constraints: leaf(sender) is in `root`; for each output, `type_i != T_REG` or leaf(recipient_i) is in
`root`; recipients of regulated outputs are user keys. `T_REG` is a constant of the gate relation
(the regulated type, which the fixture derives from the mint address, domain separator and this
gate's own address and entry point). The gate is a hand-written zk-stdlib v1 relation registered as
a `ContractOperation` with a `v2` verifier key; its proof travels as `ProofVersioned::V2`.

### D10 Proof pipeline

The hand-written zk-stdlib v1 relation becomes the production spend prover. Stage 0 switches the
unchanged relation into `zswap/src/prove.rs` (a `Zkir`-like prover for `KeyLocation
"midnight/zswap/spend"`), embeds the verifier key it generates, bumps `static/version`, and shows a
proof from it passing strict verification while a proof under the previous key fails. The CSL
constraints (D2 to D4) are then added to that relation. Deviation from revision 2 of the plan:
native spend proofs stay on the v1 verification pipeline (`transient_crypto_old`), because that is
the only path `Input::well_formed` uses; what changes is the embedded key, and old-key proofs are
rejected by it. `ProofVersioned` dispatch for contract proofs is untouched.

### D11 Segment atomicity and ordering

Matching (D6) is keyed by logical segment. `apply_section` applies a segment's offer and its
transcripts together and fails the whole segment on any error, so a failed gate never leaves a
regulated spend committed (V6, T16). Within a transaction, a gate call and an `update_root` call in
the same segment are rejected by the gate's design: the gate reads the root before any write, and the
ledger's call sequencing rules order calls within an intent; the Stage 3 tests pin both orders (T25).

### D12 Public disclosures (what a block observer learns)

Per regulated input: that it is regulated, by which gate address and entry point, and a binding
value that is a Poseidon commitment. Per gate call: the gate address, the claimed bindings, and the
claimed commitments, all of which are already public in the offer. Nothing about Alice's or Bob's
keys, the whitelist contents, or membership paths. The asset family of a regulated input is
disclosed (narrowed to the types sharing this gate), as the plan anticipated (V9, T28).

## 4. First supported shape and explicit rejections

Supported: one regulated user-owned input and one regulated user-owned output of equal value, in one
logical segment, with one gate call in that segment, fees in DUST.

Rejected at the protocol boundary in Stage 2: regulated change or any second output in the segment
unless the gate covers it (the gate does cover every output, so a second approved output is in fact
accepted; an unapproved one is not); regulated transients (P5); regulated inputs or outputs owned by
contracts (P2, P4); `GateCircuit` descriptors (D2); merged offers (P6); claims of a guarded type (P9).

## 5. Implementation order (Stage 2)

1. `coin-structure`: fixed-layout encoding test for `descriptor_hash`.
2. `zkir/src/zswap_spend.rs`: witness fields and constraints for D2 and D4; keep `rc` last so
   `Input::delta` and `binding_randomness` keep reading the witness tail.
3. `zswap`: `SpendPolicyBinding`, `Input` field and tag, `Input::well_formed` statement slot,
   `construct.rs` witness assembly, prover via the relation (D10).
4. `onchain-runtime`: two `Effects` fields, VM encode and decode, serde, cost model entry.
5. `ledger/src/verify.rs`: the matching rule (D6) with proof-free unit tests using `Transaction<_, (), _>`.
6. Gate contract: hand-written relations for `authorize` and `update_root`, deploy helper, fixture.
7. `ledger/tests`: Stage 3 scenario runner (T01 to T08, T10 to T14, T16, T22, T24, T25).

## 6. Implementation notes (Stage 2, as built)

Everything below is what the experiment branch actually implements; where it departs from
sections 3 to 5 the departure is stated.

### 6.1 Wire format and tags

| Change | Where | Tag |
| --- | --- | --- |
| `Input.policy: Option<SpendPolicyBinding { gate, entry_point_hash, binding }>` | `zswap/src/structure.rs` | `zswap-input[v3]`, `zswap-offer[v6]`, `zswap-spend-policy-binding[v1]` |
| `Effects.claimed_spend_authorizations: HashSet<Fr>` (VM effects index 9) and `Effects.claimed_output_coverage: HashSet<CoinCommitment>` (index 10), appended so indices 0 to 8 are unchanged | `onchain-runtime/src/context.rs` | `contract-effects[v5]`, `contract-transcript[v6]` |
| Containers of the above | `ledger/src/structure.rs` | `contract-call[v5]`, `contract-action[v11]`, `intent[v11]` family, `standard-transaction[v14]`, `transaction[v14]` |
| Kernel fragments `kernel_claim_spend_authorization!` and `kernel_claim_output_coverage!` | `onchain-runtime/src/csl_fragments.rs` | n/a |
| Cost model: the two new maps are priced like `claimed_shielded_receives` | `ledger/src/structure.rs` | n/a |

### 6.2 Spend circuit (`zkir/src/zswap_spend_csl.rs`)

- Witness: nine CSL elements `[rule_kind, domain_sep(2), mint_address(2), gate(2), ep_hash(2)]`
  prepended to the legacy 77-element layout (86 total); `Input::delta` and
  `Input::binding_randomness` keep reading the tail. `rule_kind` is a bit, so `GateCircuit`
  cannot be witnessed.
- Descriptor bytes: `"midnight:spend-rule[v1]:" || 0x02 || gate || ep_hash` (89 bytes), SHA-256,
  then `SHA256(pad32("midnight:derive_token") || domain_sep || mint_address [|| descriptor_hash])`
  as in `coin_structure::contract::ContractAddress::custom_token_type`, pinned by
  `coin-structure`'s `descriptor_hash_matches_fixed_layout` and by
  `zkir/tests/zswap_spend_csl.rs::derivation_matches_coin_structure`.
- Native all-zero type accepted under `Empty` only.
- Binding: `Poseidon("midnight:csl-bind[v1]", nullifier_hi, nullifier_lo, sender_hi, sender_lo, gate_hi, gate_lo, ep_hi, ep_lo)`
  in the first public input; `0` for `Empty`. Off-circuit mirror:
  `coin_structure::custom_spend::csl_policy_binding`.
- Size: `k = 15` (unchanged from the legacy circuit's parameter size).
- Production path: `zkir::LocalProvingProvider` proves `midnight/zswap/spend` preimages with the
  relation (keys generated once per process from the public parameters); the ledger's test
  prover (`CombinedProofProvider`) routes native relations the same way. The embedded
  `zswap/static/spend.verifier` is the CSL key (`spend.verifier.csl.sha256`, pinned by
  `zswap::verify::embedded_spend_verifier_key_is_the_csl_key`). The legacy key and IR live in
  `zswap/static/legacy/` for the historical equivalence test. Departure from section D10: the
  `spend.verifier.sha256` sidecar keeps the legacy hash because it only governs verification of
  files downloaded from the data provider, which still serves the legacy IR artifacts; and
  `static/version` stays `9` because the version only names download paths.
- Old route closed: `legacy_relation_proofs_do_not_verify_under_csl_key`.

### 6.3 Gate contract (`zkir/src/csl_gate.rs`, `zkir/src/csl_whitelist.rs`)

State `[root: Fr, token_type: Bytes<32>, admin: Fr]`; entry points `authorize` and
`update_root`, both hand-written zk-stdlib v1 relations registered as `v2` verifier keys
(`ProofVersioned::V2`). The token type cell is written by `update_root` after deployment, which
breaks the circularity between the gate's address and the regulated type that names it.

Transcript templates are emitted as constants with holes, using the `Op::field_repr`
encodings measured by `ledger/tests/csl_gate_layout.rs`:

| Fragment | Field representation |
| --- | --- |
| `Cell_read` of an `Fr` at key `k` | `30 · 50 1 1 k · 0c 1 (-2) VALUE` |
| `Cell_read` of 32 bytes at key `k` | `30 · 50 1 1 k · 0c 1 0x20 HI LO` |
| claim into effects map `e` (Fr) | `40 · 80 1 1 e · 10 1 1 (-2) VALUE · 10 0 · a2 · 40` |
| claim into effects map `e` (32 bytes) | `40 · 80 1 1 e · 10 1 1 0x20 HI LO · 10 0 · a2 · 40` |
| write of an `Fr` at key `k` | `10 1 1 1 k · 11 1 1 (-2) VALUE · 91` |
| write of 32 bytes at key `k` | `10 1 1 1 k · 11 1 1 0x20 HI LO · 91` |

`authorize` (first shape, one output): read root, read token type, claim the binding, claim
the output commitment; proves sender membership under the root it read, the binding for that
sender and nullifier, the output commitment opening for a user recipient, and recipient
membership when the output's type equals the token type cell. `update_root`: read admin, write
root, write token type; proves `Poseidon("midnight:csl-admn[v1]", secret) == admin`. The
whitelist is a depth-8 Poseidon tree of leaves `Poseidon("midnight:csl-leaf[v1]", 1, pk_hi, pk_lo, r)`.

### 6.4 Ledger matching (`ledger/src/verify.rs`, `effects_check`)

Multiset `{(segment, gate, ep_hash, binding)}` over inputs with `policy` must equal the
multiset over claimed authorizations of calls, keyed by each transcript's logical segment;
every transcript that claims anything must claim exactly the output and transient commitments
of its logical segment. Failures: `EffectsCheckError::SpendAuthorizationsNEClaimed` and
`EffectsCheckError::OutputCoverageNESegmentCommitments`.

### 6.5 Fixture (`ledger/tests/csl_common.rs`)

Issuance is by harness state injection (`TestState::rewards_shielded` of the regulated type),
the gate is deployed with placeholder cells and then `update_root` publishes the administrator's
root and the token type, and guarded transfers are built by a raw builder with knobs to omit
the gate call, misstate the sender, pay a different recipient, or prove against a forged root.
Fees are paid exactly in DUST from a trial proof, because the shared balancing helper prices
against mock proofs and underpays real ones by a fixed amount.
