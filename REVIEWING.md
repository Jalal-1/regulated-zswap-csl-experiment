# Reviewing and picking up this experiment

This guide is for someone who has to review the change or continue the work. It assumes you know
the Midnight ledger (`midnightntwrk/midnight-ledger`) but have not seen this experiment.
`README.md` says what was done and not done; this file says where to look, what to check, and how
to run and extend it.

## 1. Reading order

Thirty minutes:

1. `README.md`, sections "The question and the design in brief", "Evidence", "What was not done".
2. `design/stage1-design-decision.md`, section 3 (decisions D1 to D12) and section 6 (as built).
3. `ledger/tests/csl_regulated_transfer.rs` on the `ledger-experiment` branch: the nine scenarios
   read top to bottom as the argument.

Three hours (a real review):

4. `plan/regulated_zswap_csl_experiment_plan_v2.md`: the requirements, in particular "What the
   experiment must validate" (V1 to V10) and the acceptance table (T01 to T32).
5. The diff, in the order of section 3 below.
6. `results/results.md` and the raw logs in `results/`, including the three failed scenario runs.
7. `design/next-steps.md`: what the next person should do, in order.

## 2. The argument, mapped to code and tests

The plan's validation properties, the mechanism that is supposed to deliver each, and the test
that shows it. "Untested" means the mechanism exists but no test exercises that property.

| Property | Mechanism | Where | Test |
| --- | --- | --- | --- |
| V1 policy is mandatory | The spend circuit re-derives the token type from `(domain_sep, mint_address, rule)` so a guarded coin cannot be presented as `Empty`; for a guarded rule it emits a non-zero binding in public input 0; the ledger requires every guarded input's binding to be claimed by a gate call | `zkir/src/zswap_spend_csl.rs` (constraints), `zswap/src/verify.rs` (statement slot), `ledger/src/verify.rs` `effects_check` | T06 (ledger); `csl_spend_relation_rejects_wrong_rule_witness` (zkir: Empty-for-guarded, wrong gate, underivable type) |
| V2 actual spender | The binding commits to `sender_pk` derived in-circuit from the witnessed spending key; the gate's claim must equal it | `zswap_spend_csl.rs` (`binding`), `csl_gate.rs` (`GateAuthorize`) | T07 |
| V3 every actual recipient | A claiming gate call must claim exactly the output and transient commitments of its logical segment; the gate proves the recipient of each regulated output is a member | `ledger/src/verify.rs` (coverage equality), `csl_gate.rs` | T08, T04. Change and second outputs: untested (`N_OUTPUTS = 1`) |
| V4 approval is current | The gate reads the root from its own state cell in the public transcript; the ledger replays the transcript against current state at application | `csl_gate.rs` (`Cell_read` of `CELL_ROOT`), ledger `apply` (unchanged) | T02 stale case, T13a |
| V5 authorization belongs to this movement | The binding includes the nullifier; matching is keyed by logical segment, gate address and entry point | `coin-structure/src/custom_spend.rs` `csl_policy_binding`, `ledger/src/verify.rs` | Untested at the ledger level (T14, T15 not done) |
| V6 atomicity | Matching per logical segment; `apply_section` already fails a segment as a whole | `ledger/src/verify.rs`, `ledger/src/semantics.rs` (unchanged) | Untested (T16 not done) |
| V7 no alternate path | Legacy key rejected; transients have no `policy` field so a guarded transient's proof cannot verify; `GateCircuit` cannot be witnessed; contract owners cannot obtain a gate claim (leaves encode user keys only) | `zswap/static/spend.verifier`, `zswap/src/structure.rs`, `zswap_spend_csl.rs` | Legacy key: `legacy_relation_proofs_do_not_verify_under_csl_key`, `embedded_spend_verifier_key_is_the_csl_key`. Transients, contract owners, merges, mint, claim: untested |
| V8 native invariants | Unchanged balancing, nullifier and commitment logic; the `Empty` rule keeps the 96-byte derivation and the native type is special-cased | `zswap`, `ledger` existing tests | `csl_baseline` (plain transfer accepted; corrupt proof and altered statement rejected), `malicious_imbalance`, the zswap suite |
| V9 privacy | Only a Poseidon binding, the gate address and entry point are added per guarded input; the gate's claims are already-public commitments | D12 in the design document | Untested (T28 not done) |
| V10 node | Nothing | | Not done |

## 3. The diff, file by file

Base: `fa995fa5791bc19112e97334a2d9265751c35fad`. Three commits, 54 files, about 4,300 lines added
(1,600 of them tests, 450 docs). Read in this order.

### Token derivation and binding (the ledger-side constants the circuit must match)

| File | What it adds | What to check |
| --- | --- | --- |
| `coin-structure/src/custom_spend.rs` (+106) | `TokenDerivation`, `csl_policy_binding`, `fr_pair`, `csl_bind_domain`, and `descriptor_hash_matches_fixed_layout` | That the pinned descriptor layout (`"midnight:spend-rule[v1]:" ‖ 0x02 ‖ gate ‖ ep_hash`, 89 bytes) really is what `tagged_serialize(SpendRule::GateContract)` produces, so the circuit constant cannot drift; that the hi/lo split (byte 31, bytes 0..31) is injective on 32-byte values. |

### The spend circuit

| File | What it adds | What to check |
| --- | --- | --- |
| `zkir/src/zswap_spend_csl.rs` (+738) | The production spend relation: witness prefix, three in-circuit SHA-256s, native-type special case, Poseidon binding, legacy transcript public inputs, key cache, `prove_from_preimage` | The derivation constraints are unconditional (a coin with no derivation cannot be spent); `rule_kind` is constrained to a bit; the `Empty` branch rejects a non-zero gate; the binding uses the same `sender_pk` the legacy circuit derives; the public input count and order are unchanged (68) so `Input::well_formed` is compatible; the domain separation of the binding (`"midnight:csl-bind[v1]"`) cannot collide with other Poseidon uses. |
| `zkir/src/zswap_spend.rs` (+22/−) | Constants made public for reuse | Nothing behavioural. |
| `zkir/tests/zswap_spend_csl.rs` (+307), `zkir/tests/zswap_spend.rs` | Derivation equality with coin-structure; end-to-end prove/verify; negative witnesses; legacy key rejection; the ignored `write_csl_spend_verifier_key` that regenerates the embedded key | That the negative cases assert non-verification, not prover errors. |
| `zswap/static/spend.verifier`, `spend.verifier.csl.sha256`, `static/legacy/*` | The embedded CSL key; the shipped key and IR kept for the equivalence test | `spend.verifier.sha256` deliberately keeps the legacy hash (download verification only). Decide whether that is acceptable or whether `static/version` should be bumped and the data provider updated. |

### Proving-pipeline routing

| File | What it adds | What to check |
| --- | --- | --- |
| `zkir/src/lib.rs` (+24) | `is_native_relation`; `check` returns "all ops active" for native relations; `prove` dispatches to the hand-written relations before IR resolution | That `check` returning a fixed vector is correct for these relations (their transcripts have no untaken branches). |
| `ledger/src/test_utilities.rs` (+6) | `CombinedProofProvider` routes native relations the same way | Test harness only. |
| `zswap/src/prove.rs`, `zswap/src/ledger.rs` | Call sites | Nothing behavioural. |

### Wire format

| File | What it adds | What to check |
| --- | --- | --- |
| `zswap/src/structure.rs` (+24/−) | `SpendPolicyBinding`, `Input.policy`, tags `zswap-input[v3]`, `zswap-offer[v6]`, `zswap-spend-policy-binding[v1]`; `erase_proof` and `as_input` carry the field | That `policy` is part of what is signed and bound (it is inside `Input`, which is inside the offer that the Pedersen binding covers). |
| `zswap/src/verify.rs` (+33/−) | Statement slot 0 = `policy.binding` or 0; the embedded-key pin test | The slot was constant 0 before; nothing else in the statement moved. |
| `zswap/src/construct.rs` (+46/−), `zswap/src/local.rs` (+29/−), `zswap/src/error.rs` | Constructors take `Option<&TokenDerivation>`; CSL witness prefix; `UnsupportedSpendRule` | For `SenderEvidence::Contract` the binding commits to the contract address (designed, untested). |

### Effects and the ledger rule

| File | What it adds | What to check |
| --- | --- | --- |
| `onchain-runtime/src/context.rs` (+55/−) | `claimed_spend_authorizations` (effects index 9), `claimed_output_coverage` (index 10); VM encode/decode, serde, `Distribution`; tag `contract-effects[v5]` | Indices 0 to 8 unchanged; array length 11 both ways. |
| `onchain-runtime/src/csl_fragments.rs` (+49), `lib.rs`, `transcript.rs` | Kernel fragment macros for the two claims; `contract-transcript[v6]` | The fragments mirror the existing `kernel_claim_*` shapes. |
| `ledger/src/verify.rs` (+100) | The matching rule in `effects_check`: `{(logical_seg, gate, ep_hash, binding)}` over guarded inputs must equal the multiset of claimed authorizations; any claiming transcript must claim exactly its segment's output and transient commitments | **This is the core of the ledger change.** Check: logical segment of a transcript (guaranteed → 0, fallible → intent segment); that transients are included on both sides consistently; duplicate handling; that the rule runs for every `Transaction::Standard` under default strictness and is not gated by any flag. |
| `ledger/src/error.rs` (+28) | `SpendAuthorizationsNEClaimed`, `OutputCoverageNESegmentCommitments` | Display only. |
| `ledger/src/structure.rs` (+20/−) | Container tag bumps; cost-model entries for the two maps | The cost entries copy `claimed_shielded_receives`; not measured. |
| `.tag-decompositions/*` (14 files) | Regenerated decomposition records for the bumped tags | Generated by the `tag_enforcement_test!` tests (`serialize/src/util.rs`): a test writes the file when absent and asserts equality when present. To bump a tag: change it, delete the stale file, run `cargo test -p <crate> --lib`. |

### The gate contract

| File | What it adds | What to check |
| --- | --- | --- |
| `zkir/src/csl_whitelist.rs` (+148) | Depth-8 Poseidon tree: leaf `Poseidon("midnight:csl-leaf[v1]", 1, pk_hi, pk_lo, r)`, root, path | Leaf domain separation; `owner_kind = 1` for user keys (contracts reserved). |
| `zkir/src/csl_gate.rs` (+827) | Constants (key locations, entry points, cells, effects indices, admin domain), `admin_key`, transcript templates (`authorize_template`, `update_root_template`), witnesses, the two relations, key caches, `verifier_key_bytes`, `prove_from_preimage` | **Templates are built from op encodings measured by `ledger/tests/csl_gate_layout.rs`**, not derived from the VM; re-run that probe if `Op::field_repr` changes. In `GateAuthorize`: the root used for both membership proofs is the one claimed in the transcript; the binding uses the gate's own address and entry point; recipient membership is required only when the output's type equals the token-type cell. In `GateUpdateRoot`: the admin preimage check. |

### The fixture and scenarios

| File | What it adds | What to check |
| --- | --- | --- |
| `ledger/tests/csl_baseline.rs` (+258) | Stage 0 strict controls with exact DUST fee payment | The controls use `WellFormedStrictness::default()` (nothing relaxed). |
| `ledger/tests/csl_gate_layout.rs` (+96) | The op-encoding probe | Prints only. |
| `ledger/tests/csl_common.rs` (+688) | Resolver serving the gate keys, `Party`, `Gate`, `deploy_gate`, `update_root_tx`, `publish_root`, issuance, `TransferOptions` and `regulated_transfer_tx`, `pay_exact_dust_fee`, `pay_and_prove`, `Rejection`/`attempt`/`apply_rejected`, `fixture` | Issuance is harness state injection (`rewards_shielded`), not a mint. `publish_root` applies with `enforce_balancing = false` (the admin pays no fee in the fixture); every transfer is applied under default strictness. The fee-intent TTL is ten minutes. |
| `ledger/tests/csl_regulated_transfer.rs` (+244) | T01, T02/T12, T04, T06, T07, T08, T13a, T13b, T24 | Each negative test asserts the specific rejection variant and that Alice's nullifier is absent afterwards. |
| `ledger/tests/micro-dao.rs`, `token_vault_shielded.rs` | Signature changes only (`None` derivation) | See README "Known issues" for their run status. |

## 4. Questions a reviewer should answer

These are the places where the design makes a claim that a reviewer should confirm or refute.

1. **Coverage equality and fees.** The rule requires a claiming gate call to claim *every* output
   commitment of its logical segment. Fees are paid in DUST (intent-level), so a transfer's offer
   holds only regulated coins in the fixture. Would a real wallet ever put an unrelated shielded
   output (say, NIGHT change from another operation) in the same segment? If so the gate would
   have to cover it, which is allowed (non-regulated outputs need no membership) but means the gate
   must see every output's opening.
2. **Logical segment identity.** Is `effects_check`'s notion of a transcript's logical segment
   exactly the one `apply_section` uses? A mismatch would let a gate in one segment satisfy an
   input in another.
3. **`check` for native relations.** `ProvingProvider::check` is used to prune untaken transcript
   branches before proving. Returning "all active" is right for fixed transcripts; confirm nothing
   else consumes that vector.
4. **Binding collision resistance.** Nine Poseidon inputs with a fixed domain constant; hi/lo
   splitting of 32-byte values into (1 byte, 31 bytes). Confirm the split is injective and the
   domain constant is distinct from every other Poseidon domain in the ledger.
5. **Native type special case.** The all-zero type is accepted under `Empty` with no derivation.
   Are there other fixed types (now or planned) that would need the same treatment?
6. **The `Transient` fail-closed claim** (V7) is argued, not tested: a guarded transient's spend
   proof would have statement slot 0 = 0, which the circuit refuses for a guarded rule. Write the
   test.
7. **Legacy artifacts still downloadable.** The data provider still serves the legacy spend IR and
   key under `zswap/9/`. The ledger ignores them for spends. Is leaving `static/version` at 9
   acceptable for an experiment, and what is the right production story (new version, new
   artifacts on the provider)?
8. **Cost model.** The two new maps are priced by copying `claimed_shielded_receives`; is that a
   reasonable placeholder?
9. **Governance.** `update_root` is authorized by a single Poseidon preimage; whoever holds it
   controls who may transact. The token type does not change when the root (or the admin) does.

## 5. Running it

```
scripts/reproduce.sh            # everything: clone, params, CLIs, artifacts, unit, controls, scenarios
scripts/reproduce.sh scenarios  # only the nine scenarios (needs params, artifacts and a checkout)
```

Environment variables (`LEDGER`, `MIDNIGHT_PP`, `MIDNIGHT_LEDGER_TEST_STATIC_DIR`, `BIN`, `LOGS`) are
documented at the top of the script. The `params` and `artifacts` stages of the script were
validated against the experiment's own verified material; the cargo stages run the exact commands
recorded in `results/results.md`.

What you will see from the scenarios (`--nocapture`): each negative test prints the ledger's
disposal, for example `stale transfer: rejected at application: Failure(Transcript(Execution(ReadMismatch ...)))`.
A test that fails prints `unexpected disposal: ...` with the actual error, which is the first thing
to read.

## 6. Extending it

- **Add a scenario.** Build the transaction with `regulated_transfer_tx(&state, &mut rng, &gate,
  &sender, &recipient, &coin, &TransferOptions { ... })`; the knobs are `omit_gate_call`,
  `claim_sender`, `pay_instead`, `whitelist_override`, `claim_forged_root`. Then either
  `pay_and_prove` + `state.apply` for a positive case, or `attempt` and match on `Rejection` for a
  negative one. Each test takes a fresh `fixture(seed)` (deterministic from the seed).
- **Change the gate's shape** (for example `N_OUTPUTS = 2` for change). Update `csl_gate.rs`
  (`N_OUTPUTS`, `AuthorizeWitness.outputs`, the template's claim count), the fixture's witness
  assembly and the coverage claims; the ledger rule needs no change.
- **Regenerate the embedded spend key** after changing the spend relation:
  `cargo test --release -p midnight-zkir --test zswap_spend_csl write_csl_spend_verifier_key -- --ignored`
  (writes `zswap/static/spend.verifier` and `spend.verifier.csl.sha256`), then run
  `cargo test --release -p midnight-zswap embedded_spend_verifier_key_is_the_csl_key`.
- **Re-measure op encodings** after any VM change: `cargo test --release -p midnight-ledger-v10
  --features proving --test csl_gate_layout -- --nocapture` prints the field representation of each
  fragment; update the templates in `csl_gate.rs`.
- **Bump a storable tag**: edit the tag string, delete the stale file in `.tag-decompositions/`,
  run the crate's `--lib` tests; the enforcement test writes the new decomposition. Every container
  of the type needs the same treatment (the tests tell you which).
- **Next steps in order** are in `design/next-steps.md`: proof-free matching tests first, then the
  Stage 4 shapes, the mint and claim rules, the node, and the measurements.
