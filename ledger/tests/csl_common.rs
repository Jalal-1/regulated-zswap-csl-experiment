// This file is part of midnight-ledger.
// Copyright (C) Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Shared fixture for the regulated ZSwap CSL experiment: the whitelist gate
//! contract, its administrator, approved parties, synthetic issuance of the
//! regulated token, exact DUST fee payment, and a raw builder for guarded
//! transfers that can deliberately omit or misstate any part of the policy
//! linkage (for the adversarial tests).
#![cfg(feature = "proving")]
#![allow(dead_code)]

use std::borrow::Cow;

use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use base_crypto::time::Duration;
use base_crypto::fab::AlignedValue;
use base_crypto::hash::HashOutput;
use base_crypto::rng::SplittableRng;
use coin_structure::coin::{
    Commitment, Info as CoinInfo, Nullifier, QualifiedInfo as QualifiedCoinInfo, ShieldedTokenType,
};
use coin_structure::contract::ContractAddress;
use coin_structure::custom_spend::{SpendRule, TokenDerivation, csl_policy_binding, fr_pair};
use midnight_ledger::construct::{ContractCallPrototype, PreTranscript, partition_transcripts};
use midnight_ledger::dust::{DUST_EXPECTED_FILES, DustActions, DustOutput, DustResolver};
use midnight_ledger::error::{MalformedTransaction, TransactionInvalid};
use midnight_ledger::semantics::TransactionResult;
use midnight_ledger::structure::{
    ContractDeploy, INITIAL_PARAMETERS, Intent, ProofPreimageMarker, Signature, Transaction,
};
use midnight_ledger::test_utilities::{
    PUBLIC_PARAMS, Resolver, TestState, Tx, contract_operation, dbg_fees_with_state, test_intents,
    tx_prove,
};
use midnight_ledger::verify::WellFormedStrictness;
use midnight_ledger_v10 as midnight_ledger;
use zkir_v2::csl_gate::{
    self, AUTHORIZE_ENTRY_POINT, AUTHORIZE_KEY_LOCATION, AuthorizeWitness, OutputWitness,
    UPDATE_ROOT_ENTRY_POINT, UPDATE_ROOT_KEY_LOCATION, UpdateRootWitness,
};
use zkir_v2::csl_whitelist::{Whitelist, user_leaf};
use onchain_runtime::context::QueryContext;
use onchain_runtime::ops::{Key, Op};
use onchain_runtime::result_mode::ResultModeVerify;
use onchain_runtime::state::{
    ChargedState, ContractOperation, ContractState, EntryPointBuf, StateValue, stval,
};
use onchain_runtime::{kernel_claim_output_coverage, kernel_claim_spend_authorization};
use rand::{Rng, SeedableRng, rngs::StdRng};
use storage::arena::Sp;
use storage::db::InMemoryDB;
use storage::storage::HashMap;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{KeyLocation, ProvingKeyMaterial};
use zswap::keys::SecretKeys;
use zswap::{Offer, Output};

pub type UnprovenTx = Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>;

/// Value of the regulated coin issued to Alice and transferred to Bob.
pub const AMOUNT: u128 = 100_000_000;
/// Fixture issuer: the minting contract's domain separator and address. The
/// coin is issued by harness state injection, so no contract is deployed at it.
pub const MINT_DOMAIN: [u8; 32] = [0xD0; 32];
pub const MINT_ADDRESS: [u8; 32] = [0xA1; 32];

/// A resolver that serves the gate's hand-written verifier keys and the
/// standard zswap and dust material.
pub async fn csl_resolver() -> Resolver {
    let authorize_vk = csl_gate::verifier_key_bytes(&*PUBLIC_PARAMS, AUTHORIZE_KEY_LOCATION)
        .await
        .expect("authorize key generation")
        .expect("authorize key location");
    let update_vk = csl_gate::verifier_key_bytes(&*PUBLIC_PARAMS, UPDATE_ROOT_KEY_LOCATION)
        .await
        .expect("update_root key generation")
        .expect("update_root key location");
    Resolver::new(
        PUBLIC_PARAMS.clone(),
        DustResolver(
            MidnightDataProvider::new(
                FetchMode::OnDemand,
                OutputMode::Log,
                DUST_EXPECTED_FILES.to_owned(),
            )
            .expect("dust data provider"),
        ),
        Box::new(move |KeyLocation(loc)| {
            let material = |vk: &Vec<u8>| ProvingKeyMaterial {
                prover_key: vec![],
                verifier_key: vk.clone(),
                ir_source: vec![],
            };
            let res = match &*loc {
                AUTHORIZE_KEY_LOCATION => Ok(Some(material(&authorize_vk))),
                UPDATE_ROOT_KEY_LOCATION => Ok(Some(material(&update_vk))),
                _ => Ok(None),
            };
            Box::pin(std::future::ready(res))
        }),
    )
}

/// A whitelisted party: its wallet keys and whitelist slot.
pub struct Party {
    pub keys: SecretKeys,
    pub slot: usize,
    pub r: Fr,
}

impl Party {
    pub fn new(rng: &mut StdRng, slot: usize) -> Self {
        Party {
            keys: SecretKeys::from_rng_seed(rng),
            slot,
            r: rng.r#gen(),
        }
    }
    pub fn pk(&self) -> [u8; 32] {
        self.keys.coin_public_key().0.0
    }
    pub fn leaf(&self) -> Fr {
        user_leaf(&self.pk(), self.r)
    }
}

/// The deployed gate and the administrator's view of it.
pub struct Gate {
    pub address: ContractAddress,
    pub ep_authorize: HashOutput,
    pub ep_update_root: HashOutput,
    pub authorize_op: ContractOperation,
    pub update_root_op: ContractOperation,
    pub admin_secret: Fr,
    pub whitelist: Whitelist,
    pub current_root: Fr,
    pub derivation: TokenDerivation,
    pub token_type: ShieldedTokenType,
}

fn fr_of_hash(h: &HashOutput) -> [Fr; 2] {
    fr_pair(&h.0)
}

/// Deploys the gate with an empty root, a zero token type and the admin key.
pub async fn deploy_gate(
    state: &mut TestState<InMemoryDB>,
    rng: &mut StdRng,
    resolver: &Resolver,
) -> Gate {
    let authorize_op = contract_operation(resolver, AUTHORIZE_KEY_LOCATION).await;
    let update_root_op = contract_operation(resolver, UPDATE_ROOT_KEY_LOCATION).await;
    let admin_secret: Fr = rng.r#gen();
    let admin = csl_gate::admin_key(admin_secret);
    let contract = ContractState::new(
        stval!([(Fr::from(0)), (HashOutput([0u8; 32])), (admin)]),
        HashMap::new()
            .insert(AUTHORIZE_ENTRY_POINT.into(), authorize_op.clone())
            .insert(UPDATE_ROOT_ENTRY_POINT.into(), update_root_op.clone()),
        Default::default(),
    );
    let deploy = ContractDeploy::new(rng, contract);
    let address = deploy.address();
    let tx = tx_prove(
        rng.split(),
        &Transaction::from_intents(
            "local-test",
            test_intents(rng, Vec::new(), Vec::new(), vec![deploy], state.time),
        ),
        resolver,
    )
    .await
    .expect("deploy proving");
    let mut strictness = WellFormedStrictness::default();
    strictness.enforce_balancing = false;
    state.assert_apply(&tx, strictness);

    let ep_authorize = EntryPointBuf::from(AUTHORIZE_ENTRY_POINT).ep_hash();
    let ep_update_root = EntryPointBuf::from(UPDATE_ROOT_ENTRY_POINT).ep_hash();
    let derivation = TokenDerivation {
        domain_sep: HashOutput(MINT_DOMAIN),
        mint_address: ContractAddress(HashOutput(MINT_ADDRESS)),
        rule: SpendRule::GateContract(address, ep_authorize),
    };
    let token_type = derivation.token_type();
    Gate {
        address,
        ep_authorize,
        ep_update_root,
        authorize_op,
        update_root_op,
        admin_secret,
        whitelist: Whitelist::new(),
        current_root: Fr::from(0),
        derivation,
        token_type,
    }
}

fn read_cell(key: u8, result: AlignedValue) -> Vec<Op<ResultModeVerify, InMemoryDB>> {
    vec![
        Op::Dup { n: 0 },
        Op::Idx {
            cached: false,
            push_path: false,
            path: vec![Key::Value(AlignedValue::from(key))].into(),
        },
        Op::Popeq {
            cached: false,
            result,
        },
    ]
}

fn write_cell(key: u8, value: AlignedValue) -> Vec<Op<ResultModeVerify, InMemoryDB>> {
    vec![
        Op::Push {
            storage: false,
            value: StateValue::Cell(Sp::new(AlignedValue::from(key))),
        },
        Op::Push {
            storage: true,
            value: StateValue::Cell(Sp::new(value)),
        },
        Op::Ins { cached: false, n: 1 },
    ]
}

fn gate_call(
    state: &TestState<InMemoryDB>,
    rng: &mut StdRng,
    gate: &Gate,
    entry_point: &'static [u8],
    op: &ContractOperation,
    key_location: &'static str,
    program: Vec<Op<ResultModeVerify, InMemoryDB>>,
    private_transcript: Vec<Fr>,
    run_against: Option<ChargedState<InMemoryDB>>,
) -> ContractCallPrototype<InMemoryDB> {
    // The transcript is produced by running the program against a contract
    // state. Honest callers use the ledger's; an attacker may run it against
    // any state they like (T13), which is why the ledger replays it.
    let contract_state = run_against.unwrap_or_else(|| {
        state
            .ledger
            .index(gate.address)
            .expect("gate deployed")
            .data
    });
    let context = QueryContext::new(contract_state, gate.address);
    let pair = partition_transcripts(
        &[PreTranscript {
            context,
            program,
            comm_comm: None,
        }],
        &INITIAL_PARAMETERS,
    )
    .expect("transcript partition")[0]
        .clone();
    ContractCallPrototype {
        address: gate.address,
        entry_point: entry_point.into(),
        op: op.clone(),
        guaranteed_public_transcript: pair.0,
        fallible_public_transcript: pair.1,
        private_transcript_outputs: private_transcript.into_iter().map(AlignedValue::from).collect(),
        input: ().into(),
        output: ().into(),
        communication_commitment_rand: rng.r#gen(),
        key_location: KeyLocation(Cow::Borrowed(key_location)),
        inner_proofs: vec![],
    }
}

/// An unproven `update_root` transaction publishing `new_root` and the token
/// type, authenticated with `secret`.
pub fn update_root_tx(
    state: &TestState<InMemoryDB>,
    rng: &mut StdRng,
    gate: &Gate,
    new_root: Fr,
    secret: Fr,
) -> UnprovenTx {
    let admin = csl_gate::admin_key(gate.admin_secret);
    let mut program = Vec::new();
    program.extend(read_cell(csl_gate::CELL_ADMIN as u8, admin.into()));
    program.extend(write_cell(csl_gate::CELL_ROOT as u8, new_root.into()));
    program.extend(write_cell(
        csl_gate::CELL_TOKEN_TYPE as u8,
        gate.token_type.0.into(),
    ));
    let witness = UpdateRootWitness {
        binding_input: 0.into(),
        communication_commitment: 0.into(),
        admin_secret: secret,
        new_root,
        new_token_type: fr_of_hash(&gate.token_type.0),
    };
    let call = gate_call(
        state,
        rng,
        gate,
        UPDATE_ROOT_ENTRY_POINT,
        &gate.update_root_op,
        UPDATE_ROOT_KEY_LOCATION,
        program,
        witness.private_transcript(),
        None,
    );
    Transaction::from_intents(
        "local-test",
        test_intents(rng, vec![call], Vec::new(), Vec::new(), state.time),
    )
}

/// Publishes the administrator's current whitelist root (and the token type).
pub async fn publish_root(
    state: &mut TestState<InMemoryDB>,
    rng: &mut StdRng,
    resolver: &Resolver,
    gate: &mut Gate,
) {
    let root = gate.whitelist.root();
    let tx = update_root_tx(state, rng, gate, root, gate.admin_secret);
    let tx = tx_prove(rng.split(), &tx, resolver)
        .await
        .expect("update_root proving");
    let mut strictness = WellFormedStrictness::default();
    strictness.enforce_balancing = false;
    state.assert_apply(&tx, strictness);
    gate.current_root = root;
}

/// Issues `value` of the regulated token to the test wallet (Alice) by harness
/// state injection, as `TestState::rewards_shielded` does for any type.
pub fn issue_regulated(state: &mut TestState<InMemoryDB>, rng: &mut StdRng, gate: &Gate, value: u128) {
    state.rewards_shielded(rng, gate.token_type, value);
}

/// The test wallet's regulated coins.
pub fn regulated_coins(state: &TestState<InMemoryDB>, gate: &Gate) -> Vec<QualifiedCoinInfo> {
    state
        .zswap
        .coins
        .iter()
        .filter(|(_, c)| c.type_ == gate.token_type)
        .map(|(_, c)| *c)
        .collect()
}

/// Knobs for building a guarded transfer with deliberate defects.
#[derive(Default)]
pub struct TransferOptions<'a> {
    /// Leave the gate call out entirely (T06).
    pub omit_gate_call: bool,
    /// Present another whitelisted party as the sender inside the gate (T07).
    pub claim_sender: Option<&'a Party>,
    /// Pay this party instead of the one the gate checks (T08).
    pub pay_instead: Option<&'a Party>,
    /// Prove membership (root, sender path and recipient path) against this
    /// whitelist instead of the gate's (T13).
    pub whitelist_override: Option<&'a Whitelist>,
    /// Claim the overriding whitelist's root in the public transcript, running
    /// the program against a forged copy of the contract state (T13a). When
    /// false the gate's current root is claimed (T13b).
    pub claim_forged_root: bool,
}

/// A guarded Alice -> Bob transfer, unproven: one regulated input, one regulated
/// output and one gate call whose transcript runs in the guaranteed segment.
pub fn regulated_transfer_tx(
    state: &TestState<InMemoryDB>,
    rng: &mut StdRng,
    gate: &Gate,
    alice: &Party,
    bob: &Party,
    coin: &QualifiedCoinInfo,
    opts: &TransferOptions<'_>,
) -> UnprovenTx {
    let (_, input) = state
        .zswap
        .spend_with_derivation(rng, &state.zswap_keys, coin, Some(0), &gate.derivation)
        .expect("guarded spend construction");
    assert!(input.policy.is_some(), "guarded input carries a policy");
    let paid = opts.pay_instead.unwrap_or(bob);
    let bob_coin = CoinInfo {
        nonce: rng.r#gen(),
        value: coin.value,
        type_: gate.token_type,
    };
    let output = Output::new(
        rng,
        &bob_coin,
        Some(0),
        &paid.keys.coin_public_key(),
        Some(paid.keys.enc_public_key()),
    )
    .expect("output construction");
    let offer = Offer {
        inputs: vec![input.clone()].into(),
        outputs: vec![output.clone()].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };

    let calls = if opts.omit_gate_call {
        Vec::new()
    } else {
        let sender = opts.claim_sender.unwrap_or(alice);
        let list = opts.whitelist_override.unwrap_or(&gate.whitelist);
        let root = if opts.whitelist_override.is_some() { list.root() } else { gate.current_root };
        let sender_path = list.path(sender.slot);
        // What the gate claims to have checked: Bob's coin, whoever the offer actually pays.
        let checked_coin = CoinInfo {
            nonce: bob_coin.nonce,
            value: bob_coin.value,
            type_: bob_coin.type_,
        };
        let checked_commitment: Commitment = checked_coin
            .commitment(&coin_structure::transfer::Recipient::User(bob.keys.coin_public_key()));
        let binding = csl_policy_binding(
            &input.nullifier,
            &sender.keys.coin_public_key().0,
            &gate.address,
            &gate.ep_authorize,
        );
        let witness = AuthorizeWitness {
            binding_input: 0.into(),
            communication_commitment: 0.into(),
            root,
            token_type: fr_of_hash(&gate.token_type.0),
            nullifier: fr_of_hash(&input.nullifier.0),
            sender_pk: fr_pair(&sender.pk()),
            sender_r: sender.r,
            sender_path,
            gate_address: fr_of_hash(&gate.address.0),
            ep_hash: fr_of_hash(&gate.ep_authorize),
            outputs: vec![OutputWitness {
                nonce: fr_of_hash(&bob_coin.nonce.0),
                token_type: fr_of_hash(&gate.token_type.0),
                value: Fr::from(bob_coin.value),
                recipient_pk: fr_pair(&bob.pk()),
                recipient_r: bob.r,
                recipient_path: list.path(bob.slot),
            }],
        };
        let mut program: Vec<Op<ResultModeVerify, InMemoryDB>> = Vec::new();
        let claimed_root = if opts.claim_forged_root { root } else { gate.current_root };
        program.extend(read_cell(csl_gate::CELL_ROOT as u8, claimed_root.into()));
        // A claimed root other than the gate's needs a forged copy of the
        // contract state to run the program against.
        let run_against = (claimed_root != gate.current_root).then(|| {
            ChargedState::new(stval!([
                (claimed_root),
                (gate.token_type.0),
                (csl_gate::admin_key(gate.admin_secret))
            ]))
        });
        program.extend(read_cell(
            csl_gate::CELL_TOKEN_TYPE as u8,
            gate.token_type.0.into(),
        ));
        program.extend(kernel_claim_spend_authorization!(binding));
        program.extend(kernel_claim_output_coverage!(checked_commitment));
        vec![gate_call(
            state,
            rng,
            gate,
            AUTHORIZE_ENTRY_POINT,
            &gate.authorize_op,
            AUTHORIZE_KEY_LOCATION,
            program,
            witness.private_transcript(),
            run_against,
        )]
    };
    Transaction::new(
        "local-test",
        test_intents(rng, calls, Vec::new(), Vec::new(), state.time),
        Some(offer),
        Default::default(),
    )
}

/// The policy binding of the first guaranteed input of an unproven transaction.
pub fn first_input_nullifier(tx: &UnprovenTx) -> Nullifier {
    let Transaction::Standard(stx) = tx else {
        panic!("standard transaction expected")
    };
    let offer = stx.guaranteed_coins.as_ref().expect("guaranteed offer");
    let input = offer.inputs.iter().next().expect("one input");
    input.nullifier
}

/// Pays exactly `fee` Specks of DUST for `tx` from the test wallet in a fee-only
/// intent at segment `0xFEED`.
pub fn pay_exact_dust_fee(
    state: &mut TestState<InMemoryDB>,
    rng: &mut StdRng,
    tx: UnprovenTx,
    fee: u128,
) -> UnprovenTx {
    let mut remaining = fee;
    let mut spends = storage::storage::Array::new();
    let utxos = state.dust.utxos().collect::<Vec<_>>();
    for qdo in utxos {
        if remaining == 0 {
            break;
        }
        let gen_info = state.dust.generation_info(&qdo).expect("generation info");
        let value = DustOutput::from(qdo).updated_value(
            &gen_info,
            state.time,
            &state.ledger.parameters.dust,
        );
        let v_fee = u128::min(value, remaining);
        let (next, spend) = state
            .dust
            .spend(&state.dust_key, &qdo, v_fee, state.time)
            .expect("dust spend");
        state.dust = next;
        spends = spends.push(spend);
        remaining -= v_fee;
    }
    assert_eq!(remaining, 0, "test wallet cannot cover the fee");
    // A TTL of ten minutes (within the global hour): the harness advances the
    // block time by ten seconds per applied block, and a retained transaction
    // must survive the administrator's update block to be tested at all.
    let mut intent = Intent::empty(rng, state.time + Duration::from_secs(600));
    intent.dust_actions = Some(Sp::new(DustActions {
        spends,
        registrations: vec![].into(),
        ctime: state.time,
    }));
    let fee_tx = Transaction::from_intents(
        "local-test",
        storage::storage::HashMap::new().insert(0xFEED, intent),
    );
    tx.merge(&fee_tx).expect("merge fee intent")
}

/// Pays the fee of `tx` in DUST and proves it. The ledger prices the proven
/// transaction by size, and the DUST spend's own encoded value is part of that
/// size, so the fee is found by iterating proofs to a fixed point: pay `fee`,
/// prove, measure; stop when the payment covers the measured fee.
pub async fn pay_and_prove(
    state: &mut TestState<InMemoryDB>,
    rng: &mut StdRng,
    resolver: &Resolver,
    tx: UnprovenTx,
) -> Result<Tx<Signature, InMemoryDB>, String> {
    let mut fee: u128 = 1_000_000_000_000_000;
    for _ in 0..5 {
        let mut attempt = state.clone();
        let paid = pay_exact_dust_fee(&mut attempt, rng, tx.clone(), fee);
        let proven = tx_prove(rng.split(), &paid, resolver)
            .await
            .map_err(|e| format!("{e:?}"))?;
        let measured = dbg_fees_with_state(&proven, &state.ledger.parameters, &state.ledger, true)
            .map_err(|e| format!("{e:?}"))?;
        if measured <= fee {
            *state = attempt;
            return Ok(proven);
        }
        fee = measured;
    }
    Err("DUST fee did not converge".to_owned())
}

/// How the ledger disposed of a transaction that must not move a coin. The
/// prover does not check satisfiability (`create_proof` emits a proof for any
/// witness), so an attacker can always produce *some* proof; what the
/// experiment has to show is that no such proof is accepted.
pub enum Rejection {
    /// The prover refused the witness.
    Proving(String),
    /// Strict `well_formed` rejected the proven transaction; nothing was applied.
    Verification(MalformedTransaction<InMemoryDB>),
    /// Verification passed and application failed (the state replay).
    Application(TransactionResult<InMemoryDB>),
}

impl Rejection {
    pub fn describe(&self) -> String {
        match self {
            Rejection::Proving(e) => format!("rejected by the prover: {e}"),
            Rejection::Verification(e) => format!("rejected at verification: {e:?}"),
            Rejection::Application(r) => format!("rejected at application: {r:?}"),
        }
    }

    /// The proof did not verify under the embedded verifier key.
    pub fn is_invalid_proof(&self) -> bool {
        matches!(
            self,
            Rejection::Verification(MalformedTransaction::InvalidProof(_))
        )
    }

    /// The proof verified, but the public transcript it is bound to did not
    /// replay against the contract's current state.
    pub fn is_transcript_failure(&self) -> bool {
        matches!(
            self,
            Rejection::Application(TransactionResult::Failure(TransactionInvalid::Transcript(_)))
        )
    }
}

/// Pays, proves and applies `tx`, which must not succeed. Panics if the ledger
/// accepts and applies it; otherwise reports how it was rejected.
pub async fn attempt(
    state: &mut TestState<InMemoryDB>,
    rng: &mut StdRng,
    resolver: &Resolver,
    tx: UnprovenTx,
) -> Rejection {
    let proven = match pay_and_prove(state, rng, resolver, tx).await {
        Err(e) => return Rejection::Proving(e),
        Ok(proven) => proven,
    };
    apply_rejected(state, &proven, WellFormedStrictness::default())
}

/// Applies an already proven transaction that must not succeed.
pub fn apply_rejected(
    state: &mut TestState<InMemoryDB>,
    proven: &Tx<Signature, InMemoryDB>,
    strictness: WellFormedStrictness,
) -> Rejection {
    match state.apply(proven, strictness) {
        Ok(TransactionResult::Success(_)) => panic!("the transaction was accepted and applied"),
        Ok(other) => Rejection::Application(other),
        Err(e) => Rejection::Verification(e),
    }
}

/// The complete Stage 3 fixture: funded wallet, deployed gate, Alice (the test
/// wallet) and Bob approved with the root published, and one regulated coin
/// issued to Alice.
pub struct Fixture {
    pub rng: StdRng,
    pub state: TestState<InMemoryDB>,
    pub resolver: Resolver,
    pub gate: Gate,
    pub alice: Party,
    pub bob: Party,
}

pub async fn fixture(seed: u64) -> Fixture {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut state: TestState<InMemoryDB> = TestState::new(&mut rng);
    state.give_fee_token(&mut rng, 10).await;
    let resolver = csl_resolver().await;
    let mut gate = deploy_gate(&mut state, &mut rng, &resolver).await;
    // Alice is the test wallet (the wallet `rewards_shielded` funds); Bob is an
    // independent, exchange-operated wallet that only receives.
    let alice = Party {
        keys: state.zswap_keys.clone(),
        slot: 1,
        r: rng.r#gen(),
    };
    let bob = Party::new(&mut rng, 2);
    gate.whitelist.set(alice.slot, alice.leaf());
    gate.whitelist.set(bob.slot, bob.leaf());
    publish_root(&mut state, &mut rng, &resolver, &mut gate).await;
    issue_regulated(&mut state, &mut rng, &gate, AMOUNT);
    Fixture {
        rng,
        state,
        resolver,
        gate,
        alice,
        bob,
    }
}
