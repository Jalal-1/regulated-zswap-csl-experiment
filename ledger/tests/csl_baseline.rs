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

//! Stage 0 controls for the regulated ZSwap Custom Spend Logic experiment.
//!
//! Every later CSL claim is measured against these three facts, all taken
//! through the real transaction verifier (`Transaction::well_formed` with the
//! default `WellFormedStrictness`, i.e. native proofs, contract proofs and
//! balancing all enforced) and then through state application:
//!
//! 1. an ordinary shielded transfer from one user wallet to another is
//!    accepted and applied (positive control);
//! 2. the same transaction with one corrupted byte in the spend proof is
//!    rejected with `MalformedOffer::InvalidProof` (proof-integrity control);
//! 3. the same transaction with an altered public statement, here the input's
//!    nullifier, is rejected the same way (statement-binding control).
//!
//! The negative controls never touch the ledger state: `well_formed` is pure,
//! and the assertions check that the original coin's nullifier is still absent
//! from the nullifier set afterwards.
#![cfg(feature = "proving")]

use std::ops::Deref;
use std::sync::Arc;

use base_crypto::rng::SplittableRng;
use coin_structure::coin::{Info as CoinInfo, Nullifier};
use lazy_static::lazy_static;
use midnight_ledger::error::MalformedTransaction;
use midnight_ledger::semantics::TransactionResult;
use midnight_ledger::structure::{ProofPreimageMarker, Signature, Transaction};
use midnight_ledger::test_utilities::{
    Resolver, TestState, Tx, test_intents, test_resolver, tx_prove,
};
use midnight_ledger::verify::WellFormedStrictness;
use midnight_ledger_v10 as midnight_ledger;
use rand::{Rng, SeedableRng, rngs::StdRng};
use storage::arena::Sp;
use storage::db::InMemoryDB;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::proofs::Proof;
use zswap::error::MalformedOffer;
use zswap::keys::SecretKeys;
use zswap::{Input, Offer, Output};

lazy_static! {
    static ref RESOLVER: Resolver = test_resolver("");
}

const AMOUNT: u128 = 100_000_000;

/// Pays exactly `fee` Specks of DUST for `tx`, from the test wallet, in a
/// fee-only intent at segment `0xFEED` (the layout `TestState::balance_tx` uses).
///
/// The ledger prices a transaction by its serialized size, and a real proof is
/// larger than the mock proof the balancing helper prices against, so the
/// helper underpays by a fixed amount. Paying a known exact fee avoids that:
/// proof sizes are deterministic, so the fee of the transaction built here
/// equals the fee measured on an earlier proven build of the same shape.
fn pay_exact_dust_fee(
    state: &mut TestState<InMemoryDB>,
    rng: &mut StdRng,
    tx: Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>,
    fee: u128,
) -> Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB> {
    use midnight_ledger::dust::{DustActions, DustOutput};
    use midnight_ledger::structure::Intent;
    let mut remaining = fee;
    let mut spends = storage::storage::Array::new();
    let utxos = state.dust.utxos().collect::<Vec<_>>();
    for qdo in utxos {
        if remaining == 0 {
            break;
        }
        let gen_info = state.dust.generation_info(&qdo).expect("generation info");
        let value = DustOutput::from(qdo).updated_value(&gen_info, state.time, &state.ledger.parameters.dust);
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
    let mut intent = Intent::empty(rng, state.time);
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

/// Builds and proves a plain Alice -> Bob shielded transfer of `AMOUNT` of the
/// default (unguarded) shielded token. Fees are paid in DUST in a separate
/// intent, so the zswap offer carries exactly one input and one output.
async fn proven_transfer(seed: u64) -> (TestState<InMemoryDB>, Tx<Signature, InMemoryDB>, Nullifier) {
    use midnight_ledger::test_utilities::dbg_fees_with_state;
    let mut rng = StdRng::seed_from_u64(seed);
    let mut state: TestState<InMemoryDB> = TestState::new(&mut rng);
    let token = Default::default();
    state.give_fee_token(&mut rng, 10).await;
    state.rewards_shielded(&mut rng, token, AMOUNT);

    let alice_coin = *state.zswap.coins.iter().next().expect("rewarded coin").1;
    let bob = SecretKeys::from_rng_seed(&mut rng);

    let (_, input) = state
        .zswap
        .spend(&mut rng, &state.zswap_keys, &alice_coin, Some(0))
        .expect("spend construction");
    let nullifier = input.nullifier;
    let bob_coin = CoinInfo {
        nonce: rng.r#gen(),
        value: AMOUNT,
        type_: token,
    };
    let output = Output::new(
        &mut rng,
        &bob_coin,
        Some(0),
        &bob.coin_public_key(),
        Some(bob.enc_public_key()),
    )
    .expect("output construction");
    let offer = Offer {
        inputs: vec![input].into(),
        outputs: vec![output].into(),
        transient: vec![].into(),
        deltas: vec![].into(),
    };
    let tx: Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB> =
        Transaction::new(
            "local-test",
            test_intents(&mut rng, Vec::new(), Vec::new(), Vec::new(), state.time),
            Some(offer),
            Default::default(),
        );

    // Pass 1: learn the exact fee of the proven shape.
    let mut trial = state.clone();
    let trial_tx = pay_exact_dust_fee(&mut trial, &mut rng.clone(), tx.clone(), 1);
    let trial_proven = tx_prove(rng.split(), &trial_tx, &RESOLVER).await.expect("trial proving");
    let fee = dbg_fees_with_state(&trial_proven, &state.ledger.parameters, &state.ledger, true)
        .expect("fee computation");

    // Pass 2: pay it.
    let paid = pay_exact_dust_fee(&mut state, &mut rng, tx, fee);
    let proven = tx_prove(rng.split(), &paid, &RESOLVER).await.expect("proving");
    (state, proven, nullifier)
}

/// Returns a copy of `tx` whose first guaranteed input was altered by `f`.
fn with_altered_first_input(
    tx: &Tx<Signature, InMemoryDB>,
    f: impl FnOnce(&mut Input<Proof, InMemoryDB>),
) -> Tx<Signature, InMemoryDB> {
    let mut tx = tx.clone();
    let Transaction::Standard(stx) = &mut tx else {
        panic!("standard transaction expected");
    };
    let offer = stx
        .guaranteed_coins
        .as_ref()
        .expect("guaranteed offer")
        .deref()
        .clone();
    let mut inputs: Vec<Input<Proof, InMemoryDB>> = offer.inputs.iter_deref().cloned().collect();
    f(&mut inputs[0]);
    let altered = Offer {
        inputs: inputs.into(),
        outputs: offer.outputs.clone(),
        transient: offer.transient.clone(),
        deltas: offer.deltas.clone(),
    };
    stx.guaranteed_coins = Some(Sp::new(altered));
    tx
}

fn assert_invalid_proof(err: MalformedTransaction<InMemoryDB>) {
    assert!(
        matches!(
            err,
            MalformedTransaction::Zswap(MalformedOffer::InvalidProof(_))
        ),
        "expected the spend proof to be rejected, got: {err:?}"
    );
}

#[tokio::test]
async fn csl_baseline_plain_transfer_is_accepted() {
    let (mut state, proven, nullifier) = proven_transfer(0x5e).await;
    assert!(state.ledger.zswap.nullifiers.get(&nullifier).is_none());
    let result = state
        .apply(&proven, WellFormedStrictness::default())
        .expect("plain transfer must be well-formed under default strictness");
    assert!(
        matches!(result, TransactionResult::Success(_)),
        "plain transfer must apply fully, got: {result:?}"
    );
    assert!(
        state.ledger.zswap.nullifiers.get(&nullifier).is_some(),
        "the spent coin's nullifier must be recorded"
    );
}

#[tokio::test]
async fn csl_baseline_corrupted_spend_proof_is_rejected() {
    let (state, proven, nullifier) = proven_transfer(0x5e).await;
    let bad = with_altered_first_input(&proven, |input| {
        let mut proof = (*input.proof).clone();
        let i = proof.bytes.len() / 2;
        proof.bytes[i] ^= 0x01;
        input.proof = Arc::new(proof);
    });
    let err = bad
        .well_formed(&state.ledger, WellFormedStrictness::default(), state.time)
        .err()
        .expect("corrupted proof must be rejected");
    assert_invalid_proof(err);
    assert!(state.ledger.zswap.nullifiers.get(&nullifier).is_none());
}

#[tokio::test]
async fn csl_baseline_altered_statement_is_rejected() {
    let (state, proven, nullifier) = proven_transfer(0x5e).await;
    let mut rng = StdRng::seed_from_u64(0x77);
    let bad = with_altered_first_input(&proven, |input| {
        input.nullifier = rng.r#gen();
    });
    let err = bad
        .well_formed(&state.ledger, WellFormedStrictness::default(), state.time)
        .err()
        .expect("altered statement must be rejected");
    assert_invalid_proof(err);
    assert!(state.ledger.zswap.nullifiers.get(&nullifier).is_none());
}
