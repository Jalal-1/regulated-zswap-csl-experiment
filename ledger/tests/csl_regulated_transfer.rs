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

//! Stage 3 of the regulated ZSwap CSL experiment: the decisive revoked-Alice
//! scenario and its controls, through real proofs, strict
//! `Transaction::well_formed` (default strictness) and state application.
//!
//! Test ids refer to the experiment plan's acceptance table.
#![cfg(feature = "proving")]

mod csl_common;

use csl_common::*;
use midnight_ledger::error::{EffectsCheckError, MalformedTransaction};
use midnight_ledger::semantics::TransactionResult;
use midnight_ledger::structure::Transaction;
use midnight_ledger::verify::WellFormedStrictness;
use midnight_ledger_v10 as midnight_ledger;
use rand::Rng;
use transient_crypto::curve::Fr;

fn bob_commitment(tx: &Transaction<midnight_ledger::structure::Signature, midnight_ledger::structure::ProofMarker, transient_crypto::commitment::PedersenRandomness, storage::db::InMemoryDB>) -> coin_structure::coin::Commitment {
    let Transaction::Standard(stx) = tx else {
        panic!("standard transaction expected")
    };
    let offer = stx.guaranteed_coins.as_ref().expect("guaranteed offer");
    offer.outputs.iter().next().expect("one output").coin_com
}

/// T01: approved Alice -> approved Bob is accepted and applied.
#[tokio::test]
async fn t01_approved_to_approved_is_accepted() {
    let mut f = fixture(0x01).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &Default::default());
    let nullifier = first_input_nullifier(&tx);
    let proven = pay_and_prove(&mut f.state, &mut f.rng, &f.resolver, tx)
        .await
        .expect("an approved transfer must prove");
    let cm = bob_commitment(&proven);
    let result = f
        .state
        .apply(&proven, WellFormedStrictness::default())
        .expect("an approved transfer must be well-formed");
    assert!(matches!(result, TransactionResult::Success(_)), "got {result:?}");
    assert!(f.state.ledger.zswap.nullifiers.get(&nullifier).is_some(), "Alice's coin must be consumed");
    assert!(f.state.ledger.zswap.coin_coms_set.get(&cm).is_some(), "Bob's coin must be created");
}

/// T02 / T12: Alice is funded while approved, then removed. A proof she made
/// before removal verifies (it is valid for the old root) but fails when the
/// ledger replays the gate's transcript against the current root; her coin is
/// not consumed; and a fresh proof under the new root does not verify.
#[tokio::test]
async fn t02_revoked_sender_cannot_move_the_coin() {
    let mut f = fixture(0x02).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    // Pre-removal proof, retained by Alice.
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &Default::default());
    let nullifier = first_input_nullifier(&tx);
    let stale = pay_and_prove(&mut f.state, &mut f.rng, &f.resolver, tx)
        .await
        .expect("pre-removal transfer must prove");
    // Monument removes Alice and publishes the new root.
    f.gate.whitelist.remove(f.alice.slot);
    publish_root(&mut f.state, &mut f.rng, &f.resolver, &mut f.gate).await;
    // The stale transaction fails when the ledger replays the gate's root claim.
    let before = f.state.ledger.clone();
    let rej = apply_rejected(&mut f.state, &stale, WellFormedStrictness::default());
    eprintln!("stale transfer: {}", rej.describe());
    assert!(rej.is_transcript_failure(), "unexpected disposal of the stale transfer: {}", rej.describe());
    assert!(f.state.ledger.zswap.nullifiers.get(&nullifier).is_none(), "Alice's coin must not be consumed");
    assert_eq!(f.state.ledger.zswap.coin_coms_set.size(), before.zswap.coin_coms_set.size(), "no output may be created");
    // A fresh attempt: Alice has no membership path under the new root, so the
    // only proof she can make is invalid.
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &Default::default());
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("fresh transfer after removal: {}", rej.describe());
    assert!(rej.is_invalid_proof(), "unexpected disposal of the fresh transfer: {}", rej.describe());
    assert!(f.state.ledger.zswap.nullifiers.get(&nullifier).is_none(), "Alice's coin must not be consumed");
}

/// T06: a raw spend of the regulated coin with no gate call is rejected by the
/// real verifier, before any state change.
#[tokio::test]
async fn t06_omitted_gate_call_is_rejected() {
    let mut f = fixture(0x06).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let opts = TransferOptions { omit_gate_call: true, ..Default::default() };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &opts);
    let nullifier = first_input_nullifier(&tx);
    let proven = pay_and_prove(&mut f.state, &mut f.rng, &f.resolver, tx)
        .await
        .expect("the spend itself proves; the policy is enforced by the ledger");
    let err = proven
        .well_formed(&f.state.ledger, WellFormedStrictness::default(), f.state.time)
        .err()
        .expect("must be rejected");
    assert!(
        matches!(err, MalformedTransaction::EffectsCheckFailure(EffectsCheckError::SpendAuthorizationsNEClaimed { .. })),
        "unexpected rejection: {err:?}"
    );
    assert!(f.state.ledger.zswap.nullifiers.get(&nullifier).is_none());
}

/// T07: the gate is shown an approved sender (Bob) while Alice's coin is spent.
/// The spend proof binds Alice's real key, so the ledger sees two different
/// bindings and rejects the transaction.
#[tokio::test]
async fn t07_substituted_sender_is_rejected() {
    let mut f = fixture(0x07).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let bob = Party { keys: f.bob.keys.clone(), slot: f.bob.slot, r: f.bob.r };
    let opts = TransferOptions { claim_sender: Some(&bob), ..Default::default() };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &opts);
    let proven = pay_and_prove(&mut f.state, &mut f.rng, &f.resolver, tx)
        .await
        .expect("the gate accepts Bob as a sender; the mismatch is the ledger's to catch");
    let err = proven
        .well_formed(&f.state.ledger, WellFormedStrictness::default(), f.state.time)
        .err()
        .expect("must be rejected");
    assert!(
        matches!(err, MalformedTransaction::EffectsCheckFailure(EffectsCheckError::SpendAuthorizationsNEClaimed { .. })),
        "unexpected rejection: {err:?}"
    );
}

/// T08: the gate checks Bob, but the offer's output pays Carol.
#[tokio::test]
async fn t08_output_to_unchecked_recipient_is_rejected() {
    let mut f = fixture(0x08).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let carol = Party::new(&mut f.rng, 9);
    let opts = TransferOptions { pay_instead: Some(&carol), ..Default::default() };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &opts);
    let proven = pay_and_prove(&mut f.state, &mut f.rng, &f.resolver, tx)
        .await
        .expect("the gate's own statement is consistent; the coverage mismatch is the ledger's to catch");
    let err = proven
        .well_formed(&f.state.ledger, WellFormedStrictness::default(), f.state.time)
        .err()
        .expect("must be rejected");
    assert!(
        matches!(err, MalformedTransaction::EffectsCheckFailure(EffectsCheckError::OutputCoverageNESegmentCommitments { .. })),
        "unexpected rejection: {err:?}"
    );
}

/// T04: approved Alice -> unapproved Carol. Carol has no membership path under
/// the published root, so the gate's proof is invalid and strict verification
/// rejects the transaction.
#[tokio::test]
async fn t04_unapproved_recipient_cannot_be_proven() {
    let mut f = fixture(0x04).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let carol = Party::new(&mut f.rng, 9);
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &carol, &coin, &Default::default());
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("transfer to an unapproved recipient: {}", rej.describe());
    assert!(rej.is_invalid_proof(), "unexpected disposal: {}", rej.describe());
    assert!(f.state.ledger.zswap.nullifiers.get(&nullifier).is_none());
}

/// T13 (a): membership proven against an attacker-chosen root that the
/// transcript also claims. The proof is valid for its own statement, but the
/// ledger replays the root claim against the contract state and the
/// transaction fails at application.
#[tokio::test]
async fn t13_attacker_chosen_root_fails_at_replay() {
    let mut f = fixture(0x13).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let mut forged = f.gate.whitelist.clone();
    let carol = Party::new(&mut f.rng, 9);
    forged.set(carol.slot, carol.leaf());
    let opts = TransferOptions {
        whitelist_override: Some(&forged),
        claim_forged_root: true,
        ..Default::default()
    };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &opts);
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("forged root, claimed: {}", rej.describe());
    assert!(rej.is_transcript_failure(), "unexpected disposal: {}", rej.describe());
    assert!(f.state.ledger.zswap.nullifiers.get(&nullifier).is_none());
}

/// T13 (b): membership proven against an attacker-chosen root while the
/// transcript claims the real one. The statement and the witness disagree, so
/// the proof is invalid.
#[tokio::test]
async fn t13b_forged_root_in_witness_is_an_invalid_proof() {
    let mut f = fixture(0x14).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let mut forged = f.gate.whitelist.clone();
    let carol = Party::new(&mut f.rng, 9);
    forged.set(carol.slot, carol.leaf());
    let opts = TransferOptions {
        whitelist_override: Some(&forged),
        ..Default::default()
    };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &opts);
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("forged root, unclaimed: {}", rej.describe());
    assert!(rej.is_invalid_proof(), "unexpected disposal: {}", rej.describe());
    assert!(f.state.ledger.zswap.nullifiers.get(&nullifier).is_none());
}

/// T24: a whitelist update with the wrong administrator secret. The relation
/// ties the secret to the admin key in the contract state, so the proof is
/// invalid and nothing is applied.
#[tokio::test]
async fn t24_wrong_admin_secret_cannot_update_root() {
    let mut f = fixture(0x24).await;
    let wrong: Fr = f.rng.r#gen();
    let tx = update_root_tx(&f.state, &mut f.rng, &f.gate, Fr::from(7), wrong);
    let rej = match midnight_ledger::test_utilities::tx_prove(f.rng.clone(), &tx, &f.resolver).await {
        Err(e) => Rejection::Proving(format!("{e:?}")),
        Ok(proven) => {
            let mut strictness = WellFormedStrictness::default();
            strictness.enforce_balancing = false;
            apply_rejected(&mut f.state, &proven, strictness)
        }
    };
    eprintln!("update with the wrong secret: {}", rej.describe());
    assert!(
        matches!(rej, Rejection::Proving(_)) || rej.is_invalid_proof(),
        "unexpected disposal: {}",
        rej.describe()
    );
}
