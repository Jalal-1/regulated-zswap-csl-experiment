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

//! Regression tests for the regulated ZSwap CSL fixes (fix prompt sections 1-5).
//!
//! Every test uses real proofs, strict `Transaction::well_formed`, and state
//! application. The headline case is the malicious-gate attack of section 1: a
//! genuine spend whose on-the-wire policy routing fields are repointed to an
//! attacker-controlled permissive gate. Against the reviewed (pre-fix)
//! implementation this attack is ACCEPTED (see
//! `results/attack_reproduction_*_8285f69.log`); the fixed implementation
//! authenticates the route in the spend statement, so it is rejected at
//! verification with no state change.
#![cfg(feature = "proving")]

mod csl_common;

use csl_common::*;
use midnight_ledger::verify::WellFormedStrictness;
use midnight_ledger_v10 as midnight_ledger;

fn assert_coin_untouched(before: &midnight_ledger::structure::LedgerState<storage::db::InMemoryDB>, f: &Fixture, nullifier: coin_structure::coin::Nullifier) {
    assert!(f.state.ledger.zswap.nullifiers.get(&nullifier).is_none(), "the regulated coin must not be consumed");
    assert_eq!(
        f.state.ledger.zswap.coin_coms_set.size(),
        before.zswap.coin_coms_set.size(),
        "no output may be created"
    );
}

// ---------------------------------------------------------------------------
// Section 1: authenticate the gate the ledger routes on.
// ---------------------------------------------------------------------------

/// 1a. Gate-address substitution with the genuine binding/proof retained, by a
/// sender Monument has removed from the whitelist (the decisive scenario).
#[tokio::test]
async fn attack_gate_substitution_is_rejected() {
    let mut f = fixture(0x101).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    f.gate.whitelist.remove(f.alice.slot);
    publish_root(&mut f.state, &mut f.rng, &f.resolver, &mut f.gate).await;
    let permissive =
        deploy_permissive_gate(&mut f.state, &mut f.rng, &f.resolver, f.gate.token_type).await;
    let before = f.state.ledger.clone();
    let tx = attack_substitute_gate_tx(&f.state, &mut f.rng, &f.gate, &permissive, &f.bob, &coin);
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("gate-substitution attack: {}", rej.describe());
    assert!(rej.is_spend_proof_invalid(), "must fail native spend verification; got {}", rej.describe());
    assert_coin_untouched(&before, &f, nullifier);
}

/// 1b. Entry-point substitution: route a genuine spend to a different entry
/// point hash on the real gate. The statement authenticates the entry point.
#[tokio::test]
async fn route_entry_point_substitution_is_rejected() {
    let mut f = fixture(0x102).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let before = f.state.ledger.clone();
    let opts = TransferOptions { route_ep: Some(f.gate.ep_update_root), ..Default::default() };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &opts);
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("entry-point substitution: {}", rej.describe());
    assert!(rej.is_spend_proof_invalid(), "got {}", rej.describe());
    assert_coin_untouched(&before, &f, nullifier);
}

/// 1c. A cloned gate with an attacker-controlled whitelist: Alice (revoked at
/// the real gate) deploys a clone that approves her, and routes to it. The coin
/// type is bound to the real gate's address, which the clone cannot have, so the
/// route cannot be authenticated.
#[tokio::test]
async fn attack_cloned_gate_is_rejected() {
    let mut f = fixture(0x103).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    f.gate.whitelist.remove(f.alice.slot);
    publish_root(&mut f.state, &mut f.rng, &f.resolver, &mut f.gate).await;
    // The clone is a real, permissive gate at a fresh address (its "whitelist"
    // approves everyone). Routing to it is the same class as 1a and is rejected.
    let clone = deploy_permissive_gate(&mut f.state, &mut f.rng, &f.resolver, f.gate.token_type).await;
    let before = f.state.ledger.clone();
    let tx = attack_substitute_gate_tx(&f.state, &mut f.rng, &f.gate, &clone, &f.bob, &coin);
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("cloned-gate attack: {}", rej.describe());
    assert!(rej.is_spend_proof_invalid(), "got {}", rej.describe());
    assert_coin_untouched(&before, &f, nullifier);
}

/// 1d. Omitting the policy (presenting a guarded coin as unguarded) fails: the
/// spend statement's mode input is authenticated, so an unguarded reading needs
/// mode 0, which the proof (mode 1) does not provide.
#[tokio::test]
async fn omitted_policy_is_rejected() {
    let mut f = fixture(0x104).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let before = f.state.ledger.clone();
    let opts = TransferOptions { omit_policy: true, omit_gate_call: true, ..Default::default() };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &opts);
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("omitted policy: {}", rej.describe());
    assert!(rej.is_spend_proof_invalid(), "got {}", rej.describe());
    assert_coin_untouched(&before, &f, nullifier);
}

/// 1e. Omitting the gate call while keeping the policy fails the matching rule.
#[tokio::test]
async fn omitted_gate_call_is_rejected() {
    let mut f = fixture(0x105).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let before = f.state.ledger.clone();
    let opts = TransferOptions { omit_gate_call: true, ..Default::default() };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &opts);
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("omitted gate call: {}", rej.describe());
    assert!(rej.is_authorization_mismatch(), "got {}", rej.describe());
    assert_coin_untouched(&before, &f, nullifier);
}

/// 1f. The correctly routed approved transfer still succeeds.
#[tokio::test]
async fn approved_transfer_still_succeeds() {
    let mut f = fixture(0x106).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let nullifier;
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &Default::default());
    nullifier = first_input_nullifier(&tx);
    let proven = pay_and_prove(&mut f.state, &mut f.rng, &f.resolver, tx).await.expect("approved transfer must prove");
    let result = f.state.apply(&proven, WellFormedStrictness::default()).expect("must be well-formed");
    assert!(matches!(result, midnight_ledger::semantics::TransactionResult::Success(_)), "got {result:?}");
    assert!(f.state.ledger.zswap.nullifiers.get(&nullifier).is_some(), "the coin is consumed");
}

// ---------------------------------------------------------------------------
// Section 2: the hiding binding.
// ---------------------------------------------------------------------------

/// 2a. Mismatched blinding between the native spend and the gate proof cannot
/// authorize: the two bindings differ, so the matching rule rejects it.
#[tokio::test]
async fn mismatched_blinding_is_rejected() {
    let mut f = fixture(0x201).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let before = f.state.ledger.clone();
    let opts = TransferOptions { gate_rho_override: Some(transient_crypto::curve::Fr::from(0xBADBAD)), ..Default::default() };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &opts);
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("mismatched blinding: {}", rej.describe());
    assert!(rej.is_authorization_mismatch(), "got {}", rej.describe());
    assert_coin_untouched(&before, &f, nullifier);
}

/// 2b. Tampering with the public binding value fails the native spend proof.
#[tokio::test]
async fn tampered_binding_is_rejected() {
    let mut f = fixture(0x202).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let before = f.state.ledger.clone();
    let opts = TransferOptions { tamper_binding: true, ..Default::default() };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &opts);
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("tampered binding: {}", rej.describe());
    assert!(rej.is_spend_proof_invalid(), "got {}", rej.describe());
    assert_coin_untouched(&before, &f, nullifier);
}

// ---------------------------------------------------------------------------
// Section 3: protected-token configuration.
// ---------------------------------------------------------------------------

/// 3a. A transfer fails before the gate's protected type is initialized.
#[tokio::test]
async fn transfer_before_initialization_is_rejected() {
    let mut f = fixture_uninitialized(0x301).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let before = f.state.ledger.clone();
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &Default::default());
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("transfer before init: {}", rej.describe());
    assert!(
        matches!(rej, Rejection::Proving(_)) || rej.is_authorization_mismatch() || rej.is_spend_proof_invalid(),
        "a transfer before initialization must be rejected; got {}",
        rej.describe()
    );
    assert_coin_untouched(&before, &f, nullifier);
}

/// 3b. Initialization cannot be repeated to retarget the protected type: the
/// honest second `init` claims the cell is still zero and the ledger's replay
/// rejects it; and a forged-state second `init` (run against a faked zero cell)
/// is rejected the same way when replayed against real state.
#[tokio::test]
async fn second_initialization_cannot_retarget() {
    let mut f = fixture(0x302).await; // already initialized
    let other = sibling_derivation(&f.gate, [0x5a; 32]).token_type();
    // A second `init` can only be *built* against a forged copy of the state in
    // which the type cell is still zero (an honest second init fails at
    // transcript construction, because the real cell is no longer zero -- the
    // one-time guarantee already bites there). The attacker forges that state to
    // get a provable transcript; the ledger then replays it against the real
    // (set) cell and rejects it with a read mismatch.
    let tx = init_gate_tx(&f.state, &mut f.rng, &f.gate, f.gate.current_root, other, f.gate.admin_secret, true);
    let rej = match midnight_ledger::test_utilities::tx_prove(f.rng.clone(), &tx, &f.resolver).await {
        Err(e) => Rejection::Proving(format!("{e:?}")),
        Ok(proven) => {
            let mut st = WellFormedStrictness::default();
            st.enforce_balancing = false;
            apply_rejected(&mut f.state, &proven, st)
        }
    };
    eprintln!("second init (forged state): {}", rej.describe());
    assert!(rej.is_transcript_failure(), "a forged-state re-init must fail at replay; got {}", rej.describe());
}

/// 3c. Initialization with the wrong administrator secret cannot be proven.
#[tokio::test]
async fn init_with_wrong_admin_is_rejected() {
    let mut f = fixture_uninitialized(0x303).await;
    let wrong = transient_crypto::curve::Fr::from(0x1234);
    let tx = init_gate_tx(&f.state, &mut f.rng, &f.gate, f.gate.whitelist.root(), f.gate.token_type, wrong, false);
    let rej = match midnight_ledger::test_utilities::tx_prove(f.rng.clone(), &tx, &f.resolver).await {
        Err(e) => Rejection::Proving(format!("{e:?}")),
        Ok(proven) => {
            let mut st = WellFormedStrictness::default();
            st.enforce_balancing = false;
            apply_rejected(&mut f.state, &proven, st)
        }
    };
    eprintln!("init with wrong admin: {}", rej.describe());
    assert!(
        matches!(rej, Rejection::Proving(_)) || rej.is_invalid_proof(),
        "an unauthorized init must be rejected; got {}",
        rej.describe()
    );
}

/// 3d. A second asset whose descriptor names the same gate obtains no
/// authorization at all (not sender-only): its spend binding commits to its own
/// type, which the gate's cell type does not match.
#[tokio::test]
async fn second_asset_at_same_gate_gets_no_authorization() {
    let mut f = fixture(0x304).await;
    let deriv2 = sibling_derivation(&f.gate, [0x77; 32]);
    let t2 = deriv2.token_type();
    issue_token(&mut f.state, &mut f.rng, t2, AMOUNT);
    let coin2 = coins_of_type(&f.state, t2)[0];
    let before = f.state.ledger.clone();
    let opts = TransferOptions { derivation_override: Some(&deriv2), ..Default::default() };
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin2, &opts);
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("second asset at same gate: {}", rej.describe());
    assert!(rej.is_authorization_mismatch(), "got {}", rej.describe());
    assert_coin_untouched(&before, &f, nullifier);
}

/// 3e. After an ordinary root update, the protected asset is unchanged: approved
/// transfers still work and approved -> unapproved is still rejected.
#[tokio::test]
async fn protected_asset_survives_root_update() {
    let mut f = fixture(0x305).await;
    // A second regulated coin, so one remains after the successful transfer.
    issue_regulated(&mut f.state, &mut f.rng, &f.gate, AMOUNT);
    // An ordinary update (re-publishing the same membership) touches only the root.
    publish_root(&mut f.state, &mut f.rng, &f.resolver, &mut f.gate).await;
    // Approved -> approved still succeeds: the protected type still authorizes.
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &Default::default());
    let proven = pay_and_prove(&mut f.state, &mut f.rng, &f.resolver, tx)
        .await
        .expect("approved transfer after update must prove");
    let result = f.state.apply(&proven, WellFormedStrictness::default()).expect("must be well-formed");
    assert!(matches!(result, midnight_ledger::semantics::TransactionResult::Success(_)), "got {result:?}");
    // Approved -> unapproved is still rejected: the gate proof cannot show Carol's
    // membership, so the (contract) gate proof is invalid.
    let coin = regulated_coins(&f.state, &f.gate)[0];
    let carol = Party::new(&mut f.rng, 9);
    let before = f.state.ledger.clone();
    let tx = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &carol, &coin, &Default::default());
    let nullifier = first_input_nullifier(&tx);
    let rej = attempt(&mut f.state, &mut f.rng, &f.resolver, tx).await;
    eprintln!("approved->unapproved after update: {}", rej.describe());
    assert!(rej.is_invalid_proof(), "got {}", rej.describe());
    assert_coin_untouched(&before, &f, nullifier);
}

// ---------------------------------------------------------------------------
// Section 5: no active fallback accepts an old-layout spend proof.
// ---------------------------------------------------------------------------

/// A spend proof in the historical v1 CSL layout (68 public inputs, gate/ep in
/// the binding, no blinding, no route authenticators), produced by the frozen
/// `zswap_spend_csl_v1_historical` relation and spliced into an otherwise valid
/// transfer, is rejected by the ledger's embedded (v2) verifier through the full
/// `Transaction::well_formed` path.
#[tokio::test]
async fn historical_v1_spend_proof_is_rejected_by_the_ledger() {
    let mut f = fixture(0x501).await;
    let coin = regulated_coins(&f.state, &f.gate)[0];
    // Build the unproven transfer and lift the spend preimage out of it.
    let unproven = regulated_transfer_tx(&f.state, &mut f.rng, &f.gate, &f.alice, &f.bob, &coin, &Default::default());
    let nullifier = first_input_nullifier(&unproven);
    let preimage = first_input_preimage(&unproven);
    let (v1_proof, _pis) = zkir_v2::zswap_spend_csl_v1_historical::prove_v1_from_v2_preimage(
        f.rng.clone(),
        &*midnight_ledger::test_utilities::PUBLIC_PARAMS,
        &preimage,
    )
    .await
    .expect("historical v1 spend proving must succeed");
    // Prove the transfer normally, then splice the v1-layout spend proof in.
    let before = f.state.ledger.clone();
    let proven = pay_and_prove(&mut f.state, &mut f.rng, &f.resolver, unproven)
        .await
        .expect("baseline transfer proves");
    let v1_bytes = v1_proof.bytes.clone();
    let spliced = with_altered_first_input(&proven, |input| {
        let mut proof = (*input.proof).clone();
        proof.bytes = v1_bytes.clone();
        input.proof = std::sync::Arc::new(proof);
    });
    let rej = apply_rejected(&mut f.state, &spliced, WellFormedStrictness::default());
    eprintln!("spliced historical v1 spend proof: {}", rej.describe());
    assert!(rej.is_spend_proof_invalid(), "the embedded v2 verifier must reject a v1-layout proof; got {}", rej.describe());
    assert!(f.state.ledger.zswap.nullifiers.get(&nullifier).is_none(), "coin not consumed");
    let _ = before;
}
