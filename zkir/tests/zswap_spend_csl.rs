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

//! Real-proof tests of the CSL spend relation (`ZswapSpendCsl`).
//!
//! - the relation's off-circuit type derivation matches `coin-structure`;
//! - a guarded spend proves and verifies, with a non-zero policy binding;
//! - an `Empty` spend of a legacy (derivable) coin proves with binding `0`;
//! - the native all-zero type proves under `Empty`;
//! - tampering with the binding public input fails verification;
//! - witnessing `Empty` for a guarded coin, or a wrong gate for a guarded
//!   coin, does not yield a verifying proof (the derivation constraint).

use base_crypto::hash::HashOutput;
use coin_structure::contract::ContractAddress;
use coin_structure::custom_spend::SpendRule;
use midnight_zkir::zswap_spend::{SpendWitness, ZSWAP_TREE_HEIGHT, split_bytes32};
use midnight_zkir::zswap_spend_csl::{
    CSL_NUM_PUBLIC_INPUTS, CslSpendWitness, RULE_EMPTY, RULE_GATE_CONTRACT, ZswapSpendCsl,
    derive_token_type,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fs::File;
use std::io::BufReader;
use transient_crypto::curve::Fr;
use transient_crypto_old::proofs::{ParamsProver, VerifierKey};

const PARAMS_DIR: &str = env!("MIDNIGHT_PP");

fn params(k: u8) -> ParamsProver {
    ParamsProver::read(BufReader::new(
        File::open(format!("{PARAMS_DIR}/bls_midnight_2p{k}")).expect("params file must exist"),
    ))
    .expect("params must parse")
}

fn to_old(f: Fr) -> transient_crypto_old::curve::Fr {
    transient_crypto_old::curve::Fr::from_le_bytes(&f.as_le_bytes()).expect("Fr round-trip")
}

fn fr_bytes32(rng: &mut impl Rng) -> [Fr; 2] {
    let bytes: [u8; 32] = rng.r#gen();
    split_bytes32(&bytes)
}

/// A user-owned coin of the given type, with the commitment and Merkle path
/// consistent with the witness, as the equivalence test builds them.
fn base_witness(rng: &mut ChaCha20Rng, token_type: [u8; 32], is_user: bool) -> SpendWitness {
    let mut w = SpendWitness {
        is_user,
        sk: fr_bytes32(rng),
        contract_address: fr_bytes32(rng),
        commitment: [0.into(), 0.into()],
        path: [(Fr::from(0), false); ZSWAP_TREE_HEIGHT],
        nonce: fr_bytes32(rng),
        token_type: split_bytes32(&token_type),
        value: Fr::from(rng.r#gen::<u64>()),
        rc: Fr::from(rng.r#gen::<u64>()),
        binding_input: 0.into(),
        check_root_result: 1.into(),
        segment: Fr::from(rng.r#gen::<u16>() as u64),
    };
    for slot in w.path.iter_mut() {
        *slot = (Fr::from(rng.r#gen::<u64>()), rng.r#gen());
    }
    w.commitment = w.implied_commitment();
    w
}

struct Fixture {
    domain_sep: [u8; 32],
    mint: [u8; 32],
    gate: [u8; 32],
    ep_hash: [u8; 32],
}

impl Fixture {
    fn new(rng: &mut impl Rng) -> Self {
        Fixture {
            domain_sep: rng.r#gen(),
            mint: rng.r#gen(),
            gate: rng.r#gen(),
            ep_hash: rng.r#gen(),
        }
    }
    fn gated_type(&self) -> [u8; 32] {
        derive_token_type(RULE_GATE_CONTRACT, &self.domain_sep, &self.mint, &self.gate, &self.ep_hash)
    }
    fn empty_type(&self) -> [u8; 32] {
        derive_token_type(RULE_EMPTY, &self.domain_sep, &self.mint, &[0u8; 32], &[0u8; 32])
    }
    fn witness(&self, rule_kind: u64, base: SpendWitness) -> CslSpendWitness {
        let (gate, ep) = if rule_kind == RULE_GATE_CONTRACT {
            (self.gate, self.ep_hash)
        } else {
            ([0u8; 32], [0u8; 32])
        };
        CslSpendWitness {
            rule_kind: Fr::from(rule_kind),
            domain_sep: split_bytes32(&self.domain_sep),
            mint_address: split_bytes32(&self.mint),
            gate_address: split_bytes32(&gate),
            ep_hash: split_bytes32(&ep),
            rho: if rule_kind == RULE_GATE_CONTRACT { Fr::from(0xC0FFEE) } else { 0.into() },
            base,
        }
    }
}

#[test]
fn derivation_matches_coin_structure() {
    let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
    let f = Fixture::new(&mut rng);
    let mint = ContractAddress(HashOutput(f.mint));
    let gated = mint.custom_shielded_token_type(
        HashOutput(f.domain_sep),
        &SpendRule::GateContract(ContractAddress(HashOutput(f.gate)), HashOutput(f.ep_hash)),
    );
    assert_eq!(gated.0.0, f.gated_type());
    let empty = mint.custom_shielded_token_type(HashOutput(f.domain_sep), &SpendRule::Empty);
    assert_eq!(empty.0.0, f.empty_type());
}

struct Keys {
    params: ParamsProver,
    vk: midnight_zk_stdlib_v1::MidnightVK,
    pk: midnight_zk_stdlib_v1::MidnightPK<ZswapSpendCsl>,
}

fn keys() -> Keys {
    let relation = ZswapSpendCsl;
    let circuit = midnight_zk_stdlib_v1::MidnightCircuit::from_relation(&relation);
    let k = circuit.min_k() as u8;
    eprintln!("CSL spend relation: k = {k}");
    let params = params(k);
    let vk = midnight_zk_stdlib_v1::setup_vk(params.as_ref(), &relation);
    let pk = midnight_zk_stdlib_v1::setup_pk(&relation, &vk);
    Keys { params, vk, pk }
}

fn prove(keys: &Keys, rng: &mut ChaCha20Rng, witness: &CslSpendWitness) -> Result<(Vec<u8>, Vec<Fr>), String> {
    let pis = witness.public_inputs();
    assert_eq!(pis.len(), CSL_NUM_PUBLIC_INPUTS);
    let pis_old: Vec<_> = pis.iter().map(|pi| to_old(*pi).0).collect();
    midnight_zk_stdlib_v1::prove::<_, transient_crypto_old::proofs::TranscriptHash>(
        keys.params.as_ref(),
        &keys.pk,
        &ZswapSpendCsl,
        &pis_old,
        witness.clone(),
        rng,
    )
    .map(|proof| (proof, pis))
    .map_err(|e| format!("{e:?}"))
}

fn verifies(keys: &Keys, proof: &[u8], pis: &[Fr]) -> bool {
    let vk = VerifierKey::from(keys.vk.clone());
    vk.verify(
        &transient_crypto_old::proofs::PARAMS_VERIFIER,
        &transient_crypto_old::proofs::Proof(proof.to_vec()),
        pis.iter().copied().map(to_old),
    )
    .is_ok()
}

#[test]
fn csl_spend_relation_end_to_end() {
    let mut rng = ChaCha20Rng::from_seed([0x5e; 32]);
    let keys = keys();
    let f = Fixture::new(&mut rng);

    // 1. Guarded coin, correct witness: proves, verifies, binding is non-zero.
    let gated = f.witness(RULE_GATE_CONTRACT, base_witness(&mut rng, f.gated_type(), true));
    assert_eq!(gated.derived_token_type(), f.gated_type());
    let (proof, pis) = prove(&keys, &mut rng, &gated).expect("guarded spend must prove");
    assert!(verifies(&keys, &proof, &pis), "guarded spend must verify");
    assert_ne!(pis[0], Fr::from(0), "guarded spend must carry a policy binding");
    assert_eq!(pis[0], gated.binding());

    // 2. Tampering with the binding slot fails verification (the ledger would
    //    see this when an input claims a different policy than it was proven for).
    let mut bad = pis.clone();
    bad[0] = bad[0] + Fr::from(1);
    assert!(!verifies(&keys, &proof, &bad));
    let mut zeroed = pis.clone();
    zeroed[0] = 0.into();
    assert!(!verifies(&keys, &proof, &zeroed), "a guarded spend cannot be presented as unguarded");
    // 2b. The appended route authenticators are the gate and entry point; changing
    //     any of them (as a claiming contract would) fails verification.
    let n = pis.len();
    for i in [n - 5, n - 4, n - 3, n - 2, n - 1] {
        let mut routed = pis.clone();
        routed[i] = routed[i] + Fr::from(1);
        assert!(!verifies(&keys, &proof, &routed), "tampering with route public input {i} must fail");
    }
    // The mode input is 1 for a guarded coin.
    assert_eq!(pis[n - 5], Fr::from(1), "mode must be GateContract");
    assert_eq!(&pis[n - 4..n - 2], &gated.gate_address, "gate address is authenticated");
    assert_eq!(&pis[n - 2..], &gated.ep_hash, "entry point is authenticated");

    // 3. Legacy coin of an Empty-rule type: proves with binding 0.
    let legacy = f.witness(RULE_EMPTY, base_witness(&mut rng, f.empty_type(), true));
    let (proof, pis) = prove(&keys, &mut rng, &legacy).expect("legacy spend must prove");
    assert!(verifies(&keys, &proof, &pis));
    assert_eq!(pis[0], Fr::from(0));

    // 4. Native (all-zero) type under Empty: proves without a preimage.
    let native = f.witness(RULE_EMPTY, base_witness(&mut rng, [0u8; 32], true));
    let (proof, pis) = prove(&keys, &mut rng, &native).expect("native spend must prove");
    assert!(verifies(&keys, &proof, &pis));

    // 5. Contract-owned guarded coin also binds (sender = contract address).
    let gated_contract = f.witness(RULE_GATE_CONTRACT, base_witness(&mut rng, f.gated_type(), false));
    let (proof, pis) = prove(&keys, &mut rng, &gated_contract).expect("contract-owned guarded spend must prove");
    assert!(verifies(&keys, &proof, &pis));
    assert_ne!(pis[0], Fr::from(0));
}

#[test]
fn csl_spend_relation_rejects_wrong_rule_witness() {
    let mut rng = ChaCha20Rng::from_seed([0x77; 32]);
    let keys = keys();
    let f = Fixture::new(&mut rng);

    // A guarded coin presented as Empty: the derivation does not match.
    let base = base_witness(&mut rng, f.gated_type(), true);
    let as_empty = f.witness(RULE_EMPTY, base.clone());
    match prove(&keys, &mut rng, &as_empty) {
        Err(_) => {}
        Ok((proof, pis)) => assert!(!verifies(&keys, &proof, &pis), "Empty witness for a guarded coin must not verify"),
    }

    // A guarded coin presented with a different gate: the derivation does not match.
    let mut other_gate = f.witness(RULE_GATE_CONTRACT, base.clone());
    other_gate.gate_address = split_bytes32(&rng.r#gen::<[u8; 32]>());
    match prove(&keys, &mut rng, &other_gate) {
        Err(_) => {}
        Ok((proof, pis)) => assert!(!verifies(&keys, &proof, &pis), "wrong gate for a guarded coin must not verify"),
    }

    // A random (underivable) type under Empty: no preimage exists, so it fails.
    let underivable: [u8; 32] = rng.r#gen();
    let random_type = f.witness(RULE_EMPTY, base_witness(&mut rng, underivable, true));
    match prove(&keys, &mut rng, &random_type) {
        Err(_) => {}
        Ok((proof, pis)) => assert!(!verifies(&keys, &proof, &pis), "an underivable type must not spend"),
    }
}

/// Writes the CSL spend verifier key into `zswap/static/spend.verifier` (and its
/// `.sha256` sidecar) in the ledger's embedded format. Run explicitly:
/// `cargo test --release -p midnight-zkir --test zswap_spend_csl write_csl_spend_verifier_key -- --ignored`.
#[test]
#[ignore]
fn write_csl_spend_verifier_key() {
    let keys = keys();
    let vk = VerifierKey::from(keys.vk.clone());
    let mut bytes = Vec::new();
    serialize::tagged_serialize(&vk, &mut bytes).expect("vk serialization must succeed");
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../zswap/static");
    std::fs::write(format!("{dir}/spend.verifier"), &bytes).expect("write vk");
    // The embedded-key pin is `spend.verifier.csl.sha256` (verified by
    // `zswap::verify::embedded_spend_verifier_key_is_the_csl_key`). The
    // `spend.verifier.sha256` sidecar is left untouched: it governs download
    // verification of the legacy artifacts the data provider still serves.
    let digest = base_crypto::hash::persistent_hash(&bytes);
    std::fs::write(
        format!("{dir}/spend.verifier.csl.sha256"),
        format!("{}  spend.verifier\n", hex::encode(digest.0)),
    )
    .expect("write csl sha256");
    eprintln!("wrote {} bytes, persistent_hash {}", bytes.len(), hex::encode(digest.0));
}

/// Closing the previous CSL route: a spend proven with the historical v1 CSL
/// relation (the reviewed implementation's layout: 68 public inputs, gate/ep in
/// the binding, no blinding, no route authenticators) does not verify under the
/// current v2 CSL verifier key. This is the same key the ledger embeds, so the
/// ledger rejects a v1-layout spend proof.
#[test]
fn historical_v1_csl_proofs_do_not_verify_under_v2_key() {
    use midnight_zkir::zswap_spend_csl_v1_historical::{CslSpendWitnessV1, ZswapSpendCslV1};
    let mut rng = ChaCha20Rng::from_seed([0x1a; 32]);
    let keys = keys(); // the current (v2) relation's key
    let f = Fixture::new(&mut rng);

    // Build and prove a v1-layout witness for a guarded coin of a type derived
    // the v1 way (gate/ep in the binding). We reuse the current fixture's gated
    // type, which is identical (the token derivation did not change).
    let base = base_witness(&mut rng, f.gated_type(), true);
    let v1 = CslSpendWitnessV1 {
        rule_kind: Fr::from(RULE_GATE_CONTRACT),
        domain_sep: split_bytes32(&f.domain_sep),
        mint_address: split_bytes32(&f.mint),
        gate_address: split_bytes32(&f.gate),
        ep_hash: split_bytes32(&f.ep_hash),
        base,
    };
    let relation = ZswapSpendCslV1;
    let circuit = midnight_zk_stdlib_v1::MidnightCircuit::from_relation(&relation);
    let k = circuit.min_k() as u8;
    let v1_params = params(k);
    let vk1 = midnight_zk_stdlib_v1::setup_vk(v1_params.as_ref(), &relation);
    let pk1 = midnight_zk_stdlib_v1::setup_pk(&relation, &vk1);
    let pis_v1 = v1.public_inputs();
    let pis_old: Vec<_> = pis_v1.iter().map(|pi| to_old(*pi).0).collect();
    let proof = midnight_zk_stdlib_v1::prove::<_, transient_crypto_old::proofs::TranscriptHash>(
        v1_params.as_ref(),
        &pk1,
        &relation,
        &pis_old,
        v1,
        &mut rng,
    )
    .expect("historical v1 proving must succeed");
    // Sanity: it verifies under its own v1 key.
    assert!(
        VerifierKey::from(vk1)
            .verify(
                &transient_crypto_old::proofs::PARAMS_VERIFIER,
                &transient_crypto_old::proofs::Proof(proof.clone()),
                pis_v1.iter().copied().map(to_old),
            )
            .is_ok(),
        "sanity: the v1 proof verifies under the v1 key"
    );
    // It must NOT verify under the current v2 key, with its own 68 inputs or when
    // padded toward the v2 layout.
    assert!(!verifies(&keys, &proof, &pis_v1), "a v1 CSL proof must be rejected by the v2 key");
}

/// Closing the old proof route: a spend proven with the pre-CSL relation and
/// its proving key does not verify under the CSL verifier key, even for a
/// native coin whose statement is otherwise identical (binding `0`).
#[test]
fn legacy_relation_proofs_do_not_verify_under_csl_key() {
    let mut rng = ChaCha20Rng::from_seed([0x99; 32]);
    let keys = keys();
    let legacy = midnight_zkir::zswap_spend::ZswapSpend;
    let circuit = midnight_zk_stdlib_v1::MidnightCircuit::from_relation(&legacy);
    let k = circuit.min_k() as u8;
    let legacy_params = params(k);
    let vk_legacy = midnight_zk_stdlib_v1::setup_vk(legacy_params.as_ref(), &legacy);
    let pk_legacy = midnight_zk_stdlib_v1::setup_pk(&legacy, &vk_legacy);
    let witness = base_witness(&mut rng, [0u8; 32], true);
    let pis = witness.public_inputs();
    let pis_old: Vec<_> = pis.iter().map(|pi| to_old(*pi).0).collect();
    let proof = midnight_zk_stdlib_v1::prove::<_, transient_crypto_old::proofs::TranscriptHash>(
        legacy_params.as_ref(),
        &pk_legacy,
        &legacy,
        &pis_old,
        witness,
        &mut rng,
    )
    .expect("legacy proving must succeed");
    let legacy_ok = VerifierKey::from(vk_legacy)
        .verify(
            &transient_crypto_old::proofs::PARAMS_VERIFIER,
            &transient_crypto_old::proofs::Proof(proof.clone()),
            pis.iter().copied().map(to_old),
        )
        .is_ok();
    assert!(legacy_ok, "sanity: the legacy proof verifies under the legacy key");
    assert!(
        !verifies(&keys, &proof, &pis),
        "a legacy-relation proof must be rejected by the CSL verifier key"
    );
}
