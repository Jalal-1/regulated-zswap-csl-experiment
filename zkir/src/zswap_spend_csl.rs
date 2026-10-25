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

//! The Custom Spend Logic (CSL) variant of the zswap spend circuit.
//!
//! This relation is the production spend circuit of the regulated ZSwap
//! experiment. It proves everything [`ZswapSpend`](crate::zswap_spend::ZswapSpend)
//! proves, with the same 68 public inputs in the same order, plus two CSL
//! obligations that are asserted unconditionally on every spend:
//!
//! 1. *Type re-derivation.* The coin's token type is the ledger derivation of a
//!    witnessed `(domain separator, minting contract address, spend rule)`:
//!    `SHA256(sep32 || domain_sep || mint_address)` for `SpendRule::Empty`, or
//!    `SHA256(sep32 || domain_sep || mint_address || SHA256(descriptor_bytes))`
//!    for `SpendRule::GateContract(gate, ep_hash)`, where `descriptor_bytes` is
//!    the tagged serialization `"midnight:spend-rule[v1]:" || 0x02 || gate || ep_hash`.
//!    The all-zero native token type is accepted under `Empty` without a
//!    preimage. `GateCircuit` descriptors cannot be expressed (the rule kind
//!    is a bit) and therefore fail closed.
//! 2. *Policy binding.* The first public input, the binding slot that is
//!    constant zero for every spend today, becomes
//!    `Poseidon(DOM_BIND, nullifier, sender, gate, ep_hash)` for guarded coins
//!    and stays `0` for `Empty` coins. `sender` is the coin public key derived
//!    in-circuit from the spending key (or the owning contract address). The
//!    ledger matches this value against the gate contract's claimed
//!    authorizations, so a guarded coin cannot be spent without a bound gate
//!    call, and the gate cannot be shown a different sender than the one whose
//!    key authorizes the spend.
//!
//! Witness layout: nine CSL field elements are *prepended* to the legacy
//! [`SpendWitness`] layout, so the tail-based accessors on `ProofPreimage`
//! (`Input::delta`, `Input::binding_randomness`) keep working unchanged.

use group::Group;
use midnight_circuits_v1::instructions::{
    AssignmentInstructions, ControlFlowInstructions, ConversionInstructions,
    DecompositionInstructions, EccInstructions, EqualityInstructions, PublicInputInstructions,
    ZeroInstructions,
};
use midnight_circuits_v1::types::{AssignedBit, AssignedNative};
use midnight_proofs_v1::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use midnight_zk_stdlib_v1::{MidnightPK, MidnightVK, Relation, ZkStdLib, ZkStdLibArch};
use rand::{CryptoRng, Rng};
use std::sync::{Arc, OnceLock};
use transient_crypto::curve::Fr;
use transient_crypto::hash::transient_hash;
use transient_crypto::proofs::{Proof, ProofPreimage};

use crate::ir_v1::{
    OldEmbeddedAffine, OldEmbeddedAffineExt, OldScalar, V1Params, cvt, v1_assemble_bytes,
    v1_ecc_from_parts, v1_fab_decode_to_bytes,
};
use crate::zswap_spend::{
    CC_DOMAIN_SEP, CN_DOMAIN_SEP, NUM_INPUTS as LEGACY_NUM_INPUTS, NUM_PUBLIC_INPUTS,
    PK_DOMAIN_SEP, SpendWitness, ZSWAP_TREE_HEIGHT, join_bytes32, split_bytes32,
};
use base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};

/// Number of CSL witness elements prepended to the legacy spend witness.
pub const CSL_PREFIX_INPUTS: usize = 9;
/// Total witness length of the CSL spend circuit.
pub const NUM_INPUTS: usize = CSL_PREFIX_INPUTS + LEGACY_NUM_INPUTS;

/// Key location under which the ledger requests zswap spend proofs.
pub const SPEND_KEY_LOCATION: &str = "midnight/zswap/spend";

/// `SpendRule::Empty`: no gate.
pub const RULE_EMPTY: u64 = 0;
/// `SpendRule::GateContract(address, ep_hash)`: a bound gate call is required.
pub const RULE_GATE_CONTRACT: u64 = 1;

/// Tag framing of `SpendRule`'s tagged serialization (`serialize::GLOBAL_TAG` + tag + `:`).
pub const DESCRIPTOR_TAG_PREFIX: &[u8; 24] = b"midnight:spend-rule[v1]:";
/// Serialized discriminant of `SpendRule::GateContract`.
pub const GATE_CONTRACT_DISCRIMINANT: u8 = 2;
/// The inner domain separator of token-type derivation, zero-padded to 32 bytes
/// (see `coin_structure::contract::ContractAddress::custom_token_type`).
pub const DERIVE_TOKEN_SEP: [u8; 32] = *b"midnight:derive_token\0\0\0\0\0\0\0\0\0\0\0";
/// Poseidon domain for the policy binding.
pub const BIND_DOMAIN_SEP: &[u8; 21] = b"midnight:csl-bind[v1]";

/// Field constant for [`BIND_DOMAIN_SEP`].
pub fn bind_domain() -> Fr {
    Fr::from_le_bytes(BIND_DOMAIN_SEP).expect("21 bytes fit in Fr")
}

/// The tagged serialization of `SpendRule::GateContract(gate, ep_hash)`, byte for byte.
pub fn gate_contract_descriptor_bytes(gate: &[u8; 32], ep_hash: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(24 + 1 + 32 + 32);
    bytes.extend_from_slice(DESCRIPTOR_TAG_PREFIX);
    bytes.push(GATE_CONTRACT_DISCRIMINANT);
    bytes.extend_from_slice(gate);
    bytes.extend_from_slice(ep_hash);
    bytes
}

/// The ledger's token type derivation for the two rule kinds this circuit supports.
pub fn derive_token_type(
    rule_kind: u64,
    domain_sep: &[u8; 32],
    mint_address: &[u8; 32],
    gate: &[u8; 32],
    ep_hash: &[u8; 32],
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(128);
    pre.extend_from_slice(&DERIVE_TOKEN_SEP);
    pre.extend_from_slice(domain_sep);
    pre.extend_from_slice(mint_address);
    if rule_kind == RULE_GATE_CONTRACT {
        let descriptor = base_crypto::hash::persistent_hash(&gate_contract_descriptor_bytes(gate, ep_hash));
        pre.extend_from_slice(&descriptor.0);
    }
    base_crypto::hash::persistent_hash(&pre).0
}

/// Witness of the CSL spend circuit: the CSL prefix plus the legacy spend witness.
#[derive(Clone, Debug)]
pub struct CslSpendWitness {
    /// [`RULE_EMPTY`] or [`RULE_GATE_CONTRACT`], as a field element.
    pub rule_kind: Fr,
    /// Domain separator chosen by the minting contract.
    pub domain_sep: [Fr; 2],
    /// Address of the minting contract.
    pub mint_address: [Fr; 2],
    /// Gate contract address (zero for `Empty`).
    pub gate_address: [Fr; 2],
    /// Gate entry point hash (zero for `Empty`).
    pub ep_hash: [Fr; 2],
    /// The legacy witness. Its `binding_input` is ignored: the binding is
    /// recomputed by [`CslSpendWitness::binding`].
    pub base: SpendWitness,
}

impl CslSpendWitness {
    /// Flattened witness, CSL prefix first, then the legacy layout.
    pub fn flatten(&self) -> Vec<Fr> {
        let mut inputs = Vec::with_capacity(NUM_INPUTS);
        inputs.push(self.rule_kind);
        inputs.extend(self.domain_sep);
        inputs.extend(self.mint_address);
        inputs.extend(self.gate_address);
        inputs.extend(self.ep_hash);
        inputs.extend(self.base.flatten());
        debug_assert_eq!(inputs.len(), NUM_INPUTS);
        inputs
    }

    fn is_gated(&self) -> bool {
        self.rule_kind == Fr::from(RULE_GATE_CONTRACT)
    }

    /// The policy binding this witness commits to: `0` for `Empty`, otherwise
    /// `Poseidon(DOM, nullifier, sender, gate, ep_hash)`.
    pub fn binding(&self) -> Fr {
        if !self.is_gated() {
            return 0.into();
        }
        let [cn_hi, cn_lo] = self.base.nullifier();
        let [snd_hi, snd_lo] = self.base.target();
        transient_hash(&[
            bind_domain(),
            cn_hi,
            cn_lo,
            snd_hi,
            snd_lo,
            self.gate_address[0],
            self.gate_address[1],
            self.ep_hash[0],
            self.ep_hash[1],
        ])
    }

    /// The token type this witness derives (off-circuit mirror of the constraint).
    pub fn derived_token_type(&self) -> [u8; 32] {
        derive_token_type(
            if self.is_gated() { RULE_GATE_CONTRACT } else { RULE_EMPTY },
            &join_bytes32(&self.domain_sep),
            &join_bytes32(&self.mint_address),
            &join_bytes32(&self.gate_address),
            &join_bytes32(&self.ep_hash),
        )
    }

    /// The 68 public inputs, identical to the legacy layout except that the
    /// first element is the policy binding.
    pub fn public_inputs(&self) -> Vec<Fr> {
        let mut pis = self.base.public_inputs();
        pis[0] = self.binding();
        pis
    }

    /// Reconstructs the witness from a spend proof preimage produced by
    /// `zswap::construct` with CSL inputs prepended.
    pub fn from_preimage(preimage: &ProofPreimage) -> Result<Self, anyhow::Error> {
        let inputs = &preimage.inputs;
        if inputs.len() != NUM_INPUTS {
            anyhow::bail!(
                "CSL spend preimage has {} inputs, expected {}",
                inputs.len(),
                NUM_INPUTS
            );
        }
        if preimage.public_transcript_outputs.len() != 2 {
            anyhow::bail!("CSL spend preimage must carry [check_root_result, segment] outputs");
        }
        let legacy = &inputs[CSL_PREFIX_INPUTS..];
        let two = |i: usize| [legacy[i], legacy[i + 1]];
        let mut path = [(Fr::from(0), false); ZSWAP_TREE_HEIGHT];
        for (i, slot) in path.iter_mut().enumerate() {
            let goes_left = legacy[8 + 2 * i];
            let goes_left = if goes_left == Fr::from(1) {
                true
            } else if goes_left == Fr::from(0) {
                false
            } else {
                anyhow::bail!("path direction bit is not boolean");
            };
            *slot = (legacy[7 + 2 * i], goes_left);
        }
        let is_user = legacy[0];
        let is_user = if is_user == Fr::from(1) {
            true
        } else if is_user == Fr::from(0) {
            false
        } else {
            anyhow::bail!("is_user is not boolean");
        };
        let base = SpendWitness {
            is_user,
            sk: two(1),
            contract_address: two(3),
            commitment: two(5),
            path,
            nonce: two(71),
            token_type: two(73),
            value: legacy[75],
            rc: legacy[76],
            binding_input: preimage.binding_input,
            check_root_result: preimage.public_transcript_outputs[0],
            segment: preimage.public_transcript_outputs[1],
        };
        let two_in = |i: usize| [inputs[i], inputs[i + 1]];
        Ok(CslSpendWitness {
            rule_kind: inputs[0],
            domain_sep: two_in(1),
            mint_address: two_in(3),
            gate_address: two_in(5),
            ep_hash: two_in(7),
            base,
        })
    }
}

/// The CSL spend relation.
#[derive(Clone, Debug, Default)]
pub struct ZswapSpendCsl;

type Assigned = AssignedNative<OldScalar>;

/// `if bit != 0 { a } else { b }`
fn cond_select(
    std: &ZkStdLib,
    layouter: &mut impl Layouter<OldScalar>,
    bit: &Assigned,
    a: &Assigned,
    b: &Assigned,
) -> Result<Assigned, Error> {
    let bit_is_zero = std.is_zero(layouter, bit)?;
    std.select(layouter, &bit_is_zero, b, a)
}

/// SHA-256 over the decoded bytes of `inputs` under `alignment`, as `(hi, lo)`.
fn persistent_hash(
    std: &ZkStdLib,
    layouter: &mut impl Layouter<OldScalar>,
    alignment: &Alignment,
    inputs: &[Assigned],
) -> Result<(Assigned, Assigned), Error> {
    let bytes = v1_fab_decode_to_bytes(std, layouter, alignment, inputs)?;
    let res_bytes = std.sha2_256(layouter, &bytes)?;
    let hi = std.convert(layouter, &res_bytes[31])?;
    let lo = v1_assemble_bytes(std, layouter, &res_bytes[..31])?;
    Ok((hi, lo))
}

fn bytes_alignment(lengths: &[u32]) -> Alignment {
    Alignment(
        lengths
            .iter()
            .map(|length| AlignmentSegment::Atom(AlignmentAtom::Bytes { length: *length }))
            .collect(),
    )
}

/// Range-checks a `(hi, lo)` pair as the split of a 32-byte value.
fn check_bytes32(
    std: &ZkStdLib,
    layouter: &mut impl Layouter<OldScalar>,
    hi: &Assigned,
    lo: &Assigned,
) -> Result<(), Error> {
    drop(std.assigned_to_le_bits(layouter, hi, Some(8), false)?);
    drop(std.assigned_to_le_bits(layouter, lo, Some(248), false)?);
    Ok(())
}

/// `1` if `a == b` for the 32-byte pair, else `0`.
fn eq_bytes32(
    std: &ZkStdLib,
    layouter: &mut impl Layouter<OldScalar>,
    a: (&Assigned, &Assigned),
    b: (&Assigned, &Assigned),
    zero: &Assigned,
) -> Result<Assigned, Error> {
    let eq_hi = {
        let bit = std.is_equal(layouter, a.0, b.0)?;
        std.convert(layouter, &bit)?
    };
    let eq_lo = {
        let bit = std.is_equal(layouter, a.1, b.1)?;
        std.convert(layouter, &bit)?
    };
    cond_select(std, layouter, &eq_hi, &eq_lo, zero)
}

impl Relation for ZswapSpendCsl {
    type Instance = Vec<OldScalar>;
    type Witness = CslSpendWitness;

    fn format_instance(instance: &Self::Instance) -> Result<Vec<OldScalar>, Error> {
        Ok(instance.clone())
    }

    fn circuit(
        &self,
        std: &ZkStdLib,
        layouter: &mut impl Layouter<OldScalar>,
        _instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let fixed = |layouter: &mut _, v: u64| -> Result<Assigned, Error> {
            std.assign_fixed(layouter, OldScalar::from(v))
        };
        let fixed_fr = |layouter: &mut _, v: Fr| -> Result<Assigned, Error> {
            std.assign_fixed(layouter, cvt(v.0))
        };

        let input_values = witness.as_ref().map(|w| {
            w.flatten()
                .into_iter()
                .map(|f| cvt(f.0))
                .collect::<Vec<_>>()
        });
        let memory = std.assign_many(layouter, &input_values.transpose_vec(NUM_INPUTS))?;

        // CSL prefix.
        let rule_kind = &memory[0];
        let domain_sep = [&memory[1], &memory[2]];
        let mint_address = [&memory[3], &memory[4]];
        let gate_address = [&memory[5], &memory[6]];
        let ep_hash = [&memory[7], &memory[8]];
        // Legacy layout, offset by the prefix.
        let o = CSL_PREFIX_INPUTS;
        let is_user = &memory[o];
        let sk = [&memory[o + 1], &memory[o + 2]];
        let contract_address = [&memory[o + 3], &memory[o + 4]];
        let commitment = [&memory[o + 5], &memory[o + 6]];
        let path = (0..ZSWAP_TREE_HEIGHT)
            .map(|i| (&memory[o + 7 + 2 * i], &memory[o + 8 + 2 * i]))
            .collect::<Vec<_>>();
        let nonce = [&memory[o + 71], &memory[o + 72]];
        let token_type = [&memory[o + 73], &memory[o + 74]];
        let value = &memory[o + 75];
        let rc = &memory[o + 76];

        // Well-formedness of the witness.
        let rule_bit: AssignedBit<_> = std.convert(layouter, rule_kind)?;
        for [hi, lo] in [domain_sep, mint_address, gate_address, ep_hash] {
            check_bytes32(std, layouter, hi, lo)?;
        }
        let _: AssignedBit<_> = std.convert(layouter, is_user)?;
        for [hi, lo] in [sk, contract_address, commitment] {
            check_bytes32(std, layouter, hi, lo)?;
        }
        for (_, goes_left) in &path {
            let _: AssignedBit<_> = std.convert(layouter, *goes_left)?;
        }
        for [hi, lo] in [nonce, token_type] {
            check_bytes32(std, layouter, hi, lo)?;
        }
        drop(std.assigned_to_le_bits(layouter, value, Some(128), false)?);

        let one = fixed(layouter, 1)?;
        let zero = fixed(layouter, 0)?;
        let two = fixed(layouter, 2)?;

        // Merkle membership of the commitment.
        let mut node = commitment[1].clone();
        for (sibling, goes_left) in &path {
            let left = cond_select(std, layouter, goes_left, &node, sibling)?;
            let right = cond_select(std, layouter, goes_left, sibling, &node)?;
            node = std.poseidon(layouter, &[left, right])?;
        }
        let root = node;

        // Ownership: public key from the secret key, or the contract address.
        let ds_pk = fixed_fr(layouter, Fr::from_le_bytes(PK_DOMAIN_SEP).expect("21 bytes fit in Fr"))?;
        let (pk_hi, pk_lo) = persistent_hash(
            std,
            layouter,
            &bytes_alignment(&[21, 32]),
            &[ds_pk, sk[0].clone(), sk[1].clone()],
        )?;
        let is_contract = cond_select(std, layouter, is_user, &zero, &one)?;
        let target_hi = cond_select(std, layouter, is_user, &pk_hi, contract_address[0])?;
        let target_lo = cond_select(std, layouter, is_user, &pk_lo, contract_address[1])?;

        // Commitment opening.
        let ds_cc = fixed_fr(layouter, Fr::from_le_bytes(CC_DOMAIN_SEP).expect("21 bytes fit in Fr"))?;
        let coin_alignment = bytes_alignment(&[21, 32, 32, 16, 1, 32]);
        let (cc_hi, cc_lo) = persistent_hash(
            std,
            layouter,
            &coin_alignment,
            &[
                ds_cc,
                nonce[0].clone(),
                nonce[1].clone(),
                token_type[0].clone(),
                token_type[1].clone(),
                value.clone(),
                is_user.clone(),
                target_hi.clone(),
                target_lo.clone(),
            ],
        )?;
        let cc_ok = eq_bytes32(std, layouter, (&cc_hi, &cc_lo), (commitment[0], commitment[1]), &zero)?;
        std.assert_non_zero(layouter, &cc_ok)?;

        // Nullifier.
        let sender_hi = cond_select(std, layouter, is_user, sk[0], contract_address[0])?;
        let sender_lo = cond_select(std, layouter, is_user, sk[1], contract_address[1])?;
        let ds_cn = fixed_fr(layouter, Fr::from_le_bytes(CN_DOMAIN_SEP).expect("21 bytes fit in Fr"))?;
        let (cn_hi, cn_lo) = persistent_hash(
            std,
            layouter,
            &coin_alignment,
            &[
                ds_cn,
                nonce[0].clone(),
                nonce[1].clone(),
                token_type[0].clone(),
                token_type[1].clone(),
                value.clone(),
                is_user.clone(),
                sender_hi,
                sender_lo,
            ],
        )?;

        // CSL 1: type re-derivation.
        let prefix = fixed_fr(
            layouter,
            Fr::from_le_bytes(DESCRIPTOR_TAG_PREFIX).expect("24 bytes fit in Fr"),
        )?;
        let discriminant = fixed(layouter, GATE_CONTRACT_DISCRIMINANT as u64)?;
        let (dh_hi, dh_lo) = persistent_hash(
            std,
            layouter,
            &bytes_alignment(&[24, 1, 32, 32]),
            &[
                prefix,
                discriminant,
                gate_address[0].clone(),
                gate_address[1].clone(),
                ep_hash[0].clone(),
                ep_hash[1].clone(),
            ],
        )?;
        let [sep_hi_v, sep_lo_v] = split_bytes32(&DERIVE_TOKEN_SEP);
        let sep_hi = fixed_fr(layouter, sep_hi_v)?;
        let sep_lo = fixed_fr(layouter, sep_lo_v)?;
        let (te_hi, te_lo) = persistent_hash(
            std,
            layouter,
            &bytes_alignment(&[32, 32, 32]),
            &[
                sep_hi.clone(),
                sep_lo.clone(),
                domain_sep[0].clone(),
                domain_sep[1].clone(),
                mint_address[0].clone(),
                mint_address[1].clone(),
            ],
        )?;
        let (tg_hi, tg_lo) = persistent_hash(
            std,
            layouter,
            &bytes_alignment(&[32, 32, 32, 32]),
            &[
                sep_hi,
                sep_lo,
                domain_sep[0].clone(),
                domain_sep[1].clone(),
                mint_address[0].clone(),
                mint_address[1].clone(),
                dh_hi,
                dh_lo,
            ],
        )?;
        let expected_hi = std.select(layouter, &rule_bit, &tg_hi, &te_hi)?;
        let expected_lo = std.select(layouter, &rule_bit, &tg_lo, &te_lo)?;
        let type_ok = eq_bytes32(
            std,
            layouter,
            (&expected_hi, &expected_lo),
            (token_type[0], token_type[1]),
            &zero,
        )?;
        // The native token type is all zeroes and has no derivation preimage; it
        // is accepted under `Empty` only.
        let is_native = eq_bytes32(std, layouter, (token_type[0], token_type[1]), (&zero, &zero), &zero)?;
        let native_ok = std.select(layouter, &rule_bit, &zero, &is_native)?;
        let derivation_ok = cond_select(std, layouter, &type_ok, &one, &native_ok)?;
        std.assert_non_zero(layouter, &derivation_ok)?;

        // CSL 2: the policy binding in the first public input.
        let dom_bind = fixed_fr(layouter, bind_domain())?;
        let bound = std.poseidon(
            layouter,
            &[
                dom_bind,
                cn_hi.clone(),
                cn_lo.clone(),
                target_hi,
                target_lo,
                gate_address[0].clone(),
                gate_address[1].clone(),
                ep_hash[0].clone(),
                ep_hash[1].clone(),
            ],
        )?;
        let binding = std.select(layouter, &rule_bit, &bound, &zero)?;
        let mut pis = vec![binding]; // pi[0]

        // Public transcript: identical to the legacy relation from here on.
        let op_dup_0 = fixed(layouter, crate::zswap_spend::OP_DUP_0)?;
        pis.push(op_dup_0.clone()); // pi[1]
        let op_idx_1 = fixed(layouter, crate::zswap_spend::OP_IDX_1)?;
        pis.extend([op_idx_1.clone(), one.clone(), one.clone(), zero.clone()]); // pi[2..6]
        pis.extend([op_idx_1.clone(), one.clone(), one.clone(), two.clone()]); // pi[6..10]
        let op_push = fixed(layouter, crate::zswap_spend::OP_PUSH)?;
        let neg_two: Assigned = std.assign_fixed(layouter, -OldScalar::from(2))?;
        pis.extend([op_push.clone(), one.clone(), one.clone(), neg_two.clone(), root]); // pi[10..15]
        let op_member = fixed(layouter, crate::zswap_spend::OP_MEMBER)?;
        pis.push(op_member); // pi[15]
        let check_root_result = std.assign(
            layouter,
            witness.as_ref().map(|w| cvt(w.base.check_root_result.0)),
        )?;
        let op_popeq_c = fixed(layouter, crate::zswap_spend::OP_POPEQ_C)?;
        pis.extend([op_popeq_c, one.clone(), one.clone(), check_root_result]); // pi[16..20]

        let op_idx_pp_1 = fixed(layouter, crate::zswap_spend::OP_IDX_PP_1)?;
        pis.extend([op_idx_pp_1, one.clone(), one.clone(), one.clone()]); // pi[20..24]
        let bytes32_len = fixed(layouter, 0x20)?;
        pis.extend([op_push.clone(), one.clone(), one.clone(), bytes32_len.clone(), cn_hi, cn_lo]); // pi[24..30]
        let op_push_s = fixed(layouter, crate::zswap_spend::OP_PUSH_S)?;
        pis.extend([op_push_s.clone(), zero.clone()]); // pi[30..32]
        let op_ins_1 = fixed(layouter, crate::zswap_spend::OP_INS_1)?;
        pis.push(op_ins_1.clone()); // pi[32]
        let op_ins_c_1 = fixed(layouter, crate::zswap_spend::OP_INS_C_1)?;
        pis.push(op_ins_c_1); // pi[33]

        let three = fixed(layouter, 3)?;
        let select_contract =
            |std: &ZkStdLib, layouter: &mut _, var: &Assigned| -> Result<Assigned, Error> {
                cond_select(std, layouter, &is_contract, var, &zero)
            };
        let g_push = select_contract(std, layouter, &op_push)?;
        pis.extend([g_push, is_contract.clone(), is_contract.clone(), is_contract.clone()]); // pi[34..38]
        let g_three = select_contract(std, layouter, &three)?;
        pis.push(g_three); // pi[38]
        let g_push_s = select_contract(std, layouter, &op_push_s)?;
        pis.extend([g_push_s, is_contract.clone(), is_contract.clone()]); // pi[39..42]
        let g_bytes32_len = select_contract(std, layouter, &bytes32_len)?;
        pis.push(g_bytes32_len); // pi[42]
        let g_addr_hi = select_contract(std, layouter, contract_address[0])?;
        pis.push(g_addr_hi); // pi[43]
        let g_addr_lo = select_contract(std, layouter, contract_address[1])?;
        pis.push(g_addr_lo); // pi[44]
        let g_ins = select_contract(std, layouter, &op_ins_1)?;
        pis.push(g_ins); // pi[45]

        pis.push(op_dup_0); // pi[46]
        let five = fixed(layouter, 5)?;
        pis.extend([op_idx_1, one.clone(), one.clone(), five]); // pi[47..51]
        let segment: Assigned =
            std.assign(layouter, witness.as_ref().map(|w| cvt(w.base.segment.0)))?;
        let op_popeq = fixed(layouter, crate::zswap_spend::OP_POPEQ)?;
        pis.extend([op_popeq, one.clone(), two.clone(), segment.clone()]); // pi[51..55]

        // Value commitment.
        let base_point = std.hash_to_curve(
            layouter,
            &[token_type[0].clone(), token_type[1].clone(), segment],
        )?;
        let base_x = std.jubjub().x_coordinate(&base_point);
        let base_y = std.jubjub().y_coordinate(&base_point);
        let generator: midnight_circuits_v1::types::AssignedNativePoint<OldEmbeddedAffineExt> = std
            .jubjub()
            .assign_fixed(layouter, OldEmbeddedAffine::generator())?;
        let rc_scalar = std.jubjub().convert(layouter, rc)?;
        let blind = std.jubjub().msm(layouter, &[rc_scalar], &[generator])?;
        let blind_x = std.jubjub().x_coordinate(&blind);
        let blind_y = std.jubjub().y_coordinate(&blind);
        let base = v1_ecc_from_parts(std, layouter, &base_x, &base_y)?;
        let value_scalar = std.jubjub().convert(layouter, value)?;
        let committed = std.jubjub().msm(layouter, &[value_scalar], &[base])?;
        let committed_x = std.jubjub().x_coordinate(&committed);
        let committed_y = std.jubjub().y_coordinate(&committed);
        let blind_pt = v1_ecc_from_parts(std, layouter, &blind_x, &blind_y)?;
        let committed_pt = v1_ecc_from_parts(std, layouter, &committed_x, &committed_y)?;
        let vc = std.jubjub().add(layouter, &blind_pt, &committed_pt)?;
        let vc_x = std.jubjub().x_coordinate(&vc);
        let vc_y = std.jubjub().y_coordinate(&vc);

        pis.extend([op_push, one.clone(), one.clone(), one.clone(), two.clone()]); // pi[55..60]
        pis.extend([op_push_s, one, two, neg_two.clone(), neg_two, vc_x, vc_y]); // pi[60..67]
        pis.push(op_ins_1); // pi[67]

        debug_assert_eq!(pis.len(), NUM_PUBLIC_INPUTS);
        pis.iter()
            .try_for_each(|pi| std.constrain_as_public_input(layouter, pi))
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: true,
            poseidon: true,
            sha2_256: true,
            sha2_512: false,
            sha3_256: false,
            keccak_256: false,
            blake2b: false,
            nr_pow2range_cols: 1,
            secp256k1: false,
            bls12_381: false,
            base64: false,
            automaton: false,
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(ZswapSpendCsl)
    }
}

/// Proving and verifying keys of the CSL spend relation, generated once per process.
pub struct CslSpendKeys {
    /// The parameter size the circuit needs.
    pub k: u8,
    pub vk: MidnightVK,
    pub pk: MidnightPK<ZswapSpendCsl>,
}

static CSL_SPEND_KEYS: OnceLock<Arc<CslSpendKeys>> = OnceLock::new();

/// The circuit size of the CSL spend relation.
pub fn csl_spend_k() -> u8 {
    midnight_zk_stdlib_v1::MidnightCircuit::from_relation(&ZswapSpendCsl).min_k() as u8
}

/// Generates (or returns the cached) CSL spend keys from the given parameters provider.
pub async fn csl_spend_keys(
    params: &impl transient_crypto::proofs::ParamsProverProvider,
) -> Result<Arc<CslSpendKeys>, anyhow::Error> {
    if let Some(keys) = CSL_SPEND_KEYS.get() {
        return Ok(keys.clone());
    }
    let k = csl_spend_k();
    let params_k = transient_crypto_old::proofs::ParamsProverProvider::get_params(&V1Params(params), k).await?;
    let vk = midnight_zk_stdlib_v1::setup_vk(params_k.as_ref(), &ZswapSpendCsl);
    let pk = midnight_zk_stdlib_v1::setup_pk(&ZswapSpendCsl, &vk);
    Ok(CSL_SPEND_KEYS
        .get_or_init(|| Arc::new(CslSpendKeys { k, vk, pk }))
        .clone())
}

/// The CSL spend verifier key in the ledger's embedded format (`transient_crypto_old` tagged bytes).
pub async fn csl_spend_verifier_key_bytes(
    params: &impl transient_crypto::proofs::ParamsProverProvider,
) -> Result<Vec<u8>, anyhow::Error> {
    let keys = csl_spend_keys(params).await?;
    let vk = transient_crypto_old::proofs::VerifierKey::from(keys.vk.clone());
    let mut bytes = Vec::new();
    serialize::tagged_serialize(&vk, &mut bytes)?;
    Ok(bytes)
}

/// Proves a zswap spend preimage with the CSL relation.
pub async fn prove_from_preimage(
    rng: impl Rng + CryptoRng,
    params: &impl transient_crypto::proofs::ParamsProverProvider,
    preimage: &ProofPreimage,
) -> Result<Proof, anyhow::Error> {
    let witness = CslSpendWitness::from_preimage(preimage)?;
    let pis: Vec<OldScalar> = witness.public_inputs().iter().map(|f| cvt(f.0)).collect();
    let keys = csl_spend_keys(params).await?;
    let params_k = transient_crypto_old::proofs::ParamsProverProvider::get_params(&V1Params(params), keys.k).await?;
    let bytes = midnight_zk_stdlib_v1::prove::<_, transient_crypto_old::proofs::TranscriptHash>(
        params_k.as_ref(),
        &keys.pk,
        &ZswapSpendCsl,
        &pis,
        witness,
        rng,
    )
    .map_err(|e| anyhow::anyhow!("CSL spend prove: {e}"))?;
    Ok(Proof::from_bytes(bytes))
}
