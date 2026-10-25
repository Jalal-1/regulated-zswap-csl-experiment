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

//! The CSL whitelist gate contract: two hand-written zk-stdlib v1 relations
//! registered as contract operations (`v2` verifier keys, `ProofVersioned::V2`).
//!
//! Contract state (an array of cells): `[root: Fr, token_type: Bytes<32>, admin: Fr]`.
//!
//! * `authorize` (one call per segment that spends the regulated type) reads
//!   `root` and `token_type`, claims the policy binding of the guarded input
//!   (effects index 9) and every output commitment of the segment (effects
//!   index 10), and proves: the sender's key is in the whitelist under `root`;
//!   the binding is `Poseidon(DOM_BIND, nullifier, sender, gate, ep_hash)` for
//!   that sender; every claimed output commitment opens to a user-owned coin,
//!   and if its type is `token_type` the recipient's key is in the whitelist.
//! * `update_root` (administrator) reads `admin`, writes `root` and
//!   `token_type`, and proves knowledge of the administrator secret.
//!
//! A contract call's public inputs are, in order, the transaction binding
//! input, the communication commitment and the field representation of the
//! transcript program the ledger replays (`ContractCall::public_inputs`). The
//! program is fixed per entry point, so each relation emits the program's
//! representation as constants with holes for the values it proves: the
//! encodings below were taken from `Op::field_repr` (see
//! `ledger/tests/csl_gate_layout.rs`). Whatever the prover puts in a hole is
//! what the ledger replays against the contract's current state and effects.

use midnight_circuits_v1::instructions::{
    AssertionInstructions, AssignmentInstructions, ControlFlowInstructions,
    ConversionInstructions, DecompositionInstructions, EqualityInstructions,
    PublicInputInstructions, ZeroInstructions,
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

use crate::csl_whitelist::{WHITELIST_DEPTH, leaf_domain, OWNER_KIND_USER};
use crate::ir_v1::{OldScalar, V1Params, cvt, v1_assemble_bytes, v1_fab_decode_to_bytes};
use crate::zswap_spend::CC_DOMAIN_SEP;
use crate::zswap_spend_csl::bind_domain;
use base_crypto::fab::{Alignment, AlignmentAtom, AlignmentSegment};

/// Key-location prefix of the gate's entry points.
pub const KEY_PREFIX: &str = "midnight/csl-gate/";
/// Key location of the `authorize` entry point.
pub const AUTHORIZE_KEY_LOCATION: &str = "midnight/csl-gate/authorize";
/// Key location of the `update_root` entry point.
pub const UPDATE_ROOT_KEY_LOCATION: &str = "midnight/csl-gate/update-root";
/// Entry point names as they appear in the contract's operation map.
pub const AUTHORIZE_ENTRY_POINT: &[u8] = b"authorize";
pub const UPDATE_ROOT_ENTRY_POINT: &[u8] = b"update_root";

/// Outputs covered by one `authorize` call in the first supported shape.
pub const N_OUTPUTS: usize = 1;

/// State cell indices.
pub const CELL_ROOT: u64 = 0;
pub const CELL_TOKEN_TYPE: u64 = 1;
pub const CELL_ADMIN: u64 = 2;
/// Effects map indices (see `onchain_runtime::context::Effects`).
pub const EFFECT_SPEND_AUTHORIZATIONS: u64 = 9;
pub const EFFECT_OUTPUT_COVERAGE: u64 = 10;

/// Poseidon domain of the administrator key: `admin = Poseidon(DOM, secret)`.
pub const ADMIN_DOMAIN_SEP: &[u8; 21] = b"midnight:csl-admn[v1]";

pub fn admin_domain() -> Fr {
    Fr::from_le_bytes(ADMIN_DOMAIN_SEP).expect("21 bytes fit in Fr")
}

/// `admin` cell value for an administrator secret.
pub fn admin_key(secret: Fr) -> Fr {
    transient_hash(&[admin_domain(), secret])
}

// Op encodings in field representation (`Op::field_repr`).
const OP_DUP_0: u64 = 0x30;
const OP_SWAP_0: u64 = 0x40;
const OP_IDX_1: u64 = 0x50; // Idx { cached: false, push_path: false }, 1-entry path
const OP_IDX_PC_1: u64 = 0x80; // Idx { cached: true, push_path: true }, 1-entry path
const OP_PUSH: u64 = 0x10;
const OP_PUSH_S: u64 = 0x11;
const OP_POPEQ: u64 = 0x0c; // Popeq { cached: false }
const OP_INS_1: u64 = 0x91; // Ins { cached: false, n: 1 }
const OP_INS_C_2: u64 = 0xa2; // Ins { cached: true, n: 2 }

/// One element of a transcript template: a constant, the field-alignment
/// marker (`-2`), or a hole the relation fills with a proven value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pi {
    C(u64),
    NegTwo,
    Root,
    TokenHi,
    TokenLo,
    Binding,
    CmHi(usize),
    CmLo(usize),
    Admin,
    NewRoot,
    NewTokenHi,
    NewTokenLo,
}

fn read_fr(key: u64, hole: Pi) -> Vec<Pi> {
    use Pi::*;
    vec![C(OP_DUP_0), C(OP_IDX_1), C(1), C(1), C(key), C(OP_POPEQ), C(1), NegTwo, hole]
}

fn read_bytes32(key: u64, hi: Pi, lo: Pi) -> Vec<Pi> {
    use Pi::*;
    vec![C(OP_DUP_0), C(OP_IDX_1), C(1), C(1), C(key), C(OP_POPEQ), C(1), C(0x20), hi, lo]
}

fn claim_fr(effect: u64, hole: Pi) -> Vec<Pi> {
    use Pi::*;
    vec![
        C(OP_SWAP_0),
        C(OP_IDX_PC_1), C(1), C(1), C(effect),
        C(OP_PUSH), C(1), C(1), NegTwo, hole,
        C(OP_PUSH), C(0),
        C(OP_INS_C_2),
        C(OP_SWAP_0),
    ]
}

fn claim_bytes32(effect: u64, hi: Pi, lo: Pi) -> Vec<Pi> {
    use Pi::*;
    vec![
        C(OP_SWAP_0),
        C(OP_IDX_PC_1), C(1), C(1), C(effect),
        C(OP_PUSH), C(1), C(1), C(0x20), hi, lo,
        C(OP_PUSH), C(0),
        C(OP_INS_C_2),
        C(OP_SWAP_0),
    ]
}

fn write_fr(key: u64, hole: Pi) -> Vec<Pi> {
    use Pi::*;
    vec![C(OP_PUSH), C(1), C(1), C(1), C(key), C(OP_PUSH_S), C(1), C(1), NegTwo, hole, C(OP_INS_1)]
}

fn write_bytes32(key: u64, hi: Pi, lo: Pi) -> Vec<Pi> {
    use Pi::*;
    vec![C(OP_PUSH), C(1), C(1), C(1), C(key), C(OP_PUSH_S), C(1), C(1), C(0x20), hi, lo, C(OP_INS_1)]
}

/// The transcript template of `authorize` (after the two leading public inputs).
pub fn authorize_template() -> Vec<Pi> {
    let mut t = Vec::new();
    t.extend(read_fr(CELL_ROOT, Pi::Root));
    t.extend(read_bytes32(CELL_TOKEN_TYPE, Pi::TokenHi, Pi::TokenLo));
    t.extend(claim_fr(EFFECT_SPEND_AUTHORIZATIONS, Pi::Binding));
    for i in 0..N_OUTPUTS {
        t.extend(claim_bytes32(EFFECT_OUTPUT_COVERAGE, Pi::CmHi(i), Pi::CmLo(i)));
    }
    t
}

/// The transcript template of `update_root`.
pub fn update_root_template() -> Vec<Pi> {
    let mut t = Vec::new();
    t.extend(read_fr(CELL_ADMIN, Pi::Admin));
    t.extend(write_fr(CELL_ROOT, Pi::NewRoot));
    t.extend(write_bytes32(CELL_TOKEN_TYPE, Pi::NewTokenHi, Pi::NewTokenLo));
    t
}

/// Evaluates a template off-circuit with the given hole values (for building
/// and checking the expected public transcript).
pub fn template_values(template: &[Pi], hole: impl Fn(Pi) -> Fr) -> Vec<Fr> {
    template
        .iter()
        .map(|pi| match pi {
            Pi::C(c) => Fr::from(*c),
            Pi::NegTwo => -Fr::from(2),
            other => hole(*other),
        })
        .collect()
}

/// A covered output as the gate witnesses it.
#[derive(Clone, Debug)]
pub struct OutputWitness {
    pub nonce: [Fr; 2],
    pub token_type: [Fr; 2],
    pub value: Fr,
    pub recipient_pk: [Fr; 2],
    pub recipient_r: Fr,
    pub recipient_path: [(Fr, bool); WHITELIST_DEPTH],
}

/// Witness of `authorize`.
#[derive(Clone, Debug)]
pub struct AuthorizeWitness {
    pub binding_input: Fr,
    pub communication_commitment: Fr,
    pub root: Fr,
    pub token_type: [Fr; 2],
    pub nullifier: [Fr; 2],
    pub sender_pk: [Fr; 2],
    pub sender_r: Fr,
    pub sender_path: [(Fr, bool); WHITELIST_DEPTH],
    pub gate_address: [Fr; 2],
    pub ep_hash: [Fr; 2],
    pub outputs: Vec<OutputWitness>,
}

/// Witness of `update_root`.
#[derive(Clone, Debug)]
pub struct UpdateRootWitness {
    pub binding_input: Fr,
    pub communication_commitment: Fr,
    pub admin_secret: Fr,
    pub new_root: Fr,
    pub new_token_type: [Fr; 2],
}

fn path_to_fields(path: &[(Fr, bool)]) -> Vec<Fr> {
    path.iter()
        .flat_map(|(s, b)| [*s, Fr::from(*b as u64)])
        .collect()
}

fn fields_to_path(fields: &[Fr]) -> Result<[(Fr, bool); WHITELIST_DEPTH], anyhow::Error> {
    let mut path = [(Fr::from(0), false); WHITELIST_DEPTH];
    for (i, slot) in path.iter_mut().enumerate() {
        let bit = fields[2 * i + 1];
        let goes_left = if bit == Fr::from(1) {
            true
        } else if bit == Fr::from(0) {
            false
        } else {
            anyhow::bail!("path direction is not boolean");
        };
        *slot = (fields[2 * i], goes_left);
    }
    Ok(path)
}

/// Private-transcript length of `authorize`.
pub const AUTHORIZE_PRIVATE_LEN: usize = 3 + 4 + 1 + 2 * WHITELIST_DEPTH + 4 + N_OUTPUTS * (7 + 1 + 2 * WHITELIST_DEPTH);
/// Private-transcript length of `update_root`.
pub const UPDATE_ROOT_PRIVATE_LEN: usize = 4;

impl AuthorizeWitness {
    /// The private transcript carried by the proof preimage.
    pub fn private_transcript(&self) -> Vec<Fr> {
        let mut v = vec![self.root];
        v.extend(self.token_type);
        v.extend(self.nullifier);
        v.extend(self.sender_pk);
        v.push(self.sender_r);
        v.extend(path_to_fields(&self.sender_path));
        v.extend(self.gate_address);
        v.extend(self.ep_hash);
        for o in &self.outputs {
            v.extend(o.nonce);
            v.extend(o.token_type);
            v.push(o.value);
            v.extend(o.recipient_pk);
            v.push(o.recipient_r);
            v.extend(path_to_fields(&o.recipient_path));
        }
        debug_assert_eq!(v.len(), AUTHORIZE_PRIVATE_LEN);
        v
    }

    pub fn from_preimage(preimage: &ProofPreimage) -> Result<Self, anyhow::Error> {
        let p = &preimage.private_transcript;
        if p.len() != AUTHORIZE_PRIVATE_LEN {
            anyhow::bail!("authorize preimage has {} private elements, expected {}", p.len(), AUTHORIZE_PRIVATE_LEN);
        }
        let cc = preimage
            .communications_commitment
            .map(|(c, _)| c)
            .ok_or_else(|| anyhow::anyhow!("gate call preimage must carry a communication commitment"))?;
        let mut i = 0;
        let mut take = |n: usize| {
            let s = &p[i..i + n];
            i += n;
            s.to_vec()
        };
        let root = take(1)[0];
        let tt = take(2);
        let cn = take(2);
        let pk = take(2);
        let sender_r = take(1)[0];
        let sender_path = fields_to_path(&take(2 * WHITELIST_DEPTH))?;
        let gate = take(2);
        let ep = take(2);
        let mut outputs = Vec::with_capacity(N_OUTPUTS);
        for _ in 0..N_OUTPUTS {
            let nonce = take(2);
            let token_type = take(2);
            let value = take(1)[0];
            let rpk = take(2);
            let recipient_r = take(1)[0];
            let recipient_path = fields_to_path(&take(2 * WHITELIST_DEPTH))?;
            outputs.push(OutputWitness {
                nonce: [nonce[0], nonce[1]],
                token_type: [token_type[0], token_type[1]],
                value,
                recipient_pk: [rpk[0], rpk[1]],
                recipient_r,
                recipient_path,
            });
        }
        Ok(AuthorizeWitness {
            binding_input: preimage.binding_input,
            communication_commitment: cc,
            root,
            token_type: [tt[0], tt[1]],
            nullifier: [cn[0], cn[1]],
            sender_pk: [pk[0], pk[1]],
            sender_r,
            sender_path,
            gate_address: [gate[0], gate[1]],
            ep_hash: [ep[0], ep[1]],
            outputs,
        })
    }
}

impl UpdateRootWitness {
    pub fn private_transcript(&self) -> Vec<Fr> {
        vec![self.admin_secret, self.new_root, self.new_token_type[0], self.new_token_type[1]]
    }

    pub fn from_preimage(preimage: &ProofPreimage) -> Result<Self, anyhow::Error> {
        let p = &preimage.private_transcript;
        if p.len() != UPDATE_ROOT_PRIVATE_LEN {
            anyhow::bail!("update_root preimage has {} private elements, expected {}", p.len(), UPDATE_ROOT_PRIVATE_LEN);
        }
        let cc = preimage
            .communications_commitment
            .map(|(c, _)| c)
            .ok_or_else(|| anyhow::anyhow!("gate call preimage must carry a communication commitment"))?;
        Ok(UpdateRootWitness {
            binding_input: preimage.binding_input,
            communication_commitment: cc,
            admin_secret: p[0],
            new_root: p[1],
            new_token_type: [p[2], p[3]],
        })
    }
}

type Assigned = AssignedNative<OldScalar>;

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

/// Assigns a Merkle path and folds it from `leaf` with the zswap convention.
fn fold_path(
    std: &ZkStdLib,
    layouter: &mut impl Layouter<OldScalar>,
    leaf: &Assigned,
    path: &[(Assigned, Assigned)],
) -> Result<Assigned, Error> {
    let mut node = leaf.clone();
    for (sibling, goes_left) in path {
        let _: AssignedBit<_> = std.convert(layouter, goes_left)?;
        let left = cond_select(std, layouter, goes_left, &node, sibling)?;
        let right = cond_select(std, layouter, goes_left, sibling, &node)?;
        node = std.poseidon(layouter, &[left, right])?;
    }
    Ok(node)
}

fn user_leaf_in_circuit(
    std: &ZkStdLib,
    layouter: &mut impl Layouter<OldScalar>,
    dom: &Assigned,
    one: &Assigned,
    pk: [&Assigned; 2],
    r: &Assigned,
) -> Result<Assigned, Error> {
    std.poseidon(layouter, &[dom.clone(), one.clone(), pk[0].clone(), pk[1].clone(), r.clone()])
}

fn emit_template(
    std: &ZkStdLib,
    layouter: &mut impl Layouter<OldScalar>,
    template: &[Pi],
    hole: impl Fn(Pi) -> Assigned,
) -> Result<Vec<Assigned>, Error> {
    let mut pis = Vec::with_capacity(template.len());
    for pi in template {
        pis.push(match pi {
            Pi::C(c) => std.assign_fixed(layouter, OldScalar::from(*c))?,
            Pi::NegTwo => std.assign_fixed(layouter, -OldScalar::from(2))?,
            other => hole(*other),
        });
    }
    Ok(pis)
}

/// The `authorize` relation.
#[derive(Clone, Debug, Default)]
pub struct GateAuthorize;

impl Relation for GateAuthorize {
    type Instance = Vec<OldScalar>;
    type Witness = AuthorizeWitness;

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
        let w = witness.as_ref();
        let assign = |layouter: &mut _, v: Value<Fr>| -> Result<Assigned, Error> {
            std.assign(layouter, v.map(|f| cvt(f.0)))
        };
        let assign2 = |layouter: &mut _, v: Value<[Fr; 2]>| -> Result<[Assigned; 2], Error> {
            Ok([
                std.assign(layouter, v.map(|f| cvt(f[0].0)))?,
                std.assign(layouter, v.map(|f| cvt(f[1].0)))?,
            ])
        };
        let assign_path = |layouter: &mut _,
                           v: Value<[(Fr, bool); WHITELIST_DEPTH]>|
         -> Result<Vec<(Assigned, Assigned)>, Error> {
            let mut out = Vec::with_capacity(WHITELIST_DEPTH);
            for i in 0..WHITELIST_DEPTH {
                let s = std.assign(layouter, v.map(|p| cvt(p[i].0.0)))?;
                let b = std.assign(layouter, v.map(|p| OldScalar::from(p[i].1 as u64)))?;
                out.push((s, b));
            }
            Ok(out)
        };

        let binding_input = assign(layouter, w.map(|w| w.binding_input))?;
        let cc = assign(layouter, w.map(|w| w.communication_commitment))?;
        let root = assign(layouter, w.map(|w| w.root))?;
        let token_type = assign2(layouter, w.map(|w| w.token_type))?;
        let nullifier = assign2(layouter, w.map(|w| w.nullifier))?;
        let sender_pk = assign2(layouter, w.map(|w| w.sender_pk))?;
        let sender_r = assign(layouter, w.map(|w| w.sender_r))?;
        let sender_path = assign_path(layouter, w.map(|w| w.sender_path))?;
        let gate = assign2(layouter, w.map(|w| w.gate_address))?;
        let ep = assign2(layouter, w.map(|w| w.ep_hash))?;

        for [hi, lo] in [&token_type, &nullifier, &sender_pk, &gate, &ep] {
            check_bytes32(std, layouter, hi, lo)?;
        }

        let one: Assigned = std.assign_fixed(layouter, OldScalar::from(1))?;
        let zero: Assigned = std.assign_fixed(layouter, OldScalar::from(0))?;
        let dom_leaf: Assigned = std.assign_fixed(layouter, cvt(leaf_domain().0))?;
        let kind_user: Assigned = std.assign_fixed(layouter, OldScalar::from(OWNER_KIND_USER))?;

        // The sender is whitelisted under the root the ledger will check.
        let sender_leaf = user_leaf_in_circuit(std, layouter, &dom_leaf, &kind_user, [&sender_pk[0], &sender_pk[1]], &sender_r)?;
        let sender_root = fold_path(std, layouter, &sender_leaf, &sender_path)?;
        std.assert_equal(layouter, &sender_root, &root)?;

        // The policy binding for exactly this sender and nullifier.
        let dom_bind: Assigned = std.assign_fixed(layouter, cvt(bind_domain().0))?;
        let binding = std.poseidon(
            layouter,
            &[
                dom_bind,
                nullifier[0].clone(),
                nullifier[1].clone(),
                sender_pk[0].clone(),
                sender_pk[1].clone(),
                gate[0].clone(),
                gate[1].clone(),
                ep[0].clone(),
                ep[1].clone(),
            ],
        )?;

        // Every covered output: commitment opening, and recipient eligibility
        // when the coin is of the regulated type.
        let ds_cc: Assigned = std.assign_fixed(layouter, cvt(Fr::from_le_bytes(CC_DOMAIN_SEP).expect("21 bytes fit in Fr").0))?;
        let coin_alignment = bytes_alignment(&[21, 32, 32, 16, 1, 32]);
        let mut commitments: Vec<(Assigned, Assigned)> = Vec::with_capacity(N_OUTPUTS);
        for i in 0..N_OUTPUTS {
            let nonce = assign2(layouter, w.map(|w| w.outputs[i].nonce))?;
            let o_type = assign2(layouter, w.map(|w| w.outputs[i].token_type))?;
            let value = assign(layouter, w.map(|w| w.outputs[i].value))?;
            let rpk = assign2(layouter, w.map(|w| w.outputs[i].recipient_pk))?;
            let r_r = assign(layouter, w.map(|w| w.outputs[i].recipient_r))?;
            let rpath = assign_path(layouter, w.map(|w| w.outputs[i].recipient_path))?;
            for [hi, lo] in [&nonce, &o_type, &rpk] {
                check_bytes32(std, layouter, hi, lo)?;
            }
            drop(std.assigned_to_le_bits(layouter, &value, Some(128), false)?);
            let (cm_hi, cm_lo) = persistent_hash(
                std,
                layouter,
                &coin_alignment,
                &[
                    ds_cc.clone(),
                    nonce[0].clone(),
                    nonce[1].clone(),
                    o_type[0].clone(),
                    o_type[1].clone(),
                    value.clone(),
                    one.clone(),
                    rpk[0].clone(),
                    rpk[1].clone(),
                ],
            )?;
            let eq_hi = {
                let b = std.is_equal(layouter, &o_type[0], &token_type[0])?;
                std.convert(layouter, &b)?
            };
            let eq_lo = {
                let b = std.is_equal(layouter, &o_type[1], &token_type[1])?;
                std.convert(layouter, &b)?
            };
            let is_regulated = cond_select(std, layouter, &eq_hi, &eq_lo, &zero)?;
            let rleaf = user_leaf_in_circuit(std, layouter, &dom_leaf, &kind_user, [&rpk[0], &rpk[1]], &r_r)?;
            let rroot = fold_path(std, layouter, &rleaf, &rpath)?;
            let recipient_ok = {
                let b = std.is_equal(layouter, &rroot, &root)?;
                std.convert(layouter, &b)?
            };
            let ok = cond_select(std, layouter, &is_regulated, &recipient_ok, &one)?;
            std.assert_non_zero(layouter, &ok)?;
            commitments.push((cm_hi, cm_lo));
        }

        let template = authorize_template();
        let body = emit_template(std, layouter, &template, |pi| match pi {
            Pi::Root => root.clone(),
            Pi::TokenHi => token_type[0].clone(),
            Pi::TokenLo => token_type[1].clone(),
            Pi::Binding => binding.clone(),
            Pi::CmHi(i) => commitments[i].0.clone(),
            Pi::CmLo(i) => commitments[i].1.clone(),
            _ => unreachable!("hole kind not used by authorize"),
        })?;
        let mut pis = vec![binding_input, cc];
        pis.extend(body);
        pis.iter()
            .try_for_each(|pi| std.constrain_as_public_input(layouter, pi))
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: false,
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
        Ok(GateAuthorize)
    }
}

/// The `update_root` relation.
#[derive(Clone, Debug, Default)]
pub struct GateUpdateRoot;

impl Relation for GateUpdateRoot {
    type Instance = Vec<OldScalar>;
    type Witness = UpdateRootWitness;

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
        let w = witness.as_ref();
        let assign = |layouter: &mut _, v: Value<Fr>| -> Result<Assigned, Error> {
            std.assign(layouter, v.map(|f| cvt(f.0)))
        };
        let binding_input = assign(layouter, w.map(|w| w.binding_input))?;
        let cc = assign(layouter, w.map(|w| w.communication_commitment))?;
        let secret = assign(layouter, w.map(|w| w.admin_secret))?;
        let new_root = assign(layouter, w.map(|w| w.new_root))?;
        let tt_hi = assign(layouter, w.map(|w| w.new_token_type[0]))?;
        let tt_lo = assign(layouter, w.map(|w| w.new_token_type[1]))?;
        check_bytes32(std, layouter, &tt_hi, &tt_lo)?;
        let dom: Assigned = std.assign_fixed(layouter, cvt(admin_domain().0))?;
        let admin = std.poseidon(layouter, &[dom, secret])?;

        let template = update_root_template();
        let body = emit_template(std, layouter, &template, |pi| match pi {
            Pi::Admin => admin.clone(),
            Pi::NewRoot => new_root.clone(),
            Pi::NewTokenHi => tt_hi.clone(),
            Pi::NewTokenLo => tt_lo.clone(),
            _ => unreachable!("hole kind not used by update_root"),
        })?;
        let mut pis = vec![binding_input, cc];
        pis.extend(body);
        pis.iter()
            .try_for_each(|pi| std.constrain_as_public_input(layouter, pi))
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: false,
            poseidon: true,
            sha2_256: false,
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
        Ok(GateUpdateRoot)
    }
}

/// Keys of one gate relation, generated once per process.
pub struct GateKeys<R: Relation> {
    pub k: u8,
    pub vk: MidnightVK,
    pub pk: MidnightPK<R>,
}

static AUTHORIZE_KEYS: OnceLock<Arc<GateKeys<GateAuthorize>>> = OnceLock::new();
static UPDATE_ROOT_KEYS: OnceLock<Arc<GateKeys<GateUpdateRoot>>> = OnceLock::new();

async fn gen_keys<R: Relation + Default>(
    params: &impl transient_crypto::proofs::ParamsProverProvider,
) -> Result<GateKeys<R>, anyhow::Error> {
    let relation = R::default();
    let k = midnight_zk_stdlib_v1::MidnightCircuit::from_relation(&relation).min_k() as u8;
    let params_k = transient_crypto_old::proofs::ParamsProverProvider::get_params(&V1Params(params), k).await?;
    let vk = midnight_zk_stdlib_v1::setup_vk(params_k.as_ref(), &relation);
    let pk = midnight_zk_stdlib_v1::setup_pk(&relation, &vk);
    Ok(GateKeys { k, vk, pk })
}

pub async fn authorize_keys(
    params: &impl transient_crypto::proofs::ParamsProverProvider,
) -> Result<Arc<GateKeys<GateAuthorize>>, anyhow::Error> {
    if let Some(k) = AUTHORIZE_KEYS.get() {
        return Ok(k.clone());
    }
    let keys = gen_keys::<GateAuthorize>(params).await?;
    Ok(AUTHORIZE_KEYS.get_or_init(|| Arc::new(keys)).clone())
}

pub async fn update_root_keys(
    params: &impl transient_crypto::proofs::ParamsProverProvider,
) -> Result<Arc<GateKeys<GateUpdateRoot>>, anyhow::Error> {
    if let Some(k) = UPDATE_ROOT_KEYS.get() {
        return Ok(k.clone());
    }
    let keys = gen_keys::<GateUpdateRoot>(params).await?;
    Ok(UPDATE_ROOT_KEYS.get_or_init(|| Arc::new(keys)).clone())
}

fn vk_bytes(vk: &MidnightVK) -> Result<Vec<u8>, anyhow::Error> {
    let vk = transient_crypto_old::proofs::VerifierKey::from(vk.clone());
    let mut bytes = Vec::new();
    serialize::tagged_serialize(&vk, &mut bytes)?;
    Ok(bytes)
}

/// The verifier key bytes (ledger `ContractOperation.v2` format) of an entry point.
pub async fn verifier_key_bytes(
    params: &impl transient_crypto::proofs::ParamsProverProvider,
    key_location: &str,
) -> Result<Option<Vec<u8>>, anyhow::Error> {
    Ok(match key_location {
        AUTHORIZE_KEY_LOCATION => Some(vk_bytes(&authorize_keys(params).await?.vk)?),
        UPDATE_ROOT_KEY_LOCATION => Some(vk_bytes(&update_root_keys(params).await?.vk)?),
        _ => None,
    })
}

/// The statement of a gate call: binding input, communication commitment, transcript.
fn instance(preimage: &ProofPreimage) -> Result<Vec<OldScalar>, anyhow::Error> {
    let cc = preimage
        .communications_commitment
        .map(|(c, _)| c)
        .ok_or_else(|| anyhow::anyhow!("gate call preimage must carry a communication commitment"))?;
    let mut pis = vec![cvt(preimage.binding_input.0), cvt(cc.0)];
    pis.extend(preimage.public_transcript_inputs.iter().map(|f| cvt(f.0)));
    Ok(pis)
}

/// Proves a gate entry-point preimage.
pub async fn prove_from_preimage(
    rng: impl Rng + CryptoRng,
    params: &impl transient_crypto::proofs::ParamsProverProvider,
    preimage: &ProofPreimage,
) -> Result<Proof, anyhow::Error> {
    let pis = instance(preimage)?;
    let bytes = match &*preimage.key_location.0 {
        AUTHORIZE_KEY_LOCATION => {
            let witness = AuthorizeWitness::from_preimage(preimage)?;
            let expected = template_values(&authorize_template(), |_| Fr::from(0)).len();
            if preimage.public_transcript_inputs.len() != expected {
                anyhow::bail!(
                    "authorize transcript has {} public elements, relation expects {}",
                    preimage.public_transcript_inputs.len(),
                    expected
                );
            }
            let keys = authorize_keys(params).await?;
            let params_k = transient_crypto_old::proofs::ParamsProverProvider::get_params(&V1Params(params), keys.k).await?;
            midnight_zk_stdlib_v1::prove::<_, transient_crypto_old::proofs::TranscriptHash>(
                params_k.as_ref(),
                &keys.pk,
                &GateAuthorize,
                &pis,
                witness,
                rng,
            )
            .map_err(|e| anyhow::anyhow!("gate authorize prove: {e}"))?
        }
        UPDATE_ROOT_KEY_LOCATION => {
            let witness = UpdateRootWitness::from_preimage(preimage)?;
            let keys = update_root_keys(params).await?;
            let params_k = transient_crypto_old::proofs::ParamsProverProvider::get_params(&V1Params(params), keys.k).await?;
            midnight_zk_stdlib_v1::prove::<_, transient_crypto_old::proofs::TranscriptHash>(
                params_k.as_ref(),
                &keys.pk,
                &GateUpdateRoot,
                &pis,
                witness,
                rng,
            )
            .map_err(|e| anyhow::anyhow!("gate update_root prove: {e}"))?
        }
        other => anyhow::bail!("not a CSL gate key location: {other}"),
    };
    Ok(Proof::from_bytes(bytes))
}
