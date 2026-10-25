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

//! Custom spend rules for shielded tokens.
//!
//! A [`SpendRule`] is folded into a token type at derivation time (see
//! [`ContractAddress::custom_shielded_token_type`](crate::contract::ContractAddress)),
//! committing all coins of that type to additional spend conditions. The rule
//! itself never appears on-chain; only the token type derived from its
//! [`descriptor_hash`](SpendRule::descriptor_hash) does.

use crate::contract::ContractAddress;
use base_crypto::hash::persistent_hash;
use fake::Dummy;
#[cfg(feature = "proptest")]
use proptest_derive::Arbitrary;
use serialize::{
    Deserializable, Serializable, Tagged, tag_enforcement_test, tagged_serialize,
    tagged_serialized_size,
};
use storage::db::DB;
use storage::{Storable, arena::ArenaKey, storable::Loader};
use transient_crypto::hash::HashOutput;

/// An additional condition attached to spending a shielded token, committed
/// to in the token type's derivation.
///
/// [`SpendRule::Empty`] denotes the absence of a custom rule and MUST map to
/// the legacy (pre-descriptor) token type derivation; it must never be hashed
/// into a derivation preimage itself.
#[derive(
    Debug, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Dummy, Serializable, Storable,
)]
#[storable(base)]
#[tag = "spend-rule[v1]"]
#[cfg_attr(feature = "proptest", derive(Arbitrary))]
pub enum SpendRule {
    /// No custom spend condition; the token behaves as a plain zswap token.
    #[default]
    Empty,
    /// Spending additionally requires satisfying the circuit whose verifier
    /// key hashes (via `persistent_hash` of its canonical serialization) to
    /// the contained value.
    GateCircuit(HashOutput),
    /// Spending additionally requires a call, within the same transaction, to
    /// the given contract entry point (identified by its `ep_hash`).
    GateContract(ContractAddress, HashOutput),
}
tag_enforcement_test!(SpendRule);

/// Everything a wallet needs to re-derive a coin's token type inside the CSL
/// spend circuit: the minting contract's address and domain separator, and
/// the spend rule the type was minted under.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenDerivation {
    pub domain_sep: HashOutput,
    pub mint_address: ContractAddress,
    pub rule: SpendRule,
}

impl TokenDerivation {
    /// The token type these inputs derive.
    pub fn token_type(&self) -> crate::coin::ShieldedTokenType {
        self.mint_address
            .custom_shielded_token_type(self.domain_sep, &self.rule)
    }

    /// The gate contract and entry point hash, for `GateContract` rules.
    pub fn gate(&self) -> Option<(ContractAddress, HashOutput)> {
        match &self.rule {
            SpendRule::GateContract(address, ep_hash) => Some((*address, *ep_hash)),
            _ => None,
        }
    }
}

/// Poseidon domain separator of the CSL policy binding.
///
/// `[v2]`: the hiding binding. The preimage commits to the spent token type and
/// to fresh per-spend randomness `rho`, and no longer to the gate and entry
/// point, which are authenticated as explicit public inputs of the spend
/// statement instead (see `zswap::verify`).
pub const CSL_BIND_DOMAIN_SEP: &[u8; 21] = b"midnight:csl-bind[v2]";

/// Field constant for [`CSL_BIND_DOMAIN_SEP`].
pub fn csl_bind_domain() -> transient_crypto::curve::Fr {
    transient_crypto::curve::Fr::from_le_bytes(CSL_BIND_DOMAIN_SEP).expect("21 bytes fit in Fr")
}

/// Splits a 32-byte value into the `[hi, lo]` field pair the zswap circuits use:
/// `hi` is the last byte, `lo` the first 31 bytes, both little-endian.
pub fn fr_pair(bytes: &[u8; 32]) -> [transient_crypto::curve::Fr; 2] {
    use transient_crypto::curve::Fr;
    [
        Fr::from_le_bytes(&bytes[31..]).expect("single byte fits in Fr"),
        Fr::from_le_bytes(&bytes[..31]).expect("31 bytes fit in Fr"),
    ]
}

/// The hiding policy binding a guarded spend exposes in its first public input:
/// `Poseidon(DOM, nullifier, sender, token_type, rho)`, where `sender` is the
/// coin public key (user-owned coins) or the owning contract address, and `rho`
/// is fresh, uniformly random field element drawn by the wallet once per spend.
///
/// `rho` is a private witness of both the spend proof and the gate proof; it is
/// never serialized, never a public input, never written to contract effects
/// and never logged. The nullifier is public and the token type is narrowed by
/// the (public) gate address, so without `rho` an observer who knows a
/// candidate sender key could recompute the binding and recognise that
/// sender's spends; with a secret uniform `rho` the value is a hiding
/// commitment and reveals nothing about the sender or type under the
/// standard assumption that Poseidon is a hiding commitment in its randomness.
/// What stays public is unchanged: the nullifier, the gate and entry point,
/// and the fact that the input is guarded.
pub fn csl_policy_binding(
    nullifier: &crate::coin::Nullifier,
    sender: &HashOutput,
    token_type: &crate::coin::ShieldedTokenType,
    rho: transient_crypto::curve::Fr,
) -> transient_crypto::curve::Fr {
    let mut preimage = vec![csl_bind_domain()];
    preimage.extend(fr_pair(&nullifier.0.0));
    preimage.extend(fr_pair(&sender.0));
    preimage.extend(fr_pair(&token_type.0.0));
    preimage.push(rho);
    transient_crypto::hash::transient_hash(&preimage)
}

impl SpendRule {
    /// A fixed-length (32-byte) commitment to this rule, appended to the
    /// token type derivation preimage for non-[`Empty`](SpendRule::Empty)
    /// rules. The hash preimage is the rule's tagged serialization
    /// (`midnight:spend-rule[v1]:` followed by the canonical encoding), so
    /// domain separation follows the crate-wide tagging scheme.
    ///
    /// Returns [`None`] for [`Empty`](SpendRule::Empty): the legacy 96-byte
    /// derivation preimage must be preserved exactly, so the absence of a
    /// rule contributes no bytes at all.
    pub fn descriptor_hash(&self) -> Option<HashOutput> {
        match self {
            SpendRule::Empty => None,
            _ => {
                let mut data = Vec::with_capacity(tagged_serialized_size(self));
                tagged_serialize(self, &mut data)
                    .expect("SpendRule serialization into a Vec cannot fail");
                Some(persistent_hash(&data))
            }
        }
    }
}

impl rand::distributions::Distribution<SpendRule> for rand::distributions::Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> SpendRule {
        match rng.gen_range(0..3u8) {
            0 => SpendRule::Empty,
            1 => SpendRule::GateCircuit(rng.r#gen()),
            _ => SpendRule::GateContract(ContractAddress(rng.r#gen()), rng.r#gen()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base_crypto::hash::persistent_commit;

    #[test]
    fn empty_rule_preserves_legacy_derivation() {
        let addr = ContractAddress(HashOutput([1u8; 32]));
        let domain_sep = HashOutput([2u8; 32]);
        // The pre-`SpendRule` derivation, spelled out independently of the
        // implementation in `contract.rs`.
        let legacy = persistent_commit(
            &(domain_sep, addr.0),
            HashOutput(*b"midnight:derive_token\0\0\0\0\0\0\0\0\0\0\0"),
        );
        assert_eq!(
            addr.custom_shielded_token_type(domain_sep, &SpendRule::Empty)
                .0,
            legacy
        );
        assert_eq!(addr.custom_unshielded_token_type(domain_sep).0, legacy);
    }

    #[test]
    fn rules_produce_distinct_token_types() {
        let addr = ContractAddress(HashOutput([1u8; 32]));
        let domain_sep = HashOutput([2u8; 32]);
        let types = [
            SpendRule::Empty,
            SpendRule::GateCircuit(HashOutput([3u8; 32])),
            SpendRule::GateCircuit(HashOutput([4u8; 32])),
            SpendRule::GateContract(addr, HashOutput([3u8; 32])),
        ]
        .iter()
        .map(|rule| addr.custom_shielded_token_type(domain_sep, rule))
        .collect::<std::collections::HashSet<_>>();
        assert_eq!(types.len(), 4);
    }

    /// The hiding binding depends on `rho` and on the token type: the same
    /// nullifier and sender under two different blindings, or under two types,
    /// give unrelated bindings (so a known key cannot be recognised without `rho`).
    #[test]
    fn policy_binding_is_blinded_and_type_bound() {
        use crate::coin::{Nullifier, ShieldedTokenType};
        use transient_crypto::curve::Fr;
        let nullifier = Nullifier(HashOutput([5u8; 32]));
        let sender = HashOutput([6u8; 32]);
        let t1 = ShieldedTokenType(HashOutput([7u8; 32]));
        let t2 = ShieldedTokenType(HashOutput([8u8; 32]));
        let b1 = csl_policy_binding(&nullifier, &sender, &t1, Fr::from(11));
        let b2 = csl_policy_binding(&nullifier, &sender, &t1, Fr::from(12));
        let b3 = csl_policy_binding(&nullifier, &sender, &t2, Fr::from(11));
        assert_ne!(b1, b2, "different randomness must change the binding");
        assert_ne!(b1, b3, "a different token type must change the binding");
        assert_eq!(b1, csl_policy_binding(&nullifier, &sender, &t1, Fr::from(11)), "deterministic for equal inputs");
    }

    /// Pins the exact byte layout the CSL spend circuit re-derives in-circuit:
    /// `descriptor_hash = SHA256("midnight:spend-rule[v1]:" || 0x02 || gate || ep_hash)` and
    /// `type = SHA256(pad32("midnight:derive_token") || domain_sep || mint_address || descriptor_hash)`.
    /// Any change to the tagged serialization of `SpendRule` or to the derivation must
    /// also change the circuit constants, and this test is what catches the drift.
    #[test]
    fn descriptor_hash_matches_fixed_layout() {
        use base_crypto::hash::persistent_hash;
        let gate = ContractAddress(HashOutput([7u8; 32]));
        let ep_hash = HashOutput([9u8; 32]);
        let rule = SpendRule::GateContract(gate, ep_hash);

        let mut descriptor_bytes = Vec::new();
        descriptor_bytes.extend_from_slice(b"midnight:spend-rule[v1]:");
        descriptor_bytes.push(2u8);
        descriptor_bytes.extend_from_slice(&gate.0.0);
        descriptor_bytes.extend_from_slice(&ep_hash.0);
        assert_eq!(descriptor_bytes.len(), 89);
        let descriptor_hash = persistent_hash(&descriptor_bytes);
        assert_eq!(rule.descriptor_hash(), Some(descriptor_hash));

        let domain_sep = HashOutput([2u8; 32]);
        let mint = ContractAddress(HashOutput([5u8; 32]));
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"midnight:derive_token\0\0\0\0\0\0\0\0\0\0\0");
        preimage.extend_from_slice(&domain_sep.0);
        preimage.extend_from_slice(&mint.0.0);
        preimage.extend_from_slice(&descriptor_hash.0);
        assert_eq!(preimage.len(), 128);
        assert_eq!(
            mint.custom_shielded_token_type(domain_sep, &rule).0,
            persistent_hash(&preimage)
        );

        let mut legacy = Vec::new();
        legacy.extend_from_slice(b"midnight:derive_token\0\0\0\0\0\0\0\0\0\0\0");
        legacy.extend_from_slice(&domain_sep.0);
        legacy.extend_from_slice(&mint.0.0);
        assert_eq!(legacy.len(), 96);
        assert_eq!(
            mint.custom_shielded_token_type(domain_sep, &SpendRule::Empty).0,
            persistent_hash(&legacy)
        );
    }
}
