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

//! The issuer's whitelist as the CSL gate sees it: a Poseidon Merkle tree of
//! owner commitments, maintained off chain by the administrator, whose root is
//! published in the gate contract's state.
//!
//! Leaf: `Poseidon(DOM_LEAF, owner_kind, pk_hi, pk_lo, r)` with `owner_kind = 1`
//! for user coin public keys (contract owners are reserved for a later stage)
//! and `r` enrollment randomness. Empty slots are the zero leaf. Path
//! convention is the one the zswap spend circuit uses
//! (`SpendWitness::merkle_root`): `goes_left` means the running node is the
//! left child.

use transient_crypto::curve::Fr;
use transient_crypto::hash::transient_hash;

use crate::zswap_spend::split_bytes32;

/// Depth of the fixture whitelist tree (256 members).
pub const WHITELIST_DEPTH: usize = 8;
/// Poseidon domain separator of whitelist leaves.
pub const LEAF_DOMAIN_SEP: &[u8; 21] = b"midnight:csl-leaf[v1]";
/// Owner kind of a user coin public key.
pub const OWNER_KIND_USER: u64 = 1;

/// Field constant for [`LEAF_DOMAIN_SEP`].
pub fn leaf_domain() -> Fr {
    Fr::from_le_bytes(LEAF_DOMAIN_SEP).expect("21 bytes fit in Fr")
}

/// A whitelist leaf for a user coin public key with enrollment randomness `r`.
pub fn user_leaf(pk: &[u8; 32], r: Fr) -> Fr {
    let [hi, lo] = split_bytes32(pk);
    transient_hash(&[leaf_domain(), Fr::from(OWNER_KIND_USER), hi, lo, r])
}

/// Membership evidence for one leaf: its enrollment randomness and Merkle path.
#[derive(Clone, Debug)]
pub struct Membership {
    pub r: Fr,
    pub path: [(Fr, bool); WHITELIST_DEPTH],
}

/// Recomputes a root from a leaf and a path, with the zswap path convention.
pub fn root_from_path(leaf: Fr, path: &[(Fr, bool)]) -> Fr {
    path.iter().fold(leaf, |acc, (sibling, goes_left)| {
        if *goes_left {
            transient_hash(&[acc, *sibling])
        } else {
            transient_hash(&[*sibling, acc])
        }
    })
}

/// The administrator's off-chain whitelist: a fixed-depth tree of leaves.
#[derive(Clone, Debug)]
pub struct Whitelist {
    leaves: Vec<Fr>,
}

impl Whitelist {
    /// An empty whitelist (every slot is the zero leaf).
    pub fn new() -> Self {
        Whitelist {
            leaves: vec![Fr::from(0); 1 << WHITELIST_DEPTH],
        }
    }

    /// Places `leaf` at `index`, replacing whatever was there.
    pub fn set(&mut self, index: usize, leaf: Fr) {
        self.leaves[index] = leaf;
    }

    /// Removes the leaf at `index` (zero leaf).
    pub fn remove(&mut self, index: usize) {
        self.leaves[index] = Fr::from(0);
    }

    fn levels(&self) -> Vec<Vec<Fr>> {
        let mut levels = vec![self.leaves.clone()];
        for _ in 0..WHITELIST_DEPTH {
            let prev = levels.last().expect("non-empty");
            let next = prev
                .chunks(2)
                .map(|pair| transient_hash(&[pair[0], pair[1]]))
                .collect::<Vec<_>>();
            levels.push(next);
        }
        levels
    }

    /// The current root.
    pub fn root(&self) -> Fr {
        self.levels()[WHITELIST_DEPTH][0]
    }

    /// The Merkle path of the leaf at `index`.
    pub fn path(&self, index: usize) -> [(Fr, bool); WHITELIST_DEPTH] {
        let levels = self.levels();
        let mut path = [(Fr::from(0), false); WHITELIST_DEPTH];
        let mut i = index;
        for (level, slot) in path.iter_mut().enumerate() {
            let goes_left = i % 2 == 0;
            let sibling = levels[level][if goes_left { i + 1 } else { i - 1 }];
            *slot = (sibling, goes_left);
            i /= 2;
        }
        path
    }
}

impl Default for Whitelist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_recompute_the_root() {
        let mut wl = Whitelist::new();
        let leaf_a = user_leaf(&[1u8; 32], Fr::from(11));
        let leaf_b = user_leaf(&[2u8; 32], Fr::from(22));
        wl.set(3, leaf_a);
        wl.set(200, leaf_b);
        let root = wl.root();
        assert_eq!(root_from_path(leaf_a, &wl.path(3)), root);
        assert_eq!(root_from_path(leaf_b, &wl.path(200)), root);
        assert_ne!(root_from_path(leaf_a, &wl.path(200)), root);
        wl.remove(3);
        assert_ne!(wl.root(), root);
        assert_ne!(root_from_path(leaf_a, &wl.path(3)), wl.root());
    }
}
