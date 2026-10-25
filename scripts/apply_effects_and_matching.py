# Applies the CSL effects fields (indices 9 and 10), kernel claim macros, the ledger
# matching rule, test literal updates and tag bumps. Run from the ledger checkout root.
import re
def patch(path, pairs):
    s = open(path).read()
    for old, new in pairs:
        assert s.count(old) == 1, f"{path}: anchor not unique/found (count={s.count(old)}): {old[:70]!r}"
        s = s.replace(old, new, 1)
    open(path, 'w').write(s); print("patched", path)

# ---------------- onchain-runtime: Effects --------------------------------------------------
patch('onchain-runtime/src/context.rs', [
('#[tag = "contract-effects[v4]"]\npub struct Effects<D: DB> {',
 '#[tag = "contract-effects[v5]"]\npub struct Effects<D: DB> {'),
("""    pub claimed_unshielded_spends: storage::storage::HashMap<ClaimedUnshieldedSpendsKey, u128, D>,
}
tag_enforcement_test!(Effects<InMemoryDB>);""",
"""    pub claimed_unshielded_spends: storage::storage::HashMap<ClaimedUnshieldedSpendsKey, u128, D>,
    /// CSL: policy bindings of guarded zswap inputs this call authorizes
    /// (effects index 9). The ledger matches them one-to-one against the
    /// `policy` fields of the inputs in the call's logical segment.
    pub claimed_spend_authorizations: storage::storage::HashSet<Fr, D>,
    /// CSL: the output commitments this call has checked (effects index 10).
    /// When a call claims anything under CSL, this must equal the full set of
    /// output and transient commitments of its logical segment.
    pub claimed_output_coverage: storage::storage::HashSet<CoinCommitment, D>,
}
tag_enforcement_test!(Effects<InMemoryDB>);"""),
("""            claimed_unshielded_spends: vec![rng.r#gen(); 5].into_iter().collect(),
        }
    }
}""",
"""            claimed_unshielded_spends: vec![rng.r#gen(); 5].into_iter().collect(),
            claimed_spend_authorizations: vec![rng.r#gen(); 5].into_iter().collect(),
            claimed_output_coverage: vec![rng.r#gen(); 5].into_iter().collect(),
        }
    }
}"""),
("""    claimed_unshielded_spends: HashMap<(SerdeTokenType, SerdePublicAddress), u128>,
}""",
"""    claimed_unshielded_spends: HashMap<(SerdeTokenType, SerdePublicAddress), u128>,
    #[serde(default)]
    claimed_spend_authorizations: HashSet<Fr>,
    #[serde(default)]
    claimed_output_coverage: HashSet<String>,
}"""),
("""                    .collect::<Result<
                        storage::storage::HashMap<ClaimedUnshieldedSpendsKey, u128, D>,
                        _,
                    >>()?,
        })
    }
}""",
"""                    .collect::<Result<
                        storage::storage::HashMap<ClaimedUnshieldedSpendsKey, u128, D>,
                        _,
                    >>()?,
            claimed_spend_authorizations: eff.claimed_spend_authorizations.into_iter().collect(),
            claimed_output_coverage: eff
                .claimed_output_coverage
                .into_iter()
                .map(|cm| Ok::<_, FromHexError>(CoinCommitment(HashOutput(FromHex::from_hex(cm)?))))
                .collect::<Result<_, _>>()
                .map_err(err_conv)?,
        })
    }
}"""),
("""                                (key.into(), StateValue::Cell(Sp::new(value.into())))
                            })
                            .collect(),
                    ),
                ]
                .into(),""",
"""                                (key.into(), StateValue::Cell(Sp::new(value.into())))
                            })
                            .collect(),
                    ),
                    StateValue::Map(
                        eff.claimed_spend_authorizations
                            .iter()
                            .map(|k| ((**k).into(), StateValue::Null))
                            .collect(),
                    ),
                    StateValue::Map(
                        eff.claimed_output_coverage
                            .iter()
                            .map(|k| ((**k).into(), StateValue::Null))
                            .collect(),
                    ),
                ]
                .into(),"""),
("""        if let StateValue::Array(arr) = &val.value
            && arr.len() == 9
        {""",
"""        if let StateValue::Array(arr) = &val.value
            && arr.len() == 11
        {"""),
("""                claimed_unshielded_spends: map_from(arr.get(8).unwrap())?,
            });""",
"""                claimed_unshielded_spends: map_from(arr.get(8).unwrap())?,
                claimed_spend_authorizations: map_from::<Fr, (), D>(arr.get(9).unwrap())?
                    .iter()
                    .map(|x| *x.0)
                    .collect(),
                claimed_output_coverage: map_from::<CoinCommitment, (), D>(arr.get(10).unwrap())?
                    .iter()
                    .map(|x| *x.0)
                    .collect(),
            });"""),
])
# From<Effects> for SerdeEffects: append the two conversions
s = open('onchain-runtime/src/context.rs').read()
i = s.index("impl<D: DB> From<Effects<D>> for SerdeEffects {")
j = s.index("\n        }\n    }\n}\n", i)
assert "claimed_unshielded_spends" in s[i:j]
s = s[:j] + """
            claimed_spend_authorizations: eff
                .claimed_spend_authorizations
                .iter()
                .map(|b| *(*b).deref())
                .collect(),
            claimed_output_coverage: eff
                .claimed_output_coverage
                .iter()
                .map(|cm| cm.0.0.encode_hex())
                .collect(),""" + s[j:]
open('onchain-runtime/src/context.rs', 'w').write(s); print("patched SerdeEffects conversion")

# ---------------- onchain-runtime: kernel claim macros -------------------------------------
open('onchain-runtime/src/csl_fragments.rs', 'w').write('''// This file is part of midnight-ledger.
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

//! Custom Spend Logic kernel fragments: the claims a gate contract makes about
//! the guarded zswap movement it authorizes. Modelled on the vendored
//! `kernel_claim_zswap_*` fragments; they insert into the two CSL effects maps
//! (indices 9 and 10 of the effects array, see `context::Effects`).

/// Claims the policy binding of a guarded input (effects index 9).
#[macro_export]
macro_rules! kernel_claim_spend_authorization {
  ($binding:expr_2021) => {
    [
      Op::Swap { n: 0.try_into().unwrap() },
      Op::Idx { cached: true.try_into().unwrap(), push_path: true.try_into().unwrap(), path: vec![Key::Value(AlignedValue::from(9 as u8).into())].try_into().unwrap() },
      Op::Push { storage: false.try_into().unwrap(), value: StateValue::Cell(Sp::new(AlignedValue::from($binding.clone()).try_into().unwrap())).try_into().unwrap() },
      Op::Push { storage: false.try_into().unwrap(), value: StateValue::Null.try_into().unwrap() },
      Op::Ins { cached: true.try_into().unwrap(), n: 2.try_into().unwrap() },
      Op::Swap { n: 0.try_into().unwrap() },
    ]
  };
}
pub use kernel_claim_spend_authorization;

/// Claims one output commitment as checked (effects index 10).
#[macro_export]
macro_rules! kernel_claim_output_coverage {
  ($cm:expr_2021) => {
    [
      Op::Swap { n: 0.try_into().unwrap() },
      Op::Idx { cached: true.try_into().unwrap(), push_path: true.try_into().unwrap(), path: vec![Key::Value(AlignedValue::from(10 as u8).into())].try_into().unwrap() },
      Op::Push { storage: false.try_into().unwrap(), value: StateValue::Cell(Sp::new($cm.clone().try_into().unwrap())).try_into().unwrap() },
      Op::Push { storage: false.try_into().unwrap(), value: StateValue::Null.try_into().unwrap() },
      Op::Ins { cached: true.try_into().unwrap(), n: 2.try_into().unwrap() },
      Op::Swap { n: 0.try_into().unwrap() },
    ]
  };
}
pub use kernel_claim_output_coverage;
''')
patch('onchain-runtime/src/lib.rs', [("pub mod program_fragments;\n", "pub mod program_fragments;\npub mod csl_fragments;\n")])

# ---------------- onchain-runtime: transcript tag ------------------------------------------
patch('onchain-runtime/src/transcript.rs', [('#[tag = "contract-transcript[v5]"]', '#[tag = "contract-transcript[v6]"]')])

# ---------------- ledger: tags ---------------------------------------------------------------
s = open('ledger/src/structure.rs').read()
for old, new in [('#[tag = "contract-call[v4]"]', '#[tag = "contract-call[v5]"]'),
                 ('#[tag = "contract-action[v10]"]', '#[tag = "contract-action[v11]"]'),
                 ('#[tag = "transaction[v13]"]', '#[tag = "transaction[v14]"]'),
                 ('#[tag = "standard-transaction[v13]"]', '#[tag = "standard-transaction[v14]"]')]:
    assert s.count(old) == 1, old
    s = s.replace(old, new, 1)
n = len(re.findall(r'#\[tag = "((?:inner-)?intent[^"\]]*)\[v10\]"\]', s))
s = re.sub(r'#\[tag = "((?:inner-)?intent[^"\]]*)\[v10\]"\]', r'#[tag = "\1[v11]"]', s)
print("intent-family tags bumped:", n)
# cost accounting for the two new maps
old = """            (
                eff.claimed_unshielded_spends.size(),
                PERSISTENT_HASH_BYTES * 2 + 1,
            ),
        ];"""
assert s.count(old) == 1
s = s.replace(old, """            (
                eff.claimed_unshielded_spends.size(),
                PERSISTENT_HASH_BYTES * 2 + 1,
            ),
            (eff.claimed_spend_authorizations.size(), PERSISTENT_HASH_BYTES),
            (eff.claimed_output_coverage.size(), PERSISTENT_HASH_BYTES),
        ];""", 1)
open('ledger/src/structure.rs', 'w').write(s); print("patched ledger/src/structure.rs")

# ---------------- ledger: error variants ----------------------------------------------------
patch('ledger/src/error.rs', [
("""    CommitmentsNEClaimedShieldedReceives {
        commitments: Vec<(u16, Commitment, ContractAddress)>,
        claimed_shielded_receives: Vec<(u16, Commitment, ContractAddress)>,
    },
}""",
"""    CommitmentsNEClaimedShieldedReceives {
        commitments: Vec<(u16, Commitment, ContractAddress)>,
        claimed_shielded_receives: Vec<(u16, Commitment, ContractAddress)>,
    },
    /// CSL: the policy bindings of guarded inputs and the spend authorizations
    /// claimed by gate calls differ (keyed by logical segment, gate address,
    /// entry point hash and binding).
    SpendAuthorizationsNEClaimed {
        inputs: Vec<(u16, ContractAddress, HashOutput, Fr)>,
        claimed: Vec<(u16, ContractAddress, HashOutput, Fr)>,
    },
    /// CSL: a gate call claimed an output coverage that is not the full output
    /// commitment set of its logical segment.
    OutputCoverageNESegmentCommitments {
        segment: u16,
        gate: ContractAddress,
        claimed: Vec<Commitment>,
        actual: Vec<Commitment>,
    },
}"""),
("""                "all contract-associated commitments must be claimed by exactly one instance of the same contract in the same segment. commitments: {commitments:?}, claimed_shielded_receives: {claimed_shielded_receives:?}"
            ),
        }
    }
}""",
"""                "all contract-associated commitments must be claimed by exactly one instance of the same contract in the same segment. commitments: {commitments:?}, claimed_shielded_receives: {claimed_shielded_receives:?}"
            ),
            EffectsCheckError::SpendAuthorizationsNEClaimed { inputs, claimed } => write!(
                formatter,
                "every guarded (CSL) input must be authorized by exactly one claimed spend authorization of its gate in the same segment, and vice versa. inputs: {inputs:?}, claimed: {claimed:?}"
            ),
            EffectsCheckError::OutputCoverageNESegmentCommitments {
                segment,
                gate,
                claimed,
                actual,
            } => write!(
                formatter,
                "the CSL gate {gate:?} must claim exactly the output commitments of segment {segment}. claimed: {claimed:?}, actual: {actual:?}"
            ),
        }
    }
}"""),
])

# ---------------- ledger: matching rule + test literals ------------------------------------
s = open('ledger/src/verify.rs').read()
anchor = "        let claimed_calls: MultiSet<(u16, (ContractAddress, HashOutput, Fr))> = transcripts"
assert s.count(anchor) == 1
rule = """        // --- Custom Spend Logic: guarded spends must be authorized by their gate ---------
        // Every guarded input (one carrying a `policy`) in logical segment `s` must be
        // matched by exactly one claimed spend authorization made by a call to its gate
        // address and entry point whose transcript executes in `s`, and every such claim
        // must match an input. Multiset equality gives both directions.
        let policy_inputs: MultiSet<(u16, ContractAddress, HashOutput, Fr)> = offers
            .iter()
            .flat_map(|(segment, offer)| {
                offer
                    .inputs
                    .iter()
                    .filter_map(|i| {
                        i.policy
                            .as_ref()
                            .map(|p| (*segment, p.gate, p.entry_point_hash, p.binding))
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let claimed_authorizations: MultiSet<(u16, ContractAddress, HashOutput, Fr)> = calls
            .iter()
            .flat_map(|(segment, call)| {
                let ep_hash = call.entry_point.ep_hash();
                call.guaranteed_transcript
                    .iter()
                    .map(|t| (GUARANTEED_SEGMENT, t))
                    .chain(call.fallible_transcript.iter().map(|t| (*segment, t)))
                    .flat_map(|(logical, t)| {
                        t.effects
                            .claimed_spend_authorizations
                            .iter()
                            .map(|b| (logical, call.address, ep_hash, *(*b).deref()))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        if policy_inputs != claimed_authorizations {
            return Err(MalformedTransaction::EffectsCheckFailure(
                EffectsCheckError::SpendAuthorizationsNEClaimed {
                    inputs: policy_inputs.into_iter().map(|(v, _)| v).collect(),
                    claimed: claimed_authorizations.into_iter().map(|(v, _)| v).collect(),
                },
            ));
        }
        // A call that claims anything under CSL must have checked the complete output
        // commitment set (outputs and transients) of its logical segment.
        for (segment, call) in calls.iter() {
            for (logical, t) in call
                .guaranteed_transcript
                .iter()
                .map(|t| (GUARANTEED_SEGMENT, t))
                .chain(call.fallible_transcript.iter().map(|t| (*segment, t)))
            {
                let claims_nothing = t.effects.claimed_spend_authorizations.iter().next().is_none()
                    && t.effects.claimed_output_coverage.iter().next().is_none();
                if claims_nothing {
                    continue;
                }
                let claimed: MultiSet<Commitment> = t
                    .effects
                    .claimed_output_coverage
                    .iter()
                    .map(|c| *(*c).deref())
                    .collect();
                let actual: MultiSet<Commitment> = offers
                    .get(&logical)
                    .map(|offer| {
                        offer
                            .outputs
                            .iter()
                            .map(|o| o.coin_com)
                            .chain(offer.transient.iter().map(|tr| tr.coin_com))
                            .collect()
                    })
                    .unwrap_or_else(MultiSet::new);
                if claimed != actual {
                    return Err(MalformedTransaction::EffectsCheckFailure(
                        EffectsCheckError::OutputCoverageNESegmentCommitments {
                            segment: logical,
                            gate: call.address,
                            claimed: claimed.into_iter().map(|(v, _)| v).collect(),
                            actual: actual.into_iter().map(|(v, _)| v).collect(),
                        },
                    ));
                }
            }
        }
"""
s = s.replace(anchor, rule + anchor, 1)
n = len(re.findall(r'(\n\s*)claimed_unshielded_spends: rng\.r#gen\(\),\n', s))
s = re.sub(r'(\n(\s*))claimed_unshielded_spends: rng\.r#gen\(\),\n',
           r'\1claimed_unshielded_spends: rng.r#gen(),\n\2claimed_spend_authorizations: rng.r#gen(),\n\2claimed_output_coverage: rng.r#gen(),\n', s)
print("test Effects literals extended:", n)
open('ledger/src/verify.rs', 'w').write(s); print("patched ledger/src/verify.rs")
print("ALL PATCHES APPLIED")
