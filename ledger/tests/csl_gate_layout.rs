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

//! Layout probe for the CSL gate contract's public transcript.
//!
//! The gate relation is hand-written and must emit, as public inputs, exactly
//! the field representation of the transcript program the ledger replays. This
//! probe prints that representation for the program fragments the gate uses so
//! the relation's hole positions can be pinned (and later asserted) against it.

use base_crypto::fab::AlignedValue;
use onchain_runtime::ops::{Key, Op};
use onchain_runtime::result_mode::ResultModeVerify;
use onchain_runtime::state::StateValue;
use onchain_runtime::{Cell_read, Cell_write, ops::key};
use storage::arena::Sp;
use storage::db::InMemoryDB;
use transient_crypto::curve::Fr;
use transient_crypto::repr::FieldRepr;

fn repr(ops: &[Op<ResultModeVerify, InMemoryDB>]) -> Vec<Fr> {
    let mut out = Vec::new();
    for op in ops {
        op.field_repr(&mut out);
    }
    out
}

fn show(label: &str, ops: &[Op<ResultModeVerify, InMemoryDB>]) {
    let r = repr(ops);
    eprintln!("{label}: {} ops, {} field elements", ops.len(), r.len());
    for (i, op) in ops.iter().enumerate() {
        let mut one = Vec::new();
        op.field_repr(&mut one);
        eprintln!("  op[{i}] {:?} -> {:?}", op, one.iter().map(|f| format!("{f:?}")).collect::<Vec<_>>());
    }
}

#[test]
fn print_gate_program_layout() {
    let root: Fr = Fr::from(0x1234u64);
    let token_type: [u8; 32] = [0xAB; 32];
    let admin: Fr = Fr::from(0x77u64);
    // Reads the gate uses (results are translated to concrete values as the verifier sees them).
    let read_root: Vec<Op<ResultModeVerify, InMemoryDB>> = Cell_read!([key!(0u8)], false, Fr)
        .into_iter()
        .map(|op: Op<onchain_runtime::result_mode::ResultModeGather, InMemoryDB>| op.translate(|()| root.into()))
        .collect();
    show("Cell_read root (Fr)", &read_root);
    let read_type: Vec<Op<ResultModeVerify, InMemoryDB>> = Cell_read!([key!(1u8)], false, [u8; 32])
        .into_iter()
        .map(|op: Op<onchain_runtime::result_mode::ResultModeGather, InMemoryDB>| op.translate(|()| token_type.into()))
        .collect();
    show("Cell_read token type ([u8;32])", &read_type);
    let read_admin: Vec<Op<ResultModeVerify, InMemoryDB>> = Cell_read!([key!(2u8)], false, Fr)
        .into_iter()
        .map(|op: Op<onchain_runtime::result_mode::ResultModeGather, InMemoryDB>| op.translate(|()| admin.into()))
        .collect();
    show("Cell_read admin (Fr)", &read_admin);
    let write_root: Vec<Op<ResultModeVerify, InMemoryDB>> = Cell_write!([key!(0u8)], false, Fr, root).to_vec();
    show("Cell_write root (Fr)", &write_root);
    let write_type: Vec<Op<ResultModeVerify, InMemoryDB>> = Cell_write!([key!(1u8)], false, [u8; 32], token_type).to_vec();
    show("Cell_write token type", &write_type);
    // A claim-style insertion into an effects map, modelled on kernel_claim_zswap_nullifier
    // but targeting effects index 9 (claimed spend authorizations) with an Fr value.
    let binding: Fr = Fr::from(0x5555u64);
    let claim_auth: Vec<Op<ResultModeVerify, InMemoryDB>> = vec![
        Op::Swap { n: 0 },
        Op::Idx { cached: true, push_path: true, path: vec![Key::Value(AlignedValue::from(9u8))].into() },
        Op::Push { storage: false, value: StateValue::Cell(Sp::new(AlignedValue::from(binding))) },
        Op::Push { storage: false, value: StateValue::Null },
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ];
    show("claim spend authorization (effects[9], Fr)", &claim_auth);
    let cm: [u8; 32] = [0xCD; 32];
    let claim_cov: Vec<Op<ResultModeVerify, InMemoryDB>> = vec![
        Op::Swap { n: 0 },
        Op::Idx { cached: true, push_path: true, path: vec![Key::Value(AlignedValue::from(10u8))].into() },
        Op::Push { storage: false, value: StateValue::Cell(Sp::new(AlignedValue::from(cm))) },
        Op::Push { storage: false, value: StateValue::Null },
        Op::Ins { cached: true, n: 2 },
        Op::Swap { n: 0 },
    ];
    show("claim output coverage (effects[10], [u8;32])", &claim_cov);
}
