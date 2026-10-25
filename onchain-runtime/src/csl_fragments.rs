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
