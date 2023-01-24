/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#[cfg(all(feature = "target-c-lib", feature = "capability-sdk"))]
mod in3_request_list;

#[cfg(feature = "capability-c-lib")]
mod c_lib;
#[cfg(feature = "target-java-lib")]
mod java_lib;
// wasm only
#[cfg(target_arch = "wasm32")]
pub extern crate log;
#[cfg(target_arch = "wasm32")]
mod wasm_lib;

mod api;
mod helpers;

pub use crate::api::{VadeEvan, VadeEvanConfig, VadeEvanError, DEFAULT_SIGNER, DEFAULT_TARGET};
