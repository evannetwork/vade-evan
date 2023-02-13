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

use serde::Deserialize;
use std::str::FromStr;

pub const EVAN_METHOD: &str = "did:evan";
pub const TYPE_SIDETREE_OPTIONS: &str = r#"{ "type": "sidetree", "waitForCompletion":true }"#;

pub const TYPE_BBS_KEY: &str = "Bls12381G2Key2020";
pub const TYPE_JSONWEB_KEY: &str = "JsonWebKey2020";

#[derive(Debug, PartialEq)]
pub enum DIDOperationType {
    AddKey,
    RemoveKey,
    AddServiceEnpoint,
    RemoveServiceEnpoint,
}

impl FromStr for DIDOperationType {
    type Err = ();
    fn from_str(input: &str) -> Result<DIDOperationType, Self::Err> {
        match input {
            "AddKey" => Ok(DIDOperationType::AddKey),
            "RemoveKey" => Ok(DIDOperationType::RemoveKey),
            "AddServiceEnpoint" => Ok(DIDOperationType::AddServiceEnpoint),
            "RemoveServiceEnpoint" => Ok(DIDOperationType::RemoveServiceEnpoint),
            _ => Err(()),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentResult<T> {
    pub did_document: T,
}
