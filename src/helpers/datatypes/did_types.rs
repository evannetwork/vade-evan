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
use std::str::FromStr;
use serde::{Deserialize, Serialize};

#[cfg(feature = "plugin-did-sidetree")]
pub const TYPE_SIDETREE_OPTIONS: &str = r#"{ "type": "sidetree", "waitForCompletion":true }"#;
pub const EVAN_METHOD: &str = "did:evan";

#[derive(Debug, PartialEq)]
pub enum DIDOperationType {
    AddKey,
    RemoveKey,
    AddServiceEnpoint,
    RemoveServiceEnpoint,
    ReplaceDidDoc
}

impl FromStr for DIDOperationType {
    type Err = ();
    fn from_str(input: &str) -> Result<DIDOperationType, Self::Err> {
        match input {
            "AddKey" => Ok(DIDOperationType::AddKey),
            "RemoveKey" => Ok(DIDOperationType::RemoveKey),
            "AddServiceEnpoint" => Ok(DIDOperationType::AddServiceEnpoint),
            "RemoveServiceEnpoint" => Ok(DIDOperationType::RemoveServiceEnpoint),
            "ReplaceDidDoc" => Ok(DIDOperationType::ReplaceDidDoc),
            _ => Err(()),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentResult<T> {
    pub did_document: T,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IdentityDidDocument {
    pub id: String,
    pub verification_method: Option<Vec<VerificationMethod>>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    pub public_key_jwk: PublicKeyJwk,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJwk {
    pub crv: String,
    pub kty: String,
    pub x: String,
    pub y: Option<String>,
}
