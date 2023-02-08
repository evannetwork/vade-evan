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

use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub const EVAN_METHOD: &str = "did:evan";
pub const TYPE_SIDETREE_OPTIONS: &str = r#"{ "type": "sidetree", "waitForCompletion":true }"#;

pub const TYPE_BBS_KEY: &str = "Bls12381G2Key2020";
pub const TYPE_JSONWEB_KEY: &str = "JsonWebKey2020";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemovePublicKeys {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddPublicKeys {
    pub public_keys: Vec<PublicKeyModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveServices {
    pub ids: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddServices {
    pub services: Vec<Service>,
}

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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum PublicKeyPurpose {
    Authentication,
    AssertionMethod,
    CapabilityInvocation,
    CapabilityDelegation,
    KeyAgreement,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyModel {
    pub id: String,
    pub r#type: String,
    pub public_key_jwk: PublicKeyJWK,
    pub purposes: Vec<PublicKeyPurpose>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJWK {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "action")]
#[serde(rename_all(serialize = "kebab-case", deserialize = "kebab-case"))]
pub enum Patch {
    AddPublicKeys(AddPublicKeys),
    RemovePublicKeys(RemovePublicKeys),
    AddServices(AddServices),
    RemoveServices(RemoveServices),
    Default,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DidUpdatePayload {
    pub update_type: String,
    pub update_key: Option<PublicKeyJWK>,
    pub recovery_key: Option<PublicKeyJWK>,
    pub next_update_key: Option<PublicKeyJWK>,
    pub next_recovery_key: Option<PublicKeyJWK>,
    pub patches: Option<Vec<Patch>>,
}

/// Payload for DID creation. If keys are not provided, they will be generated automatically
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidPayload {
    pub update_key: Option<PublicKeyJWK>,
    pub recovery_key: Option<PublicKeyJWK>,
    pub public_keys: Option<Vec<PublicKeyModel>>,
    pub services: Option<Vec<Service>>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct IdentityDidDocument {
    #[serde(rename = "@context")]
    pub context: (String, String, DidDocumentContext),
    pub id: String,
    pub service: Vec<Service>,
    pub verification_method: Vec<VerificationMethod>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentContext {
    #[serde(rename = "@vocab")]
    pub vocab: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    pub service_endpoint: String,
    #[serde(rename = "type")]
    pub type_field: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub controller: String,
    pub id: String,
    pub public_key_jwk: PublicKeyJWK,
    #[serde(rename = "type")]
    pub type_field: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentResult<T> {
    pub did_document: T,
}
