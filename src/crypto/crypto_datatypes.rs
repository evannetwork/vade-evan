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
use ursa::{
    bn::BigNumber,
    cl::{
        BlindedCredentialSecrets,
        BlindedCredentialSecretsCorrectnessProof,
        CredentialKeyCorrectnessProof,
        CredentialPublicKey,
        CredentialSchema as CryptoCredentialSchema,
        RevocationKeyPublic,
        RevocationRegistry,
        RevocationRegistryDelta,
        RevocationTailsGenerator,
        SubProofRequest,
    },
};

pub struct CryptoCredentialRequest {
    pub subject: String,
    pub blinded_credential_secrets: BlindedCredentialSecrets,
    pub blinded_credential_secrets_correctness_proof: BlindedCredentialSecretsCorrectnessProof,
    pub credential_nonce: BigNumber,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoCredentialDefinition {
    pub public_key: CredentialPublicKey,
    pub credential_key_correctness_proof: CredentialKeyCorrectnessProof,
}

// TODO: More supported fields?
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaProperty {
    pub r#type: String,
    pub format: Option<String>,
    pub items: Option<Vec<String>>,
}

pub struct CryptoProofRequest {
    pub credential_schema: CryptoCredentialSchema,
    pub crypto_proof_request: SubProofRequest,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssertionProof {
    pub r#type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub jws: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoRevocationRegistryDefinition {
    pub registry: RevocationRegistry,
    pub registry_delta: RevocationRegistryDelta, // No delta before a credential has been revoked
    pub tails: RevocationTailsGenerator,
    pub revocation_public_key: RevocationKeyPublic,
    pub maximum_credential_count: u32,
}
