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

use crate::crypto::crypto_datatypes::AssertionProof;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
};
use ursa::cl::{
    issuer::Issuer as UrsaIssuer,
    BlindedCredentialSecrets,
    BlindedCredentialSecretsCorrectnessProof,
    CredentialKeyCorrectnessProof,
    CredentialPublicKey,
    CredentialSchema as UrsaCredentialSchema,
    CredentialSignature as CryptoCredentialSignature,
    Nonce,
    RevocationKeyPublic,
    RevocationRegistry,
    RevocationRegistryDelta,
    RevocationTailsGenerator,
    SignatureCorrectnessProof,
    Witness,
};
pub use ursa::cl::{
    CredentialPrivateKey,
    CredentialSecretsBlindingFactors,
    MasterSecret,
    RevocationKeyPrivate,
};

/// Holds metadata and the key material used to issue and process credentials,
/// and create and verify proofs.
/// Needs to be stored publicly available and temper-proof.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDefinition {
    pub id: String,
    pub r#type: String,
    pub issuer: String,
    pub schema: String,
    pub created_at: String,
    pub public_key: CredentialPublicKey,
    pub public_key_correctness_proof: CredentialKeyCorrectnessProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<AssertionProof>,
}

/// Specifies the properties of a credential, as well as metadata.
/// Needs to be stored publicly available and temper-proof.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
    pub id: String,
    pub r#type: String,
    pub name: String,
    pub author: String,
    pub created_at: String,
    pub description: String,
    pub properties: HashMap<String, SchemaProperty>,
    pub required: Vec<String>,
    pub additional_properties: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<AssertionProof>,
}

impl TryInto<UrsaCredentialSchema> for CredentialSchema {
    type Error = ();

    fn try_into(self) -> Result<UrsaCredentialSchema, Self::Error> {
        let mut credential_schema_builder = match UrsaIssuer::new_credential_schema_builder() {
            Ok(result) => result,
            Err(_) => {
                return Err(());
            }
        };
        for property in &self.properties {
            match credential_schema_builder.add_attr(&property.0) {
                Ok(result) => result,
                Err(_) => {
                    return Err(());
                }
            };
        }
        let result = match credential_schema_builder.finalize() {
            Ok(result) => result,
            Err(_) => {
                return Err(());
            }
        };
        Ok(result)
    }
}

// TODO: More supported fields?
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaProperty {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<String>>,
}

/// Message following a `CredentialProposal`, sent by an issuer.
/// Specifies the DIDs of both the `CredentialSchema` and `CredentialDefinition`
/// to be used for issuance.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOffer {
    pub issuer: String,
    pub subject: String,
    pub r#type: String,
    pub schema: String,
    pub credential_definition: String,
    pub nonce: Nonce,
}

/// Message following a `CredentialOffer`, sent by a potential credential prover.
/// Provides the values that need to be signed by the issuer in both encoded/cleartext, and blinded format.
/// Incorporates the nonce value sent in `CredentialOffer`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRequest {
    pub subject: String,
    pub schema: String,
    pub credential_definition: String,
    pub r#type: String,
    pub blinded_credential_secrets: BlindedCredentialSecrets,
    pub blinded_credential_secrets_correctness_proof: BlindedCredentialSecretsCorrectnessProof,
    pub credential_nonce: Nonce,
    pub credential_values: HashMap<String, EncodedCredentialValue>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSignature {
    pub r#type: String,
    pub credential_definition: String,
    pub signature: CryptoCredentialSignature,
    pub signature_correctness_proof: SignatureCorrectnessProof,
    pub issuance_nonce: Nonce,
    pub revocation_id: u32,
    pub revocation_registry_definition: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaReference {
    pub id: String,
    pub r#type: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    pub id: String,
    pub data: HashMap<String, EncodedCredentialValue>,
}

/// A verifiable credential issued by an issuer upon receiving a `CredentialRequest`.
/// Specifies the signed values, the DID of the prover/subject, the `CredentialSchema`, and the `CredentialSignature`
/// including revocation info.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub proof: CredentialSignature,
}

/// Contains all necessary cryptographic information for credential revocation.
/// The `registry` and `registry_delta` properties need to be updated after every revocation
/// (and, depending on the type of the revocation registry, after every issuance).
/// Contains a `DeltaHistory` to let provers update their credential's `Witness` before proving non-revocation.
/// Needs to be stored publicly available and temper-proof.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDefinition {
    pub id: String,
    pub credential_definition: String,
    pub updated_at: String,
    pub registry: RevocationRegistry,
    pub registry_delta: RevocationRegistryDelta,
    pub delta_history: Vec<DeltaHistory>,
    pub tails: RevocationTailsGenerator,
    pub revocation_public_key: RevocationKeyPublic,
    pub maximum_credential_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<AssertionProof>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DeltaHistory {
    pub created: u64,
    pub delta: RevocationRegistryDelta,
}

/// Holds the current `Witness` for a credential. Witnesses need to be updated before creating proofs.
/// To do this, the prover needs to retrieve the `DeltaHistory` of the relevant `RevocationRegistryDefinition`
/// and update the witness with all deltas that are newer than the `updated` property of the `RevocationState`.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationState {
    pub credential_id: String,
    pub revocation_id: u32,
    pub updated: u64,
    pub delta: RevocationRegistryDelta,
    pub witness: Witness,
}

/// Message to initiate credential issuance, sent by (potential) prover.
/// Specifies the schema to be used for the credential.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProposal {
    pub issuer: String,
    pub subject: String,
    pub r#type: String,
    pub schema: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubProofRequest {
    pub schema: String,
    pub revealed_attributes: Vec<String>,
}

/// Message sent by a verifier to prompt a prover to prove one or many assertions.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofRequest {
    pub verifier: String,
    pub prover: String,
    pub created_at: String,
    pub nonce: Nonce,
    pub sub_proof_requests: Vec<SubProofRequest>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubProof {
    pub credential_definition: String,
    pub revocation_registry_definition: String,
    pub proof: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregatedProof {
    pub nonce: Nonce,
    pub aggregated_proof: String,
}

/// A single proof of a schema requested in a `ProofRequest` that reveals the requested attributes.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofCredential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub proof: CredentialSubProof,
}

/// A collection of all proofs requested in a `ProofRequest`. Sent to a verifier as the response to
/// a `ProofRequest`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofPresentation {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub verifiable_credential: Vec<ProofCredential>,
    pub proof: AggregatedProof,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofVerification {
    pub presented_proof: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncodedCredentialValue {
    pub raw: String,
    pub encoded: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationIdInformation {
    pub definition_id: String,
    pub next_unused_id: u32,
    pub used_ids: HashSet<u32>,
}
