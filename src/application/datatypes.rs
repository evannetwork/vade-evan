use ursa::cl::{
  CredentialPublicKey,
  CredentialKeyCorrectnessProof,
  Nonce,
  CredentialSignature,
  SignatureCorrectnessProof,
  BlindedCredentialSecrets,
  BlindedCredentialSecretsCorrectnessProof,
  RevocationRegistry,
  RevocationRegistryDelta,
  RevocationTailsGenerator,
  RevocationKeyPublic
};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::crypto::crypto_datatypes::AssertionProof;

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
  pub proof: Option<AssertionProof>
}

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
  pub proof: Option<AssertionProof>
}

// TODO: More supported fields?
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaProperty {
  pub r#type: String,
  pub format: Option<String>,
  pub items: Option<Vec<String>>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOffer {
  pub issuer: String,
  pub subject: String,
  pub r#type: String,
  pub schema: String,
  pub credential_definition: String,
  pub nonce: Nonce
}

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
  pub credential_values: HashMap<String, String>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProof {
  pub r#type: String,
  pub credential_definition: String,
  pub signature: CredentialSignature,
  pub signature_correctness_proof: SignatureCorrectnessProof,
  pub issuance_nonce: Nonce,
  pub revocation_id: u32,
  pub revocation_registry_definition: String
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaReference {
  pub id: String,
  pub r#type: String
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
  pub id: String,
  pub data: HashMap<String, String>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
  #[serde(rename(serialize = "@context", deserialize = "context"))]
  pub context: Vec<String>,
  pub id: String,
  pub r#type: Vec<String>,
  pub issuer: String,
  pub credential_subject: CredentialSubject,
  pub credential_schema: CredentialSchemaReference,
  pub proof: CredentialProof
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationRegistryDefinition {
  pub id: String,
  pub credential_definition: String,
  pub updated_at: String,
  pub registry: RevocationRegistry,
  pub registry_delta: Option<RevocationRegistryDelta>, // No delta before a credential has been revoked
  pub tails: RevocationTailsGenerator,
  pub revocation_public_key: RevocationKeyPublic,
  pub maximum_credential_count: u32,
  pub proof: Option<AssertionProof>
}
