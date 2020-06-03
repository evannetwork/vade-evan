use ursa::cl::{
  CredentialPublicKey,
  CredentialKeyCorrectnessProof,
  Nonce,
  CredentialSignature as CryptoCredentialSignature,
  SignatureCorrectnessProof,
  BlindedCredentialSecrets,
  BlindedCredentialSecretsCorrectnessProof,
  RevocationRegistry,
  RevocationRegistryDelta,
  RevocationTailsGenerator,
  RevocationKeyPublic,
  CredentialSchema as UrsaCredentialSchema,
  issuer::Issuer as UrsaIssuer,
  Witness
};
use serde::{Serialize, Deserialize};
use std::collections::{
  HashMap,
  HashSet
};
pub use ursa::cl::{
    CredentialPrivateKey,
    CredentialSecretsBlindingFactors,
    RevocationKeyPrivate,
    MasterSecret,
};
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
  #[serde(skip_serializing_if = "Option::is_none")]
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
  #[serde(skip_serializing_if = "Option::is_none")]
  pub proof: Option<AssertionProof>
}

impl Into<UrsaCredentialSchema> for CredentialSchema {
  fn into(self) -> UrsaCredentialSchema {
    let mut credential_schema_builder = UrsaIssuer::new_credential_schema_builder().unwrap();
    for property in &self.properties {
      credential_schema_builder.add_attr(&property.0).unwrap();
    }
    return credential_schema_builder.finalize().unwrap();
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
  pub credential_values: HashMap<String, EncodedCredentialValue>
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
  pub witness: Witness
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaReference {
  pub id: String,
  pub r#type: String
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
  pub id: String,
  pub data: HashMap<String, EncodedCredentialValue>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
  #[serde(rename(serialize = "@context", deserialize = "@context"))]
  pub context: Vec<String>,
  pub id: String,
  pub r#type: Vec<String>,
  pub issuer: String,
  pub credential_subject: CredentialSubject,
  pub credential_schema: CredentialSchemaReference,
  pub signature: CredentialSignature
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
  #[serde(skip_serializing_if = "Option::is_none")]
  pub proof: Option<AssertionProof>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProposal {
  pub issuer: String,
  pub subject: String,
  pub r#type: String,
  pub schema: String
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubProofRequest {
  pub schema: String,
  pub revealed_attributes: Vec<String>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofRequest {
  pub verifier: String,
  pub prover: String,
  pub created_at: String,
  pub nonce: Nonce,
  pub sub_proof_requests: Vec<SubProofRequest>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubProof {
  pub credential_definition: String,
  pub revocation_registry_definition: String,
  pub proof: String
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregatedProof {
  pub nonce: Nonce,
  pub aggregated_proof: String
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofCredential {
  #[serde(rename(serialize = "@context", deserialize = "@context"))]
  pub context: Vec<String>,
  pub id: String,
  pub r#type: Vec<String>,
  pub issuer: String,
  pub credential_subject: CredentialSubject,
  pub credential_schema: CredentialSchemaReference,
  pub proof: CredentialSubProof
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofPresentation {
  #[serde(rename(serialize = "@context", deserialize = "@context"))]
  pub context: Vec<String>,
  pub id: String,
  pub r#type: Vec<String>,
  pub verifiable_credential: Vec<ProofCredential>,
  pub proof: AggregatedProof
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofVerification {
  pub presented_proof: String,
  pub status: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub reason: Option<String>
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EncodedCredentialValue {
  pub raw: String,
  pub encoded: String
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationIdInformation {
  pub definition_id: String,
  pub next_unused_id: u32,
  pub used_ids: HashSet<u32>
}
