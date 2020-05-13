pub mod datatypes {
  use ursa::cl::{
    BlindedCredentialSecrets,
    BlindedCredentialSecretsCorrectnessProof,
    CredentialValues,
    CredentialPublicKey,
    CredentialKeyCorrectnessProof,
    CredentialSignature,
    SignatureCorrectnessProof};
  use ursa::bn::BigNumber;
  use serde::{Serialize, Deserialize};
  use std::collections::HashMap;

  pub struct CredentialRequest {
    pub schema: String,
    pub credential_definition: String,
    pub subject: String,
    pub r#type: String,
    pub blinded_credential_secrets: BlindedCredentialSecrets,
    pub blinded_credential_secrets_correctness_proof: BlindedCredentialSecretsCorrectnessProof,
    pub credential_nonce: BigNumber,
    pub credential_values: CredentialValues
  }


  #[derive(Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct AssertionProof {
    pub r#type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub jws: String
  }

  #[derive(Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct CredentialDefinition {
    pub id: String,
    pub r#type: String,
    pub issuer: String,
    pub schema: String,
    pub created_at: String,
    pub public_key: CredentialPublicKey,
    pub credential_key_correctness_proof: CredentialKeyCorrectnessProof,
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

  #[derive(Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct SignedCredential {
    pub signature: CredentialSignature,
    pub correctness_proof: SignatureCorrectnessProof,
    pub issuance_nonce: BigNumber
  }
}

