pub mod datatypes {
  use ursa::cl::{
    BlindedCredentialSecrets,
    BlindedCredentialSecretsCorrectnessProof,
    CredentialValues,
    CredentialPublicKey,
    CredentialKeyCorrectnessProof,
    CredentialSignature,
    SignatureCorrectnessProof,
    RevocationKeyPublic,
    RevocationRegistry,
    RevocationRegistryDelta,
    RevocationTailsGenerator,
    SubProofRequest,
    CredentialSchema as CryptoCredentialSchema
  };
  use ursa::bn::BigNumber;
  use serde::{Serialize, Deserialize};
  use std::collections::HashMap;

  pub struct CryptoCredentialRequest {
    pub subject: String,
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
  pub struct CryptoCredentialDefinition {
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

  #[derive(Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  pub struct RevocationRegistryDefinition {
    pub registry: RevocationRegistry,
    pub registryDelta: RevocationRegistryDelta,
    pub tails: RevocationTailsGenerator,
    pub revocation_public_key: RevocationKeyPublic,
    pub maximum_credential_count: u32
  }

  pub struct ProofRequest {
    pub credential_schema: CryptoCredentialSchema,
    pub crypto_proof_request: SubProofRequest,
  }
}

