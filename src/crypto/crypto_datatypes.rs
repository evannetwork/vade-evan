use ursa::cl::{
  BlindedCredentialSecrets,
  BlindedCredentialSecretsCorrectnessProof,
  CredentialPublicKey,
  CredentialKeyCorrectnessProof,
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
  pub credential_values: HashMap<String, String>
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
  pub items: Option<Vec<String>>
}

pub struct CryptoProofRequest {
  pub credential_schema: CryptoCredentialSchema,
  pub crypto_proof_request: SubProofRequest,
}

// impl From<ProofRequest> for CryptoProofRequest {
//   fn from(request: ProofRequest) -> Self {
//     let mut sub_proof_request_builder = UrsaVerifier::new_sub_proof_request_builder().unwrap();
//     request.sub_proof_requests[0].
//       for i in 0 .. attributes.len() {
//         sub_proof_request_builder.add_revealed_attr(&attributes[i]).unwrap();
//       }
//       let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

//       return sub_proof_request;
//     return CryptoProofRequest {

//     };
//   }
// }

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
pub struct CryptoRevocationRegistryDefinition {
  pub registry: RevocationRegistry,
  pub registry_delta: Option<RevocationRegistryDelta>, // No delta before a credential has been revoked
  pub tails: RevocationTailsGenerator,
  pub revocation_public_key: RevocationKeyPublic,
  pub maximum_credential_count: u32,
}

