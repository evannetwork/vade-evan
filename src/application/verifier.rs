use crate::application::datatypes::{
  ProofRequest,
  SubProofRequest,
  ProofVerification,
  ProofPresentation,
  CredentialDefinition,
  CredentialSchema,
  RevocationRegistryDefinition
};
use crate::crypto::crypto_verifier::verifier::CredVerifier;
use crate::utils::utils::get_now_as_iso_string;
use ursa::cl::new_nonce;
use std::collections::HashMap;

pub struct Verifier {}

impl Verifier {
  pub fn new() -> Verifier {
    Verifier { }
  }

  pub fn request_proof(
    verifier_did: &str,
    prover_did: &str,
    sub_proof_requests: Vec<SubProofRequest>
  ) -> ProofRequest {

    return ProofRequest {
      verifier: verifier_did.to_owned(),
      prover: prover_did.to_owned(),
      created_at: get_now_as_iso_string().to_owned(),
      nonce: new_nonce().unwrap(),
      sub_proof_requests
    }
  }

  pub fn validate_proof(
    presented_proof: ProofPresentation,
    proof_request: ProofRequest,
    credential_definitions: HashMap<String, CredentialDefinition>,
    credential_schemas: HashMap<String, CredentialSchema>,
    revocation_registry_definition: HashMap<String, Option<RevocationRegistryDefinition>>
  ) -> ProofVerification {

    let status: &str;
    let mut reason: Option<String> = None;
    match CredVerifier::verify_proof(
      &presented_proof,
      &proof_request,
      &credential_definitions,
      &credential_schemas,
      &revocation_registry_definition
    ) {
      Ok(()) => { status = "verified" }
      Err(e) => { status = "rejected"; reason = Some(e.to_string()); }
    };

    return ProofVerification {
      presented_proof: presented_proof.id.to_owned(),
      status: status.to_owned(),
      reason
    };
  }
}
