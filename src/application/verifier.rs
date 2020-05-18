use crate::application::datatypes::{
  ProofRequest,
  SubProofRequest,
  ProofVerification,
  ProofPresentation,
  CredentialDefinition,
  CredentialSchema
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
    credential_schemas: HashMap<String, CredentialSchema>
  ) -> ProofVerification {
    // CredVerifier::verify_proof(
    //   presented_proof,
    //   proof_request,
    //   credential_definitions,
    //   credential_schemas
    // );
    unimplemented!();


  }
}
