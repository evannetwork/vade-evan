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

/// Holds the logic needed to verify proofs
pub struct Verifier {}

impl Verifier {
  pub fn new() -> Verifier {
    Verifier { }
  }

  /// Request a proof from a prover.
  ///
  /// # Arguments
  /// * `verifier_did` - DID of the verifier
  /// * `prover_did` - DID of the prover
  /// * `sub_proof_requests` - Collection of subproof requests to be requested from the prover
  ///
  /// # Returns
  /// * `ProofRequest` - The message to be sent to a prover
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

  /// Validates a proof presentation received from a prover.
  ///
  /// # Arguments
  /// * `presented_proof` - The proof presentation from a prover
  /// * `proof_request` - The proof request sent by the verifier to the prover beforehand
  /// * `credential_definitions` - All definitions associated to the sent proofs, indexed by the according `CredentialSchema`'s ID
  /// * `credential_schemas` - All schemas associated to the sent proofs, indexed by their ID
  /// * `revocation_registry_definition` - All revocation registry definitions associated to the sent proofs, indexed by the according `CredentialSchema`'s ID
  ///
  /// # Returns
  /// * `ProofVerification` - States whether the verification was successful or not
  pub fn verify_proof(
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
