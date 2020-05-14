extern crate ursa;

use ursa::cl::prover::Prover as CryptoProver;
use ursa::cl::issuer::Issuer as CryptoIssuer;
use ursa::bn::BigNumber;
use ursa::cl::{
  CredentialPublicKey,
  CredentialSecretsBlindingFactors,
  MasterSecret,
  Proof,
  CredentialSchema,
  Nonce,
  CredentialValues,
  RevocationKeyPublic,
  RevocationRegistry,
  Witness,
  SimpleTailsAccessor
};
use std::collections::HashMap;
use crate::crypto::crypto_datatypes::{
  CryptoCredentialRequest,
  SignedCredential,
  CryptoCredentialDefinition,
  ProofRequest
};
use crate::application::datatypes::{
  RevocationRegistryDefinition
};


pub struct Prover {
}

impl Prover {

  pub fn new() -> Prover {
    Prover {
    }
  }

  ///
  pub fn request_credential(
    requester_did: String,
    encoded_credential_values: HashMap<String, String>,
    master_secret: MasterSecret,
    credential_definition: CryptoCredentialDefinition,
    credential_nonce: Nonce,
  ) -> (CryptoCredentialRequest, CredentialSecretsBlindingFactors) {

    // Master secret will be used to prove that each proof was really issued to the holder/subject/prover
    // Needs to stay secret
    // Will probably be stored in profile/wallet
    let mut credential_values_builder = CryptoIssuer::new_credential_values_builder().unwrap();
    for value in &encoded_credential_values {
      credential_values_builder.add_dec_known(value.0, value.1).unwrap();
    }
    credential_values_builder.add_value_hidden("master_secret", &master_secret.value().unwrap()).unwrap();
    let credential_values = credential_values_builder.finalize().unwrap();

    let (
      blinded_credential_secrets,
      blinding_factors,
      blinded_credential_secrets_correctness_proof
    ) = CryptoProver::blind_credential_secrets(
        &credential_definition.public_key,
        &credential_definition.credential_key_correctness_proof,
        &credential_values,
        &credential_nonce
    ).unwrap();

    let req = CryptoCredentialRequest {
      subject: requester_did,
      blinded_credential_secrets,
      blinded_credential_secrets_correctness_proof,
      credential_nonce,
      credential_values,
    };

    return (req, blinding_factors);
  }

  pub fn create_proof(
    proof_requests: Vec<ProofRequest>,
    credentials: Vec<SignedCredential>,
    credential_definitions: Vec<CryptoCredentialDefinition>,
    credential_schemas: Vec<CredentialSchema>,
    credential_values: Vec<CredentialValues>,
    proof_request_nonce: Nonce,
    revocation_registry: Option<&RevocationRegistry>,
    witness: Option<&Witness>
  ) -> Proof {
    let mut non_credential_schema_builder = CryptoIssuer::new_non_credential_schema_builder().unwrap();
    non_credential_schema_builder.add_attr("master_secret").unwrap();
    let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

    // TODO: Check vectors' lengths for equality
    let mut proof_builder = CryptoProver::new_proof_builder().unwrap();
    proof_builder.add_common_attribute("master_secret").unwrap();

    for i in 0 .. proof_requests.len() {
      proof_builder.add_sub_proof_request(
        &proof_requests[i].crypto_proof_request,
        &credential_schemas[i],
        &non_credential_schema,
        &credentials[i].signature,
        &credential_values[i],
        &credential_definitions[i].public_key,
        revocation_registry,
        witness).unwrap();
    }
    let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

    return proof;
  }

  pub fn process_credential(
    credential: &mut SignedCredential,
    credential_request: &CryptoCredentialRequest,
    credential_public_key: &CredentialPublicKey,
    credential_blinding_factors: &CredentialSecretsBlindingFactors,
    credential_revocation_id: u32,
    revocation_registry_definition: Option<RevocationRegistryDefinition>,
  ) {

    let mut revocation_key_public: Option<RevocationKeyPublic> = None;
    let mut revocation_registry: Option<RevocationRegistry> = None;
    let mut witness: Option<Witness> = None;
    if revocation_registry_definition.is_some() {
      let mut rev_def = revocation_registry_definition.unwrap();
      revocation_key_public = Some(rev_def.revocation_public_key);
      revocation_registry = Some(rev_def.registry);

      let tails = SimpleTailsAccessor::new(&mut rev_def.tails).unwrap();

      witness = Some(Witness::new(
        credential_revocation_id,
        rev_def.maximum_credential_count,
        true, // TODO: Global const
        &rev_def.registry_delta.unwrap(),
        &tails
      ).unwrap());
    }

    CryptoProver::process_credential_signature(&mut credential.signature,
      &credential_request.credential_values,
      &credential.correctness_proof,
      credential_blinding_factors,
      &credential_public_key,
      &credential.issuance_nonce,
      revocation_key_public.as_ref(),
      revocation_registry.as_ref(),
      witness.as_ref()
    ).unwrap();
  }

  /**
   * Encoding raw values to BigNumber representations.
   * Indy currently does not offer a standard for this, everyone is free and obliged to implement that themselves
   * See: https://jira.hyperledger.org/browse/IS-786
   */
  fn encode_value(value: &str) -> String {
    let string = String::from(value);
    let bytes = string.as_bytes();
    let val = BigNumber::from_bytes(bytes).unwrap();
    println!("Converting {} to {}", string, val.to_dec().unwrap());
    return val.to_dec().unwrap();
  }

}
