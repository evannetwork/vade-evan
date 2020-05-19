extern crate ursa;

use ursa::cl::prover::Prover as CryptoProver;
use ursa::cl::issuer::Issuer as CryptoIssuer;
use ursa::bn::BigNumber;
use ursa::cl::{
  CredentialPublicKey,
  CredentialSecretsBlindingFactors,
  MasterSecret,
  Proof,
  Nonce,
  RevocationKeyPublic,
  RevocationRegistry,
  Witness,
  SimpleTailsAccessor,
  verifier::Verifier as CryptoVerifier
};
use std::collections::HashMap;
use crate::crypto::crypto_datatypes::{
  CryptoCredentialDefinition,
  CryptoCredentialRequest
};
use crate::application::datatypes::{
  RevocationRegistryDefinition,
  CredentialSignature,
  CredentialSchema,
  Credential,
  CredentialDefinition,
  ProofRequest,
  EncodedCredentialValue,
  CredentialRequest
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
    requester_did: &str,
    encoded_credential_values: &HashMap<String, EncodedCredentialValue>,
    master_secret: MasterSecret,
    credential_definition: CryptoCredentialDefinition,
    credential_nonce: Nonce,
  ) -> (CryptoCredentialRequest, CredentialSecretsBlindingFactors) {

    // Master secret will be used to prove that each proof was really issued to the holder/subject/prover
    // Needs to stay secret
    let mut credential_values_builder = CryptoIssuer::new_credential_values_builder().unwrap();
    for value in encoded_credential_values {
      credential_values_builder.add_dec_known(value.0, &value.1.encoded).unwrap();
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
      subject: requester_did.to_owned(),
      blinded_credential_secrets,
      blinded_credential_secrets_correctness_proof,
      credential_nonce
    };

    return (req, blinding_factors);
  }

  pub fn create_proof_with_revoc(
    proof_request: &ProofRequest,
    credentials: &HashMap<String, Credential>,
    credential_definitions: &HashMap<String, CredentialDefinition>,
    credential_schemas: &HashMap<String, CredentialSchema>,
    revocation_registries: &HashMap<String, RevocationRegistryDefinition>
  ) -> Proof {
    let mut non_credential_schema_builder = CryptoIssuer::new_non_credential_schema_builder().unwrap();
    non_credential_schema_builder.add_attr("master_secret").unwrap();
    let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

    let mut proof_builder = CryptoProver::new_proof_builder().unwrap();
    proof_builder.add_common_attribute("master_secret").unwrap();

    let mut credential_schema_builder;
    let mut sub_proof_request_builder;
    let mut credential_values_builder;
    let mut witness;
    let mut registry;
    for sub_proof in &proof_request.sub_proof_requests {

      // Build Ursa credential schema & proof requests
      credential_schema_builder = CryptoIssuer::new_credential_schema_builder().unwrap();
      sub_proof_request_builder = CryptoVerifier::new_sub_proof_request_builder().unwrap();
      for property in credential_schemas.get(&sub_proof.schema).unwrap().properties.keys() {
        credential_schema_builder.add_attr(property).unwrap();
        sub_proof_request_builder.add_revealed_attr(property).unwrap();
      }

      // Build ursa credential values
      credential_values_builder = CryptoIssuer::new_credential_values_builder().unwrap();
      for values in &credentials.get(&sub_proof.schema).expect("Credentials missing for schema").credential_subject.data {
        credential_values_builder.add_dec_known(&values.0, &values.1).unwrap();
      }

      // Build witness with revocation data
      registry = revocation_registries.get(&sub_proof.schema).unwrap();
      let tails_accessor = SimpleTailsAccessor::new(&mut registry.tails.clone()).unwrap();
      witness = Some(Witness::new(
        credentials.get(&sub_proof.schema).unwrap().signature.revocation_id,
        registry.maximum_credential_count,
        true, // TODO: Global const
        &registry.registry_delta.as_ref().unwrap(),
        &tails_accessor
      ).unwrap());

      // Build proof for requested schema & attributes
      proof_builder.add_sub_proof_request(
        &sub_proof_request_builder.finalize().unwrap(),
        &credential_schema_builder.finalize().unwrap(),
        &non_credential_schema,
        &credentials.get(&sub_proof.schema).unwrap().signature.signature,
        &credential_values_builder.finalize().unwrap(),
        &credential_definitions.get(&sub_proof.schema).unwrap().public_key,
        Some(&registry.registry),
        witness.as_ref()).unwrap();
    }

    let proof = proof_builder.finalize(&proof_request.nonce).unwrap();

    return proof;
  }

  pub fn process_credential(
    credential: &mut CredentialSignature,
    credential_request: &CredentialRequest,
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

    let mut credential_values_builder = CryptoIssuer::new_credential_values_builder().unwrap();
    for value in &credential_request.credential_values {
      credential_values_builder.add_dec_known(value.0, &value.1.encoded).unwrap();
    }
    let values = credential_values_builder.finalize().unwrap();

    CryptoProver::process_credential_signature(&mut credential.signature,
      &values,
      &credential.signature_correctness_proof,
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
