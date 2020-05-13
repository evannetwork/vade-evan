pub mod prover {
  extern crate ursa;

  use ursa::cl::prover::Prover as CryptoProver;
  use ursa::cl::issuer::Issuer as CryptoIssuer;
  use ursa::bn::BigNumber;
  use ursa::cl::{
    new_nonce,
    CredentialPublicKey,
    CredentialKeyCorrectnessProof,
    CredentialSecretsBlindingFactors,
    MasterSecret,
    Proof,
    CredentialSchema,
    Nonce,
    CredentialValues
  };
  use crate::verifier::verifier::ProofRequest;
  use std::collections::HashMap;
  use crate::datatypes::datatypes::{
    CredentialRequest,
    SignedCredential,
    CredentialDefinition
  };


  pub struct Prover {
    identity: &'static str,
    // Mapping credential nonce (BigNumber as string representation) to prover secrets
    secrets_registry: HashMap<String, (MasterSecret, CredentialSecretsBlindingFactors)>,
    // Mapping credential nonce to credential
    credential_registry: HashMap<String, (SignedCredential, CredentialRequest)>,
  }

  impl Prover {

    pub fn new(did: &'static str) -> Prover {
      Prover {
        identity: did,
        secrets_registry: HashMap::new(),
        credential_registry: HashMap::new(),
      }
    }

    ///
    pub fn request_credential(
      requester_did: String,
      schema_did: String,
      encoded_credential_values: HashMap<String, String>,
      master_secret: MasterSecret,
      credential_definition: CredentialDefinition,
      credential_nonce: Nonce,
    ) -> (CredentialRequest, CredentialSecretsBlindingFactors) {

      // Master secret will be used to prove that each proof was really issued to the holder/subject/prover
      // Needs to stay secret
      // Will probably be stored in profile/wallet
      let mut credential_values_builder = CryptoIssuer::new_credential_values_builder().unwrap();
      for value in &encoded_credential_values {
        credential_values_builder.add_dec_hidden(value.0, value.1);
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

      let req = CredentialRequest {
        schema: schema_did,
        subject: requester_did,
        blinded_credential_secrets,
        blinded_credential_secrets_correctness_proof,
        credential_nonce,
        credential_values,
        r#type: "EvanZKPCredentialRequest".to_string(),
        credential_definition: credential_definition.id
      };

      return (req, blinding_factors);
    }

    pub fn create_proof(
      proof_requests: Vec<ProofRequest>,
      credentials: Vec<SignedCredential>,
      credential_definitions: Vec<CredentialDefinition>,
      credential_schemas: Vec<CredentialSchema>,
      credential_values: Vec<CredentialValues>,
      proof_request_nonce: Nonce
    ) -> Proof {
      let mut non_credential_schema_builder = CryptoIssuer::new_non_credential_schema_builder().unwrap();
      non_credential_schema_builder.add_attr("master_secret").unwrap();
      let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

      // TODO: Check vectors' lengths for equality
      let mut proof_builder = CryptoProver::new_proof_builder().unwrap();
      proof_builder.add_common_attribute("master_secret").unwrap();

      for i in 0 .. &proof_requests.len() - 1 {
        proof_builder.add_sub_proof_request(
          &proof_requests[i].crypto_proof_request,
          &credential_schemas[i],
          &non_credential_schema,
          &credentials[i].signature,
          &credential_values[i],
          &credential_definitions[i].public_key,
          None,
          None).unwrap();
      }
      let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

      return proof;
    }

    pub fn process_credential(
      credential: &mut SignedCredential,
      credential_request: &CredentialRequest,
      credential_public_key: &CredentialPublicKey,
      credential_blinding_factors: &CredentialSecretsBlindingFactors
    ) {
      let nonce = &credential_request.credential_nonce.to_dec().unwrap();

      CryptoProver::process_credential_signature(&mut credential.signature,
        &credential_request.credential_values,
        &credential.correctness_proof,
        credential_blinding_factors,
        &credential_public_key,
        &credential.issuance_nonce,
        None, None, None).unwrap();
    }

    pub fn store_credential(
      &mut self,
      credential: SignedCredential,
      credential_request: CredentialRequest
    ) {
      self.credential_registry.insert(
        credential_request.credential_nonce.to_dec().unwrap(),
        (credential, credential_request)
      );
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

}
