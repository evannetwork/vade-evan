pub mod verifier {
  extern crate ursa;

  use ursa::cl::issuer::Issuer as CryptoIssuer;
  use ursa::cl::verifier::Verifier as CryptoVerifier;
  use ursa::bn::BigNumber;
  use ursa::cl::CredentialPublicKey;
  use ursa::cl::SubProofRequest;
  use ursa::cl::Proof;

  use crate::crypto::crypto_datatypes::ProofRequest;


  pub struct CredVerifier {

  }

  impl CredVerifier {

    pub fn new() -> CredVerifier {
      CredVerifier {
      }
    }

    pub fn request_proof(attributes: Vec<String>) -> SubProofRequest {
      let mut sub_proof_request_builder = CryptoVerifier::new_sub_proof_request_builder().unwrap();
      for i in 0 .. attributes.len() {
        sub_proof_request_builder.add_revealed_attr(&attributes[i]).unwrap();
      }
      let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

      return sub_proof_request;
    }

    pub fn verify_proof(
      proof: &Proof,
      proof_requests: Vec<&ProofRequest>,
      pub_keys: Vec<&CredentialPublicKey>,
      proof_request_nonce: &BigNumber
    ) {
      let mut proof_verifier = CryptoVerifier::new_proof_verifier().unwrap();

      let mut non_credential_schema_builder = CryptoIssuer::new_non_credential_schema_builder().unwrap();
      non_credential_schema_builder.add_attr("master_secret").unwrap();
      let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

      for i in 0 .. proof_requests.len() {
        proof_verifier.add_sub_proof_request(
          &proof_requests[i].crypto_proof_request,
          &proof_requests[i].credential_schema,
          &non_credential_schema,
          &pub_keys[i],
          None,
          None
        ).unwrap();
      }

      assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
    }

    /**
     * Decoding BigNumber representations to raw values.
     * Indy currently does not offer a standard for this, everyone is free and obliged to implement that themselves
     * See: https://jira.hyperledger.org/browse/IS-786
     */
    // TODO: BigNumbers will lead to problems when working with predicates, since they only accept i32 values
    fn decode_value(&self, encoded: &str) -> String{
      let val = BigNumber::from_dec(encoded).unwrap();
      let bytes = BigNumber::to_bytes(&val).unwrap();
      let decoded = String::from_utf8(bytes).unwrap();
      return decoded;
    }

  }

}
