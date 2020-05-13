pub mod verifier {
  extern crate ursa;

  use ursa::cl::issuer::Issuer as CryptoIssuer;
  use ursa::cl::verifier::Verifier as CryptoVerifier;
  use ursa::bn::BigNumber;
  use ursa::cl::CredentialPublicKey;
  use ursa::cl::SubProofRequest;
  use ursa::cl::Proof;
  use ursa::cl::CredentialSchema;


  pub struct CredVerifier {

  }

  pub struct ProofRequest {
    pub credential_schema_id: String,
    pub crypto_proof_request: SubProofRequest,
  }

  impl CredVerifier {

    pub fn new() -> CredVerifier {
      CredVerifier {
      }
    }

    pub fn request_iso_proof(&self, iso_schema_did: &String) -> ProofRequest {
      let mut sub_proof_request_builder = CryptoVerifiernew_sub_proof_request_builder().unwrap();
      sub_proof_request_builder.add_revealed_attr("ISO-certified").unwrap();
      let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

      return ProofRequest {
        credential_schema_id: iso_schema_did.clone(),
        proof_request: sub_proof_request,
      }
    }

    pub fn request_revenue_proof(&self, iso_schema_did: &String) -> ProofRequest {
      let mut sub_proof_request_builder = CryptoVerifiernew_sub_proof_request_builder().unwrap();
      sub_proof_request_builder.add_revealed_attr("revenue").unwrap();
      let sub_proof_request = sub_proof_request_builder.finalize().unwrap();

      return ProofRequest {
        credential_schema_id: iso_schema_did.clone(),
        proof_request: sub_proof_request,
      }
    }

    pub fn verify_iso_proof(
      &self,
      proof: &Proof,
      proof_request_iso: &ProofRequest,
      proof_request_revenue: &ProofRequest,
      pub_key: &CredentialPublicKey,
      credential_schema: &CredentialSchema,
      proof_request_nonce: &BigNumber
    ) {
      let mut proof_verifier = CryptoVerifiernew_proof_verifier().unwrap();

      let mut non_credential_schema_builder = CryptoIssuernew_non_credential_schema_builder().unwrap();
      non_credential_schema_builder.add_attr("master_secret").unwrap();
      let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

      proof_verifier.add_sub_proof_request(&proof_request_iso.proof_request,
                                          &credential_schema,
                                          &non_credential_schema,
                                          &pub_key,
                                          None,
                                          None).unwrap();
      proof_verifier.add_sub_proof_request(&proof_request_revenue.proof_request,
                                            &credential_schema,
                                            &non_credential_schema,
                                            &pub_key,
                                            None,
                                            None).unwrap();
      assert!(proof_verifier.verify(&proof, &proof_request_nonce).unwrap());
      println!("Proof is valid.");
      println!("Recovering attributes: ");
      for i in proof.proofs.iter() {
        for (k, v) in i.revealed_attrs().unwrap() {
          println!("{:?}: {:?}", k, self.decode_value(&v));
        }
      }

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
