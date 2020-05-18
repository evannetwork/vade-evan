use crate::application::datatypes::{
  CredentialProposal,
  CredentialRequest,
  CredentialOffer,
  CredentialDefinition,
  ProofRequest,
  ProofPresentation,
  Credential,
  ProofCredential,
  CredentialSubject,
  CredentialSchema,
  RevocationRegistryDefinition,
  CredentialSubProof,
  AggregatedProof
};
use ursa::cl::{
  MasterSecret,
  CredentialSecretsBlindingFactors
};
use crate::crypto::crypto_utils::create_id_hash;
use crate::crypto::crypto_prover::Prover as CryptoProver;
use crate::crypto::crypto_datatypes::{
  CryptoCredentialDefinition
};
use std::collections::HashMap;

pub struct Prover {
}

impl Prover {
  pub fn new() -> Prover {
    Prover { }
  }

  pub fn propose_credential(issuer_did: &str, subject_did: &str, schema_did: &str) -> CredentialProposal {
    return CredentialProposal {
      issuer: issuer_did.to_owned(),
      subject: subject_did.to_owned(),
      schema: schema_did.to_owned(),
      r#type: "EvanZKPCredentialProposal".to_string()
    };
  }

  pub fn request_credential(
    credential_offering: CredentialOffer,
    credential_definition: CredentialDefinition,
    master_secret: MasterSecret,
    credential_values: HashMap<String, String>
  ) -> (CredentialRequest, CredentialSecretsBlindingFactors) {

    let crypto_cred_def = CryptoCredentialDefinition {
      public_key: credential_definition.public_key,
      credential_key_correctness_proof: credential_definition.public_key_correctness_proof
    };

    let encoded_credential_values = Prover::encode_values(credential_values);

    let (crypto_cred_request, blinding_factors) = CryptoProver::request_credential(
      &credential_offering.subject,
      encoded_credential_values,
      master_secret,
      crypto_cred_def,
      credential_offering.nonce
    );

    return (CredentialRequest {
      blinded_credential_secrets: crypto_cred_request.blinded_credential_secrets,
      blinded_credential_secrets_correctness_proof: crypto_cred_request.blinded_credential_secrets_correctness_proof,
      credential_definition: credential_definition.id,
      credential_nonce: crypto_cred_request.credential_nonce,
      schema: credential_definition.schema,
      subject: credential_offering.subject,
      r#type: "EvanZKPCredentialRequest".to_string(),
      credential_values: crypto_cred_request.credential_values
    }, blinding_factors);
  }

  pub fn present_proof(
    proof_request: ProofRequest,
    credentials: HashMap<String, Credential>,
    credential_definitions: HashMap<String, CredentialDefinition>,
    credential_schemas: HashMap<String, CredentialSchema>,
    revocation_registries: HashMap<String, RevocationRegistryDefinition> // RevDef ID to RevDef
  ) -> ProofPresentation {

    let id = create_id_hash();

    let (vcs, aggregated_proof) = Prover::create_proof_credentials(
      proof_request,
      credentials,
      credential_definitions,
      credential_schemas,
      revocation_registries
    );

    return ProofPresentation {
      context: vec!["https://www.w3.org/2018/credentials/v1".to_owned()],
      id,
      r#type: vec!["VerifiablePresentation".to_owned()],
      verifiable_credential: vcs,
      proof: aggregated_proof
    };
  }

  fn encode_values(values: HashMap<String, String>) -> HashMap<String, String> {
    unimplemented!();
  }

  fn create_proof_credentials(
    proof_request: ProofRequest,
    credentials: HashMap<String, Credential>,
    credential_definitions: HashMap<String, CredentialDefinition>,
    credential_schemas: HashMap<String, CredentialSchema>,
    revocation_registries: HashMap<String, RevocationRegistryDefinition>
  ) -> (Vec<ProofCredential>, AggregatedProof)  {

    let crypto_proof = CryptoProver::create_proof_with_revoc(
      &proof_request,
      &credentials,
      &credential_definitions,
      &credential_schemas,
      &revocation_registries
    );

    let mut proof_creds: Vec<ProofCredential> = Vec::new();
    let mut i = 0;
    for sub_request in proof_request.sub_proof_requests {
      let credential = credentials.get(&sub_request.schema).expect("Requested credential not provided");
      let mut revealed_data: HashMap<String, String> = HashMap::new();

      for attribute in sub_request.revealed_attributes {
        revealed_data.insert(
          attribute.to_owned(),
          credential.credential_subject
          .data
          .get(&attribute)
          .expect("Requested attribute not found in credential")
          .to_owned()
        );
      }

      let credential_subject = CredentialSubject {
        id: credential.credential_subject.id.to_owned(),
        data: revealed_data
      };

      let sub_proof = CredentialSubProof {
        credential_definition: credential.signature.credential_definition.to_owned(),
        proof: serde_json::to_string(&crypto_proof.proofs[i]).unwrap()
      };

      let proof_cred = ProofCredential {
        context: vec!["https://www.w3.org/2018/credentials/v1".to_owned()],
        id: credential.id.to_owned(),
        r#type: vec!["VerifiablePresentation".to_owned()],
        credential_schema: credential.credential_schema.clone(),
        credential_subject,
        issuer: credential.issuer.to_owned(),
        proof: sub_proof
      };

      proof_creds.push(proof_cred);

      i += 1;
    }

    let aggregated = AggregatedProof {
      nonce: proof_request.nonce,
      aggregated_proof: serde_json::to_value(&crypto_proof).unwrap()["aggregated_proof"].to_string()
    };

    return (proof_creds, aggregated);
  }
}
