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
  AggregatedProof,
  EncodedCredentialValue,
  RevocationState,
  DeltaHistory
};
use ursa::cl::{
  MasterSecret,
  CredentialSecretsBlindingFactors,
  Witness,
  RevocationTailsGenerator,
  SimpleTailsAccessor
};
use ursa::bn::BigNumber;
use crate::crypto::crypto_prover::Prover as CryptoProver;
use crate::crypto::crypto_datatypes::{
  CryptoCredentialDefinition
};
use crate::utils::utils::generate_uuid;
use std::collections::HashMap;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Prover {
}

impl Prover {
  pub fn new() -> Prover {
    Prover { }
  }

  /// Create a new credential proposal to send to a potential issuer.
  ///
  /// # Arguments
  /// * `issuer_did` - DID of the issuer the proposal is for
  /// * `subject_did` - DID of the proposal creator and potential subject of the credential
  /// * `schema_did` - DID of the schema to propose the credential for
  pub fn propose_credential(issuer_did: &str, subject_did: &str, schema_did: &str) -> CredentialProposal {
    return CredentialProposal {
      issuer: issuer_did.to_owned(),
      subject: subject_did.to_owned(),
      schema: schema_did.to_owned(),
      r#type: "EvanZKPCredentialProposal".to_string()
    };
  }

  /// Request a new credential based on a received credential offering.
  ///
  /// # Arguments
  /// * `credential_offering` - The received credential offering sent by the potential issuer
  /// * `credential_definition` - The credential definition that is referenced in the credential offering
  /// * `master_secret` - The master secret to incorporate into the blinded values to be signed by the issuer
  /// * `credential_values` - A mapping of property names to their stringified cleartext values
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
      &encoded_credential_values,
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
      credential_values: encoded_credential_values
    }, blinding_factors);
  }

  pub fn present_proof(
    proof_request: ProofRequest,
    credentials: HashMap<String, Credential>,
    credential_definitions: HashMap<String, CredentialDefinition>,
    credential_schemas: HashMap<String, CredentialSchema>,
    revocation_registries: HashMap<String, RevocationRegistryDefinition>, // RevDef ID to RevDef
    witnesses: HashMap<String, Witness>,
    master_secret: &MasterSecret,
  ) -> ProofPresentation {

    let (vcs, aggregated_proof) = Prover::create_proof_credentials(
      proof_request,
      credentials,
      credential_definitions,
      credential_schemas,
      revocation_registries,
      witnesses,
      &master_secret,
    );

    return ProofPresentation {
      context: vec!["https://www.w3.org/2018/credentials/v1".to_owned()],
      id: generate_uuid(),
      r#type: vec!["VerifiablePresentation".to_owned()],
      verifiable_credential: vcs,
      proof: aggregated_proof
    };
  }

  fn create_proof_credentials(
    proof_request: ProofRequest,
    credentials: HashMap<String, Credential>,
    credential_definitions: HashMap<String, CredentialDefinition>,
    credential_schemas: HashMap<String, CredentialSchema>,
    revocation_registries: HashMap<String, RevocationRegistryDefinition>,
    witnesses: HashMap<String, Witness>,
    master_secret: &MasterSecret
  ) -> (Vec<ProofCredential>, AggregatedProof)  {
    println!("Creating proof credentials");
    let crypto_proof = CryptoProver::create_proof_with_revoc(
      &proof_request,
      &credentials,
      &credential_definitions,
      &credential_schemas,
      &revocation_registries,
      &master_secret,
      &witnesses
    );

    let mut proof_creds: Vec<ProofCredential> = Vec::new();
    let mut i = 0;
    for sub_request in proof_request.sub_proof_requests {
      let credential = credentials.get(&sub_request.schema).expect("Requested credential not provided");
      let mut revealed_data: HashMap<String, EncodedCredentialValue> = HashMap::new();

      for attribute in sub_request.revealed_attributes {
        revealed_data.insert(
          attribute.to_owned(),
          credential.credential_subject
          .data
          .get(&attribute)
          .expect("Requested attribute not found in credential")
          .clone()
        );
      }

      let credential_subject = CredentialSubject {
        id: credential.credential_subject.id.to_owned(),
        data: revealed_data
      };

      let sub_proof = CredentialSubProof {
        credential_definition: credential.signature.credential_definition.to_owned(),
        revocation_registry_definition: credential.signature.revocation_registry_definition.to_owned(),
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

  /// Encodes values into a format compatible with Ursa's CL algorithm.
  /// Leaves i32 integers as is and transforms anything into 256 bit integers.
  /// Implements the encoding algorithm suggested by Hyperledger Indy
  ///   https://github.com/hyperledger/aries-rfcs/tree/master/features/0036-issue-credential#encoding-claims-for-indy-based-verifiable-credentials
  ///
  /// # Arguments
  ///
  /// * `credential_values` - A mapping of property names to stringified property values
  ///
  /// # Example
  /// ```
  /// # use std::collections::HashMap;
  /// # use vade_tnt::application::prover::Prover;
  /// let mut values: HashMap<String, String> = HashMap::new();
  /// values.insert("string".to_owned(), "101 Wilson Lane".to_owned());
  /// let encoded = Prover::encode_values(values);
  /// ```
  pub fn encode_values(credential_values: HashMap<String, String>) -> HashMap<String, EncodedCredentialValue> {

    let mut encoded_values: HashMap<String, EncodedCredentialValue> = HashMap::new();

    let mut encoded: String;
    let mut raw: String;
    for entry in credential_values {
      raw = entry.1.to_owned();
      match entry.1.to_string().parse::<i32>() {
        Ok(_) => { // parsing successful, but leave integer as is
          encoded = entry.1.to_owned();
        }
        Err(_) => { // not an integer, therefore encode it
          let mut hasher = Sha256::new();
          hasher.input(&entry.1.to_owned());
          let hash = hasher.result();
          let hash_arr: [u8; 32] = hash.try_into().expect("slice with incorrect length");
          let as_number = BigNumber::from_bytes(&hash_arr).unwrap();
          encoded = as_number.to_dec().unwrap();
        }
      }

      encoded_values.insert(
        entry.0,
        EncodedCredentialValue {
          raw: raw.to_owned(),
          encoded: encoded.to_owned()
        }
      );
    }

    return encoded_values;
  }

  pub fn create_master_secret() -> MasterSecret {
    match CryptoProver::create_master_secret() {
      Ok(secret) => return secret,
      Err(e) => panic!(e) // TODO how to handle error
    }
  }

  pub fn post_process_credential_signature(
    credential: &mut Credential,
    credential_request: &CredentialRequest,
    credential_definition: &CredentialDefinition,
    blinding_factors: CredentialSecretsBlindingFactors,
    master_secret: &MasterSecret,
    revocation_registry_definition: &RevocationRegistryDefinition,
    witness: &Witness
  ) {
    let rev_reg_def: RevocationRegistryDefinition = serde_json::from_str(
      &serde_json::to_string(revocation_registry_definition).unwrap()
    ).unwrap();

    CryptoProver::process_credential(
      &mut credential.signature,
      credential_request,
      &credential_definition.public_key,
      &blinding_factors,
      master_secret,
      Some(rev_reg_def),
      witness
    );
  }

  pub fn update_revocation_state_for_credential(
    revocation_state: RevocationState,
    rev_reg_def: RevocationRegistryDefinition
  ) -> RevocationState {
    let mut witness: Witness = revocation_state.witness.clone();

    let deltas: Vec<DeltaHistory> = rev_reg_def.delta_history.iter().cloned().filter(|entry| entry.created > revocation_state.updated).collect();

    let max_cred = rev_reg_def.maximum_credential_count;
    let generator: RevocationTailsGenerator = rev_reg_def.tails.clone();
    for delta in deltas {
      let mut generator_copy = generator.clone();
      witness.update(
        revocation_state.revocation_id,
        max_cred,
        &delta.delta,
        &SimpleTailsAccessor::new(&mut generator_copy).unwrap()
      ).unwrap();
    }

    return RevocationState {
      credential_id: revocation_state.credential_id.clone(),
      revocation_id: revocation_state.revocation_id,
      witness: witness.clone(),
      updated: SystemTime::now().duration_since(UNIX_EPOCH).expect("Error generating unix timestamp for delta history").as_secs(),
    }
  }
}
