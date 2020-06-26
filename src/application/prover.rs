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
#[cfg(target_arch = "wasm32")]
use wasm_timer::{SystemTime, UNIX_EPOCH};
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};
use simple_error::SimpleError;

/// Holds the logic needed to request credentials and create proofs.
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
  ///
  /// # Returns
  /// * `CredentialProposal` - The message to be sent to an issuer
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
  ///
  /// # Returns
  /// * `CredentialRequest` - The request to be sent to the issuer
  /// * `CredentialSecretsBlindingFactors` - Blinding factors used for blinding the credential values. Need to be stored privately at the prover's site
  pub fn request_credential(
    credential_offering: CredentialOffer,
    credential_definition: CredentialDefinition,
    credential_schema: CredentialSchema,
    master_secret: MasterSecret,
    credential_values: HashMap<String, String>
  ) -> Result<(CredentialRequest, CredentialSecretsBlindingFactors), Box<dyn std::error::Error>> {

    for required in &credential_schema.required {
      if (credential_values.get(required).is_none()) {
        let error = format!("Missing required schema property: {}", required);
        return Err(Box::new(SimpleError::new(error)));
      }
    }

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

    return Ok((CredentialRequest {
      blinded_credential_secrets: crypto_cred_request.blinded_credential_secrets,
      blinded_credential_secrets_correctness_proof: crypto_cred_request.blinded_credential_secrets_correctness_proof,
      credential_definition: credential_definition.id,
      credential_nonce: crypto_cred_request.credential_nonce,
      schema: credential_definition.schema,
      subject: credential_offering.subject,
      r#type: "EvanZKPCredentialRequest".to_string(),
      credential_values: encoded_credential_values
    }, blinding_factors));
  }

  /// Create a `ProofPresentation` to send to a verifier based on a received `ProofRequest`
  ///
  /// # Arguments
  /// * `proof_request` - The received proof_requested sent by the verifier
  /// * `credentials` - All credentials necessary for answering the proof request, indexed by their according `CredentialSchema`'s ID.
  /// * `credential_definitions` - All credential definitions necessary for answering the proof request, indexed by their according `CredentialSchema`'s ID.
  /// * `credential_schemas` - All credential schemas necessary for answering the proof request, indexed by their ID.
  /// * `revocation_registries` - All revocation registry definitions necessary for answering the proof request, indexed by their according `CredentialSchema`'s ID.
  /// * `witnesses` - All witnesses needed to prove non-revocation, indexed by their according **`Credential`'s ID**
  /// * `master_secret` - The master secret all credentials share
  ///
  /// # Returns
  /// * `ProofPresentation` - All proofs collected into a presentation object that is to be sent to the verifier
  pub fn present_proof(
    proof_request: ProofRequest,
    credentials: HashMap<String, Credential>,
    credential_definitions: HashMap<String, CredentialDefinition>,
    credential_schemas: HashMap<String, CredentialSchema>,
    revocation_registries: HashMap<String, RevocationRegistryDefinition>,
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

  /// Create a new master secret to be stored privately on the prover's site.
  pub fn create_master_secret() -> MasterSecret {
    match CryptoProver::create_master_secret() {
      Ok(secret) => return secret,
      Err(e) => panic!(e) // TODO how to handle error
    }
  }

  /// Incorporate the prover's master secret into the credential signature after issuance.
  ///
  /// # Arguments
  /// * `credential` - The credential to alter
  /// * `credential_request` - The original credential request for this credential
  /// * `credential_definition` - The definition the credential was issued with
  /// * `blinding_factors` - The blinding factors created by the prover while creating the credential request
  /// * `master_secret` - The master secret to incorporate in this credential
  /// * `revocation_registry_definition` - The revocation registry definition for this credential
  /// * `witnesses` - All witnesses needed to prove non-revocation, indexed by their according **`Credential`'s ID**
  pub fn post_process_credential_signature(
    credential: &mut Credential,
    credential_schema: &CredentialSchema,
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

    let mut extended_credential_request: CredentialRequest = serde_json::from_str(&serde_json::to_string(&credential_request).unwrap()).unwrap();
    let mut null_values: HashMap<String, String> = HashMap::new();
    for property in &credential_schema.properties {
      if (credential_request.credential_values.get(property.0).is_none()) {
        null_values.insert(property.0.clone(), "null".to_owned());
      }
    }
    extended_credential_request.credential_values.extend(Prover::encode_values(null_values)); // Add encoded null values

    CryptoProver::process_credential(
      &mut credential.signature,
      &extended_credential_request,
      &credential_definition.public_key,
      &blinding_factors,
      master_secret,
      Some(rev_reg_def),
      witness
    );
  }

  /// Updates the revocation state associated witha credential.
  ///
  /// # Arguments
  /// * `revocation_state` - Current revocation state (that is to be updated)
  /// * `rev_reg_def` - Revocation registry definition the credential that is associated with this state belongs to
  ///
  /// # Returns
  /// * `RevocationState` - The updated revocaiton state
  pub fn update_revocation_state_for_credential(
    revocation_state: RevocationState,
    rev_reg_def: RevocationRegistryDefinition
  ) -> RevocationState {
    let mut witness: Witness = revocation_state.witness.clone();

    let mut deltas: Vec<DeltaHistory> = rev_reg_def.delta_history.iter().cloned().filter(|entry| entry.created > revocation_state.updated).collect();
    deltas.sort_by(|a, b| a.created.cmp(&b.created));
    let max_cred = rev_reg_def.maximum_credential_count;
    let mut generator: RevocationTailsGenerator = rev_reg_def.tails.clone();
    let mut big_delta = revocation_state.delta.clone();
    for delta in deltas {
      big_delta.merge(&delta.delta).unwrap();
    }

    witness.update(
      revocation_state.revocation_id,
      max_cred,
      &big_delta,
      &SimpleTailsAccessor::new(&mut generator).unwrap()
    ).unwrap();

    return RevocationState {
      credential_id: revocation_state.credential_id.clone(),
      revocation_id: revocation_state.revocation_id,
      witness: witness.clone(),
      delta: big_delta.clone(),
      updated: SystemTime::now().duration_since(UNIX_EPOCH).expect("Error generating unix timestamp for delta history").as_secs(),
    }
  }
}
