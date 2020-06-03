use crate::application::datatypes::{
  CredentialDefinition,
  CredentialSchema,
  SchemaProperty,
  CredentialOffer,
  Credential,
  CredentialSchemaReference,
  CredentialSubject,
  CredentialSignature,
  CredentialRequest,
  RevocationRegistryDefinition,
  EncodedCredentialValue,
  RevocationIdInformation
};
use crate::crypto::crypto_issuer::Issuer as CryptoIssuer;
use crate::crypto::crypto_utils::create_assertion_proof;
use crate::utils::utils::{
  get_now_as_iso_string,
  generate_uuid
};
use ursa::cl::{
  CredentialPrivateKey,
  new_nonce,
  RevocationKeyPrivate
};
use std::collections::{
  HashMap,
  HashSet
};
use ursa::cl::RevocationTailsGenerator;
use simple_error::SimpleError;

pub struct Issuer {
}

impl Issuer {
    pub fn new() -> Issuer {
        Issuer { }
    }

    pub fn create_credential_definition(
      assigned_did: &str,
      issuer_did: &str,
      schema: &CredentialSchema,
      issuer_public_key_did: &str,
      issuer_proving_key: &str
    ) -> (CredentialDefinition, CredentialPrivateKey) {

      let created_at = get_now_as_iso_string();
      println!("Starte crypto issuer creddef");
      let (credential_private_key, crypto_credential_def) = CryptoIssuer::create_credential_definition(
        &schema
      );
      println!("Done crypto issuer creddef");
      let mut definition = CredentialDefinition {
        id: assigned_did.to_owned(),
        r#type: "EvanZKPCredentialDefinition".to_string(),
        issuer: issuer_did.to_owned(),
        schema: schema.id.to_owned(),
        created_at,
        public_key: crypto_credential_def.public_key,
        public_key_correctness_proof: crypto_credential_def.credential_key_correctness_proof,
        proof: None
      };

      let document_to_sign = serde_json::to_value(&definition).unwrap();

      let proof = create_assertion_proof(
        &document_to_sign,
        &issuer_public_key_did,
        &issuer_did,
        &issuer_proving_key
      ).unwrap();

      definition.proof = Some(proof);

      return (definition, credential_private_key);
    }

    pub fn create_credential_schema(
      assigned_did: &str,
      issuer_did: &str,
      schema_name: &str,
      description: &str,
      properties: HashMap<String, SchemaProperty>,
      required_properties: Vec<String>,
      allow_additional_properties: bool,
      issuer_public_key_did: &str,
      issuer_proving_key: &str
    ) -> CredentialSchema {

      let created_at = get_now_as_iso_string();

      let mut schema = CredentialSchema {
        id: assigned_did.to_owned(),
        r#type: "EvanVCSchema".to_string(), //TODO: Make enum
        name: schema_name.to_owned(),
        author: issuer_did.to_owned(),
        created_at,
        description: description.to_owned(),
        properties,
        required: required_properties,
        additional_properties: allow_additional_properties,
        proof: None
      };

      let document_to_sign = serde_json::to_value(&schema).unwrap();

      let proof = create_assertion_proof(
        &document_to_sign,
        &issuer_public_key_did,
        &issuer_did,
        &issuer_proving_key
      ).unwrap();

      schema.proof = Some(proof);

      return schema;
    }

    /// Creates a new revocation registry definition. This definition is used to prove the non-revocation state of a credential.
    /// It needs to be publicly published and updated after every revocation. The definition is signed by the issuer.
    ///
    /// # Arguments
    /// * `assigned_did` - DID that will point to the registry definition
    /// * `credential_definition` - Credential definition this revocation registry definition will be associated with
    /// * `issuer_public_key_did` - DID of the public key that will be associated with the created signature
    /// * `issuer_proving_key` - Private key of the issuer used for signing the definition
    /// * `maximum_credential_count` - Capacity of the revocation registry in terms of issuable credentials
    ///
    /// # Returns
    /// A 3-tuple consisting
    /// * `RevocationRegistryDefinition` - the definition
    /// * `RevocationKeyPrivate` - the according revocation private key, and an revocaiton
    /// * `RevocationIdInformation` - object used for keeping track of issued revocation IDs
    pub fn create_revocation_registry_definition(
      assigned_did: &str,
      credential_definition: &CredentialDefinition,
      issuer_public_key_did: &str,
      issuer_proving_key: &str,
      maximum_credential_count: u32
    ) -> (RevocationRegistryDefinition, RevocationKeyPrivate, RevocationIdInformation) {

      let (crypto_rev_def, rev_key_private) = CryptoIssuer::create_revocation_registry(
        &credential_definition.public_key,
        maximum_credential_count
      );

      let updated_at = get_now_as_iso_string();

      let mut rev_reg_def = RevocationRegistryDefinition {
        id: assigned_did.to_string(),
        credential_definition: credential_definition.id.to_string(),
        registry: crypto_rev_def.registry,
        registry_delta: crypto_rev_def.registry_delta,
        maximum_credential_count,
        revocation_public_key: crypto_rev_def.revocation_public_key,
        tails: crypto_rev_def.tails,
        updated_at,
        proof: None
      };

      let revoc_info = RevocationIdInformation {
        definition_id: assigned_did.to_string(),
        next_unused_id: 1, // needs to start at 1
        used_ids: HashSet::new()
      };

      let document_to_sign = serde_json::to_value(&rev_reg_def).unwrap();
      let proof = create_assertion_proof(
        &document_to_sign,
        &issuer_public_key_did,
        &credential_definition.issuer,
        &issuer_proving_key
      ).unwrap();

      rev_reg_def.proof = Some(proof);

      return (rev_reg_def, rev_key_private, revoc_info);
    }

    /// Issue a new credential, based on a credential request received by the credential subject
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer
    /// * `subject_did` - DID of the subject
    /// * `credential_request` - Credential request object sent by the subject
    /// * `credential_definition` - Credential definition to use for issuance as specified by the credential request
    /// * `credential_private_key` - Issuer's private key associated with the credential definition
    /// * `credential_schema` - Credential schema to be used as specified by the credential request
    /// * `revocation_registry_definition` - Revocation registry definition to be used for issuance
    /// * `revocation_private_key` - Private key associated to the revocation registry definition
    /// * `revocation_info` - Revocation info containing ID counter. Hold by credential definition owner
    ///
    /// # Returns
    /// Tuple containing
    /// * `Credential` - Issued credential
    /// * `RevocationIdInformation` - Updated `revocation_info` object that needs to be persisted
    pub fn issue_credential (
      issuer_did: &str,
      subject_did: &str,
      credential_request: CredentialRequest,
      credential_definition: CredentialDefinition,
      credential_private_key: CredentialPrivateKey,
      credential_schema: CredentialSchema,
      revocation_registry_definition: &mut RevocationRegistryDefinition,
      revocation_private_key: RevocationKeyPrivate,
      revocation_info: &RevocationIdInformation
    ) -> Result<(Credential, RevocationIdInformation), Box<dyn std::error::Error>> {

      let mut data: HashMap<String, EncodedCredentialValue> = HashMap::new();
      for entry in &credential_request.credential_values {
        data.insert(entry.0.to_owned(), entry.1.clone());
      }

      let credential_subject = CredentialSubject {
        id: subject_did.to_owned(),
        data
      };

      let schema_reference = CredentialSchemaReference {
        id: credential_schema.id,
        r#type: "EvanZKPSchema".to_string()
      };

      // Get next unused revocation ID for credential, mark as used & increment counter
      if revocation_info.next_unused_id == revocation_registry_definition.maximum_credential_count {
        return Err(Box::new(SimpleError::new("Maximum credential count reached for revocation definition")));
      }
      let rev_idx = revocation_info.next_unused_id;
      let mut used_ids: HashSet<u32> = revocation_info.used_ids.clone();
      if !used_ids.insert(rev_idx) {
        return Err(Box::new(SimpleError::new("Could not use next revocation ID as it has already been used - Counter information seems to be corrupted")));
      }

      let new_rev_info = RevocationIdInformation {
        definition_id: revocation_registry_definition.id.clone(),
        next_unused_id: rev_idx + 1,
        used_ids
      };

      let (
        signature,
        signature_correctness_proof,
        issuance_nonce,
        witness
      ) = CryptoIssuer::sign_credential_with_revocation(
        &credential_request,
        &credential_private_key,
        &credential_definition.public_key,
        revocation_registry_definition,
        rev_idx,
        &revocation_private_key
      );

      let cred_signature = CredentialSignature {
        r#type: "CLSignature2019".to_string(),
        credential_definition: credential_definition.id,
        issuance_nonce,
        signature,
        signature_correctness_proof,
        revocation_id: rev_idx,
        revocation_registry_definition: revocation_registry_definition.id.clone(),
        witness
      };

      let credential = Credential {
        context: vec!("https://www.w3.org/2018/credentials/v1".to_string()),
        id: generate_uuid(),
        r#type: vec!("VerifiableCredential".to_string()),
        issuer: issuer_did.to_owned(),
        credential_subject,
        credential_schema: schema_reference,
        signature: cred_signature
      };

      Ok((credential, new_rev_info))
    }

    pub fn offer_credential(
      issuer_did: &str,
      subject_did: &str,
      schema_did: &str,
      credential_definition_did: &str
    ) -> CredentialOffer {
      let nonce = new_nonce().unwrap();

      return CredentialOffer {
        issuer: issuer_did.to_owned(),
        subject: subject_did.to_owned(),
        r#type: "EvanZKPCredentialOffering".to_string(),
        schema: schema_did.to_owned(),
        credential_definition: credential_definition_did.to_owned(),
        nonce
      }
    }

    pub fn revoke_credential(
      issuer: &str,
      revocation_registry_definition: &mut RevocationRegistryDefinition,
      revocation_id: u32,
      issuer_public_key_did: &str,
      issuer_proving_key: &str
    ) -> RevocationRegistryDefinition {

      let updated_at = get_now_as_iso_string();

      let (new_registry, delta) = CryptoIssuer::revoke_credential(revocation_registry_definition, revocation_id).unwrap();
      let tails: RevocationTailsGenerator = revocation_registry_definition.tails.clone().to_owned();
      let mut rev_reg_def = RevocationRegistryDefinition {
        id: revocation_registry_definition.id.to_owned(),
        credential_definition: revocation_registry_definition.credential_definition.to_owned(),
        registry: new_registry,
        registry_delta: Some(delta),
        maximum_credential_count: revocation_registry_definition.maximum_credential_count,
        revocation_public_key: revocation_registry_definition.revocation_public_key.clone().to_owned(),
        tails,
        updated_at,
        proof: None
      };

      let document_to_sign = serde_json::to_value(&rev_reg_def).unwrap();
      let proof = create_assertion_proof(
        &document_to_sign,
        issuer_public_key_did,
        issuer,
        issuer_proving_key
      ).unwrap();

      rev_reg_def.proof = Some(proof);
      return rev_reg_def;
    }
}
