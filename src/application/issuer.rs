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
  RevocationRegistryDefinition
};
use crate::crypto::crypto_issuer::Issuer as CryptoIssuer;
use crate::crypto::crypto_utils::create_assertion_proof;
use crate::utils::utils::get_now_as_iso_string;
use ursa::cl::{
  CredentialPrivateKey,
  new_nonce,
  RevocationKeyPrivate
};
use std::collections::HashMap;
use ursa::cl::RevocationTailsGenerator;

pub struct Issuer {
}

impl Issuer {
    pub fn new() -> Issuer {
        Issuer { }
    }

    pub fn create_credential_definition(
      issuer_did: &str,
      schema: &CredentialSchema,
      issuer_public_key_did: &str,
      issuer_proving_key: &str
    ) -> (CredentialDefinition, CredentialPrivateKey) {

      let did = Issuer::mock_get_new_did();

      let created_at = get_now_as_iso_string();

      let (credential_private_key, crypto_credential_def) = CryptoIssuer::create_credential_definition(
        &schema
      );

      let mut definition = CredentialDefinition {
        id: did,
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
      issuer_did: &str,
      schema_name: &str,
      description: &str,
      properties: HashMap<String, SchemaProperty>,
      required_properties: Vec<String>,
      allow_additional_properties: bool,
      issuer_public_key_did: &str,
      issuer_proving_key: &str
    ) -> CredentialSchema {

      let schema_did = Issuer::mock_get_new_did();

      let created_at = get_now_as_iso_string();

      let mut schema = CredentialSchema {
        id: schema_did,
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

    pub fn create_revocation_registry_definition(
      credential_definition: CredentialDefinition,
      issuer_public_key_did: &str,
      issuer_proving_key: &str,
      maximum_credential_count: u32
    ) -> (RevocationRegistryDefinition, RevocationKeyPrivate) {

      let (crypto_rev_def, rev_key_private) = CryptoIssuer::create_revocation_registry(
        &credential_definition.public_key,
        maximum_credential_count
      );

      let rev_did = Issuer::mock_get_new_did();

      let updated_at = get_now_as_iso_string();

      let mut rev_reg_def = RevocationRegistryDefinition {
        id: rev_did,
        credential_definition: credential_definition.id,
        registry: crypto_rev_def.registry,
        registry_delta: crypto_rev_def.registry_delta,
        maximum_credential_count,
        revocation_public_key: crypto_rev_def.revocation_public_key,
        tails: crypto_rev_def.tails,
        updated_at,
        proof: None
      };

      let document_to_sign = serde_json::to_value(&rev_reg_def).unwrap();
      let proof = create_assertion_proof(
        &document_to_sign,
        &issuer_public_key_did,
        &credential_definition.issuer,
        &issuer_proving_key
      ).unwrap();

      rev_reg_def.proof = Some(proof);

      return (rev_reg_def, rev_key_private);
    }

    pub fn issue_credential (
      issuer_did: &str,
      subject_did: &str,
      credential_request: CredentialRequest,
      credential_definition: CredentialDefinition,
      credential_private_key: CredentialPrivateKey,
      credential_schema: CredentialSchema,
      revocation_registry_definition: &mut RevocationRegistryDefinition,
      revocation_private_key: RevocationKeyPrivate
    ) -> Credential {

      let mut data: HashMap<String, String> = HashMap::new();
      for entry in &credential_request.credential_values {
        data.insert(entry.0.to_owned(), entry.1.raw.to_owned()).unwrap();
      }

      let credential_subject = CredentialSubject {
        id: subject_did.to_owned(),
        data
      };

      let schema_reference = CredentialSchemaReference {
        id: credential_schema.id,
        r#type: "EvanZKPSchema".to_string()
      };

      let new_did = Issuer::mock_get_new_did();
      let rev_idx = Issuer::mock_get_rev_idx();

      let (
        signature,
        signature_correctness_proof,
        issuance_nonce
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
        revocation_registry_definition: revocation_registry_definition.id.clone()
      };

      return Credential {
        context: vec!("https://www.w3.org/2018/credentials/v1".to_string()),
        id: new_did,
        r#type: vec!("VerifiableCredential".to_string()),
        issuer: issuer_did.to_owned(),
        credential_subject,
        credential_schema: schema_reference,
        signature: cred_signature
      };
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
      issuer_proving_key: &str,
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

    fn mock_get_new_did() -> String {
      return "did:evan:zkp:0x123451234512345123451234512345".to_string();
    }

    fn mock_get_rev_idx() -> u32 {
      return 1;
    }
}
