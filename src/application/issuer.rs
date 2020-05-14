use crate::application::datatypes::{
  CredentialDefinition,
  CredentialSchema,
  SchemaProperty,
  CredentialOffer,
  Credential,
  CredentialSchemaReference,
  CredentialSubject,
  CredentialProof,
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

pub struct Issuer {
}

impl Issuer {
    pub fn new() -> Issuer {
        Issuer { }
    }

    pub fn create_credential_definition(
      issuer_did: String,
      schema: CredentialSchema,
      issuer_public_key_did: String,
      issuer_proving_key: String
    ) -> (CredentialDefinition, CredentialPrivateKey) {

      let did = Issuer::mock_get_new_did();

      let created_at = get_now_as_iso_string();

      let (credential_private_key, crypto_credential_def) = CryptoIssuer::create_credential_definition(
        &schema,
        true,
      );

      let mut definition = CredentialDefinition {
        id: did,
        r#type: "EvanZKPCredentialDefinition".to_string(),
        issuer: issuer_did.clone(),
        schema: schema.id.clone(),
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
      issuer_did: String,
      schema_name: String,
      description: String,
      properties: HashMap<String, SchemaProperty>,
      required_properties: Vec<String>,
      allow_additional_properties: bool,
      issuer_public_key_did: String,
      issuer_proving_key: String
    ) -> CredentialSchema {

      let schema_did = Issuer::mock_get_new_did();

      let created_at = get_now_as_iso_string();

      let mut schema = CredentialSchema {
        id: schema_did,
        r#type: "EvanVCSchema".to_string(), //TODO: Make enum
        name: schema_name,
        author: issuer_did.clone(),
        created_at,
        description,
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
      issuer_public_key_did: String,
      issuer_proving_key: String,
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
      issuer_did: String,
      subject_did: String,
      credential_request: CredentialRequest,
      credential_definition: CredentialDefinition,
      credential_private_key: CredentialPrivateKey,
      credential_schema: CredentialSchema,
      revocation_registry_definition: &mut RevocationRegistryDefinition,
      revocation_private_key: RevocationKeyPrivate
    ) -> Credential {

      let credential_subject = CredentialSubject {
        id: subject_did,
        data: credential_request.credential_values.clone()
      };

      let schema_reference = CredentialSchemaReference {
        id: credential_schema.id,
        r#type: "EvanZKPSchema".to_string()
      };

      let new_did = Issuer::mock_get_new_did();
      let rev_idx = Issuer::mock_get_rev_idx();

      let signed_credential = CryptoIssuer::sign_credential_with_revocation(
        &credential_request,
        &credential_private_key,
        &credential_definition.public_key,
        revocation_registry_definition,
        rev_idx,
        &revocation_private_key
      );

      let proof = CredentialProof {
        r#type: "CLSignature2019".to_string(),
        credential_definition: credential_definition.id,
        issuance_nonce: signed_credential.issuance_nonce,
        signature: signed_credential.signature,
        signature_correctness_proof: signed_credential.correctness_proof,
        revocation_id: rev_idx,
        revocation_registry_definition: revocation_registry_definition.id.clone()
      };

      return Credential {
        context: vec!("https://www.w3.org/2018/credentials/v1".to_string()),
        id: new_did,
        r#type: vec!("VerifiableCredential".to_string()),
        issuer: issuer_did,
        credential_subject,
        credential_schema: schema_reference,
        proof
      };
    }

    pub fn offer_credential(
      issuer_did: String,
      subject_did: String,
      schema_did: String,
      credential_definition_did: String
    ) -> CredentialOffer {
      let nonce = new_nonce().unwrap();

      return CredentialOffer {
        issuer: issuer_did,
        subject: subject_did,
        r#type: "EvanZKPCredentialOffering".to_string(),
        schema: schema_did,
        credential_definition: credential_definition_did,
        nonce
      }
    }

    fn mock_get_new_did() -> String {
      return "did:evan:zkp:0x123451234512345123451234512345".to_string();
    }

    fn mock_get_rev_idx() -> u32 {
      return 1;
    }
}
