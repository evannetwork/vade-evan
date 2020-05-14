use crate::application::datatypes::{
  CredentialDefinition,
  CredentialSchema,
  SchemaProperty
};
use crate::crypto::crypto_issuer::Issuer as CryptoIssuer;
use crate::crypto::crypto_utils::create_assertion_proof;
use crate::utils::utils::get_now_as_iso_string;
use ursa::cl::{
  CredentialPrivateKey
};
use std::collections::HashMap;
use chrono::{Utc};

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

    fn mock_get_new_did() -> String {
      return "did:evan:zkp:0x123451234512345123451234512345".to_string();
    }


}
