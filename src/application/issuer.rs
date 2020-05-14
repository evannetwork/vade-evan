use crate::application::datatypes::{
  CredentialDefinition,
  CredentialSchema
};
use crate::crypto::crypto_issuer::Issuer as CryptoIssuer;

use chrono::{Utc};

pub struct Issuer {
}

impl Issuer {
    pub fn new() -> Issuer {
        Issuer { }
    }

    pub fn create_credential_definition(
      issuer_did: String,
      schema_did: String
    ) -> CredentialDefinition {

      let did = Issuer::mock_get_new_did();

      let created_at = Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string();

      let schema: CredentialSchema = fetch_schema(schema_did);
      let properties : Vec<&String> = schema.properties.keys().collect();

      CryptoIssuer::create_credential_definition(
        issuer_did,
        schema,
        true,
        issuer_private_key: String
      );

      return CredentialDefinition {
        id: did,
        r#type: "EvanZKPCredentialDefinition".to_string(),
        issuer: issuer_did,
        schema: schema_did,
        created_at,
        public_key,
        public_key_correctness_proof,
        proof
      };
    }

    fn mock_get_new_did() -> String {
      return "did:evan:zkp:0x123451234512345123451234512345".to_string();
    }


}
