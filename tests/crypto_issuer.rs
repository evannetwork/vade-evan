extern crate vade_tnt;

mod test_data;

use vade_tnt::crypto::crypto_issuer::Issuer as CryptoIssuer;
use vade_tnt::application::datatypes::{
  CredentialSchema
};
use vade_tnt::crypto::crypto_datatypes::CryptoCredentialDefinition;
use std::collections::HashMap;
use test_data::EXAMPLE_CREDENTIAL_SCHEMA;

#[test]
fn can_create_credential_definition() {
  let credential_schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
  let def: CryptoCredentialDefinition = CryptoIssuer::create_credential_definition(&credential_schema).1;

  // Cannot access p_key.r because it is private, therefore serialize it
  let r_component_str = serde_json::to_string(&serde_json::to_value(&def.public_key).unwrap()["p_key"]["r"]).unwrap(); // :(
  let r_component: HashMap<String, String> = serde_json::from_str(&r_component_str).unwrap();

  for key in credential_schema.properties.keys() {
    assert_eq!(r_component.contains_key(key), true);
  }
}
