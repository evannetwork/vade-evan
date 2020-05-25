extern crate vade_tnt;

use vade_tnt::crypto::crypto_issuer::Issuer as CryptoIssuer;
use vade_tnt::application::datatypes::CredentialSchema;
use vade_tnt::crypto::crypto_datatypes::CryptoCredentialDefinition;
use std::collections::HashMap;

const EXAMPLE_CREDENTIAL_SCHEMA: &str = r###"
{
  "id": "did:evan:zkp:0x123451234512345123451234512345",
  "type": "EvanVCSchema",
  "name": "test_schema",
  "author": "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD1",
  "createdAt": "2020-05-19T12:54:55.000Z",
  "description": "Test description",
  "properties": {
    "test_property_string3": {
      "type": "string"
    },
    "test_property_string": {
      "type": "string"
    },
    "test_property_string2": {
      "type": "string"
    }
  },
  "required": [
    "test_property_string"
  ],
  "additionalProperties": false,
  "proof": {
    "type": "EcdsaPublicKeySecp256k1",
    "created": "2020-05-19T12:54:55.000Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "null",
    "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIwLTA1LTE5VDEyOjU0OjU1LjAwMFoiLCJkb2MiOnsiaWQiOiJkaWQ6ZXZhbjp6a3A6MHgxMjM0NTEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUiLCJ0eXBlIjoiRXZhblZDU2NoZW1hIiwibmFtZSI6InRlc3Rfc2NoZW1hIiwiYXV0aG9yIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwRjczN0QxNDc4ZUEyOWRmMDg1NjE2OUYyNWNBOTEyOTAzNWQ2RkQxIiwiY3JlYXRlZEF0IjoiMjAyMC0wNS0xOVQxMjo1NDo1NS4wMDBaIiwiZGVzY3JpcHRpb24iOiJUZXN0IGRlc2NyaXB0aW9uIiwicHJvcGVydGllcyI6eyJ0ZXN0X3Byb3BlcnR5X3N0cmluZyI6eyJ0eXBlIjoic3RyaW5nIn19LCJyZXF1aXJlZCI6WyJ0ZXN0X3Byb3BlcnR5X3N0cmluZyJdLCJhZGRpdGlvbmFsUHJvcGVydGllcyI6ZmFsc2V9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBGNzM3RDE0NzhlQTI5ZGYwODU2MTY5RjI1Y0E5MTI5MDM1ZDZGRDEifQ.byfS5tIbnCN1M4PtfQQ9mq9mR2pIzgmBFoFNrGkINJBDVxPmKC2S337a2ulytG0G9upyAuOWVMBXESxQdF_MjwA"
  }
}
"###;

fn create_credential_definition(include_master_secret: bool) {
  let credential_schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
  let def: CryptoCredentialDefinition = CryptoIssuer::create_credential_definition(&credential_schema, false).1;

  // Cannot access p_key.r because it is private, therefore serialize it
  let r_component_str = serde_json::to_string(&serde_json::to_value(&def.public_key).unwrap()["p_key"]["r"]).unwrap(); // :(
  let r_component: HashMap<String, String> = serde_json::from_str(&r_component_str).unwrap();

  for key in credential_schema.properties.keys() {
    assert_eq!(r_component.contains_key(key), true);
  }
}

#[test]
fn can_create_credential_definitionn_with_master() {
  create_credential_definition(true);
}

#[test]
fn can_create_credential_definitionn_without_master() {
  create_credential_definition(false);
}
