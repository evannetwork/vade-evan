extern crate vade_tnt;


use vade_tnt::application::issuer::Issuer;
use vade_tnt::application::datatypes::SchemaProperty;
use std::collections::HashMap;

const EXAMPLE_DID: &str = "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD1";
const EXAMPLE_DID_DOCUMENT_STR: &str = r###"
{
  "did": {
    "@context": "https://w3id.org/did/v1",
    "id": "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1",
    "publicKey": [
      {
        "id": "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1",
        "type": "Secp256k1VerificationKey2018",
        "controller": "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1",
        "ethereumAddress": "0x775018c020ae1b3fd4e8a707f8ecfeafc9055e9d"
      }
    ],
    "authentication": [
      "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1"
    ],
    "created": "2020-05-18T11:42:06.766Z",
    "updated": "2020-05-18T11:42:06.766Z",
    "proof": {
      "type": "EcdsaPublicKeySecp256k1",
      "created": "2020-05-18T11:42:06.778Z",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1",
      "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODk4MDIxMjYsImRpZERvY3VtZW50Ijp7IkBjb250ZXh0IjoiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjEiLCJpZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4MGY3MzdkMTQ3OGVhMjlkZjA4NTYxNjlmMjVjYTkxMjkwMzVkNmZkMSIsInB1YmxpY0tleSI6W3siaWQiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBmNzM3ZDE0NzhlYTI5ZGYwODU2MTY5ZjI1Y2E5MTI5MDM1ZDZmZDEja2V5LTEiLCJ0eXBlIjoiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsImNvbnRyb2xsZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBmNzM3ZDE0NzhlYTI5ZGYwODU2MTY5ZjI1Y2E5MTI5MDM1ZDZmZDEiLCJldGhlcmV1bUFkZHJlc3MiOiIweDc3NTAxOGMwMjBhZTFiM2ZkNGU4YTcwN2Y4ZWNmZWFmYzkwNTVlOWQifV0sImF1dGhlbnRpY2F0aW9uIjpbImRpZDpldmFuOnRlc3Rjb3JlOjB4MGY3MzdkMTQ3OGVhMjlkZjA4NTYxNjlmMjVjYTkxMjkwMzVkNmZkMSNrZXktMSJdLCJjcmVhdGVkIjoiMjAyMC0wNS0xOFQxMTo0MjowNi43NjZaIiwidXBkYXRlZCI6IjIwMjAtMDUtMThUMTE6NDI6MDYuNzY2WiJ9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBmNzM3ZDE0NzhlYTI5ZGYwODU2MTY5ZjI1Y2E5MTI5MDM1ZDZmZDEifQ.MBBWlq_zH5cRzlpYcc4eoX_qbg2ICG3V-MZj-5TVPzhhIAE7dJdxREQPNtBya9Rk5sWc4bItJDvOyq4hwKX66wA"
    }
  },
  "status": "success"
}
"###;
const EXAMPLE_PRIVATE_KEY: &str = "d02f8a67f22ae7d1ffc5507ca9a4e6548024562a7b36881b7a29f66dd26c532e";

#[test]
fn can_create_schema() {
  let did_document = serde_json::to_value(&EXAMPLE_DID_DOCUMENT_STR).unwrap();
  let mut required_properties: Vec<String> = Vec::new();
  let mut test_properties: HashMap<String, SchemaProperty> = HashMap::new();
  test_properties.insert(
    "test_property_string".to_owned(),
    SchemaProperty {
      r#type: "string".to_owned(),
      format: None,
      items: None
    }
  );
  required_properties.push("test_property_string".to_owned());

  let schema = Issuer::create_credential_schema(
    &EXAMPLE_DID,
    "test_schema",
    "Test description",
    test_properties,
    required_properties,
    false,
    &did_document["publicKey"][0]["id"].to_string(),
    &EXAMPLE_PRIVATE_KEY
  );

  // TODO: Validate proof
  assert_eq!(&schema.author, &EXAMPLE_DID);
  assert_eq!(&schema.additional_properties, false);
  assert_eq!(&schema.properties.keys(), &test_properties.keys());
}
