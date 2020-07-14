/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

extern crate vade_evan;

mod test_data;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use test_data::{
    SIGNER_ADDRESS,
    SIGNER_PRIVATE_KEY,
    SIGNING_URL,
};
use vade_evan::application::datatypes::{CredentialSchema, SchemaProperty};
use vade_evan::crypto::crypto_utils::{
    create_assertion_proof,
    recover_address_and_data,
    JwsData,
};
use vade_evan::utils::signing::sign_message;

const DOCUMENT_TO_SIGN: &str = r###"
{
  "id": "did:evan:zkp:0x123451234512345123451234512345",
  "type": "EvanVCSchema",
  "name": "test_schema",
  "author": "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD1",
  "createdAt": "2020-05-19T12:54:55.000Z",
  "description": "Test description",
  "properties": {
    "test_property_string": {
      "type": "string"
    }
  },
  "required": [
    "test_property_string"
  ],
  "additionalProperties": false
}
"###;

const ISSUER: &str = "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1";
const ISSUER_ETHEREUM_ADDRESS: &str = "0x775018c020ae1b3fd4e8a707f8ecfeafc9055e9d";
const VERIFICATION_METHOD: &str =
    "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1";
const EXPECTED_SIGNATURE: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODk4MDIxMjYsImRpZERvY3VtZW50Ijp7IkBjb250ZXh0IjoiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjEiLCJpZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4MGY3MzdkMTQ3OGVhMjlkZjA4NTYxNjlmMjVjYTkxMjkwMzVkNmZkMSIsInB1YmxpY0tleSI6W3siaWQiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBmNzM3ZDE0NzhlYTI5ZGYwODU2MTY5ZjI1Y2E5MTI5MDM1ZDZmZDEja2V5LTEiLCJ0eXBlIjoiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsImNvbnRyb2xsZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBmNzM3ZDE0NzhlYTI5ZGYwODU2MTY5ZjI1Y2E5MTI5MDM1ZDZmZDEiLCJldGhlcmV1bUFkZHJlc3MiOiIweDc3NTAxOGMwMjBhZTFiM2ZkNGU4YTcwN2Y4ZWNmZWFmYzkwNTVlOWQifV0sImF1dGhlbnRpY2F0aW9uIjpbImRpZDpldmFuOnRlc3Rjb3JlOjB4MGY3MzdkMTQ3OGVhMjlkZjA4NTYxNjlmMjVjYTkxMjkwMzVkNmZkMSNrZXktMSJdLCJjcmVhdGVkIjoiMjAyMC0wNS0xOFQxMTo0MjowNi43NjZaIiwidXBkYXRlZCI6IjIwMjAtMDUtMThUMTE6NDI6MDYuNzY2WiJ9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBmNzM3ZDE0NzhlYTI5ZGYwODU2MTY5ZjI1Y2E5MTI5MDM1ZDZmZDEifQ.MBBWlq_zH5cRzlpYcc4eoX_qbg2ICG3V-MZj-5TVPzhhIAE7dJdxREQPNtBya9Rk5sWc4bItJDvOyq4hwKX66wA";

#[derive(Serialize, Deserialize)]
struct JwsDoc {
    id: String,
    r#type: String,
    name: String,
    author: String,
    description: String,
    properties: HashMap<String, SchemaProperty>,
    required: Vec<String>,
}

#[test]
fn can_recover_address_and_data_from_signature() {
    let (address, data) = recover_address_and_data(EXPECTED_SIGNATURE).unwrap();
    assert_eq!(format!("0x{}", address), ISSUER_ETHEREUM_ADDRESS);

    // if we find these strings, we can assume the recovery is fine
    assert_eq!(
        true,
        data.contains(r#""id":"did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1""#)
    );
    assert_eq!(true, data.contains(r##""publicKey":[{"id":"did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1""##));
    assert_eq!(
        true,
        data.contains(r#"ethereumAddress":"0x775018c020ae1b3fd4e8a707f8ecfeafc9055e9d"#)
    );
}

#[tokio::test]
async fn can_create_assertion_proof() {
    match env_logger::try_init() {
        Ok(_) | Err(_) => (),
    };
    
    // First deserialize it into a data type or else serde_json will serialize the document into raw unformatted text
    let schema: CredentialSchema = serde_json::from_str(DOCUMENT_TO_SIGN).unwrap();
    let doc_to_sign = serde_json::to_value(&schema).unwrap();
    let proof = create_assertion_proof(
        &doc_to_sign,
        VERIFICATION_METHOD,
        ISSUER,
        SIGNER_PRIVATE_KEY,
        &(env::var("VADE_EVAN_SIGNING_URL").unwrap_or_else(|_| SIGNING_URL.to_string())),
    ).await.unwrap();

    assert_eq!(proof.proof_purpose, "assertionMethod".to_owned());
    assert_eq!(proof.r#type, "EcdsaPublicKeySecp256k1".to_owned());
    assert_eq!(proof.verification_method, VERIFICATION_METHOD.to_owned());

    // Recover document from signature and check if it equals the original
    let (address, data) = recover_address_and_data(&proof.jws).unwrap();
    let jws: JwsData = serde_json::from_str(&data).unwrap();
    let doc: JwsDoc = serde_json::from_str(jws.doc.get()).unwrap();
    let orig: JwsDoc = serde_json::from_str(DOCUMENT_TO_SIGN).unwrap();
    assert_eq!(
        serde_json::to_string(&doc).unwrap(),
        serde_json::to_string(&orig).unwrap()
    );
    assert_eq!(format!("0x{}", address), SIGNER_ADDRESS);
}

#[tokio::test]
async fn can_sign_messages() -> Result<(), Box<dyn std::error::Error>> {
    let (_signature, message): ([u8; 65], [u8; 32]) = sign_message(
        "one two three four",
        "a1c48241-5978-4348-991e-255e92d81f1e",
        "https://tntkeyservices-e0ae.azurewebsites.net/api/key/sign",
    ).await?;
    let message_hash = format!("0x{}", hex::encode(message));
    assert_eq!(
        message_hash,
        "0x52091d1299031b18c1099620a1786363855d9fcd91a7686c866ad64f83de13ff"
    );

    Ok(())
}
