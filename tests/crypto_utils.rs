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
use std::{collections::HashMap, env, error::Error};
use test_data::{
    EXAMPLE_CREDENTIAL_SCHEMA,
    SIGNER_LOCAL_ADDRESS,
    SIGNER_LOCAL_DID_DOCUMENT_JWS,
    SIGNER_LOCAL_IDENTITY,
    SIGNER_LOCAL_PRIVATE_KEY,
};
use vade_evan::{
    application::datatypes::{CredentialSchema, SchemaProperty},
    crypto::crypto_utils::{create_assertion_proof, recover_address_and_data, JwsData},
    signing::{LocalSigner, RemoteSigner, Signer},
};

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
    let (address, data) = recover_address_and_data(SIGNER_LOCAL_DID_DOCUMENT_JWS).unwrap();
    assert_eq!(format!("0x{}", address), SIGNER_LOCAL_ADDRESS);

    // if we find these strings, we can assume the recovery is fine
    println!("data: {}", &data);
    assert_eq!(
        true,
        data.contains(&format!(r#""id":"{}""#, &SIGNER_LOCAL_IDENTITY))
    );
    assert_eq!(
        true,
        data.contains(&format!(
            r##""publicKey":[{{"id":"{}#key-1""##,
            &SIGNER_LOCAL_IDENTITY
        ))
    );
    assert_eq!(
        true,
        data.contains(&format!(r#"ethereumAddress":"{}"#, &SIGNER_LOCAL_ADDRESS))
    );
}

#[tokio::test]
async fn can_create_assertion_proof() -> Result<(), Box<dyn Error>> {
    match env_logger::try_init() {
        Ok(_) | Err(_) => (),
    };

    // First deserialize it into a data type or else serde_json will serialize the document into raw unformatted text
    let schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
    let doc_to_sign = serde_json::to_value(&schema).unwrap();
    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    let proof = create_assertion_proof(
        &doc_to_sign,
        &format!("{}#key-1", &SIGNER_LOCAL_IDENTITY),
        SIGNER_LOCAL_IDENTITY,
        &SIGNER_LOCAL_PRIVATE_KEY,
        &signer,
    )
    .await
    .unwrap();

    assert_eq!(proof.proof_purpose, "assertionMethod".to_owned());
    assert_eq!(proof.r#type, "EcdsaPublicKeySecp256k1".to_owned());
    assert_eq!(
        proof.verification_method,
        format!("{}#key-1", &SIGNER_LOCAL_IDENTITY)
    );

    // Recover document from signature and check if it equals the original
    let (address, data) = recover_address_and_data(&proof.jws).unwrap();
    let jws: JwsData = serde_json::from_str(&data).unwrap();
    let doc: JwsDoc = serde_json::from_str(jws.doc.get()).unwrap();
    let orig: JwsDoc = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
    assert_eq!(
        serde_json::to_string(&doc).unwrap(),
        serde_json::to_string(&orig).unwrap()
    );
    assert_eq!(format!("0x{}", address), SIGNER_LOCAL_ADDRESS);

    Ok(())
}

#[tokio::test]
async fn can_sign_messages_remotely() -> Result<(), Box<dyn Error>> {
    let signer = RemoteSigner::new(
        env::var("VADE_EVAN_SIGNING_URL").map_err(|_| "missing VADE_EVAN_SIGNING_URL in env")?,
    );
    let (_signature, message): ([u8; 65], [u8; 32]) = signer
        .sign_message("one two three four", "33657f78-3dee-4c06-8fe5-be9af93963a1")
        .await?;
    let message_hash = format!("0x{}", hex::encode(message));
    assert_eq!(
        message_hash,
        "0x52091d1299031b18c1099620a1786363855d9fcd91a7686c866ad64f83de13ff"
    );

    Ok(())
}

#[tokio::test]
async fn can_sign_messages_locally() -> Result<(), Box<dyn Error>> {
    let signer = LocalSigner::new();
    let (_signature, message): ([u8; 65], [u8; 32]) = signer
        .sign_message("one two three four", SIGNER_LOCAL_PRIVATE_KEY)
        .await?;
    let message_hash = format!("0x{}", hex::encode(message));
    assert_eq!(
        message_hash,
        "0x216f85bc4d561a7c05231d12139a2d1a050c3baf3d33e057b8c25dcb3d7a8b94"
    );

    Ok(())
}
