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

extern crate env_logger;
extern crate log;
extern crate vade_evan;

mod test_data;

use std::{collections::HashMap, error::Error};
use test_data::{
    EXAMPLE_CREDENTIAL_SCHEMA,
    EXAMPLE_DID,
    EXAMPLE_DID_DOCUMENT_STR,
    EXAMPLE_GENERATED_DID,
    SIGNER_LOCAL_ADDRESS,
    SIGNER_LOCAL_PRIVATE_KEY,
};
use vade_evan::{
    application::{
        datatypes::{CredentialSchema, SchemaProperty},
        issuer::Issuer,
    },
    crypto::crypto_utils::check_assertion_proof,
    signing::{LocalSigner, Signer},
};

#[tokio::test]
async fn can_create_schema() -> Result<(), Box<dyn Error>> {
    match env_logger::try_init() {
        Ok(_) | Err(_) => (),
    };

    let did_document = serde_json::to_value(&EXAMPLE_DID_DOCUMENT_STR)?;
    let mut required_properties: Vec<String> = Vec::new();
    let mut test_properties: HashMap<String, SchemaProperty> = HashMap::new();
    test_properties.insert(
        "test_property_string".to_owned(),
        SchemaProperty {
            r#type: "string".to_owned(),
            format: None,
            items: None,
        },
    );
    required_properties.push("test_property_string".to_owned());

    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    let schema: CredentialSchema = Issuer::create_credential_schema(
        EXAMPLE_GENERATED_DID,
        EXAMPLE_DID,
        "test_schema",
        "Test description",
        test_properties,
        required_properties,
        false,
        &did_document["publicKey"][0]["id"].to_string(),
        &SIGNER_LOCAL_PRIVATE_KEY,
        &signer,
    )
    .await?;

    assert_eq!(&schema.author, &EXAMPLE_DID);
    assert_eq!(schema.additional_properties, false);
    let result_property: &SchemaProperty = &schema.properties.get("test_property_string").unwrap();
    let expected: SchemaProperty = SchemaProperty {
        r#type: "string".to_owned(),
        format: None,
        items: None,
    };
    assert_eq!(
        serde_json::to_string(&result_property).unwrap(),
        serde_json::to_string(&expected).unwrap(),
    );

    let serialized = serde_json::to_string(&schema).unwrap();
    assert!(
        match check_assertion_proof(&serialized, SIGNER_LOCAL_ADDRESS) {
            Ok(()) => true,
            Err(e) => panic!("assertion check failed with: {}", e),
        }
    );

    Ok(())
}

#[tokio::test]
async fn can_create_credential_definition() -> Result<(), Box<dyn Error>> {
    let schema: CredentialSchema = serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    let (definition, _) = Issuer::create_credential_definition(
        test_data::EXAMPLE_GENERATED_DID,
        &EXAMPLE_DID,
        &schema,
        "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1",
        &SIGNER_LOCAL_PRIVATE_KEY,
        &signer,
    )
    .await?;

    assert_eq!(
        serde_json::to_string(&definition.issuer).unwrap(),
        serde_json::to_string(&EXAMPLE_DID).unwrap(),
    );

    assert_eq!(
        serde_json::to_string(&definition.schema).unwrap(),
        serde_json::to_string(&schema.id).unwrap()
    );

    assert_eq!(&definition.id, EXAMPLE_GENERATED_DID);

    let serialized = serde_json::to_string(&definition).unwrap();
    assert!(
        match check_assertion_proof(&serialized, SIGNER_LOCAL_ADDRESS) {
            Ok(()) => true,
            Err(e) => panic!("assertion check failed with: {}", e),
        }
    );

    Ok(())
}
