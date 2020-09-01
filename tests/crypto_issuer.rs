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

use std::{collections::HashMap, error::Error};
use test_data::vc_zkp::EXAMPLE_CREDENTIAL_SCHEMA;
use vade_evan::application::datatypes::CredentialSchema;
use vade_evan::crypto::crypto_datatypes::CryptoCredentialDefinition;
use vade_evan::crypto::crypto_issuer::Issuer as CryptoIssuer;

#[test]
fn can_create_credential_definition() -> Result<(), Box<dyn Error>> {
    let credential_schema: CredentialSchema =
        serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
    let def: CryptoCredentialDefinition =
        CryptoIssuer::create_credential_definition(&credential_schema, None, None)?.1;

    // Cannot access p_key.r because it is private, therefore serialize it
    let r_component_str =
        serde_json::to_string(&serde_json::to_value(&def.public_key).unwrap()["p_key"]["r"])
            .unwrap(); // :(
    let r_component: HashMap<String, String> = serde_json::from_str(&r_component_str).unwrap();

    for key in credential_schema.properties.keys() {
        assert_eq!(r_component.contains_key(key), true);
    }

    Ok(())
}
