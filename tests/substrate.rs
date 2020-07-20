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

extern crate regex;
use regex::Regex;
mod test_data;
use vade_evan::utils::substrate;
use test_data::{
    SIGNER_PRIVATE_KEY,
    SIGNING_URL,
    SIGNER_IDENTITY
};

#[tokio::test]
async fn can_whitelist_identity() {
    let converted_identity = hex::decode(convert_did_to_substrate_identity(&SIGNER_IDENTITY).unwrap()).unwrap();
    substrate::whitelist_identity("127.0.0.1".to_string(), SIGNER_PRIVATE_KEY.to_string(), SIGNING_URL, converted_identity).await.unwrap();
}


#[tokio::test]
async fn can_create_a_did() {
    let converted_identity = hex::decode(convert_did_to_substrate_identity(&SIGNER_IDENTITY).unwrap()).unwrap();
    let did = substrate::create_did("127.0.0.1".to_string(), SIGNER_PRIVATE_KEY.to_string(), SIGNING_URL.to_string(), converted_identity, None).await.unwrap();

    println!("DID: {:?}", did);
}


#[tokio::test]
async fn can_add_payload_to_did() {
    match env_logger::try_init() {
        Ok(_) | Err(_) => (),
    };
    let converted_identity = hex::decode(convert_did_to_substrate_identity(&SIGNER_IDENTITY).unwrap()).unwrap();
    let did = substrate::create_did("127.0.0.1".to_string(), SIGNER_PRIVATE_KEY.to_string(), SIGNING_URL.to_string(), converted_identity.clone(), None).await.unwrap();
    substrate::add_payload_to_did("127.0.0.1".to_string(), "Hello_World".to_string(), did.clone(), SIGNER_PRIVATE_KEY.to_string(), SIGNING_URL.to_string(), converted_identity.clone()).await.unwrap();
    let detail_count = substrate::get_payload_count_for_did("127.0.0.1".to_string(), did.clone()).await.unwrap();
    let did_detail = substrate::get_did("127.0.0.1".to_string(), did.clone()).await.unwrap();
    substrate::update_payload_in_did("127.0.0.1".to_string(), 0, "Hello_World_update".to_string(), did.clone(), SIGNER_PRIVATE_KEY.to_string(), SIGNING_URL.to_string(), converted_identity.clone()).await.unwrap();
    let did_detail = substrate::get_did("127.0.0.1".to_string(), did.clone()).await.unwrap();
    substrate::update_payload_in_did("127.0.0.1".to_string(), 0, "Hello_World".to_string(), did.clone(), SIGNER_PRIVATE_KEY.to_string(), SIGNING_URL.to_string(), converted_identity.clone()).await.unwrap();
    let did_detail = substrate::get_did("127.0.0.1".to_string(), did.clone()).await.unwrap();
}


const METHOD_REGEX: &'static str = r#"^(.*):0x(.*)$"#;
fn convert_did_to_substrate_identity(did: &str) -> Result<String, Box<dyn std::error::Error>> {
    let re = Regex::new(METHOD_REGEX)?;
    let result = re.captures(&did);
    if let Some(caps) = result {
        match &caps[1] {
            "did:evan" => Ok(format!("0100{}", &caps[2])),
            "did:evan:testcore" => Ok(format!("0200{}", &caps[2])),
            "did:evan:zkp" => Ok(caps[2].to_string()),
            _ => Err(Box::from(format!("unknown DID format; {}", did))),
        }
    } else {
        Err(Box::from(format!("could not parse DID; {}", did)))
    }
}