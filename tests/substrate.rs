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
mod test_data;

use regex::Regex;
use std::error::Error;
use std::sync::Once;
use test_data::{SIGNER_IDENTITY, SIGNER_PRIVATE_KEY, SIGNING_URL};
use vade_evan::{
    signing::{RemoteSigner, Signer},
    // signing::{LocalSigner, Signer},
    utils::substrate,
};

static INIT: Once = Once::new();

// const SIGNER_IDENTITY: &str = "did:evan:testcore:0x9670f7974e7021e4940c56d47f6b31fdfdd37de8";
// const SIGNER_PRIVATE_KEY: &str = "4ea724e22ede0b7bea88771612485205cfc344131a16b8ab23d4970132be8dab";
const METHOD_REGEX: &str = r#"^(.*):0x(.*)$"#;

#[tokio::test]
async fn substrate_can_whitelist_identity() -> Result<(), Box<dyn Error>> {
    enable_logging();
    let (method, substrate_did) = convert_did_to_substrate_did(&SIGNER_IDENTITY)?;
    let signer: Box<dyn Signer> = get_signer();
    substrate::whitelist_identity(
        "127.0.0.1".to_string(),
        SIGNER_PRIVATE_KEY.to_string(),
        &signer,
        method,
        hex::decode(substrate_did)?,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn substrate_can_create_a_did() -> Result<(), Box<dyn Error>> {
    enable_logging();
    let (_, substrate_did) = convert_did_to_substrate_did(&SIGNER_IDENTITY)?;
    let signer: Box<dyn Signer> = get_signer();
    let did = substrate::create_did(
        "127.0.0.1".to_string(),
        SIGNER_PRIVATE_KEY.to_string(),
        &signer,
        hex::decode(substrate_did)?,
        None,
    )
    .await?;

    println!("DID: {:?}", did);

    Ok(())
}

#[tokio::test]
async fn substrate_can_add_payload_to_did() -> Result<(), Box<dyn Error>> {
    enable_logging();
    let (_, converted_identity) = convert_did_to_substrate_did(&SIGNER_IDENTITY)?;
    let converted_identity_vec = hex::decode(converted_identity)?;
    let signer: Box<dyn Signer> = get_signer();
    let did = substrate::create_did(
        "127.0.0.1".to_string(),
        SIGNER_PRIVATE_KEY.to_string(),
        &signer,
        converted_identity_vec.clone(),
        None,
    )
    .await?;
    substrate::add_payload_to_did(
        "127.0.0.1".to_string(),
        "Hello_World".to_string(),
        did.clone(),
        SIGNER_PRIVATE_KEY.to_string(),
        &signer,
        converted_identity_vec.clone(),
    )
    .await?;
    let _detail_count =
        substrate::get_payload_count_for_did("127.0.0.1".to_string(), did.clone()).await?;
    let did_detail1 = substrate::get_did("127.0.0.1".to_string(), did.clone()).await?;
    substrate::update_payload_in_did(
        "127.0.0.1".to_string(),
        0,
        "Hello_World_update".to_string(),
        did.clone(),
        SIGNER_PRIVATE_KEY.to_string(),
        &signer,
        converted_identity_vec.clone(),
    )
    .await?;
    let did_detail2 = substrate::get_did("127.0.0.1".to_string(), did.clone()).await?;
    substrate::update_payload_in_did(
        "127.0.0.1".to_string(),
        0,
        "Hello_World".to_string(),
        did.clone(),
        SIGNER_PRIVATE_KEY.to_string(),
        &signer,
        converted_identity_vec.clone(),
    )
    .await?;
    let did_detail3 = substrate::get_did("127.0.0.1".to_string(), did.clone()).await?;

    assert_eq!(&did_detail1, &did_detail3);
    assert_ne!(&did_detail1, &did_detail2);
    assert_ne!(&did_detail2, &did_detail3);

    Ok(())
}

fn convert_did_to_substrate_did(did: &str) -> Result<(u8, String), Box<dyn std::error::Error>> {
    let re = Regex::new(METHOD_REGEX)?;
    let result = re.captures(&did);
    if let Some(caps) = result {
        match &caps[1] {
            "did:evan" => Ok((1, caps[2].to_string())),
            "did:evan:testcore" => Ok((2, caps[2].to_string())),
            "did:evan:zkp" => Ok((0, caps[2].to_string())),
            _ => Err(Box::from(format!("unknown DID format; {}", did))),
        }
    } else {
        Err(Box::from(format!("could not parse DID; {}", did)))
    }
}

fn enable_logging() {
    INIT.call_once(|| {
        env_logger::try_init().ok();
    });
}

fn get_signer() -> Box<dyn Signer> {
    Box::new(RemoteSigner::new(SIGNING_URL.to_string()))
    // Box::new(LocalSigner::new())
}
