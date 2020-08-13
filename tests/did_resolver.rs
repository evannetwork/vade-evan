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
use std::{env, error::Error, sync::Once};
use test_data::{
    accounts::local::{SIGNER_1_DID, SIGNER_1_PRIVATE_KEY},
    did::{EXAMPLE_DID_DOCUMENT_1, EXAMPLE_DID_DOCUMENT_2},
    environment::DEFAULT_VADE_EVAN_SUBSTRATE_IP,
};
use vade::{VadePlugin, VadePluginResultValue};
use vade_evan::{
    resolver::{ResolverConfig, SubstrateDidResolverEvan},
    signing::{LocalSigner, Signer},
};

static INIT: Once = Once::new();

#[tokio::test]
async fn can_create_dids() -> Result<(), Box<dyn Error>> {
    enable_logging();
    let mut resolver: SubstrateDidResolverEvan = get_resolver();

    // whitelist identity
    resolver
        .did_update(SIGNER_1_DID, &get_options("whitelistIdentity"), "")
        .await?;

    // create did
    let did = match resolver
        .did_create("did:evan", &get_options(""), "")
        .await?
    {
        VadePluginResultValue::Success(Some(v)) => v,
        _ => {
            return Err(Box::from("could not get DID document"));
        }
    };

    let re = Regex::new(r"^(?i)did:evan:0x[0-9a-f]{64}$")?;
    assert!(re.is_match(&did));

    Ok(())
}

#[tokio::test]
async fn can_set_did_document() -> Result<(), Box<dyn Error>> {
    enable_logging();

    // whitelist identity
    let mut resolver: SubstrateDidResolverEvan = get_resolver();
    resolver
        .did_update(SIGNER_1_DID, &get_options("whitelistIdentity"), "")
        .await?;

    // create did
    let did = match resolver
        .did_create("did:evan", &get_options(""), "")
        .await?
    {
        VadePluginResultValue::Success(Some(v)) => v,
        _ => {
            return Err(Box::from("could not get DID document"));
        }
    };

    // setting did document should not run into an error
    resolver
        .did_update(
            &did,
            &get_options("setDidDocument"),
            &EXAMPLE_DID_DOCUMENT_1,
        )
        .await?;

    Ok(())
}

#[tokio::test]
async fn can_get_did_document() -> Result<(), Box<dyn Error>> {
    enable_logging();

    // whitelist identity
    let mut resolver: SubstrateDidResolverEvan = get_resolver();
    resolver
        .did_update(SIGNER_1_DID, &get_options("whitelistIdentity"), "")
        .await?;

    // create did
    let did = match resolver
        .did_create("did:evan", &get_options(""), "")
        .await?
    {
        VadePluginResultValue::Success(Some(v)) => v,
        _ => {
            return Err(Box::from("could not get DID document"));
        }
    };

    // set document
    resolver
        .did_update(
            &did,
            &get_options("setDidDocument"),
            &EXAMPLE_DID_DOCUMENT_1,
        )
        .await?;
    // fetch it
    let did_document = match resolver.did_resolve(&did).await? {
        VadePluginResultValue::Success(Some(value)) => value,
        _ => return Err(Box::from("could not get DID document")),
    };
    assert!(did_document == EXAMPLE_DID_DOCUMENT_1);

    Ok(())
}

#[tokio::test]
async fn can_update_did_document() -> Result<(), Box<dyn Error>> {
    enable_logging();

    // whitelist identity
    let mut resolver: SubstrateDidResolverEvan = get_resolver();
    resolver
        .did_update(SIGNER_1_DID, &get_options("whitelistIdentity"), "")
        .await?;

    // create did
    let did = match resolver
        .did_create("did:evan", &get_options(""), "")
        .await?
    {
        VadePluginResultValue::Success(Some(v)) => v,
        _ => {
            return Err(Box::from("could not get DID document"));
        }
    };

    // set once to ensure we have a known DID document at the beginning
    resolver
        .did_update(
            &did,
            &get_options("setDidDocument"),
            &EXAMPLE_DID_DOCUMENT_1,
        )
        .await?;
    let did_document = match resolver.did_resolve(&did).await? {
        VadePluginResultValue::Success(Some(value)) => value,
        _ => return Err(Box::from("could not get DID document")),
    };
    assert!(did_document == EXAMPLE_DID_DOCUMENT_1);

    // overwrite and check again
    resolver
        .did_update(
            &did,
            &get_options("setDidDocument"),
            &EXAMPLE_DID_DOCUMENT_2,
        )
        .await?;
    let did_document = match resolver.did_resolve(&did).await? {
        VadePluginResultValue::Success(Some(value)) => value,
        _ => return Err(Box::from("could not get DID document")),
    };
    assert!(did_document == EXAMPLE_DID_DOCUMENT_2);

    Ok(())
}

pub fn enable_logging() {
    INIT.call_once(|| {
        env_logger::try_init().ok();
    });
}

fn get_options(operation: &str) -> String {
    format!(
        r###"{{
            "privateKey": "{}",
            "identity": "{}",
            "operation": "{}"
        }}"###,
        SIGNER_1_PRIVATE_KEY, SIGNER_1_DID, operation
    )
}

fn get_resolver() -> SubstrateDidResolverEvan {
    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    SubstrateDidResolverEvan::new(ResolverConfig {
        signer,
        target: env::var("VADE_EVAN_SUBSTRATE_IP")
            .unwrap_or_else(|_| DEFAULT_VADE_EVAN_SUBSTRATE_IP.to_string()),
    })
}
