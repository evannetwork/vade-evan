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

use std::env;
use std::error::Error;
use std::sync::Once;
use vade::{VadePlugin, VadePluginResultValue};
// use test_data::{SIGNER_IDENTITY, SIGNER_PRIVATE_KEY, SIGNING_URL};
use test_data::{
    SIGNER_LOCAL_DID_DOCUMENT1,
    SIGNER_LOCAL_DID_DOCUMENT2,
    SIGNER_LOCAL_IDENTITY,
    SIGNER_LOCAL_PRIVATE_KEY,
};
use vade_evan::{
    resolver::{ResolverConfig, SubstrateDidResolverEvan},
    // signing::{RemoteSigner, Signer},
    signing::{LocalSigner, Signer},
};

static INIT: Once = Once::new();

#[tokio::test]
async fn did_resolver_can_get_did_document() -> Result<(), Box<dyn Error>> {
    enable_logging();

    let mut resolver: SubstrateDidResolverEvan = get_resolver();
    let did_document = match resolver.did_resolve(&SIGNER_LOCAL_IDENTITY).await? {
        VadePluginResultValue::Success(Some(value)) => value,
        _ => return Err(Box::from("could not get DID document")),
    };

    assert!(
        did_document == SIGNER_LOCAL_DID_DOCUMENT1 || did_document == SIGNER_LOCAL_DID_DOCUMENT2
    );

    Ok(())
}

#[tokio::test]
async fn did_resolver_can_set_did_document() -> Result<(), Box<dyn Error>> {
    enable_logging();

    // whitelist identity
    let mut resolver: SubstrateDidResolverEvan = get_resolver();
    resolver
        .did_update(SIGNER_LOCAL_IDENTITY, &get_options("whitelistIdentity"), "")
        .await?;

    let mut resolver: SubstrateDidResolverEvan = get_resolver();

    // set once to ensure we have a known DID document at the beginning
    resolver
        .did_update(
            SIGNER_LOCAL_IDENTITY,
            &get_options("setDidDocument"),
            &SIGNER_LOCAL_DID_DOCUMENT1,
        )
        .await?;
    let did_document = match resolver.did_resolve(&SIGNER_LOCAL_IDENTITY).await? {
        VadePluginResultValue::Success(Some(value)) => value,
        _ => return Err(Box::from("could not get DID document")),
    };
    assert!(did_document == SIGNER_LOCAL_DID_DOCUMENT1);

    // overwrite and check again
    resolver
        .did_update(
            SIGNER_LOCAL_IDENTITY,
            &get_options("setDidDocument"),
            &SIGNER_LOCAL_DID_DOCUMENT2,
        )
        .await?;
    let did_document = match resolver.did_resolve(&SIGNER_LOCAL_IDENTITY).await? {
        VadePluginResultValue::Success(Some(value)) => value,
        _ => return Err(Box::from("could not get DID document")),
    };
    assert!(did_document == SIGNER_LOCAL_DID_DOCUMENT2);

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
        SIGNER_LOCAL_PRIVATE_KEY, SIGNER_LOCAL_IDENTITY, operation
    )
}

fn get_resolver() -> SubstrateDidResolverEvan {
    // let signer: Box<dyn Signer> = Box::new(RemoteSigner::new(SIGNING_URL.to_string()));
    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    SubstrateDidResolverEvan::new(ResolverConfig {
        signer,
        target: env::var("VADE_EVAN_SUBSTRATE_IP").unwrap_or_else(|_| "13.69.59.185".to_string()),
    })
}
