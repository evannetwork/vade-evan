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
use vade_evan::{
    resolver::{ResolverConfig, SubstrateDidResolverEvan},
    // signing::{RemoteSigner, Signer},
    signing::{LocalSigner, Signer},
};

static INIT: Once = Once::new();

const SIGNER_IDENTITY: &str = "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906";
const SIGNER_PRIVATE_KEY: &str = "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106";
const SIGNER_DID_DOCUMENT: &str = r###"{
    '@context': 'https://w3id.org/did/v1',
    id: 'did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906',
    publicKey: [
      {
        id: 'did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1',
        type: 'Secp256k1VerificationKey2018',
        controller: 'did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906',
        ethereumAddress: '0xcd5e1dbb5552c2baa1943e6b5f66d22107e9c05c'
      }
    ],
    authentication: [
      'did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1'
    ],
    created: '2020-07-22T08:08:57.285Z',
    updated: '2020-07-22T08:08:57.285Z',
    proof: {
      type: 'EcdsaPublicKeySecp256k1',
      created: '2020-07-22T08:08:57.291Z',
      proofPurpose: 'assertionMethod',
      verificationMethod: 'did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1',
      jws: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1OTU0MDUzMzcsImRpZERvY3VtZW50Ijp7IkBjb250ZXh0IjoiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjEiLCJpZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4MGQ4NzIwNGMzOTU3ZDczYjY4YWUyOGQwYWY5NjFkM2M3MjQwMzkwNiIsInB1YmxpY0tleSI6W3siaWQiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYja2V5LTEiLCJ0eXBlIjoiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsImNvbnRyb2xsZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYiLCJldGhlcmV1bUFkZHJlc3MiOiIweGNkNWUxZGJiNTU1MmMyYmFhMTk0M2U2YjVmNjZkMjIxMDdlOWMwNWMifV0sImF1dGhlbnRpY2F0aW9uIjpbImRpZDpldmFuOnRlc3Rjb3JlOjB4MGQ4NzIwNGMzOTU3ZDczYjY4YWUyOGQwYWY5NjFkM2M3MjQwMzkwNiNrZXktMSJdLCJjcmVhdGVkIjoiMjAyMC0wNy0yMlQwODowODo1Ny4yODVaIiwidXBkYXRlZCI6IjIwMjAtMDctMjJUMDg6MDg6NTcuMjg1WiJ9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYifQ.w9cN2yaq-g-6PJe3Pqu6DwAkBZprK5UqBP1FPtoEqI41AKljQeEZsb8G4ZXjVMR3FIMaKqar-iQ2TLKYi8RQtgA'
    }
  }"###;

#[tokio::test]
async fn did_resolver_can_set_did_document() -> Result<(), Box<dyn Error>> {
    enable_logging();

    // whitelist identity
    let mut resolver: SubstrateDidResolverEvan = get_resolver();
    resolver
        .did_update(SIGNER_IDENTITY, &get_options("whitelistIdentity"), "")
        .await?;
    println!("whitelisted :3");

    // set DID document of signer
    let mut resolver: SubstrateDidResolverEvan = get_resolver();
    resolver
        .did_update(
            SIGNER_IDENTITY,
            &get_options("setDidDocument"),
            &SIGNER_DID_DOCUMENT,
        )
        .await?;
    println!("updated :3");

    // Err(Box::from("test not implemented"))
    Ok(())
}

#[ignore]
#[tokio::test]
async fn did_resolver_can_get_did_document() -> Result<(), Box<dyn Error>> {
    enable_logging();

    let mut resolver: SubstrateDidResolverEvan = get_resolver();
    let did_document = match resolver.did_resolve(&SIGNER_IDENTITY).await? {
        VadePluginResultValue::Success(Some(value)) => value,
        _ => return Err(Box::from("could not get DID document")),
    };

    println!("{}", &did_document);
    // Err(Box::from("test not implemented"))
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
        SIGNER_PRIVATE_KEY, SIGNER_IDENTITY, operation
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
