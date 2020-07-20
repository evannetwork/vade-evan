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
extern crate vade;
use crate::utils::substrate::{
    add_payload_to_did,
    create_did,
    get_did,
    get_payload_count_for_did,
    update_payload_in_did,
    whitelist_identity,
};
use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use vade::{VadePlugin, VadePluginResultValue};

const EVAN_METHOD: &str = "did:evan";
const EVAN_METHOD_PREFIX: &str = "did:evan:";
const EVAN_METHOD_ZKP_PREFIX: &str = "did:evan:zkp:";

const METHOD_REGEX: &'static str = r#"^(.*):0x(.*)$"#;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidUpdateArguments {
    pub private_key: String,
    pub identity: String,
    pub operation: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityArguments {
    pub private_key: String,
    pub identity: String,
}

pub struct ResolverConfig {
    pub signing_url: String,
    pub target: String,
}

/// Resolver for DIDs on the Trust&Trace substrate chain
pub struct SubstrateDidResolverEvan {
    config: ResolverConfig,
}

impl SubstrateDidResolverEvan {
    /// Creates new instance of `SubstrateDidResolverEvan`.
    pub fn new(config: ResolverConfig) -> SubstrateDidResolverEvan {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        SubstrateDidResolverEvan { config }
    }

    async fn set_did_document(
        &self,
        did: &str,
        private_key: &str,
        identity: &str,
        payload: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        debug!(
            "setting DID document for did: {}, iden; {}",
            &did, &identity
        );
        let payload_count: u32 =
            get_payload_count_for_did(self.config.target.clone(), did.to_string()).await?;
        if payload_count > 0 {
            update_payload_in_did(
                self.config.target.clone(),
                0 as u32,
                payload.to_string(),
                did.to_string(),
                private_key.to_string(),
                self.config.signing_url.to_string(),
                hex::decode(identity)?,
            )
            .await?;
        } else {
            add_payload_to_did(
                self.config.target.clone(),
                payload.to_string(),
                did.to_string(),
                private_key.to_string(),
                self.config.signing_url.to_string(),
                hex::decode(identity)?,
            )
            .await?;
        }
        Ok(Some("".to_string()))
    }
}

#[async_trait(?Send)]
impl VadePlugin for SubstrateDidResolverEvan {
    /// Creates a new DID on substrate.
    ///
    /// # Arguments
    ///
    /// * `did_method` - did method to cater to, usually "did:evan"
    /// * `options` - serialized [`IdentityArguments`](https://docs.rs/vade_evan/*/vade_evan/resolver/struct.IdentityArguments.html)
    /// * `payload` - no payload required, so can be left empty
    ///
    async fn did_create(
        &mut self,
        did_method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if did_method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let options: IdentityArguments = serde_json::from_str(&options)?;
        let inner_result = create_did(
            self.config.target.clone(),
            options.private_key.clone(),
            self.config.signing_url.to_string(),
            hex::decode(&convert_did_to_substrate_identity(&options.identity)?)?,
            match payload {
                "" => None,
                _ => Some(payload),
            },
        )
        .await?;
        Ok(VadePluginResultValue::Success(Some(inner_result)))
    }

    /// Updates data related to a DID. Two updates are supported depending on the value of
    /// `options.operation`.
    ///
    /// - whitelistIdentity: whitelists identity `did` on substrate, this is required to be able to
    ///   perform transactions this this identity
    /// - setDidDocument: sets the DID document for `did`
    ///
    /// # Arguments
    ///
    /// * `did` - DID to update data for
    /// * `options` - serialized [`DidUpdateArguments`](https://docs.rs/vade_evan/*/vade_evan/resolver/struct.DidUpdateArguments.html)
    /// * `payload` - DID document to set or empty
    ///
    async fn did_update(
        &mut self,
        did: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if !did.starts_with(EVAN_METHOD_PREFIX) {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: DidUpdateArguments = serde_json::from_str(&options)?;
        match input.operation.as_str() {
            "whitelistIdentity" => {
                whitelist_identity(
                    self.config.target.clone(),
                    input.private_key.clone(),
                    &self.config.signing_url,
                    hex::decode(convert_did_to_substrate_identity(&did)?)?,
                )
                .await?;
                Ok(VadePluginResultValue::Success(None))
            }
            "setDidDocument" => {
                if !did.starts_with(EVAN_METHOD_ZKP_PREFIX) {
                    return Ok(VadePluginResultValue::Ignored);
                }
                self.set_did_document(
                    &convert_did_to_substrate_identity(&did)?,
                    &input.private_key,
                    &convert_did_to_substrate_identity(&input.identity)?,
                    payload,
                )
                .await?;
                Ok(VadePluginResultValue::Success(None))
            }
            _ => Err(Box::from(format!(
                "invalid did update operation \"{}\"",
                input.operation
            ))),
        }
    }

    /// Fetch data about a DID, which returns this DID's DID document.
    ///
    /// # Arguments
    ///
    /// * `did` - did to fetch data for
    async fn did_resolve(
        &mut self,
        did_id: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if !did_id.starts_with(EVAN_METHOD_ZKP_PREFIX) {
            return Ok(VadePluginResultValue::Ignored);
        }
        let did_result = get_did(
            self.config.target.clone(),
            convert_did_to_substrate_identity(&did_id)?,
        )
        .await?;
        Ok(VadePluginResultValue::Success(Some(did_result)))
    }
}

/// Converts a DID to a substrate compatible method prefixed DID hex string.
///
/// # Arguments
///
/// `did` - a DID string, e.g. `did:evan:testcore:0x1234`
///
/// # Returns
///
/// substrate DID hex string, e.g. `02001234`
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
