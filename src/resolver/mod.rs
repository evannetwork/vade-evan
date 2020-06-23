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

extern crate vade;
use async_trait::async_trait;
use vade::traits::{ VadePlugin, VadePluginResultValue };
use crate::utils::substrate::{
    get_did,
    create_did,
    add_payload_to_did,
    get_payload_count_for_did,
    update_payload_in_did,
    whitelist_identity
};
use serde::{Serialize, Deserialize};

const EVAN_METHOD: &str = "did:evan";
const EVAN_METHOD_PREFIX: &str = "did:evan:zkp:";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityArguments {
  pub private_key: String,
  pub identity: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidUpdateArguments {
  pub private_key: String,
  pub identity: String,
  pub operation: String,
}

pub struct ResolverConfig {
  pub target: String,
  pub private_key: String,
  pub identity: Vec<u8>
}

/// Resolver for DIDs on the Trust&Trace substrate chain
pub struct SubstrateDidResolverEvan {
  config: ResolverConfig
}

impl SubstrateDidResolverEvan {
    /// Creates new instance of `SubstrateDidResolverEvan`.
    pub fn new(config: ResolverConfig) -> SubstrateDidResolverEvan {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        SubstrateDidResolverEvan {
          config
        }
    }
    
    async fn set_did_document(&self, did: &str, private_key: &str, identity: &str, payload: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        debug!("setting DID document for did: {}, iden: {}", &did, &identity);
        let payload_count: u32 = get_payload_count_for_did(self.config.target.clone(), did.to_string()).await.unwrap();
        if payload_count > 0 {
            update_payload_in_did(
                self.config.target.clone(),
                0 as u32,
                payload.to_string(),
                did.to_string(),
                private_key.to_string(),
                hex::decode(identity).unwrap(),
            ).await.unwrap();
        } else {
            add_payload_to_did(
                self.config.target.clone(),
                payload.to_string(),
                did.to_string(),
                private_key.to_string(),
                hex::decode(identity).unwrap(),
            ).await.unwrap();
        }
        Ok(Some("".to_string()))
    }
}

#[async_trait(?Send)]
impl VadePlugin for SubstrateDidResolverEvan {
    async fn did_create(&mut self, did_method: &str, options: &str, _payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if did_method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: IdentityArguments = serde_json::from_str(&options)?;
        let inner_result = create_did(
            self.config.target.clone(),
            input.private_key.clone(),
            hex::decode(input.identity).unwrap(),
        ).await.unwrap();
        Ok(VadePluginResultValue::Success(inner_result))
    }

    async fn did_update(&mut self, did: &str, options: &str, payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if !did.starts_with(EVAN_METHOD_PREFIX) {
            panic!(format!("{}", &did));
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: DidUpdateArguments = serde_json::from_str(&options)?;
        match input.operation.as_str() {
            "whitelistIdentity" => Ok(VadePluginResultValue::Success(whitelist_identity(
                self.config.target.clone(),
                input.private_key.clone(),
                hex::decode(input.identity).unwrap(),
            ).await.unwrap())),
            "setDidDocument" => {
                self.set_did_document(
                    &did.replace(EVAN_METHOD_PREFIX, ""),
                    &input.private_key,
                    &input.identity,
                    payload,
                ).await.unwrap();
                Ok(VadePluginResultValue::Success("".to_string()))
            },
            _ => Err(Box::from(format!("invalid did update operation \"{}\"", input.operation))),
        }
    }

    /// Gets document for given did name.
    ///
    /// # Arguments
    ///
    /// * `did_id` - did id to fetch
    async fn did_resolve(&mut self, did_id: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        let did_result = get_did(self.config.target.clone(), did_id.replace(EVAN_METHOD_PREFIX, "")).await;
        Ok(VadePluginResultValue::Success(did_result.unwrap()))
    }
}
