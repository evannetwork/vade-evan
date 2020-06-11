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
use vade::traits::{ DidResolver, MessageConsumer };
use crate::utils::substrate::{
    get_did,
    create_did,
    add_payload_to_did,
    get_payload_count_for_did,
    update_payload_in_did,
    whitelist_identity
};
use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetDidDocumentArguments {
  pub did: String,
  pub payload: String,
  pub private_key: String,
  pub identity: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityArguments {
  pub private_key: String,
  pub identity: String,
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
        SubstrateDidResolverEvan {
          config
        }
    }

    async fn generate_did(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: IdentityArguments = serde_json::from_str(&data)?;
        Ok(Some(create_did(self.config.target.clone(), input.private_key.clone(), hex::decode(input.identity).unwrap()).await.unwrap()))
    }

    async fn whitelist_identity(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: IdentityArguments = serde_json::from_str(&data)?;
        Ok(Some(whitelist_identity(self.config.target.clone(), input.private_key.clone(), hex::decode(input.identity).unwrap()).await.unwrap()))
    }

    async fn set_did_document_message(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: SetDidDocumentArguments = serde_json::from_str(&data)?;
        let payload_count: u32 = get_payload_count_for_did(self.config.target.clone(), input.did.to_string()).await.unwrap();
        if payload_count > 0 {
            update_payload_in_did(self.config.target.clone(), 0 as u32, input.payload.to_string(), input.did.to_string(), input.private_key.to_string(), hex::decode(input.identity).unwrap()).await.unwrap();
        } else {
            add_payload_to_did(self.config.target.clone(), input.payload.to_string(), input.did.to_string(), input.private_key.to_string(), hex::decode(input.identity).unwrap()).await.unwrap();
        }
        Ok(Some("".to_string()))
    }
}

#[async_trait(?Send)]
impl DidResolver for SubstrateDidResolverEvan {
    /// Checks given DID document.
    /// A DID document is considered as valid if returning ().
    /// Resolver may throw to indicate
    /// - that it is not responsible for this DID
    /// - that it considers this DID as invalid
    ///
    /// Currently the test `did_name` `"test"` is accepted as valid.
    ///
    /// # Arguments
    ///
    /// * `did_name` - did_name to check document for
    /// * `value` - value to check
    async fn check_did(&self, _did_name: &str, _value: &str) -> Result<(), Box<dyn std::error::Error>> {
        unimplemented!();
    }

    /// Gets document for given did name.
    ///
    /// # Arguments
    ///
    /// * `did_id` - did id to fetch
    async fn get_did_document(&self, did_id: &str) -> Result<String, Box<dyn std::error::Error>> {
        let didresult = get_did(self.config.target.clone(), did_id.to_string()).await;
        Ok(didresult.unwrap())
    }

    /// Sets document for given did name.
    ///
    /// # Arguments
    ///
    /// * `did_name` - did_name to set value for
    /// * `value` - value to set
    async fn set_did_document(&mut self, _did_id: &str, _value: &str) -> std::result::Result<(), Box<dyn std::error::Error>> {
        unimplemented!();
    }
}

#[async_trait(?Send)]
impl MessageConsumer for SubstrateDidResolverEvan {
    /// Reacts to `Vade` messages.
    ///
    /// # Arguments
    ///
    /// * `message_data` - arbitrary data for plugin, e.g. a JSON
    async fn handle_message(
        &mut self,
        message_type: &str,
        message_data: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        match message_type {
            "generateDid" => self.generate_did(message_data).await,
            "whitelistIdentity" => self.whitelist_identity(message_data).await,
            "setDidDocument" => self.set_did_document_message(message_data).await,
            _ => Err(Box::from(format!("message type '{}' not implemented", message_type)))
        }
    }
}
