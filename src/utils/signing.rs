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

use async_trait::async_trait;
use reqwest;
use serde::{Deserialize, Serialize};

const KEY_TYPE: &str = "identityKey";

/// Expected result from signing endpoint.
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum RemoteSigningResult {
    #[serde(rename_all = "camelCase")]
    Ok {
        message_hash: String,
        signature: String,
        signer_address: String,
    },
    #[serde(rename_all = "camelCase")]
    Err {
        error: String,
    },
}

/// Arguments for signing endpoint.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct RemoteSigningArguments {
    pub key: String,
    pub r#type: String,
    pub message: String,
}


#[async_trait(?Send)]
pub trait Signer {
    async fn sign_message(
        &self,
        message_to_sign: &str,
        signing_key: &str,
    ) ->  Result<([u8; 65], [u8; 32]), Box<dyn std::error::Error>>;
}

pub struct RemoteSigner {
    signing_endpoint: String,
}

impl RemoteSigner {
    pub fn new(signing_endpoint: String) -> Self {
        Self { signing_endpoint }
    }
}


#[async_trait(?Send)]
impl Signer for RemoteSigner {
    /// Signs a message by using a remote endpoint
    ///
    /// # Arguments
    /// * `message_to_sign` - String to sign
    /// * `signing_key` - key reference to sign with
    /// * `signing_url` - endpoint that signs given message
    ///
    /// # Returns
    /// `[u8; 65]` - Signature
    /// `[u8; 32]` - Hashed Message
    async fn sign_message(
        &self,
        message_to_sign: &str,
        signing_key: &str,
    ) ->  Result<([u8; 65], [u8; 32]), Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let body = RemoteSigningArguments {
            key: signing_key.to_string(),
            r#type: KEY_TYPE.to_string(),
            message: message_to_sign.to_string(),
        };
        let parsed = client
            .post(&self.signing_endpoint)
            .json(&body)
            .send()
            .await?
            .json::<RemoteSigningResult>()
            .await?;
    
        match parsed {
            RemoteSigningResult::Ok { message_hash, signature, signer_address: _ } => {
                // parse into signature and hash
                let mut signature_arr = [0u8; 65];
                hex::decode_to_slice(
                    signature.trim_start_matches("0x"),
                    &mut signature_arr,
                ).map_err(|_| "signature invalid")?;
                let mut hash_arr = [0u8; 32];
                hex::decode_to_slice(
                    message_hash.trim_start_matches("0x"),
                    &mut hash_arr,
                ).map_err(|_| "hash invalid")?;
    
                Ok((signature_arr, hash_arr))
            },
            RemoteSigningResult::Err { error }=> {
                Err(Box::from(format!("could not sign message with remote endpoint; {}", &error)))
            },
        }
    }
}
