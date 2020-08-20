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

use crate::{
    compose_extrinsic,
    signing::Signer,
    utils::extrinsic::{
        events::{DispatchError, EventsDecoder, Phase, RawEvent, RuntimeEvent, SystemEvent},
        frame_metadata::RuntimeMetadataPrefixed,
        node_metadata::Metadata,
        rpc::{
            client::{
                on_extrinsic_msg_until_broadcast,
                on_extrinsic_msg_until_finalized,
                on_extrinsic_msg_until_in_block,
                on_extrinsic_msg_until_ready,
                on_subscription_msg,
            },
            start_rpc_client_thread,
            XtStatus,
        },
        xt_primitives,
    },
};
use futures::{
    channel::mpsc::{channel, Receiver, Sender},
    stream::StreamExt,
};
use parity_scale_codec::{Decode, Encode, Error as CodecError};
use rand::Rng;
use secp256k1::{Message, RecoveryId, Signature};
use serde_json::{json, Value};
use sha2::Digest;
use sha3::Keccak256;
use sp_std::prelude::*;
use std::{
    convert::{TryFrom, TryInto},
    env,
    error::Error,
    hash::Hasher,
    time::{Duration, Instant},
};

#[cfg(not(target_arch = "wasm32"))]
use chrono::Utc;

const SUBSTRATE_TIMEOUT: u64 = 60;

pub async fn get_storage_value(
    url: &str,
    storage_prefix: &str,
    storage_key_name: &str,
) -> Result<String, Box<dyn Error>> {
    let mut bytes = twox_128(&storage_prefix.as_bytes()).to_vec();
    bytes.extend(&twox_128(&storage_key_name.as_bytes())[..]);
    let hex_string = format!("0x{}", hex::encode(bytes));
    let json = json_req("state_getStorage", &hex_string.to_string(), 1);
    let client = reqwest::Client::new();
    let body = client
        .post(&format!("http://{}:9933", url).to_string())
        .header("Content-Type", "application/json")
        .body(json.to_string())
        .send()
        .await?
        .text()
        .await?;
    let parsed: Value = serde_json::from_str(&body)?;
    print!("{}", &body);
    Ok(parsed["result"]
        .as_str()
        .ok_or("could not get storage value")?
        .to_string())
}

pub async fn get_storage_map<K: Encode + std::fmt::Debug, V: Decode + Clone>(
    url: &str,
    metadata: Metadata,
    storage_prefix: &'static str,
    storage_key_name: &'static str,
    map_key: K,
) -> Result<Option<V>, Box<dyn Error>> {
    let storagekey: sp_core::storage::StorageKey = metadata
        .module(storage_prefix)?
        .storage(storage_key_name)?
        .get_map::<K, V>()?
        .key(map_key);
    let hex_string = format!("0x{}", hex::encode(storagekey.0.clone()));
    let json = json_req("state_getStorage", &hex_string.to_string(), 1);
    let client = reqwest::Client::new();
    let body = client
        .post(&format!("http://{}:9933", url).to_string())
        .header("Content-Type", "application/json")
        .body(json.to_string())
        .send()
        .await?
        .text()
        .await?;
    let parsed: Value = serde_json::from_str(&body)?;
    let result = match parsed["result"].as_str() {
        None => None,
        _ => Some(hex::decode(
            &parsed["result"]
                .as_str()
                .ok_or("could not parse storage map result")?
                .trim_start_matches("0x"),
        )?),
    };

    if let Some(v) = result {
        match Decode::decode(&mut v.as_slice()) {
            Ok(ok) => {
                return Ok(Some(ok));
            }
            Err(err) => {
                return Err(Box::from(err));
            }
        }
    }
    Ok(None)
}

pub async fn get_metadata(url: &str) -> Result<Metadata, Box<dyn Error>> {
    let json = json!({
        "method": "state_getMetadata",
        "params": null,
        "jsonrpc": "2.0",
        "id": "1",
    });
    let client = reqwest::Client::new();
    let body = client
        .post(&format!("http://{}:9933", url).to_string())
        .header("Content-Type", "application/json")
        .body(json.to_string())
        .send()
        .await?
        .text()
        .await?;
    let parsed: Value = serde_json::from_str(&body)?;
    let hex_value = parsed["result"]
        .as_str()
        .ok_or("could parse metadata result")?
        .to_string();
    let _unhex = hexstr_to_vec(hex_value)?;
    let mut _om = _unhex.as_slice();
    let meta = RuntimeMetadataPrefixed::decode(&mut _om)?;
    let metadata2 = Metadata::parse(meta)?;
    Ok(metadata2)
}

pub async fn send_extrinsic(
    url: &str,
    xthex_prefixed: String,
    exit_on: XtStatus,
) -> Result<Option<String>, Box<dyn Error>> {
    let json = json!({
        "method": "author_submitAndWatchExtrinsic",
        "params": [xthex_prefixed],
        "jsonrpc": "2.0",
        "id": "4",
    });

    let (sender, mut receiver) = channel::<String>(100);
    match exit_on {
        XtStatus::Finalized => {
            start_rpc_client_thread(
                format!("ws://{}:9944", url),
                json.to_string(),
                sender,
                on_extrinsic_msg_until_finalized,
            );
            if let Some(data) = receiver.next().await {
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        XtStatus::InBlock => {
            let metadata = get_metadata(url).await?;
            start_rpc_client_thread(
                format!("ws://{}:9944", url),
                json.to_string(),
                sender,
                on_extrinsic_msg_until_in_block,
            );
            let (sender_status, receiver_status) = channel::<String>(100);
            subscribe_events(url, sender_status).await;
            if let Some(data) = receiver.next().await {
                let json = json_req("chain_getBlock", data.as_str(), 1);
                let client = reqwest::Client::new();
                let body = client
                    .post(&format!("http://{}:9933", url).to_string())
                    .header("Content-Type", "application/json")
                    .body(json.to_string())
                    .send()
                    .await?
                    .text()
                    .await?;

                trace!("response for extrinsic: {}", &body);
                let parsed: Value = serde_json::from_str(&body)?;
                let extrinsics = &parsed["result"]["block"]["extrinsics"]
                    .as_array()
                    .ok_or("could not parse block result")?
                    .iter()
                    .position(|ext| match ext.as_str() {
                        Some(value) => value == xthex_prefixed,
                        None => false,
                    })
                    .ok_or_else(|| {
                        let msg =
                            format!("Failed to find Extrinsic with hash {:?}", xthex_prefixed);
                        info!("{}", &msg);
                        msg
                    })?;

                let ext_status = wait_for_extrinsic_status(
                    metadata.clone(),
                    &data,
                    *extrinsics,
                    None,
                    receiver_status,
                )
                .await
                .ok_or("could not get extrinsic status")?;
                match ext_status {
                    SystemEvent::ExtrinsicFailed(
                        DispatchError::Module {
                            index,
                            error,
                            message: _,
                        },
                        _,
                    ) => {
                        let clear_error = metadata.module_with_errors(index)?;
                        return Err(Box::from(clear_error.event(error)?.name.to_string()));
                    }
                    SystemEvent::ExtrinsicFailed(_, _) => return Err(Box::from("other error")),
                    SystemEvent::ExtrinsicSuccess(_info) => {
                        return Ok(Some(data));
                    }
                }
            }
            Err(Box::from("other error"))
        }
        XtStatus::Broadcast => {
            start_rpc_client_thread(
                format!("ws://{}:9944", url),
                json.to_string(),
                sender,
                on_extrinsic_msg_until_broadcast,
            );
            if let Some(data) = receiver.next().await {
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        XtStatus::Ready => {
            start_rpc_client_thread(
                format!("ws://{}:9944", url),
                json.to_string(),
                sender,
                on_extrinsic_msg_until_ready,
            );
            if let Some(data) = receiver.next().await {
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        _ => panic!("can only wait for finalized, in block, broadcast and ready extrinsic status"),
    }
}

pub async fn subscribe_events(url: &str, sender: Sender<String>) {
    let mut bytes = twox_128(b"System").to_vec();
    bytes.extend(&twox_128(b"Events")[..]);
    let key = format!("0x{}", hex::encode(bytes));
    let jsonreq = json!({
        "method": "state_subscribeStorage",
        "params": [[key]],
        "jsonrpc": "2.0",
        "id": "1",
    });
    start_rpc_client_thread(
        format!("ws://{}:9944", url),
        jsonreq.to_string(),
        sender,
        on_subscription_msg,
    );
}

pub async fn wait_for_event<E: Decode>(
    metadata: Metadata,
    module: &str,
    variant: &str,
    decoder: Option<EventsDecoder>,
    receiver: Receiver<String>,
    on_event_check: impl Fn(&RawEvent) -> bool,
) -> Option<Result<E, CodecError>> {
    wait_for_raw_event(metadata, module, variant, decoder, receiver, on_event_check)
        .await
        .map(|raw| E::decode(&mut &raw.data[..]))
}

pub async fn wait_for_raw_event(
    metadata: Metadata,
    module: &str,
    variant: &str,
    decoder: Option<EventsDecoder>,
    mut receiver: Receiver<String>,
    on_event_check: impl Fn(&RawEvent) -> bool,
) -> Option<RawEvent> {
    let event_decoder = match decoder {
        Some(decoder) => decoder,
        None => match EventsDecoder::try_from(metadata.clone()) {
            Ok(decoder) => decoder,
            Err(err) => {
                error!("could not get decoder; {}", &err);
                return None;
            }
        },
    };
    let start = Instant::now();
    loop {
        // check if timeout reached
        let duration: Duration = start.elapsed();
        if duration.as_secs() > SUBSTRATE_TIMEOUT {
            error!(
                "substrate timeout for module '{}', variant '{}', after; {}s",
                &module, &variant, SUBSTRATE_TIMEOUT
            );
            return None;
        }

        if let Some(data) = receiver.next().await {
            let value: Value = match serde_json::from_str(&data) {
                Ok(result) => result,
                Err(err) => {
                    error!("could not parse received data; {}", &err);
                    return None;
                }
            };
            let changes = &value["changes"];
            let event_str = match changes[0][1].as_str() {
                Some(change_set) => Some(change_set),
                None => {
                    debug!("No events happened");
                    None
                }
            };
            let unhex = match hexstr_to_vec(event_str?.to_string()) {
                Ok(result) => result,
                Err(err) => {
                    error!("could not parse hex string; {}", &err);
                    return None;
                }
            };
            let mut er_enc = unhex.as_slice();

            let _events = event_decoder.decode_events(&mut er_enc);
            match _events {
                Ok(raw_events) => {
                    for (_phase, event) in raw_events.into_iter() {
                        match event {
                            RuntimeEvent::Raw(raw)
                                if raw.module == module && raw.variant == variant =>
                            {
                                match on_event_check(&raw) {
                                    true => return Some(raw),
                                    _ => debug!("on_event_check not match for event: {:?}", raw),
                                }
                            }
                            _ => {
                                debug!("ignoring unsupported module event: {:?}", event);
                            }
                        }
                    }
                }
                Err(_) => error!("couldn't decode event record list"),
            }
        }
    }
}

pub async fn wait_for_extrinsic_status(
    metadata: Metadata,
    block: &str,
    index: usize,
    decoder: Option<EventsDecoder>,
    mut receiver: Receiver<String>,
) -> Option<SystemEvent> {
    let event_decoder = match decoder {
        Some(decoder) => decoder,
        None => match EventsDecoder::try_from(metadata.clone()) {
            Ok(decoder) => decoder,
            Err(err) => {
                error!("could not get decoder; {}", &err);
                return None;
            }
        },
    };
    let start = Instant::now();
    loop {
        // check if timeout reached
        let duration: Duration = start.elapsed();
        if duration.as_secs() > SUBSTRATE_TIMEOUT {
            error!(
                "substrate timeout while waiting for extrinsic status, after; {}s",
                SUBSTRATE_TIMEOUT
            );
            return None;
        }
        if let Some(data) = receiver.next().await {
            let value: Value = match serde_json::from_str(&data) {
                Ok(result) => result,
                Err(err) => {
                    error!("json parsing error; {}", &err);
                    return None;
                }
            };
            let changes = &value["changes"];
            let event_str = match changes[0][1].as_str() {
                Some(change_set) => Some(change_set),
                None => {
                    debug!("No events happened");
                    None
                }
            };
            let _unhex = match hexstr_to_vec(event_str?.to_string()) {
                Ok(result) => result,
                Err(err) => {
                    error!("hexstr_to_vec error; {}", &err);
                    return None;
                }
            };
            let mut _er_enc = _unhex.as_slice();
            let _events = event_decoder.decode_events(&mut _er_enc);
            match _events {
                Ok(raw_events) => {
                    for (phase, event) in raw_events.into_iter() {
                        debug!("Decoded Event: {:?}, {:?}", phase, event);
                        if let Phase::ApplyExtrinsic(i) = phase {
                            if i as usize == index && value["block"].as_str()? == block {
                                match event {
                                    RuntimeEvent::System(raw) => {
                                        return Some(raw);
                                    }
                                    _ => {
                                        debug!("ignoring unsupported module event: {:?}", event);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(err) => error!("couldn't decode event record list; {}", &err),
            }
        }
    }
}

#[derive(Decode)]
struct IdentityWhitelist {
    identity: Vec<u8>,
    _account: Vec<u8>,
    approved: bool,
    nonce: u64,
}

#[derive(Decode)]
struct Created {
    hash: Vec<u8>,
    _owner: Vec<u8>,
    nonce: u64,
}

#[derive(Decode)]
struct UpdatedDid {
    hash: Vec<u8>,
    _index: u32,
    nonce: u64,
}

/// Anchors a new DID on the chain.
///
/// # Arguments
/// * `url` - Substrate URL
/// * `private_key` - Private key used to sign a message
/// * `signer` - `Signer` to sign with
/// * `identity` - Identity requesting the DID
/// * `payload` - optional payload to set as DID document
///
/// # Returns
/// * `String` - The anchored DID
pub async fn create_did(
    url: String,
    private_key: String,
    signer: &Box<dyn Signer>,
    identity: Vec<u8>,
    payload: Option<&str>,
) -> Result<String, Box<dyn Error>> {
    let metadata = get_metadata(url.as_str()).await?;
    let nonce: u64 = get_nonce();
    error!("timestamp_nanos: {}", &nonce);
    let (signature, signed_message) = signer
        .sign_message(&nonce.to_string(), &private_key.to_string())
        .await?;
    let (sender, receiver) = channel::<String>(100);
    subscribe_events(url.as_str(), sender).await;
    let xt: String = match payload {
        Some(payload) => {
            let payload_hex = hex::decode(hex::encode(payload))?;
            compose_extrinsic!(
                metadata.clone(),
                "DidModule",
                "create_did_with_detail",
                payload_hex,
                signature.to_vec(),
                signed_message.to_vec(),
                identity.to_vec(),
                nonce
            )
            .hex_encode()
        }
        None => compose_extrinsic!(
            metadata.clone(),
            "DidModule",
            "create_did",
            signature.to_vec(),
            signed_message.to_vec(),
            identity.to_vec(),
            nonce
        )
        .hex_encode(),
    };
    let ext_error = send_extrinsic(url.as_str(), xt, XtStatus::InBlock)
        .await
        .map_err(|_e| {
            format!(
                "Error creating DID with identity: {:?} and error; {}",
                hex::encode(identity.clone()),
                _e
            )
        });
    if let Err(e) = ext_error {
        return Err(Box::from(e));
    }
    let event_watch = move |raw: &RawEvent| -> bool {
        let decoded_event: Created = match Decode::decode(&mut &raw.data[..]) {
            Ok(result) => result,
            Err(err) => {
                error!("could not decode event data; {}", &err);
                return false;
            }
        };
        if nonce == decoded_event.nonce {
            return true;
        }
        false
    };
    let event_wait: Created = wait_for_event(
        metadata.clone(),
        "DidModule",
        "Created",
        None,
        receiver,
        event_watch,
    )
    .await
    .ok_or("could not create did")??;
    Ok(format!("0x{}", hex::encode(event_wait.hash)))
}

/// Retrieve the content saved at a DID reference.
///
/// # Arguments
/// * `url` - Substrate URL
/// * `did` - DID to resolve
///
/// # Returns
/// * `String` - Content saved behind the DID
pub async fn get_did(url: String, did: String) -> Result<String, Box<dyn Error>> {
    let bytes_did_arr = get_did_bytes_array(&did)?;
    let bytes_did = sp_core::H256::from(bytes_did_arr);
    let metadata = get_metadata(url.as_str()).await?;
    let detail_hash = get_storage_map::<(sp_core::H256, u32), Vec<u8>>(
        url.as_str(),
        metadata.clone(),
        "DidModule",
        "DidsDetails",
        (bytes_did, 0),
    )
    .await?
    .ok_or("DID not found")?;
    let did_url = format!(
        "http://{}:{}/ipfs/{}",
        url,
        env::var("VADE_EVAN_IPFS_PORT").unwrap_or_else(|_| "8081".to_string()),
        std::str::from_utf8(&detail_hash)?
    )
    .to_string();
    trace!("fetching DID document at: {}", &did_url);
    let body = reqwest::get(&did_url).await?.text().await?;
    Ok(body)
}

/// Add a new payload under a DID
///
/// # Arguments
/// * `url` - Substrate URL
/// * `payload` - Payload to save
/// * `did` - DID to save payload under
/// * `private_key` - key reference to sign with
/// * `signer` - `Signer` to sign with
/// * `identity` - Identity of the caller
pub async fn add_payload_to_did(
    url: String,
    payload: String,
    did: String,
    private_key: String,
    signer: &Box<dyn Signer>,
    identity: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let metadata = get_metadata(url.as_str()).await?;
    let did = did.trim_start_matches("0x").to_string();
    let bytes_did_arr = get_did_bytes_array(&did)?;
    let bytes_did = sp_core::H256::from(bytes_did_arr);
    let bytes_did_string = hex::encode(&bytes_did);
    let nonce: u64 = get_nonce();
    error!("timestamp_nanos: {}", &nonce);
    let (signature, signed_message) = signer
        .sign_message(&nonce.to_string(), &private_key.to_string())
        .await?;
    let payload_hex = hex::decode(hex::encode(payload.clone()))?;

    let (sender, receiver) = channel::<String>(100);
    subscribe_events(url.as_str(), sender).await;

    let xt: xt_primitives::UncheckedExtrinsicV4<_> = compose_extrinsic!(
        metadata.clone(),
        "DidModule",
        "add_did_detail",
        bytes_did.clone().to_fixed_bytes(),
        payload_hex,
        signature.to_vec(),
        signed_message.to_vec(),
        identity.to_vec(),
        nonce
    );
    let ext_error = send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::InBlock )
        .await
        .map_err(|_e| format!("Error adding payload to DID: {:?} with payload: {:?} and identity: {:?} and error; {}", did.clone(), payload.clone(), hex::encode(identity.clone()), _e));
    if let Err(e) = ext_error {
        return Err(Box::from(e));
    }

    fn event_watch(substrate_did: &String, nonce: u64) -> impl Fn(&RawEvent) -> bool + '_ {
        move |raw: &RawEvent| -> bool {
            let decoded_event: UpdatedDid = match Decode::decode(&mut &raw.data[..]) {
                Ok(result) => result,
                Err(err) => {
                    error!("could not event data; {}", &err);
                    return false;
                }
            };
            if decoded_event.nonce == nonce && &hex::encode(decoded_event.hash) == substrate_did {
                return true;
            }
            false
        }
    }
    let _event_result: UpdatedDid = wait_for_event(
        metadata.clone(),
        "DidModule",
        "UpdatedDid",
        None,
        receiver,
        event_watch(&bytes_did_string, nonce),
    )
    .await
    .ok_or("could not get event for updated did")??;
    Ok(())
}

/// Updates the object at the index in the payload array at this DID
///
/// # Arguments
/// * `url` - Substrate URL
/// * `index` - Index of the payload to update
/// * `payload` - Payload to save
/// * `did` - DID to save payload under
/// * `private_key` - Private key used to sign a message
/// * `signer` - `Signer` to sign with
/// * `identity` - Identity of the caller
pub async fn update_payload_in_did(
    url: String,
    index: u32,
    payload: String,
    did: String,
    private_key: String,
    signer: &Box<dyn Signer>,
    identity: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let metadata = get_metadata(url.as_str()).await?;
    let bytes_did_arr = get_did_bytes_array(&did)?;
    let bytes_did = sp_core::H256::from(bytes_did_arr);
    let nonce: u64 = get_nonce();
    error!("timestamp_nanos: {}", &nonce);
    let (signature, signed_message) = signer
        .sign_message(&nonce.to_string(), &private_key.to_string())
        .await?;
    let payload_hex = hex::decode(hex::encode(payload.clone()))?;

    let (sender, receiver) = channel::<String>(100);
    subscribe_events(url.as_str(), sender).await;

    let xt: xt_primitives::UncheckedExtrinsicV4<_> = compose_extrinsic!(
        metadata.clone(),
        "DidModule",
        "update_did_detail",
        bytes_did.clone().to_fixed_bytes(),
        payload_hex,
        index,
        signature.to_vec(),
        signed_message.to_vec(),
        identity.clone(),
        nonce
    );
    let ext_error = send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::InBlock)
        .await
        .map_err(|_e| format!("Error updating payload in DID: {:?} on index: {} with payload: {:?} and identity: {:?} and error; {}",did.clone(), index.clone(), payload.clone(), hex::encode(identity.clone()), _e));
    if let Err(e) = ext_error {
        return Err(Box::from(e));
    }

    fn event_watch(did: &String, nonce: u64) -> impl Fn(&RawEvent) -> bool + '_ {
        move |raw: &RawEvent| -> bool {
            let decoded_event: UpdatedDid = match Decode::decode(&mut &raw.data[..]) {
                Ok(result) => result,
                Err(err) => {
                    error!("could not decode event data; {}", &err);
                    return false;
                }
            };
            if decoded_event.nonce == nonce && &hex::encode(decoded_event.hash) == did {
                return true;
            }
            false
        }
    }

    let _event_result: UpdatedDid = wait_for_event(
        metadata.clone(),
        "DidModule",
        "UpdatedDid",
        None,
        receiver,
        event_watch(&hex::encode(bytes_did_arr), nonce),
    )
    .await
    .ok_or("could not could not get updated did event")??;
    Ok(())
}

/// Whitelists an identity to send transactions to the substrate chain.
///
/// # Arguments
/// * `url` - Substrate URL
/// * `private_key` - Private key used to sign a message
/// * `signer` - `Signer` to sign with
/// * `identity` - Identity of the caller
pub async fn whitelist_identity(
    url: String,
    private_key: String,
    signer: &Box<dyn Signer>,
    method: u8,
    identity: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let metadata = get_metadata(url.as_str()).await?;
    let nonce: u64 = get_nonce();
    error!("timestamp_nanos: {}", &nonce);
    let (signature, signed_message) = signer
        .sign_message(&nonce.to_string(), &private_key.to_string())
        .await?;

    let (sender, receiver) = channel::<String>(100);
    subscribe_events(url.as_str(), sender).await;

    let xt: xt_primitives::UncheckedExtrinsicV4<_> = compose_extrinsic!(
        metadata.clone(),
        "DidModule",
        "whitelist_identity",
        method,
        signature.to_vec(),
        signed_message.to_vec(),
        identity.clone(),
        nonce
    );
    let ext_error = send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::InBlock)
        .await
        .map_err(|_e| {
            format!(
                "Error whitelisting identity: {:?} with error; {}",
                hex::encode(identity.clone()),
                _e
            )
        });
    if let Err(e) = ext_error {
        return Err(Box::from(e));
    }
    fn event_watch(identity: &Vec<u8>, nonce: u64) -> impl Fn(&RawEvent) -> bool + '_ {
        move |raw: &RawEvent| -> bool {
            let decoded_event: IdentityWhitelist = match Decode::decode(&mut &raw.data[..]) {
                Ok(result) => result,
                Err(err) => {
                    error!("could not decode event data; {}", &err);
                    return false;
                }
            };
            if decoded_event.nonce == nonce && &decoded_event.identity == identity {
                return true;
            }
            false
        }
    }
    let event_result: IdentityWhitelist = wait_for_event(
        metadata.clone(),
        "DidModule",
        "IdentityWhitelist",
        None,
        receiver,
        event_watch(&identity, nonce),
    )
    .await
    .ok_or("could not get whitelist identity event")??;
    if event_result.approved {
        Ok(())
    } else {
        Err(Box::from(format!(
            "Error whitelisting identity: {:?}",
            hex::encode(identity.clone())
        )))
    }
}

/// Retrieves the number of payloads attached to a DID.
///
/// # Arguments
/// * `url` - Substrate URL
/// * `did` - DID to retrieve the count for
pub async fn get_payload_count_for_did(url: String, did: String) -> Result<u32, Box<dyn Error>> {
    let metadata = get_metadata(url.as_str()).await?;
    let bytes_did_arr = get_did_bytes_array(&did)?;
    let bytes_did = sp_core::H256::from(bytes_did_arr);
    let detail_count = get_storage_map::<sp_core::H256, u32>(
        url.as_str(),
        metadata.clone(),
        "DidModule",
        "DidsDetailsCount",
        bytes_did,
    )
    .await?;
    if detail_count.is_none() {
        Ok(0)
    } else {
        detail_count.ok_or_else(|| Box::from("could not get detail count"))
    }
}

/// Checks whether a given identity for a given account is whitelisted
pub async fn is_whitelisted(
    url: String,
    private_key: String,
    signer: &Box<dyn Signer>,
    identity: Vec<u8>,
) -> Result<bool, Box<dyn Error>> {
    let metadata = get_metadata(url.as_str()).await?;
    let nonce: u64 = get_nonce();
    error!("timestamp_nanos: {}", &nonce);

    // Sign a message to use for retrieving the account ID
    let (signature, signed_message) = signer
        .sign_message(&nonce.to_string(), &private_key.to_string())
        .await?;

    let account = recover_ethereum_account(signature, signed_message)
        .map_err(|err| format!("Error recovering etherum account: {}", err))?;

    // Access whitelist using account and identity
    let mut hasher = Keccak256::new();
    hasher.input(&account);
    let acc_hash = hasher.result();

    hasher = Keccak256::new();
    hasher.input(&identity[..identity.len()]);
    let identity_hash = hasher.result();

    let is_whitelisted = get_storage_map::<(Vec<u8>, Vec<u8>), bool>(
        url.as_str(),
        metadata.clone(),
        "DidModule",
        "WhitelistedIdentities",
        (identity_hash.to_vec(), acc_hash.to_vec()),
    )
    .await?
    .unwrap_or_else(|| false);

    Ok(is_whitelisted)
}

/// Do a XX 256-bit hash and place result in `dest`.
pub fn twox_256(data: &[u8]) -> [u8; 32] {
    let mut r: [u8; 32] = [0; 32];
    let mut h0 = twox_hash::XxHash::with_seed(0);
    let mut h1 = twox_hash::XxHash::with_seed(1);
    let mut h2 = twox_hash::XxHash::with_seed(2);
    let mut h3 = twox_hash::XxHash::with_seed(3);
    h0.write(data);
    h1.write(data);
    h2.write(data);
    h3.write(data);
    let r0 = h0.finish();
    let r1 = h1.finish();
    let r2 = h2.finish();
    let r3 = h3.finish();
    use byteorder::{ByteOrder, LittleEndian};
    LittleEndian::write_u64(&mut r[0..8], r0);
    LittleEndian::write_u64(&mut r[8..16], r1);
    LittleEndian::write_u64(&mut r[16..24], r2);
    LittleEndian::write_u64(&mut r[24..32], r3);
    r
}

/// Do a XX 128-bit hash and place result in `dest`.
pub fn twox_128(data: &[u8]) -> [u8; 16] {
    let mut r: [u8; 16] = [0; 16];
    let mut h0 = twox_hash::XxHash::with_seed(0);
    let mut h1 = twox_hash::XxHash::with_seed(1);
    h0.write(data);
    h1.write(data);
    let r0 = h0.finish();
    let r1 = h1.finish();
    use byteorder::{ByteOrder, LittleEndian};
    LittleEndian::write_u64(&mut r[0..8], r0);
    LittleEndian::write_u64(&mut r[8..16], r1);
    r
}

/// Do a XX 164-bit hash and place result in `dest`.
pub fn twox_64(data: &[u8]) -> [u8; 8] {
    let mut r: [u8; 8] = [0; 8];
    let mut h0 = twox_hash::XxHash::with_seed(0);
    h0.write(data);
    let r0 = h0.finish();
    use byteorder::{ByteOrder, LittleEndian};
    LittleEndian::write_u64(&mut r[0..8], r0);
    r
}

/// Do a Blake2 128-bit hash and return result.
pub fn blake2_128(data: &[u8]) -> [u8; 16] {
    let mut r = [0; 16];
    r.copy_from_slice(blake2_rfc::blake2b::blake2b(16, &[], data).as_bytes());
    r
}

/// Do a Blake2 256-bit hash and return result.
pub fn blake2_256(data: &[u8]) -> [u8; 32] {
    let mut r = [0; 32];
    r.copy_from_slice(blake2_rfc::blake2b::blake2b(32, &[], data).as_bytes());
    r
}

pub fn hexstr_to_vec(hexstr: String) -> Result<Vec<u8>, hex::FromHexError> {
    let hexstr = hexstr
        .trim_matches('\"')
        .to_string()
        .trim_start_matches("0x")
        .to_string();
    match hexstr.as_str() {
        "null" => Ok([0u8].to_vec()),
        _ => hex::decode(&hexstr),
    }
}

fn get_did_bytes_array(did: &String) -> Result<[u8; 32], Box<dyn Error>> {
    let did_string = did.trim_start_matches("0x");
    let mut bytes_did_arr;
    if did_string.len() == 64 {
        trace!("DID {} has length of 32B will use it as is", &did);
        bytes_did_arr = [0; 32];
        bytes_did_arr.copy_from_slice(&hex::decode(did_string)?[0..32]);
    } else {
        trace!("DID {} has length of {}B will hash it", &did, did.len());
        // create hash of data (including header)
        let mut hasher = Keccak256::new();
        hasher.input(hex::decode(&did_string)?);
        let hash = hasher.result();
        trace!("hashed DID: {:?}", &hash);
        bytes_did_arr = hash.try_into().map_err(|_| "slice with incorrect length")?;
    }

    Ok(bytes_did_arr)
}

fn json_req(method: &str, params: &str, id: u32) -> Value {
    json!({
        "method": method,
        "params": [params],
        "jsonrpc": "2.0",
        "id": id.to_string(),
    })
}

fn recover_ethereum_account(
    full_signature: [u8; 65],
    signed_message: [u8; 32],
) -> Result<[u8; 20], Box<dyn Error>> {
    // recover the account out of the signed message, otherwise throw error and fail the execution
    let mut signature: [u8; 64] = [0; 64];
    signature.copy_from_slice(&full_signature[0..64]);

    let signature_normalized = if full_signature[64] < 27 {
        full_signature[64]
    } else {
        full_signature[64] - 27
    };
    let recovery_id = RecoveryId::parse(signature_normalized)
        .map_err(|err| format!("could not parse recovery ID: {}", &err))?;

    let sig_mess = Message::parse(&signed_message);
    let sig = Signature::parse(&signature);
    let recovered_pub_key = secp256k1::recover(&sig_mess, &sig, &recovery_id)?;

    // create keccack hash of the recovered public key
    let mut hasher = Keccak256::new();
    hasher.input(&recovered_pub_key.serialize()[1..65]);
    let hash = hasher.result();

    // create the ethereum account id out of the last 20 bytes of the hash
    let mut account_id: [u8; 20] = [0; 20];
    account_id.copy_from_slice(&hash[12..32]);

    Ok(account_id)
}

fn get_nonce() -> u64 {
    let mut rng = rand::thread_rng();
    #[cfg(target_arch = "wasm32")]
    let now_timestamp = js_sys::Date::new_0().get_time() as u64;
    #[cfg(not(target_arch = "wasm32"))]
    let now_timestamp: u64 = Utc::now().timestamp_nanos() as u64;

    rng.gen_range(0, 100) + now_timestamp
}
