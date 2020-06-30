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

use crate::utils::extrinsic::rpc::{
    client::{
        on_extrinsic_msg_until_broadcast,
        on_extrinsic_msg_until_finalized,
        on_extrinsic_msg_until_in_block,
        on_extrinsic_msg_until_ready,
        on_subscription_msg,
    },
    start_rpc_client_thread,
};
use crate::utils::extrinsic::xt_primitives;
use blake2_rfc;
use hex;
use reqwest;
use serde_json::{json, Value};
use std::hash::Hasher;
use twox_hash;

use crate::crypto::crypto_utils::sign_message;

use crate::compose_extrinsic;
use crate::utils::extrinsic::events::{EventsDecoder, RawEvent, RuntimeEvent};
use crate::utils::extrinsic::frame_metadata::RuntimeMetadataPrefixed;
use crate::utils::extrinsic::node_metadata::Metadata;
use crate::utils::extrinsic::rpc_messages::XtStatus;
#[cfg(not(target_arch = "wasm32"))]
use chrono::Utc;
use futures::channel::mpsc::{channel, Receiver, Sender};
use futures::stream::StreamExt;
use parity_scale_codec::{Decode, Encode, Error as CodecError};
use sp_std::prelude::*;
use std::convert::TryFrom;
use wasm_bindgen::prelude::*;

pub async fn get_storage_value(
    url: &str,
    storage_prefix: &str,
    storage_key_name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
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
    let parsed: Value = serde_json::from_str(&body).unwrap();
    print!("{}", &body);
    Ok(parsed["result"].as_str().unwrap().to_string())
}

pub async fn get_storage_map<K: Encode + std::fmt::Debug, V: Decode + Clone>(
    url: &str,
    metadata: Metadata,
    storage_prefix: &'static str,
    storage_key_name: &'static str,
    map_key: K,
) -> Result<Option<V>, Box<dyn std::error::Error>> {
    let storagekey: sp_core::storage::StorageKey = metadata
        .module(storage_prefix)
        .unwrap()
        .storage(storage_key_name)
        .unwrap()
        .get_map::<K, V>()
        .unwrap()
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
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let result = match parsed["result"].as_str() {
        None => None,
        _ => {
            Some(hex::decode(&parsed["result"].as_str().unwrap().trim_start_matches("0x")).unwrap())
        }
    };
    Ok(result.map(|v| Decode::decode(&mut v.as_slice()).unwrap()))
}

pub async fn get_metadata(url: &str) -> Result<Metadata, Box<dyn std::error::Error>> {
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
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let hex_value = parsed["result"].as_str().unwrap().to_string();
    let _unhex = hexstr_to_vec(hex_value).unwrap();
    let mut _om = _unhex.as_slice();
    let meta = RuntimeMetadataPrefixed::decode(&mut _om).unwrap();
    let metadata2 = Metadata::parse(meta).unwrap();
    Ok(metadata2)
}

pub async fn send_extrinsic(
    url: &str,
    xthex_prefixed: String,
    exit_on: XtStatus,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let json = json!({
        "method": "author_submitAndWatchExtrinsic",
        "params": [xthex_prefixed],
        "jsonrpc": "2.0",
        "id": "4",
    });

    let (sender, mut receiver) = channel::<String>(100);
    match exit_on {
        XtStatus::Finalized => {
            info!("start send");
            start_rpc_client_thread(
                format!("ws://{}:9944", url).to_string(),
                json.to_string(),
                sender,
                on_extrinsic_msg_until_finalized,
            );
            info!("finished send");
            if let Some(data) = receiver.next().await {
                info!("finalized transaction: {}", data.clone());
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        XtStatus::InBlock => {
            start_rpc_client_thread(
                format!("ws://{}:9944", url).to_string(),
                json.to_string(),
                sender,
                on_extrinsic_msg_until_in_block,
            );
            if let Some(data) = receiver.next().await {
                info!("inBlock: {}", data.clone());
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        XtStatus::Broadcast => {
            start_rpc_client_thread(
                format!("ws://{}:9944", url).to_string(),
                json.to_string(),
                sender,
                on_extrinsic_msg_until_broadcast,
            );
            if let Some(data) = receiver.next().await {
                info!("broadcast: {}", data.clone());
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        XtStatus::Ready => {
            start_rpc_client_thread(
                format!("ws://{}:9944", url).to_string(),
                json.to_string(),
                sender,
                on_extrinsic_msg_until_ready,
            );
            if let Some(data) = receiver.next().await {
                info!("ready: {}", data.clone());
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        _ => panic!("can only wait for finalized, in block, broadcast and ready extrinsic status"),
    }
}

pub async fn subscribe_events(url: &str, sender: Sender<String>) {
    info!("subscribing to events");
    let mut bytes = twox_128("System".as_bytes()).to_vec();
    bytes.extend(&twox_128("Events".as_bytes())[..]);
    let key = format!("0x{}", hex::encode(bytes));
    let jsonreq = json!({
        "method": "state_subscribeStorage",
        "params": [[key]],
        "jsonrpc": "2.0",
        "id": "1",
    });
    start_rpc_client_thread(
        format!("ws://{}:9944", url).to_string(),
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
    let event_decoder =
        decoder.unwrap_or_else(|| EventsDecoder::try_from(metadata.clone()).unwrap());
    loop {
        if let Some(data) = receiver.next().await {
            let event_str = data;
            let _unhex = hexstr_to_vec(event_str).unwrap();
            let mut _er_enc = _unhex.as_slice();

            let _events = event_decoder.decode_events(&mut _er_enc);
            info!("wait for raw event");
            match _events {
                Ok(raw_events) => {
                    for (phase, event) in raw_events.into_iter() {
                        info!("Decoded Event: {:?}, {:?}", phase, event);

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

#[derive(Decode)]
struct ApprovedIdentity {
    identity: Vec<u8>,
    _account: Vec<u8>,
}

#[derive(Decode)]
struct Created {
    hash: sp_core::H256,
    _owner: Vec<u8>,
    nonce: u64,
}

#[derive(Decode)]
struct UpdatedDid {
    hash: sp_core::H256,
    _index: u32,
}

/// Anchors a new DID on the chain.
///
/// # Arguments
/// * `url` - Substrate URL
/// * `private_key` - Private key used to sign a message
/// * `identity` - Identity requesting the DID
///
/// # Returns
/// * `String` - The anchored DID
pub async fn create_did(
    url: String,
    private_key: String,
    identity: Vec<u8>,
) -> Result<String, JsValue> {
    let metadata = get_metadata(url.as_str()).await.unwrap();
    #[cfg(target_arch = "wasm32")]
    let now_timestamp = js_sys::Date::new_0().get_time() as u64;
    #[cfg(not(target_arch = "wasm32"))]
    let now_timestamp: u64 = Utc::now().timestamp_nanos() as u64;
    let (signature, signed_message) =
        sign_message(&now_timestamp.to_string(), &private_key.to_string());
    let (sender, receiver) = channel::<String>(100);
    subscribe_events(url.as_str(), sender).await;
    let xt: xt_primitives::UncheckedExtrinsicV4<_> = compose_extrinsic!(
        metadata.clone(),
        "DidModule",
        "create_did",
        signature.to_vec(),
        signed_message.to_vec(),
        identity.to_vec(),
        now_timestamp
    );
    send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::InBlock)
        .await
        .unwrap();
    let event_watch = move |raw: &RawEvent| -> bool {
        let decoded_event: Created = Decode::decode(&mut &raw.data[..]).unwrap();
        if now_timestamp == decoded_event.nonce {
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
    .unwrap()
    .unwrap();
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
#[wasm_bindgen]
pub async fn get_did(url: String, did: String) -> Result<String, JsValue> {
    let mut bytes_did_arr = [0; 32];
    bytes_did_arr.copy_from_slice(&hex::decode(did.trim_start_matches("0x")).unwrap()[0..32]);
    let bytes_did = sp_core::H256::from(bytes_did_arr);
    let metadata = get_metadata(url.as_str()).await.unwrap();
    let owner = get_storage_map::<sp_core::H256, Vec<u8>>(
        url.as_str(),
        metadata.clone(),
        "DidModule",
        "Dids",
        bytes_did.clone(),
    )
    .await
    .unwrap();
    info!("owner: {:?}", owner.unwrap());
    //if owner.chars().count() > 0 {
    let detail_count = get_storage_map::<sp_core::H256, u32>(
        url.as_str(),
        metadata.clone(),
        "DidModule",
        "DidsDetailsCount",
        bytes_did.clone(),
    )
    .await
    .unwrap();
    info!("detail_count: {:?}", detail_count.unwrap());
    //}
    //if detail_count.unwrap() > 0 {
    let detail_hash = get_storage_map::<(sp_core::H256, u32), Vec<u8>>(
        url.as_str(),
        metadata.clone(),
        "DidModule",
        "DidsDetails",
        (bytes_did.clone(), 0),
    )
    .await
    .unwrap();
    let body = reqwest::get(
        &format!(
            "http://{}:8081/ipfs/{}",
            url,
            std::str::from_utf8(&detail_hash.unwrap()).unwrap()
        )
        .to_string(),
    )
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
    //}
    Ok(body)
}

/// Add a new payload under a DID
///
/// # Arguments
/// * `url` - Substrate URL
/// * `payload` - Payload to save
/// * `did` - DID to save payload under
/// * `private_key` - Private key used to sign a message
/// * `identity` - Identity of the caller
#[wasm_bindgen]
pub async fn add_payload_to_did(
    url: String,
    payload: String,
    did: String,
    private_key: String,
    identity: Vec<u8>,
) -> Result<(), JsValue> {
    let metadata = get_metadata(url.as_str()).await.unwrap();
    let mut bytes_did_arr = [0; 32];
    bytes_did_arr.copy_from_slice(&hex::decode(did.trim_start_matches("0x")).unwrap()[0..32]);
    let bytes_did = sp_core::H256::from(bytes_did_arr);
    #[cfg(target_arch = "wasm32")]
    let now_timestamp = js_sys::Date::new_0().get_time() as u64;
    #[cfg(not(target_arch = "wasm32"))]
    let now_timestamp: u64 = Utc::now().timestamp_nanos() as u64;
    let (signature, signed_message) =
        sign_message(&now_timestamp.to_string(), &private_key.to_string());
    let payload_hex = hex::decode(hex::encode(payload)).unwrap();

    let (sender, receiver) = channel::<String>(100);
    subscribe_events(url.as_str(), sender).await;

    let xt: xt_primitives::UncheckedExtrinsicV4<_> = compose_extrinsic!(
        metadata.clone(),
        "DidModule",
        "add_did_detail",
        bytes_did.clone(),
        payload_hex,
        signature.to_vec(),
        signed_message.to_vec(),
        identity.to_vec(),
        now_timestamp
    );
    send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::InBlock)
        .await
        .unwrap();

    fn event_watch(did: &String) -> impl Fn(&RawEvent) -> bool + '_ {
        move |raw: &RawEvent| -> bool {
            let decoded_event: UpdatedDid = Decode::decode(&mut &raw.data[..]).unwrap();
            if &format!("0x{}", hex::encode(decoded_event.hash)) == did {
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
        event_watch(&did),
    )
    .await
    .unwrap()
    .unwrap();
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
/// * `identity` - Identity of the caller
#[wasm_bindgen]
pub async fn update_payload_in_did(
    url: String,
    index: u32,
    payload: String,
    did: String,
    private_key: String,
    identity: Vec<u8>,
) -> Result<(), JsValue> {
    let metadata = get_metadata(url.as_str()).await.unwrap();
    let mut bytes_did_arr = [0; 32];
    bytes_did_arr.copy_from_slice(&hex::decode(did.trim_start_matches("0x")).unwrap()[0..32]);
    let bytes_did = sp_core::H256::from(bytes_did_arr);
    #[cfg(target_arch = "wasm32")]
    let now_timestamp = js_sys::Date::new_0().get_time() as u64;
    #[cfg(not(target_arch = "wasm32"))]
    let now_timestamp: u64 = Utc::now().timestamp_nanos() as u64;
    let (signature, signed_message) =
        sign_message(&now_timestamp.to_string(), &private_key.to_string());
    let payload_hex = hex::decode(hex::encode(payload)).unwrap();

    let (sender, receiver) = channel::<String>(100);
    subscribe_events(url.as_str(), sender).await;

    let xt: xt_primitives::UncheckedExtrinsicV4<_> = compose_extrinsic!(
        metadata.clone(),
        "DidModule",
        "update_did_detail",
        bytes_did.clone(),
        payload_hex,
        index,
        signature.to_vec(),
        signed_message.to_vec(),
        identity,
        now_timestamp
    );
    send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::InBlock)
        .await
        .unwrap();

    fn event_watch(did: &String) -> impl Fn(&RawEvent) -> bool + '_ {
        move |raw: &RawEvent| -> bool {
            let decoded_event: UpdatedDid = Decode::decode(&mut &raw.data[..]).unwrap();
            if &format!("0x{}", hex::encode(decoded_event.hash)) == did {
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
        event_watch(&did),
    )
    .await
    .unwrap()
    .unwrap();
    Ok(())
}

/// Whitelists an identity to send transactions to the substrate chain.
///
/// # Arguments
/// * `url` - Substrate URL
/// * `private_key` - Private key used to sign a message
/// * `identity` - Identity of the caller
pub async fn whitelist_identity(
    url: String,
    private_key: String,
    identity: Vec<u8>,
) -> Result<String, JsValue> {
    let metadata = get_metadata(url.as_str()).await.unwrap();
    #[cfg(target_arch = "wasm32")]
    let now_timestamp = js_sys::Date::new_0().get_time() as u64;
    #[cfg(not(target_arch = "wasm32"))]
    let now_timestamp: u64 = Utc::now().timestamp_nanos() as u64;
    let (signature, signed_message) =
        sign_message(&now_timestamp.to_string(), &private_key.to_string());

    let (sender, receiver) = channel::<String>(100);
    subscribe_events(url.as_str(), sender).await;

    let xt: xt_primitives::UncheckedExtrinsicV4<_> = compose_extrinsic!(
        metadata.clone(),
        "DidModule",
        "whitelist_identity",
        signature.to_vec(),
        signed_message.to_vec(),
        identity.clone(),
        now_timestamp
    );
    send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::InBlock)
        .await
        .unwrap();
    fn event_watch(identity: &Vec<u8>) -> impl Fn(&RawEvent) -> bool + '_ {
        move |raw: &RawEvent| -> bool {
            let decoded_event: ApprovedIdentity = Decode::decode(&mut &raw.data[..]).unwrap();
            if &decoded_event.identity == identity {
                return true;
            }
            false
        }
    }
    let _event_result: ApprovedIdentity = wait_for_event(
        metadata.clone(),
        "DidModule",
        "ApprovedIdentity",
        None,
        receiver,
        event_watch(&identity),
    )
    .await
    .unwrap()
    .unwrap();
    Ok("".to_string())
}

/// Retrieves the number of payloads attached to a DID.
///
/// # Arguments
/// * `url` - Substrate URL
/// * `did` - DID to retrieve the count for
#[wasm_bindgen]
pub async fn get_payload_count_for_did(url: String, did: String) -> Result<u32, JsValue> {
    let metadata = get_metadata(url.as_str()).await.unwrap();
    let mut bytes_did_arr = [0; 32];
    bytes_did_arr.copy_from_slice(&hex::decode(did.trim_start_matches("0x")).unwrap()[0..32]);
    let bytes_did = sp_core::H256::from(bytes_did_arr);
    let detail_count = get_storage_map::<sp_core::H256, u32>(
        url.as_str(),
        metadata.clone(),
        "DidModule",
        "DidsDetailsCount",
        bytes_did.clone(),
    )
    .await
    .unwrap();
    if detail_count.is_none() {
        Ok(0)
    } else {
        Ok(detail_count.unwrap())
    }
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

fn json_req(method: &str, params: &str, id: u32) -> Value {
    json!({
        "method": method,
        "params": [params],
        "jsonrpc": "2.0",
        "id": id.to_string(),
    })
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
