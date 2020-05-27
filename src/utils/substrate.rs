use reqwest;
use serde_json::{json, Value};
use twox_hash;
use std::hash::Hasher;
use hex;
use blake2_rfc;
use crate::utils::extrinsic::xt_primitives;
use crate::utils::extrinsic::rpc;
use crate::utils::extrinsic::events;
use crate::utils::extrinsic::events::{EventsDecoder, RawEvent, RuntimeEvent};
use crate::utils::extrinsic::rpc_messages::{
    XtStatus,
    on_extrinsic_msg_until_finalized,
    on_subscription_msg,
    on_extrinsic_msg_until_in_block,
    on_extrinsic_msg_until_broadcast,
    on_extrinsic_msg_until_ready
};
use crate::utils::extrinsic::node_metadata::{Metadata};
use crate::utils::extrinsic::frame_metadata::RuntimeMetadataPrefixed;
use parity_scale_codec::{ Encode, Decode, Error as CodecError };
use sp_std::prelude::*;
use futures::channel::mpsc::{
    channel,
    Sender,
    Receiver
};
use futures::stream::{self, StreamExt};
use std::convert::TryFrom;

// A macro to provide `println!(..)`-style syntax for `console.log` logging.
macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}


pub async fn get_storage_value(url: &str, storage_prefix: &str, storage_key_name: &str) -> Result<String, Box<dyn std::error::Error>>  {


    let mut bytes = twox_128(&storage_prefix.as_bytes()).to_vec();
    bytes.extend(&twox_128(&storage_key_name.as_bytes())[..]);

    //"0x5c0d1176a568c1f92944340dbfed9e9c530ebca703c85910e7164cb7d1c9e47b"
    // 0x5c0d1176a568c1f9                                e7164cb7d1c9e47b
    //"0x5c0d1176a568c1f92944340dbfed9e9c530ebca703c85910e7164cb7d1c9e47b"
    let hexString = format!("0x{}", hex::encode(bytes));
    print!("{}", hexString);
    let json = json_req("state_getStorage", &hexString.to_string(), 1);
    let client = reqwest::Client::new();
    let body = client.post(&format!("http://{}:9933", url).to_string())
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

pub async fn get_storage_map<K: Encode + std::fmt::Debug, V: Decode + Clone>(url: &str, metadata: Metadata, storage_prefix: &'static str, storage_key_name: &'static str, map_key: K) -> Result<Option<V>, Box<dyn std::error::Error>>  {
   /* let mut bytes = twox_128(&storage_prefix.as_bytes()).to_vec();
    bytes.extend(&twox_128(&storage_key_name.as_bytes())[..]);
    if map_key.starts_with("0x") {
        bytes.extend(&blake2_256(&hex::decode(&map_key.trim_start_matches("0x")).unwrap()[..])[..]);
    } else {
        bytes.extend(&blake2_256(&map_key.as_bytes())[..]);
    }
*/
log!("map_key: {:?}", map_key);
    let storagekey: sp_core::storage::StorageKey = metadata
        .module(storage_prefix)
        .unwrap()
        .storage(storage_key_name)
        .unwrap()
        .get_map::<K, V>()
        .unwrap()
        .key(map_key);
    let hexString = format!("0x{}", hex::encode(storagekey.0.clone()));
    log!("hexString: {:?}", hexString);
    let json = json_req("state_getStorage", &hexString.to_string(), 1);
    let client = reqwest::Client::new();
    let body = client.post(&format!("http://{}:9933", url).to_string())
        .header("Content-Type", "application/json")
        .body(json.to_string())
        .send()
        .await?
        .text()
        .await?;
    let parsed: Value = serde_json::from_str(&body).unwrap();

    let result = match parsed["result"].as_str().unwrap() {
        "null" => None,
        _ => Some(hex::decode(&parsed["result"].as_str().unwrap().trim_start_matches("0x")).unwrap()),
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
    log!("Get metadata");
    let body = client.post(&format!("http://{}:9933", url).to_string())
        .header("Content-Type", "application/json")
        .body(json.to_string())
        .send()
        .await?
        .text()
        .await?;
    log!("Got metadata");
    let parsed: Value = serde_json::from_str(&body).unwrap();
    let hexValue = parsed["result"].as_str().unwrap().to_string();
    let _unhex = hexstr_to_vec(hexValue).unwrap();
    let mut _om = _unhex.as_slice();
    log!("Parsed Hex");
    let meta = RuntimeMetadataPrefixed::decode(&mut _om).unwrap();
    let metadata2 =  Metadata::parse(meta).unwrap();
    log!("Parsed Metadata");
    Ok(metadata2)
}

/*pub async fn get_storage_by_key_hash<V: Decode>(hash: Vec<u8>) -> Option<V> {
    self.get_opaque_storage_by_key_hash(hash).await
        .map(|v| Decode::decode(&mut v.as_slice()).unwrap())
}

pub async fn get_opaque_storage_by_key_hash(hash: Vec<u8>) -> Option<Vec<u8>> {
    let mut keyhash_str = hex::encode(hash);
    keyhash_str.insert_str(0, "0x");
    let jsonreq = json_req::state_get_storage(&keyhash_str);
    console_log!("{}", jsonreq);
    if let Ok(hexstr) = Self::_get_request(self.url.clone(), jsonreq.to_string()).await {
        console_log!("storage hex = {}", hexstr);
        let hexstr = hexstr
            .trim_matches('\"')
            .to_string()
            .trim_start_matches("0x")
            .to_string();
        match hexstr.as_str() {
            "null" => None,
            _ => Some(hex::decode(&hexstr).unwrap()),
        }
    } else {
        None
    }
}*/


pub async fn send_extrinsic(url: &str, xthex_prefixed: String, exit_on: XtStatus) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let json = json!({
        "method": "author_submitAndWatchExtrinsic",
        "params": [xthex_prefixed],
        "jsonrpc": "2.0",
        "id": "4",
    });

    let (sender, mut receiver) = channel::<String>(100);
    match exit_on {
        XtStatus::Finalized => {
            log!("start send");
            rpc::start_rpc_client_thread_sender(format!("ws://{}:9944", url).to_string(), json.to_string(), sender, on_extrinsic_msg_until_finalized);
            log!("finished send");
            if let Some(data) = receiver.next().await {
                info!("finalized transaction: {}", data.clone());
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        XtStatus::InBlock => {
            rpc::start_rpc_client_thread_sender(format!("ws://{}:9944", url).to_string(), json.to_string(), sender, on_extrinsic_msg_until_in_block);
            if let Some(data) = receiver.next().await {
                info!("inBlock: {}", data.clone());
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        XtStatus::Broadcast => {
            rpc::start_rpc_client_thread_sender(format!("ws://{}:9944", url).to_string(), json.to_string(), sender, on_extrinsic_msg_until_broadcast);
            if let Some(data) = receiver.next().await {
                info!("broadcast: {}", data.clone());
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        XtStatus::Ready => {
            rpc::start_rpc_client_thread_sender(format!("ws://{}:9944", url).to_string(), json.to_string(), sender, on_extrinsic_msg_until_ready);
            if let Some(data) = receiver.next().await {
                info!("ready: {}", data.clone());
                return Ok(Some(data));
            }
            Ok(Some("Nope".to_string()))
        }
        _ => panic!(
            "can only wait for finalized, in block, broadcast and ready extrinsic status"
        ),
    }
}



pub async fn subscribe_events(url: &str, mut sender: Sender<String>) {
    log!("subscribing to events");
    let mut bytes = twox_128("System".as_bytes()).to_vec();
    bytes.extend(&twox_128("Events".as_bytes())[..]);
    let key = format!("0x{}", hex::encode(bytes));
    let jsonreq = json!({
        "method": "state_subscribeStorage",
        "params": [[key]],
        "jsonrpc": "2.0",
        "id": "1",
    });
    rpc::start_rpc_client_thread_sender(format!("ws://{}:9944", url).to_string(), jsonreq.to_string(), sender, on_subscription_msg);
}

pub async fn wait_for_event<E: Decode>(
    metadata: Metadata,
    module: &str,
    variant: &str,
    decoder: Option<EventsDecoder>,
    receiver: Receiver<String>,
) -> Option<Result<E, CodecError>> {
    wait_for_raw_event(metadata, module, variant, decoder, receiver).await
        .map(|raw| E::decode(&mut &raw.data[..]))
}

pub async fn wait_for_raw_event(
    metadata: Metadata,
    module: &str,
    variant: &str,
    decoder: Option<EventsDecoder>,
    mut receiver: Receiver<String>,
) -> Option<RawEvent> {
    let event_decoder =
        decoder.unwrap_or_else(|| EventsDecoder::try_from(metadata.clone()).unwrap());
    


    loop {
        info!("LOOP");
        if let Some(data) = receiver.next().await {
            let event_str = data;
            info!("SENDER GOT EVENT");
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
                                return Some(raw)
                            }
                            _ => {
                                debug!("ignoring unsupported module event: {:?}", event);
                                //return Some(());
                            }
                        }
                    }
                }
                Err(_) => error!("couldn't decode event record list"),
            }
        }
        
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
pub fn blake2_128(data: &[u8]) -> [u8; 16]{
    let mut r = [0; 16];
    r.copy_from_slice(blake2_rfc::blake2b::blake2b(16, &[], data).as_bytes());
    r
}

/// Do a Blake2 256-bit hash and return result.
pub fn blake2_256(data: &[u8]) -> [u8; 32]{
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