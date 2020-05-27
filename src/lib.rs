extern crate ursa;
extern crate secp256k1;
extern crate sha3;
extern crate hex;
#[macro_use]
pub extern crate log;


pub mod application;
pub mod crypto;

#[macro_use]
pub mod utils;


use utils::substrate;

use utils::extrinsic::xt_primitives::{
    UncheckedExtrinsicV4
};
use utils::extrinsic::rpc_messages::XtStatus;
use wasm_bindgen::prelude::*;
use parity_scale_codec::Decode;
use futures::channel::mpsc::{
    Receiver,
    Sender,
    channel
};
use reqwest;


use futures::future;
// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern {
    fn alert(s: &str);
}

// A macro to provide `println!(..)`-style syntax for `console.log` logging.
macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

#[derive(Decode)]
struct ApprovedIdentity {
    account: Vec<u8>,
    identity: Vec<u8>,
}

#[derive(Decode)]
struct Created {
    hash: sp_core::H256,
    owner: Vec<u8>,
}

#[wasm_bindgen]
pub async fn send_extrinsic(url:String, nonce: u32)->String{
    //let sudo_key = substrate::get_storage_value("Sudo", "Key").await.unwrap();
    //let nonce = substrate::get_storage_value("DidModule", "Get_nonce").await.unwrap();
    log!("URL");
    let metadata = substrate::get_metadata(url.as_str()).await.unwrap();
    log!("Got Metadata for extrinsic");
    let signature = hex::decode("3b83194f7efa3b4a7d59ebe0a38b4d76813157108d8183c2fcbb8a8ce1a6f3d33feac89855dd5a15a397d92917d88572a1f054c6b7105d80f09e8a525b4e6bae1c").unwrap();
    let signed_message = hex::decode("4a5c5d454721bbbb25540c3317521e71c373ae36458f960d2ad46ef088110e95").unwrap();
    let identity = hex::decode("9670f7974e7021e4940c56d47f6b31fdfdd37de8").unwrap();
    let xt: UncheckedExtrinsicV4<_> =
    compose_extrinsic!(metadata.clone(), "DidModule", "whitelist_identity", signature, signed_message, identity, nonce);
    log!("composed extrinsic");
    substrate::send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::Finalized ).await.unwrap();
    
    let sudo_key = substrate::get_storage_value(url.as_str(), "Sudo", "Key").await.unwrap();
    sudo_key
}

#[wasm_bindgen]
pub async fn watch_event(url:String)->String{
    let metadata = substrate::get_metadata(url.as_str()).await.unwrap();
    log!("Got Metadata for event");
    let (sender, receiver2) = channel::<String>(100);
    substrate::subscribe_events(url.as_str(), sender).await;
    let args: ApprovedIdentity = substrate::wait_for_event(metadata, "DidModule", "ApprovedIdentity", None, receiver2).await
        .unwrap()
        .unwrap();
    log!("Got Event: {:?}", args.identity);
    return "done".to_string();
}

#[wasm_bindgen]
pub async fn create_did(url: String, nonce: u32) -> String {
    let metadata = substrate::get_metadata(url.as_str()).await.unwrap();
    let signature = hex::decode("3b83194f7efa3b4a7d59ebe0a38b4d76813157108d8183c2fcbb8a8ce1a6f3d33feac89855dd5a15a397d92917d88572a1f054c6b7105d80f09e8a525b4e6bae1c").unwrap();
    let signed_message = hex::decode("4a5c5d454721bbbb25540c3317521e71c373ae36458f960d2ad46ef088110e95").unwrap();
    let identity = hex::decode("9670f7974e7021e4940c56d47f6b31fdfdd37de8").unwrap();

    let (sender, receiver2) = channel::<String>(100);
    substrate::subscribe_events(url.as_str(), sender).await;

    let xt: UncheckedExtrinsicV4<_> =
    compose_extrinsic!(metadata.clone(), "DidModule", "create_did", signature, signed_message, identity, nonce);
    let extrinsic = substrate::send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::Ready );
    let event_wait = substrate::wait_for_event::<Created>(metadata, "DidModule", "Created", None, receiver2);
    let combined_future = future::join(extrinsic, event_wait);
    let results = combined_future.await;
    log!("Sent Extrinsic");
    let args: Created = results.1
        .unwrap()
        .unwrap();
    
    log!("Got Event {:?}", args.hash);
    return hex::encode(args.hash);
}


#[wasm_bindgen]
pub async fn get_did(url: String, did: String) -> Result<String, JsValue> {

    let mut bytes_did_arr = [0; 32];
    bytes_did_arr.copy_from_slice(&hex::decode(did.trim_start_matches("0x")).unwrap()[0..32]);
    let bytes_did = sp_core::H256::from(bytes_did_arr);
    let metadata = substrate::get_metadata(url.as_str()).await.unwrap();
    let owner = substrate::get_storage_map::<sp_core::H256, Vec<u8>>(url.as_str(), metadata.clone(), "DidModule", "Dids", bytes_did.clone()).await.unwrap();
    log!("owner: {:?}", owner.unwrap());
    //if owner.chars().count() > 0 {
        let detail_count = substrate::get_storage_map::<sp_core::H256, u32>(url.as_str(), metadata.clone(), "DidModule", "DidsDetailsCount", bytes_did.clone()).await.unwrap(); 
        log!("detail_count: {:?}", detail_count.unwrap());
    //}
    //if detail_count.unwrap() > 0 {
        let detail_hash = substrate::get_storage_map::<(sp_core::H256, u32), Vec<u8>>(url.as_str(), metadata.clone(), "DidModule", "DidsDetails", (bytes_did.clone(), 0)).await.unwrap(); 
        let body = reqwest::get(&format!("https://ipfs.infura.io/ipfs/{}", std::str::from_utf8(&detail_hash.unwrap()).unwrap()).to_string())
            .await?
            .text()
            .await?;
    //}
    
    /*let metadata = substrate::get_metadata(url.as_str()).await.unwrap();
    let signature = hex::decode("3b83194f7efa3b4a7d59ebe0a38b4d76813157108d8183c2fcbb8a8ce1a6f3d33feac89855dd5a15a397d92917d88572a1f054c6b7105d80f09e8a525b4e6bae1c").unwrap();
    let signed_message = hex::decode("4a5c5d454721bbbb25540c3317521e71c373ae36458f960d2ad46ef088110e95").unwrap();
    let identity = hex::decode("9670f7974e7021e4940c56d47f6b31fdfdd37de8").unwrap();

    let (sender, receiver2) = channel::<String>(100);
    substrate::subscribe_events(url.as_str(), sender).await;

    let xt: UncheckedExtrinsicV4<_> =
    compose_extrinsic!(metadata.clone(), "DidModule", "create_did", signature, signed_message, identity, nonce);
    let extrinsic = substrate::send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::Ready );
    let event_wait = substrate::wait_for_event::<Created>(metadata, "DidModule", "Created", None, receiver2);
    let combined_future = future::join(extrinsic, event_wait);
    let results = combined_future.await;
    log!("Sent Extrinsic");
    let args: Created = results.1
        .unwrap()
        .unwrap();
    
    log!("Got Event {:?}", args.hash);*/
    Ok("Huhu".to_string())
}


#[wasm_bindgen]
pub async fn add_payload_to_did(url: String, payload: String, did: String) -> Result<String, JsValue> {
    let metadata = substrate::get_metadata(url.as_str()).await.unwrap();
    let mut bytes_did_arr = [0; 32];
    bytes_did_arr.copy_from_slice(&hex::decode(did.trim_start_matches("0x")).unwrap()[0..32]);
    let bytes_did = sp_core::H256::from(bytes_did_arr);
    let signature = hex::decode("3b83194f7efa3b4a7d59ebe0a38b4d76813157108d8183c2fcbb8a8ce1a6f3d33feac89855dd5a15a397d92917d88572a1f054c6b7105d80f09e8a525b4e6bae1c").unwrap();
    let signed_message = hex::decode("4a5c5d454721bbbb25540c3317521e71c373ae36458f960d2ad46ef088110e95").unwrap();
    let identity = hex::decode("9670f7974e7021e4940c56d47f6b31fdfdd37de8").unwrap();
    let payload_hex = hex::decode(hex::encode(payload)).unwrap();

    let (sender, receiver2) = channel::<String>(100);
    substrate::subscribe_events(url.as_str(), sender).await;

    let xt: UncheckedExtrinsicV4<_> =
    compose_extrinsic!(metadata.clone(), "DidModule", "add_did_detail", bytes_did.clone(), payload_hex, signature, signed_message, identity);
    substrate::send_extrinsic(url.as_str(), xt.hex_encode(), XtStatus::Finalized ).await;
    Ok("Huhu".to_string())
}