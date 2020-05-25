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

#[wasm_bindgen]
pub async fn k(url:String)->String{
    //let sudo_key = substrate::get_storage_value("Sudo", "Key").await.unwrap();
    //let nonce = substrate::get_storage_value("DidModule", "Get_nonce").await.unwrap();
    log!("URL");
    let metadata = substrate::get_metadata().await.unwrap();
    log!("Got Metadata2");
    let signature = hex::decode("3b83194f7efa3b4a7d59ebe0a38b4d76813157108d8183c2fcbb8a8ce1a6f3d33feac89855dd5a15a397d92917d88572a1f054c6b7105d80f09e8a525b4e6bae1c").unwrap();
    let signed_message = hex::decode("4a5c5d454721bbbb25540c3317521e71c373ae36458f960d2ad46ef088110e95").unwrap();
    let identity = hex::decode("9670f7974e7021e4940c56d47f6b31fdfdd37de8").unwrap();
    let xt: UncheckedExtrinsicV4<_> =
    compose_extrinsic!(metadata.clone(), "DidModule", "whitelist_identity", signature, signed_message, identity);
    log!("composed extrinsic");
    substrate::send_extrinsic(xt.hex_encode(), XtStatus::Finalized ).await.unwrap();
    
    let sudo_key = substrate::get_storage_value("Sudo", "Key").await.unwrap();
    sudo_key
}

#[wasm_bindgen]
pub async fn i(url:String)->String{
    let metadata = substrate::get_metadata().await.unwrap();
    log!("Got Metadata2");
    let (sender, receiver2) = channel::<String>(100);
    substrate::subscribe_events(sender).await;
    let args: ApprovedIdentity = substrate::wait_for_event(metadata, "DidModule", "ApprovedIdentity", None, receiver2).await
        .unwrap()
        .unwrap();
    log!("Got Event");
    return "done".to_string();
}