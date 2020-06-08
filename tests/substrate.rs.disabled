//extern crate vade_tnt;

use vade_tnt::utils::substrate;

use vade_tnt::compose_extrinsic;
use vade_tnt::utils::extrinsic::xt_primitives::{
    UncheckedExtrinsicV4
};
use vade_tnt::utils::extrinsic::rpc_messages::XtStatus;
/*#[tokio::test]
async fn can_call_storage_values() {
    let did = substrate::get_storage_key("Sudo", "Key").await.unwrap();
}*/

/*extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
*/
//#[wasm_bindgen_test]
#[tokio::test]
async fn can_call_storage_maps() {
    //let sudo_key = substrate::get_storage_value("Sudo", "Key").await.unwrap();
    //let nonce = substrate::get_storage_value("DidModule", "Get_nonce").await.unwrap();
    let metadata = substrate::get_metadata().await.unwrap();
    let signature = hex::decode("3b83194f7efa3b4a7d59ebe0a38b4d76813157108d8183c2fcbb8a8ce1a6f3d33feac89855dd5a15a397d92917d88572a1f054c6b7105d80f09e8a525b4e6bae1c").unwrap();
    let signed_message = hex::decode("4a5c5d454721bbbb25540c3317521e71c373ae36458f960d2ad46ef088110e95").unwrap();
    let identity = hex::decode("9670f7974e7021e4940c56d47f6b31fdfdd37de8").unwrap();
    let xt: UncheckedExtrinsicV4<_> =
    compose_extrinsic!(metadata.clone(), "DidModule", "whitelist_identity", signature, signed_message, identity);
    substrate::send_extrinsic(xt.hex_encode(), XtStatus::Finalized ).await.unwrap();
    
    let sudo_key = substrate::get_storage_value("sudo", "Key").await.unwrap();
}
//0x86938e130d7a2d360ecb87f870ff5652718368a0ace36e2b1b8b6dbd7f8093c0
//0x86938e130d7a2d360ecb87f870ff5652718368a0ace36e2b1b8b6dbd7f8093c0
//0xc6ac8c4e605bee5cbf6880ef91a4a939718368a0ace36e2b1b8b6dbd7f8093c0
//0x13ce02de5903c05d23ee965e65809494718368a0ace36e2b1b8b6dbd7f8093c0
//0xf5862b9667bd2aa40f8475c9e2632bc7718368a0ace36e2b1b8b6dbd7f8093c0