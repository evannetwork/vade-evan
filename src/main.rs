use futures::executor::block_on;
use tokio::net::TcpListener;
use tokio::prelude::*;
use vade::Vade;
use vade_evan::{
    resolver::{ResolverConfig, SubstrateDidResolverEvan},
    signing::{LocalSigner, Signer},
    VadeEvan,
};

async fn hello_world() {
    println!("async hello, world!");
}

async fn get_and_log() {
    let mut vade = get_vade().unwrap();

    let results = vade
        .did_resolve("did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906")
        .await
        .unwrap();

    let err_msg = "could not get DID document";

    let document_string = results[0]
        .as_ref()
        .ok_or_else(|| err_msg.to_string())
        .unwrap()
        .to_string();

    println!("{}", &document_string);
}

async fn credo() {
    let mut vade = get_vade().unwrap();

    let options = r###"{
        "privateKey": "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106",
        "identity": "did:evan:testcore:0x0d87204C3957D73b68AE28d0AF961d3c72403906"
    }"###;

    let payload = r###"{
        "schemaDid": "did:evan:zkp:0xccc8075b38209a6678dd8d110630458fe69d8b271f698a9c6b008ed3b1341902",
        "issuerDid": "did:evan:testcore:0x0d87204C3957D73b68AE28d0AF961d3c72403906",
        "issuerPublicKeyDid": "did:evan:testcore:0x0d87204C3957D73b68AE28d0AF961d3c72403906#key-1",
        "issuerProvingKey": "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106"
    }"###;

    let results = vade
        .vc_zkp_create_credential_definition("did:evan", &options, &payload)
        .await
        .unwrap();

    let err_msg = "could not create credo";

    let document_string = results[0]
        .as_ref()
        .ok_or_else(|| err_msg.to_string())
        .unwrap()
        .to_string();

    println!("{}", &document_string);
}

#[tokio::main]
async fn main() {
    // let future = get_and_log(); // Nothing is printed
    // block_on(future); // `future` is run and "hello, world!" is printed
    // get_and_log().await;
    credo().await;
}

// fn get_config_values(
//     config: Option<&JsValue>,
//     keys: Vec<String>,
// ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
//     let mut vec = Vec::new();
//     let mut config_undefined = true;

//     let config_hash_map: HashMap<String, String>;
//     match config {
//         Some(value) => {
//             if !value.is_undefined() {
//                 config_hash_map = value.into_serde()?;
//                 config_undefined = false;
//             } else {
//                 config_hash_map = HashMap::<String, String>::new();
//             }
//         }
//         None => {
//             config_hash_map = HashMap::<String, String>::new();
//         }
//     };

//     for key in keys {
//         if config_undefined || !config_hash_map.contains_key(&key) {
//             vec.push(get_config_default(&key)?);
//         } else {
//             vec.push(
//                 config_hash_map
//                     .get(&key)
//                     .ok_or_else(|| format!("could not get key '{}' from config", &key))?
//                     .to_string(),
//             );
//         }
//     }

//     Ok(vec)
// }

// fn get_config_default(key: &str) -> Result<String, Box<dyn std::error::Error>> {
//     Ok(match key {
//         "signer" => "remote|https://tntkeyservices-e0ae.azurewebsites.net/api/key/sign",
//         // "signer" => "local",
//         "target" => "13.69.59.185",
//         _ => return Err(Box::from(format!("invalid invalid config key '{}'", key))),
//     }
//     .to_string())
// }

// #[cfg(feature = "vc-zkp")]
// fn get_options(private_key: String, identity: String) -> String {
//     format!(
//         r###"{{
//             "privateKey": "{}",
//             "identity": "{}"
//         }}"###,
//         private_key, identity,
//     )
// }

// fn get_signer(signer_config: String) -> Result<Box<dyn Signer>, Box<dyn std::error::Error>> {
//     if signer_config == "local" {
//         Ok(Box::new(LocalSigner::new()))
//     } else if signer_config.starts_with("remote|") {
//         Ok(Box::new(RemoteSigner::new(
//             signer_config
//                 .strip_prefix("remote|")
//                 .ok_or("invalid signer_config")?
//                 .to_string(),
//         )))
//     } else {
//         Err(Box::from(format!(
//             "invalid signer config {}",
//             &signer_config
//         )))
//     }
// }

fn get_vade() -> Result<Vade, Box<dyn std::error::Error>> {
    let mut vade = Vade::new();

    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    vade.register_plugin(Box::from(SubstrateDidResolverEvan::new(ResolverConfig {
        signer,
        target: "13.69.59.185".to_string(),
    })));

    vade.register_plugin(Box::from(get_vade_evan()?));

    Ok(vade)
}

fn get_vade_evan() -> Result<VadeEvan, Box<dyn std::error::Error>> {
    let mut internal_vade = Vade::new();
    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    internal_vade.register_plugin(Box::from(SubstrateDidResolverEvan::new(ResolverConfig {
        signer,
        // target: "127.0.0.1".to_string(),
        target: "13.69.59.185".to_string(),
    })));
    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());

    Ok(VadeEvan::new(internal_vade, signer))
}

// fn main() {}
