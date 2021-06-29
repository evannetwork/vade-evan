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
// shared
use console_log;
use std::{collections::HashMap, error::Error};
use vade::Vade;
// use vade_evan_substrate::signing::{LocalSigner, RemoteSigner, Signer};
use wasm_bindgen::prelude::*;

// #[cfg(feature = "did")]
// use vade_evan_substrate::{ResolverConfig, VadeEvanSubstrate};

// #[cfg(feature = "vc-zkp")]
// use vade_evan_cl::VadeEvanCl;
// #[cfg(feature = "vc-zkp")]
// use vade_evan_bbs::VadeEvanBbs;

macro_rules! handle_results {
    ($func_name:expr, $did_or_method:expr, $results:expr) => {
        let err_msg = format!(
            "'{}' did not return any result for '{}'",
            $func_name, $did_or_method,
        );
        ensure($results.len() > 0, || (&err_msg).to_string())?;

        return Ok(Some($results[0].as_ref().ok_or(err_msg)?.to_string()))
    };
}

macro_rules! create_function {
    ($func_name:ident, $did_or_method:ident, $config:ident) => {
        #[wasm_bindgen]
        pub fn $func_name(
            did_or_method: String,
            config: JsValue,
        ) -> Result<Option<String>, JsValue> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade.$func_name(&did_or_method).map_err(jsify)?;
            handle_results!(stringify!($func_name), did_or_method, results);
        }
    };
    ($func_name:ident, $did_or_method:ident, $options:ident, $payload:ident, $config:ident) => {
        #[wasm_bindgen]
        pub fn $func_name(
            did_or_method: String,
            options: String,
            payload: String,
            config: JsValue,
        ) -> Result<Option<String>, JsValue> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade
                .$func_name(&did_or_method, &options, &payload)
                .map_err(jsify)?;
            handle_results!(stringify!($func_name), did_or_method, results);
        }
    };
    ($func_name:ident, $did_or_method:ident, $function:ident, $options:ident, $payload:ident, $config:ident) => {
        #[wasm_bindgen]
        pub fn $func_name(
            did_or_method: String,
            function: String,
            options: String,
            payload: String,
            config: JsValue,
        ) -> Result<Option<String>, JsValue> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade
                .$func_name(&did_or_method, &function, &options, &payload)
                .map_err(jsify)?;
                handle_results!(format!("{}: {}", stringify!($func_name), &function), did_or_method, results);
        }
    };
}

/// small drop-in replacement for asserts
/// if condition is false, will evaluate `create_msg` function and return an Err with it
fn ensure<F>(condition: bool, create_msg: F) -> Result<(), JsValue>
where
    F: FnOnce() -> String,
{
    if condition {
        Ok(())
    } else {
        Err(JsValue::from(&create_msg().to_string()))
    }
}

#[wasm_bindgen]
pub fn set_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn set_log_level(log_level: String) {
    let _ = match log_level.as_str() {
        "trace" => console_log::init_with_level(log::Level::Trace),
        "debug" => console_log::init_with_level(log::Level::Debug),
        "info" => console_log::init_with_level(log::Level::Info),
        "error" => console_log::init_with_level(log::Level::Error),
        _ => console_log::init_with_level(log::Level::Error),
    };
}

cfg_if::cfg_if! {
    if #[cfg(feature = "did")] {
        create_function!(did_create, did_or_method, options, payload, config);
        create_function!(did_resolve, did_or_method, config);
        create_function!(did_update, did_or_method, options, payload, config);
    } else {
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "vc-zkp")] {
        create_function!(run_custom_function, did_or_method, function, options, payload, config);
        create_function!(vc_zkp_create_credential_definition, did_or_method, options, payload, config);
        create_function!(vc_zkp_create_credential_offer, did_or_method, options, payload, config);
        create_function!(vc_zkp_create_credential_proposal, did_or_method, options, payload, config);
        create_function!(vc_zkp_create_credential_schema, did_or_method, options, payload, config);
        create_function!(vc_zkp_create_revocation_registry_definition, did_or_method, options, payload, config);
        create_function!(vc_zkp_update_revocation_registry, did_or_method, options, payload, config);
        create_function!(vc_zkp_issue_credential, did_or_method, options, payload, config);
        create_function!(vc_zkp_present_proof, did_or_method, options, payload, config);
        create_function!(vc_zkp_request_credential, did_or_method, options, payload, config);
        create_function!(vc_zkp_request_proof, did_or_method, options, payload, config);
        create_function!(vc_zkp_revoke_credential, did_or_method, options, payload, config);
        create_function!(vc_zkp_verify_proof, did_or_method, options, payload, config);
    } else {
    }
}

fn get_config_values(
    config: Option<&JsValue>,
    keys: Vec<String>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut vec = Vec::new();
    let mut config_undefined = true;

    let config_hash_map: HashMap<String, String>;
    match config {
        Some(value) => {
            if !value.is_undefined() {
                config_hash_map = value.into_serde()?;
                config_undefined = false;
            } else {
                config_hash_map = HashMap::<String, String>::new();
            }
        }
        None => {
            config_hash_map = HashMap::<String, String>::new();
        }
    };

    for key in keys {
        if config_undefined || !config_hash_map.contains_key(&key) {
            vec.push(get_config_default(&key)?);
        } else {
            vec.push(
                config_hash_map
                    .get(&key)
                    .ok_or_else(|| format!("could not get key '{}' from config", &key))?
                    .to_string(),
            );
        }
    }

    Ok(vec)
}

fn get_config_default(key: &str) -> Result<String, Box<dyn Error>> {
    Ok(match key {
        "signer" => "remote|https://tntkeyservices-5b02.azurewebsites.net/api/key/sign",
        "target" => "13.69.59.185",
        _ => return Err(Box::from(format!("invalid invalid config key '{}'", key))),
    }
    .to_string())
}

// fn get_signer(signer_config: String) -> Result<Box<dyn Signer>, Box<dyn Error>> {
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

#[allow(unused_variables)] // allow possibly unused variables due to feature mix
fn get_vade(config: Option<&JsValue>) -> Result<Vade, Box<dyn Error>> {
    let config_values =
        get_config_values(config, vec!["signer".to_string(), "target".to_string()])?;
    let (signer_config, target) = match config_values.as_slice() {
        [signer_config, target, ..] => (signer_config, target),
        _ => {
            return Err(Box::from("invalid vade config"));
        }
    };

    let mut vade = Vade::new();

    // #[cfg(feature = "did")]
    // let signer: Box<dyn Signer> = get_signer(signer_config.to_string())?;
    // #[cfg(feature = "did")]
    // vade.register_plugin(Box::from(VadeEvanSubstrate::new(ResolverConfig {
    //     signer,
    //     target: target.to_string(),
    // })));
    // #[cfg(feature = "vc-zkp")]
    // vade.register_plugin(Box::from(get_vade_evan_cl(config)?));
    // #[cfg(feature = "vc-zkp")]
    // vade.register_plugin(Box::from(get_vade_evan_bbs(config)?));

    Ok(vade)
}

// #[cfg(feature = "vc-zkp")]
// #[allow(unused_variables)] // allow possibly unused variables due to feature mix
// fn get_vade_evan_cl(config: Option<&JsValue>) -> Result<VadeEvanCl, Box<dyn Error>> {
//     let config_values =
//         get_config_values(config, vec!["signer".to_string(), "target".to_string()])?;
//     let (signer_config, target) = match config_values.as_slice() {
//         [signer_config, target, ..] => (signer_config, target),
//         _ => {
//             return Err(Box::from("invalid vade config"));
//         }
//     };

//     #[cfg(not(feature = "did"))]
//     let internal_vade = Vade::new();
//     #[cfg(not(feature = "did"))]
//     let signer = "";

//     #[cfg(feature = "did")]
//     let mut internal_vade = Vade::new();
//     #[cfg(feature = "did")]
//     let signer: Box<dyn Signer> = get_signer(signer_config.to_string())?;
//     #[cfg(feature = "did")]
//     internal_vade.register_plugin(Box::from(VadeEvanSubstrate::new(ResolverConfig {
//         signer,
//         target: target.to_string(),
//     })));
//     let signer: Box<dyn Signer> = get_signer(signer_config.to_string())?;

//     Ok(VadeEvanCl::new(internal_vade, signer))
// }

// #[cfg(feature = "vc-zkp")]
// #[allow(unused_variables)] // allow possibly unused variables due to feature mix
// fn get_vade_evan_bbs(config: Option<&JsValue>) -> Result<VadeEvanBbs, Box<dyn Error>> {
//     let config_values =
//         get_config_values(config, vec!["signer".to_string(), "target".to_string()])?;
//     let (signer_config, target) = match config_values.as_slice() {
//         [signer_config, target, ..] => (signer_config, target),
//         _ => {
//             return Err(Box::from("invalid vade config"));
//         }
//     };

//     #[cfg(not(feature = "did"))]
//     let internal_vade = Vade::new();
//     #[cfg(not(feature = "did"))]
//     let signer = "";

//     #[cfg(feature = "did")]
//     let mut internal_vade = Vade::new();
//     #[cfg(feature = "did")]
//     let signer: Box<dyn Signer> = get_signer(signer_config.to_string())?;
//     #[cfg(feature = "did")]
//     internal_vade.register_plugin(Box::from(VadeEvanSubstrate::new(ResolverConfig {
//         signer,
//         target: target.to_string(),
//     })));
//     let signer: Box<dyn Signer> = get_signer(signer_config.to_string())?;

//     Ok(VadeEvanBbs::new(internal_vade, signer))
// }

fn jsify(err: Box<dyn Error>) -> JsValue {
    JsValue::from(format!("{}", err))
}
