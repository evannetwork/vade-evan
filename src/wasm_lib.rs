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

use console_log;
use std::{collections::HashMap, error::Error};
use vade::Vade;
use wasm_bindgen::prelude::*;
use crate::vade_utils::{get_vade as get_vade_from_utils, get_config_default};

macro_rules! handle_results {
    ($func_name:expr, $did_or_method:expr, $results:expr) => {
        let err_msg = format!(
            "'{}' did not return any result for '{}'",
            $func_name, $did_or_method,
        );
        ensure($results.len() > 0, || (&err_msg).to_string())?;

        let empty_result = &String::new();
        return Ok(Some($results[0].as_ref().unwrap_or(empty_result).to_string()))
    };
}

macro_rules! create_function {
    ($func_name:ident, $did_or_method:ident, $config:ident) => {
        #[wasm_bindgen]
        pub async fn $func_name(
            did_or_method: String,
            config: JsValue,
        ) -> Result<Option<String>, JsValue> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade.$func_name(&did_or_method).await.map_err(jsify)?;
            handle_results!(stringify!($func_name), did_or_method, results);
        }
    };
    ($func_name:ident, $options:ident, $payload:ident, $config:ident) => {
        #[wasm_bindgen]
        pub async fn $func_name(
            options: String,
            payload: String,
            config: JsValue,
        ) -> Result<Option<String>, JsValue> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade.$func_name(&options, &payload).await.map_err(jsify)?;
            let name = stringify!($func_name);
            handle_results!(&name, &name, results);
        }
    };
    ($func_name:ident, $did_or_method:ident, $options:ident, $payload:ident, $config:ident) => {
        #[wasm_bindgen]
        pub async fn $func_name(
            did_or_method: String,
            options: String,
            payload: String,
            config: JsValue,
        ) -> Result<Option<String>, JsValue> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade
                .$func_name(&did_or_method, &options, &payload)
                .await
                .map_err(jsify)?;
            handle_results!(stringify!($func_name), did_or_method, results);
        }
    };
    ($func_name:ident, $did_or_method:ident, $function:ident, $options:ident, $payload:ident, $config:ident) => {
        #[wasm_bindgen]
        pub async fn $func_name(
            did_or_method: String,
            function: String,
            options: String,
            payload: String,
            config: JsValue,
        ) -> Result<Option<String>, JsValue> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade
                .$func_name(&did_or_method, &function, &options, &payload)
                .await
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
    if #[cfg(feature = "did-read")] {
        create_function!(did_resolve, did_or_method, config);
    } else {
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "did-write")] {
        create_function!(did_create, did_or_method, options, payload, config);
        create_function!(did_update, did_or_method, options, payload, config);
    } else {
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "didcomm")] {
        create_function!(didcomm_receive, options, payload, config);
        create_function!(didcomm_send, options, payload, config);
    } else {
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))] {
        create_function!(run_custom_function, did_or_method, function, options, payload, config);
        #[cfg(feature = "vc-zkp-cl")]
        create_function!(vc_zkp_create_credential_definition, did_or_method, options, payload, config);
        create_function!(vc_zkp_create_credential_offer, did_or_method, options, payload, config);
        create_function!(vc_zkp_create_credential_proposal, did_or_method, options, payload, config);
        create_function!(vc_zkp_create_credential_schema, did_or_method, options, payload, config);
        create_function!(vc_zkp_create_revocation_registry_definition, did_or_method, options, payload, config);
        create_function!(vc_zkp_update_revocation_registry, did_or_method, options, payload, config);
        create_function!(vc_zkp_issue_credential, did_or_method, options, payload, config);
        create_function!(vc_zkp_finish_credential, did_or_method, options, payload, config);
        create_function!(vc_zkp_present_proof, did_or_method, options, payload, config);
        create_function!(vc_zkp_request_credential, did_or_method, options, payload, config);
        create_function!(vc_zkp_request_proof, did_or_method, options, payload, config);
        create_function!(vc_zkp_revoke_credential, did_or_method, options, payload, config);
        create_function!(vc_zkp_verify_proof, did_or_method, options, payload, config);
    } else {
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "vc-jwt")] {
        create_function!(vc_zkp_issue_credential, did_or_method, options, payload, config);
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

    return get_vade_from_utils(target, signer_config);
}

fn jsify(err: Box<dyn Error>) -> JsValue {
    JsValue::from(format!("{}", err))
}
