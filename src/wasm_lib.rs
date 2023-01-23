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

use crate::api::{VadeEvan, VadeEvanConfig, VadeEvanError, DEFAULT_SIGNER, DEFAULT_TARGET};
use console_log;
use serde::Serialize;
use std::{collections::HashMap, error::Error};
use wasm_bindgen::prelude::*;

macro_rules! create_function {
    ($func_name:ident, $did_or_method:ident, $config:ident) => {
        #[wasm_bindgen]
        pub async fn $func_name(did_or_method: String, config: JsValue) -> Result<String, JsValue> {
            let mut vade_evan = get_vade_evan(Some(&config)).map_err(jsify_generic_error)?;
            vade_evan
                .$func_name(&did_or_method)
                .await
                .map_err(jsify_vade_evan_error)
        }
    };
    ($func_name:ident, $options:ident, $payload:ident, $config:ident) => {
        #[wasm_bindgen]
        pub async fn $func_name(
            options: String,
            payload: String,
            config: JsValue,
        ) -> Result<String, JsValue> {
            let mut vade_evan = get_vade_evan(Some(&config)).map_err(jsify_generic_error)?;
            vade_evan
                .$func_name(&options, &payload)
                .await
                .map_err(jsify_vade_evan_error)
        }
    };
    ($func_name:ident, $did_or_method:ident, $options:ident, $payload:ident, $config:ident) => {
        #[wasm_bindgen]
        pub async fn $func_name(
            did_or_method: String,
            options: String,
            payload: String,
            config: JsValue,
        ) -> Result<String, JsValue> {
            let mut vade_evan = get_vade_evan(Some(&config)).map_err(jsify_generic_error)?;
            vade_evan
                .$func_name(&did_or_method, &options, &payload)
                .await
                .map_err(jsify_vade_evan_error)
        }
    };
    ($func_name:ident, $did_or_method:ident, $function:ident, $options:ident, $payload:ident, $config:ident) => {
        #[wasm_bindgen]
        pub async fn $func_name(
            did_or_method: String,
            custom_func_name: String,
            options: String,
            payload: String,
            config: JsValue,
        ) -> Result<String, JsValue> {
            let mut vade_evan = get_vade_evan(Some(&config)).map_err(jsify_generic_error)?;
            vade_evan
                .$func_name(&did_or_method, &custom_func_name, &options, &payload)
                .await
                .map_err(jsify_vade_evan_error)
        }
    };
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
    if #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs", feature = "vc-jwt"))] {
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(run_custom_function, did_or_method, custom_func_name, options, payload, config);
        #[cfg(feature = "vc-zkp-cl")]
        create_function!(vc_zkp_create_credential_definition, did_or_method, options, payload, config);
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(vc_zkp_create_credential_offer, did_or_method, options, payload, config);
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(vc_zkp_create_credential_proposal, did_or_method, options, payload, config);
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(vc_zkp_create_credential_schema, did_or_method, options, payload, config);
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(vc_zkp_create_revocation_registry_definition, did_or_method, options, payload, config);
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(vc_zkp_update_revocation_registry, did_or_method, options, payload, config);

        create_function!(vc_zkp_issue_credential, did_or_method, options, payload, config);

        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(vc_zkp_finish_credential, did_or_method, options, payload, config);
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(vc_zkp_present_proof, did_or_method, options, payload, config);
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(vc_zkp_request_credential, did_or_method, options, payload, config);
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(vc_zkp_request_proof, did_or_method, options, payload, config);
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        create_function!(vc_zkp_revoke_credential, did_or_method, options, payload, config);

        create_function!(vc_zkp_verify_proof, did_or_method, options, payload, config);

        #[wasm_bindgen]
        pub async fn get_version_info() -> Result<Option<String>, JsValue> {
            let vade_evan = get_vade_evan(None).map_err(jsify_generic_error)?;
            let version_info = vade_evan.get_version_info();
            Ok(Some(version_info))
        }

        #[wasm_bindgen]
        pub async fn create_credential_request(
            issuer_public_key: String,
            bbs_secret: String,
            credential_values: String,
            credential_offer: String,
            credential_schema: String 
        ) -> Result<Option<String>, JsValue> {

            let mut vade_evan = get_vade_evan(None).map_err(jsify_generic_error)?;
            let credential_result = vade_evan
            .create_credential_request(
                &issuer_public_key,
                &bbs_secret,
                &credential_values,
                &credential_offer,
                &credential_schema).await
                .map_err(jsify_vade_evan_error)?;
            Ok(Some(credential_result))
        }
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
            let value = match &key[..] {
                "signer" => DEFAULT_SIGNER,
                "target" => DEFAULT_TARGET,
                _ => return Err(Box::from(format!("invalid invalid config key '{}'", key))),
            };
            vec.push(value.to_string());
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
fn get_vade_evan(config: Option<&JsValue>) -> Result<VadeEvan, Box<dyn Error>> {
    let config_values =
        get_config_values(config, vec!["signer".to_string(), "target".to_string()])?;
    let (signer_config, target) = match config_values.as_slice() {
        [signer_config, target, ..] => (signer_config, target),
        _ => {
            return Err(Box::from("invalid vade config"));
        }
    };

    return VadeEvan::new(VadeEvanConfig {
        target,
        signer: signer_config,
    })
    .map_err(|err| Box::from(format!("could not create VadeEvan instance; {}", &err)));
}

fn jsify_generic_error(err: Box<dyn Error>) -> JsValue {
    JsValue::from(format!("{}", err))
}

fn jsify_vade_evan_error(err: VadeEvanError) -> JsValue {
    JsValue::from(format!("{}", err))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

#[allow(unused_variables)] // allow possibly unused variables due to feature mix
#[wasm_bindgen]
pub async fn execute_vade(
    func_name: String,
    did_or_method: String,
    options: String,
    payload: String,
    custom_func_name: String,
    config: JsValue,
) -> String {
    let result = match func_name.as_str() {
        #[cfg(feature = "did-read")]
        "did_resolve" => did_resolve(did_or_method, config).await,
        #[cfg(feature = "did-write")]
        "did_create" => did_create(did_or_method, options, payload, config).await,
        #[cfg(feature = "did-write")]
        "did_update" => did_update(did_or_method, options, payload, config).await,
        #[cfg(feature = "didcomm")]
        "didcomm_receive" => didcomm_receive(options, payload, config).await,
        #[cfg(feature = "didcomm")]
        "didcomm_send" => didcomm_send(options, payload, config).await,
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "run_custom_function" => {
            run_custom_function(did_or_method, custom_func_name, options, payload, config).await
        }
        #[cfg(feature = "vc-zkp-cl")]
        "vc_zkp_create_credential_definition" => {
            vc_zkp_create_credential_definition(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_create_credential_offer" => {
            vc_zkp_create_credential_offer(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_create_credential_proposal" => {
            vc_zkp_create_credential_proposal(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_create_credential_schema" => {
            vc_zkp_create_credential_schema(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_create_revocation_registry_definition" => {
            vc_zkp_create_revocation_registry_definition(did_or_method, options, payload, config)
                .await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_update_revocation_registry" => {
            vc_zkp_update_revocation_registry(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs", feature = "vc-jwt"))]
        "vc_zkp_issue_credential" => {
            vc_zkp_issue_credential(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_finish_credential" => {
            vc_zkp_finish_credential(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_present_proof" => {
            vc_zkp_present_proof(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_request_credential" => {
            vc_zkp_request_credential(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_request_proof" => {
            vc_zkp_request_proof(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_revoke_credential" => {
            vc_zkp_revoke_credential(did_or_method, options, payload, config).await
        }
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs", feature = "vc-jwt"))]
        "vc_zkp_verify_proof" => vc_zkp_verify_proof(did_or_method, options, payload, config).await,
        _ => {
            let empty_result = &String::new();
            return empty_result.to_string();
        }
    };

    let response = match result {
        Ok(value) => Response {
            response: Some(value.to_string()),
            error: None,
        },
        Err(e) => Response {
            response: None,
            error: Some(e.as_string().unwrap_or_default()),
        },
    };

    let serialized_response = serde_json::to_string(&response);
    let string_response = match serialized_response {
        Ok(string_result) => string_result,
        _ => "{\"error\": \"Failed to serialize response\"}".to_string(),
    };

    return string_response;
}
