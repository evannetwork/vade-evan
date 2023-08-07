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
#[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
use crate::in3_request_list::ResolveHttpRequest;
use serde::Serialize;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
#[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
use std::os::raw::c_void;
use std::slice;
use std::{collections::HashMap, error::Error};
use tokio::runtime::Builder;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

macro_rules! execute_vade_function {
    ($func_name:ident, $did_or_method:expr, $config:expr, #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] $request_id:expr, #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] $callback:expr) => {
        async {
            let mut vade_evan = get_vade_evan(
                Some(&$config.to_string()),
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                $request_id,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                $callback,
            )
            .map_err(stringify_generic_error)?;
            vade_evan
                .$func_name($did_or_method)
                .await
                .map_err(stringify_vade_evan_error)
        }
    };

    ($func_name:ident, $options:expr, $payload:expr, $config:expr,  #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] $request_id:expr, #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] $callback:expr) => {
        async {
            let mut vade_evan = get_vade_evan(
                Some(&$config),
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                $request_id,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                $callback,
            )
            .map_err(stringify_generic_error)?;
            vade_evan
                .$func_name(&$options, &$payload)
                .await
                .map_err(stringify_vade_evan_error)
        }
    };

    ($func_name:ident, $did_or_method:expr, $options:expr, $payload:expr, $config:expr, #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] $request_id:expr, #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] $callback:expr) => {
        async {
            let mut vade_evan = get_vade_evan(
                Some(&$config),
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                $request_id,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                $callback,
            )
            .map_err(stringify_generic_error)?;
            vade_evan
                .$func_name($did_or_method, $options, $payload)
                .await
                .map_err(stringify_vade_evan_error)
        }
    };

    ($func_name:ident, $did_or_method:expr, $function:expr, $options:expr, $payload:expr, $config:expr,  #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] $request_id:expr, #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] $callback:expr) => {
        async {
            let mut vade_evan = get_vade_evan(
                Some(&$config),
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                $request_id,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                $callback,
            )
            .map_err(stringify_generic_error)?;
            vade_evan
                .$func_name($did_or_method, $function, $options, $payload)
                .await
                .map_err(stringify_vade_evan_error)
        }
    };
}

fn stringify_generic_error(err: Box<dyn Error>) -> String {
    format!("{}", err)
}

fn stringify_vade_evan_error(err: VadeEvanError) -> String {
    format!("{}", err)
}

#[allow(unused_variables)] // allow possibly unused variables due to feature mix
pub fn get_vade_evan(
    config: Option<&String>,
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] request_id: *const c_void,
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
    request_function_callback: ResolveHttpRequest,
) -> Result<VadeEvan, Box<dyn Error>> {
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
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_id,
        #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
        request_function_callback,
    })
    .map_err(|err| Box::from(format!("could not create VadeEvan instance; {}", &err)));
}

fn get_config_values(
    config: Option<&String>,
    keys: Vec<String>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut vec = Vec::new();
    let mut config_undefined = true;

    let config_hash_map: HashMap<String, String>;
    match config {
        Some(value) => {
            if !value.is_empty() {
                config_hash_map = serde_json::from_str(&value)?;
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
                _ => return Err(Box::from(format!("invalid config key '{}'", key))),
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

/// Executes a vade call.
///
/// About the `config` argument setup used here:
///
/// - if built for C and having sdk target enabled: type is `*const c_void`
/// - for any other build: type is `*const c_char`
#[no_mangle]
pub extern "C" fn execute_vade(
    func_name: *const c_char,
    arguments: *const *const c_char,
    num_of_args: usize,
    options: *const c_char,
    #[cfg(all(feature = "c-lib", not(feature = "target-c-sdk")))] config: *const c_char,
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))] config: *const c_void,
    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
    request_function_callback: ResolveHttpRequest,
) -> *const c_char {
    let func = unsafe { CStr::from_ptr(func_name).to_string_lossy().into_owned() };
    let args_array: &[*const c_char] =
        unsafe { slice::from_raw_parts(arguments, num_of_args as usize) };
    // convert each element to a Rust string
    let arguments_vec: Vec<_> = args_array
        .iter()
        .map(|&v| {
            if !v.is_null() {
                unsafe { CStr::from_ptr(v).to_string_lossy().into_owned() }
            } else {
                String::new()
            }
        })
        .collect();

    let mut str_options = String::new();

    #[cfg(not(feature = "target-c-sdk"))]
    let mut str_config = String::new();
    #[cfg(feature = "target-c-sdk")]
    let str_config = String::new();

    if !options.is_null() {
        str_options = unsafe { CStr::from_ptr(options).to_string_lossy().into_owned() };
    }

    #[cfg(not(feature = "target-c-sdk"))]
    if !config.is_null() {
        str_config = unsafe { CStr::from_ptr(config).to_string_lossy().into_owned() };
    }

    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
    let ptr_request_list = config as *mut c_void;

    let no_args = String::from("");

    let runtime = Builder::new_current_thread()
        .enable_time()
        .enable_io()
        .build()
        .expect("Failed to create runtime");

    let result = match func.as_str() {
        #[cfg(feature = "did-read")]
        "did_resolve" => runtime.block_on({
            execute_vade_function!(
                did_resolve,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(feature = "did-write")]
        "did_create" => runtime.block_on({
            execute_vade_function!(
                did_create,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(feature = "did-sidetree")]
        "helper_did_create" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;
                vade_evan
                    .helper_did_create(
                        arguments_vec.get(0).map(|x| &**x),
                        arguments_vec.get(1).map(|x| &**x),
                        arguments_vec.get(2).map(|x| &**x),
                        arguments_vec.get(3).map(|x| &**x),
                        arguments_vec.get(4).map(|x| &**x),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)
            }
        }),
        #[cfg(feature = "did-write")]
        "did_update" => runtime.block_on({
            execute_vade_function!(
                did_update,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(feature = "did-sidetree")]
        "helper_did_update" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;
                vade_evan
                    .helper_did_update(
                        arguments_vec.get(0).unwrap_or_else(|| &no_args),
                        arguments_vec.get(1).unwrap_or_else(|| &no_args),
                        arguments_vec.get(2).unwrap_or_else(|| &no_args),
                        arguments_vec.get(3).unwrap_or_else(|| &no_args),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)
            }
        }),
        #[cfg(feature = "didcomm")]
        "didcomm_receive" => runtime.block_on({
            execute_vade_function!(
                didcomm_receive,
                &str_options,
                arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(feature = "didcomm")]
        "didcomm_send" => runtime.block_on({
            execute_vade_function!(
                didcomm_send,
                str_options,
                arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_create_credential_offer" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_create_credential_offer,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_create_credential_proposal" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_create_credential_proposal,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_create_credential_schema" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_create_credential_schema,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_create_revocation_registry_definition" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_create_revocation_registry_definition,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_update_revocation_registry" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_update_revocation_registry,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(feature = "vc-zkp")]
        "vc_zkp_issue_credential" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_issue_credential,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_finish_credential" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_finish_credential,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_present_proof" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_present_proof,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_request_credential" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_request_credential,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_propose_proof" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_propose_proof,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_request_proof" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_request_proof,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "vc_zkp_revoke_credential" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_revoke_credential,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(feature = "vc-zkp")]
        "vc_zkp_verify_proof" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_verify_proof,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
        "helper_create_credential_offer" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;
                let use_valid_until = match arguments_vec.get(1) {
                    Some(value) => value.to_lowercase() == "true",
                    None => false,
                };
                let is_credential_status_included = match arguments_vec.get(3) {
                    Some(value) => value.to_lowercase() == "true",
                    None => false,
                };
                vade_evan
                    .helper_create_credential_offer(
                        arguments_vec.get(0).unwrap_or_else(|| &no_args),
                        use_valid_until,
                        arguments_vec.get(2).unwrap_or_else(|| &no_args),
                        is_credential_status_included,
                        arguments_vec.get(4).unwrap_or_else(|| &no_args),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)
            }
        }),
        #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
        "helper_create_credential_request" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;
                vade_evan
                    .helper_create_credential_request(
                        arguments_vec.get(0).unwrap_or_else(|| &no_args),
                        arguments_vec.get(1).unwrap_or_else(|| &no_args),
                        arguments_vec.get(2).unwrap_or_else(|| &no_args),
                        arguments_vec.get(3).unwrap_or_else(|| &no_args),
                        arguments_vec.get(4).unwrap_or_else(|| &no_args),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)
            }
        }),
        #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
        "helper_verify_credential" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;
                vade_evan
                    .helper_verify_credential(
                        arguments_vec.get(0).unwrap_or_else(|| &no_args),
                        arguments_vec.get(1).unwrap_or_else(|| &no_args),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)?;
                Ok("".to_string())
            }
        }),

        #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
        "helper_revoke_credential" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;
                vade_evan
                    .helper_revoke_credential(
                        arguments_vec.get(0).unwrap_or_else(|| &no_args),
                        arguments_vec.get(1).unwrap_or_else(|| &no_args),
                        arguments_vec.get(2).unwrap_or_else(|| &no_args),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)?;
                Ok("".to_string())
            }
        }),
        #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
        "helper_create_self_issued_credential" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;
                vade_evan
                    .helper_create_self_issued_credential(
                        arguments_vec.get(0).unwrap_or_else(|| &no_args),
                        arguments_vec.get(1).unwrap_or_else(|| &no_args),
                        arguments_vec.get(2).map(|v| v.as_str()),
                        arguments_vec.get(3).unwrap_or_else(|| &no_args),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)
            }
        }),
        #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
        "helper_create_proof_proposal" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;

                vade_evan
                    .helper_create_proof_proposal(
                        arguments_vec.get(0).unwrap_or_else(|| &no_args),
                        arguments_vec.get(1).map(|v| v.as_str()),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)
            }
        }),
        #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
        "helper_create_proof_request" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;

                let first_arg = arguments_vec.get(0).unwrap_or_else(|| &no_args);
                match first_arg.starts_with("did:") {
                    // first arg starts with "did:", assume it's a schema
                    true => vade_evan
                        .helper_create_proof_request(
                            first_arg,
                            arguments_vec.get(1).map(|v| v.as_str()),
                        )
                        .await
                        .map_err(stringify_vade_evan_error),
                    // else assume it's a proposal
                    false => vade_evan
                        .helper_create_proof_request_from_proposal(first_arg)
                        .await
                        .map_err(stringify_vade_evan_error),
                }
            }
        }),
        #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
        "helper_create_presentation" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;
                vade_evan
                    .helper_create_presentation(
                        arguments_vec.get(0).unwrap_or_else(|| &no_args),
                        arguments_vec.get(1).unwrap_or_else(|| &no_args),
                        arguments_vec.get(2).unwrap_or_else(|| &no_args),
                        arguments_vec.get(3).map(|v| v.as_str()),
                        arguments_vec.get(4).map(|v| v.as_str()),
                        arguments_vec.get(5).map(|v| v.as_str()),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)
            }
        }),
        #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
        "helper_create_self_issued_presentation" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;
                vade_evan
                    .helper_create_self_issued_presentation(
                        arguments_vec.get(0).unwrap_or_else(|| &no_args),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)
            }
        }),
        #[cfg(all(feature = "vc-zkp-bbs", feature = "did-sidetree"))]
        "helper_verify_presentation" => runtime.block_on({
            async {
                let mut vade_evan = get_vade_evan(
                    Some(&str_config),
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    ptr_request_list,
                    #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                    request_function_callback,
                )
                .map_err(stringify_generic_error)?;
                vade_evan
                    .helper_verify_presentation(
                        arguments_vec.get(0).unwrap_or_else(|| &no_args),
                        arguments_vec.get(1).unwrap_or_else(|| &no_args),
                    )
                    .await
                    .map_err(stringify_vade_evan_error)
            }
        }),
        #[cfg(any(feature = "vc-zkp-bbs"))]
        "run_custom_function" => runtime.block_on({
            execute_vade_function!(
                run_custom_function,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(2).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                ptr_request_list,
                #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
                request_function_callback
            )
        }),
        "get_version_info" => get_vade_evan(
            Some(&str_config),
            #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
            ptr_request_list,
            #[cfg(all(feature = "c-lib", feature = "target-c-sdk"))]
            request_function_callback,
        )
        .map_err(stringify_generic_error)
        .map(|vade_evan| vade_evan.get_version_info()),
        _ => Err("Function not supported by Vade".to_string()),
    };

    let response = match result.as_ref() {
        Ok(value) => Response {
            response: Some(value.to_string()),
            error: None,
        },
        Err(e) => Response {
            response: None,
            error: Some(e.to_string()),
        },
    };

    let serialized_response = serde_json::to_string(&response);
    let string_response = match serialized_response {
        Ok(string_result) => string_result,
        _ => "{\"error\": \"Failed to serialize response\"}".to_string(),
    };

    return CString::new(string_response)
        .expect("CString::new failed to convert response")
        .into_raw();
}
