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

#[cfg(feature = "sdk")]
use crate::in3_request_list::ResolveHttpRequest;
use crate::vade_utils::{get_config_default, get_vade as get_vade_from_utils};
use serde::Serialize;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
#[cfg(feature = "sdk")]
use std::os::raw::c_void;
use std::slice;
use std::{collections::HashMap, error::Error};
use tokio::runtime::Builder;

use vade::Vade;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

macro_rules! handle_results {
    ($func_name:expr, $did_or_method:expr, $results:expr) => {
        let err_msg = format!(
            "'{}' did not return any result for '{}'",
            $func_name, $did_or_method,
        );
        ensure($results.len() > 0, || (&err_msg).to_string())?;

        let empty_result = &String::new();
        return Ok(Some(
            $results[0].as_ref().unwrap_or(empty_result).to_string(),
        ))
    };
}

macro_rules! execute_vade_function {
    ($func_name:ident, $did_or_method:expr, $config:expr, #[cfg(feature = "sdk")] $request_id:expr, #[cfg(feature = "sdk")] $callback:expr) => {
        async {
            let mut vade = get_vade(Some(&$config.to_string()), #[cfg(feature = "sdk")] $request_id, #[cfg(feature = "sdk")] $callback).map_err(to_err_str)?;
            let results = vade.$func_name($did_or_method).await.map_err(to_err_str)?;
            handle_results!(stringify!($func_name), stringify!($did_or_method), results);
        }
    };

    ($func_name:ident, $options:expr, $payload:expr, $config:expr,  #[cfg(feature = "sdk")] $request_id:expr, #[cfg(feature = "sdk")] $callback:expr) => {
        async {
            let mut vade = get_vade(Some(&$config), #[cfg(feature = "sdk")] $request_id, #[cfg(feature = "sdk")] $callback).map_err(to_err_str)?;
            let results = vade
                .$func_name(&$options, &$payload)
                .await
                .map_err(to_err_str)?;
            let name = stringify!($func_name);
            handle_results!(&name, &name, results);
        }
    };

    ($func_name:ident, $did_or_method:expr, $options:expr, $payload:expr, $config:expr, #[cfg(feature = "sdk")] $request_id:expr, #[cfg(feature = "sdk")] $callback:expr) => {
        async {
            let mut vade = get_vade(Some(&$config), #[cfg(feature = "sdk")] $request_id, #[cfg(feature = "sdk")] $callback).map_err(to_err_str)?;
            let results = vade
                .$func_name($did_or_method, $options, $payload)
                .await
                .map_err(to_err_str)?;
            handle_results!(stringify!($func_name), stringify!($did_or_method), results);
        }
    };

    ($func_name:ident, $did_or_method:expr, $function:expr, $options:expr, $payload:expr, $config:expr,  #[cfg(feature = "sdk")] $request_id:expr, #[cfg(feature = "sdk")] $callback:expr) => {
        async {
            let mut vade = get_vade(Some(&$config), #[cfg(feature = "sdk")] $request_id, #[cfg(feature = "sdk")] $callback).map_err(to_err_str)?;
            let results = vade
                .$func_name($did_or_method, $function, $options, $payload)
                .await
                .map_err(to_err_str)?;
            handle_results!(
                format!("{}: {}", stringify!($func_name), $function),
                $did_or_method,
                results
            );
        }
    };
}

fn ensure<F>(condition: bool, create_msg: F) -> Result<(), String>
where
    F: FnOnce() -> String,
{
    if condition {
        Ok(())
    } else {
        Err(create_msg().to_string())
    }
}

fn to_err_str(err: Box<dyn Error>) -> String {
    format!("{}", err)
}

#[allow(unused_variables)] // allow possibly unused variables due to feature mix
pub fn get_vade(
    config: Option<&String>,
    #[cfg(feature = "sdk")] request_id: *const c_void,
    #[cfg(feature = "sdk")] request_function_callback: ResolveHttpRequest,
) -> Result<Vade, Box<dyn Error>> {
    let config_values =
        get_config_values(config, vec!["signer".to_string(), "target".to_string()])?;
    let (signer_config, target) = match config_values.as_slice() {
        [signer_config, target, ..] => (signer_config, target),
        _ => {
            return Err(Box::from("invalid vade config"));
        }
    };
    return get_vade_from_utils(
        target,
        signer_config,
        #[cfg(feature = "sdk")]
        request_id,
        #[cfg(feature = "sdk")]
        request_function_callback,
    );
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

#[no_mangle]
pub extern "C" fn execute_vade(
    func_name: *const c_char,
    arguments: *const *const c_char,
    num_of_args: usize,
    options: *const c_char,
    #[cfg(not(feature = "sdk"))] config: *const c_char,
    #[cfg(feature = "sdk")] config: *const c_void,
    #[cfg(feature = "sdk")] request_function_callback: ResolveHttpRequest,
) -> *const c_char {
    let func = unsafe { CStr::from_ptr(func_name).to_string_lossy().into_owned() };
    let args_array: &[*const c_char] =
        unsafe { slice::from_raw_parts(arguments, num_of_args as usize) };

    // convert each element to a Rust string
    let arguments_vec: Vec<_> = args_array
        .iter()
        .map(|&v| unsafe { CStr::from_ptr(v).to_string_lossy().into_owned() })
        .collect();

    let mut str_options = String::new();

    #[cfg(not(feature = "sdk"))]
    let mut str_config = String::new();
    #[cfg(feature = "sdk")]
    let str_config = String::new();

    if !options.is_null() {
        str_options = unsafe { CStr::from_ptr(options).to_string_lossy().into_owned() };
    }

    #[cfg(not(feature = "sdk"))]
    if !config.is_null() {
        str_config = unsafe { CStr::from_ptr(config).to_string_lossy().into_owned() };
    }

    #[cfg(feature = "sdk")]
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
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
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
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(feature = "did-write")]
        "did_update" => runtime.block_on({
            execute_vade_function!(
                did_update,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(feature = "didcomm")]
        "didcomm_receive" => runtime.block_on({
            execute_vade_function!(
                didcomm_receive,
                &str_options,
                arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
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
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(feature = "vc-zkp-cl")]
        "vc_zkp_create_credential_definition" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_create_credential_definition,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_create_credential_offer" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_create_credential_offer,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_create_credential_proposal" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_create_credential_proposal,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_create_credential_schema" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_create_credential_schema,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_create_revocation_registry_definition" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_create_revocation_registry_definition,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_update_revocation_registry" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_update_revocation_registry,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs", feature = "vc-jwt"))]
        "vc_zkp_issue_credential" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_issue_credential,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_finish_credential" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_finish_credential,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_present_proof" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_present_proof,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_request_credential" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_request_credential,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_request_proof" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_request_proof,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "vc_zkp_revoke_credential" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_revoke_credential,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs", feature = "vc-jwt"))]
        "vc_zkp_verify_proof" => runtime.block_on({
            execute_vade_function!(
                vc_zkp_verify_proof,
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        #[cfg(any(feature = "vc-zkp-cl", feature = "vc-zkp-bbs"))]
        "run_custom_function" => runtime.block_on({
            execute_vade_function!(
                run_custom_function,
                arguments_vec.get(1).unwrap_or_else(|| &no_args),
                arguments_vec.get(0).unwrap_or_else(|| &no_args),
                &str_options,
                arguments_vec.get(2).unwrap_or_else(|| &no_args),
                str_config,
                #[cfg(feature = "sdk")]
                ptr_request_list,
                #[cfg(feature = "sdk")]
                request_function_callback
            )
        }),
        _ => Err("Function not supported by Vade".to_string()),
    };

    let response = match result.as_ref() {
        Ok(Some(value)) => Response {
            response: Some(value.to_string()),
            error: None,
        },
        Err(e) => Response {
            response: None,
            error: Some(e.to_string()),
        },
        _ => Response {
            response: None,
            error: Some("Unknown error".to_string()),
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
