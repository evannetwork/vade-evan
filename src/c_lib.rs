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

use crate::vade_utils::{get_config_default, get_vade as get_vade_from_utils};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::slice;
use std::{collections::HashMap, error::Error};
use tokio::runtime::Builder;
use vade::Vade;

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

macro_rules! create_function {
    ($func_name:ident, $did_or_method:ident, $config:ident) => {
        pub async fn $func_name(
            did_or_method: String,
            config: String,
        ) -> Result<Option<String>, String> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade.$func_name(&did_or_method).await.map_err(jsify)?;
            handle_results!(stringify!($func_name), did_or_method, results);
        }
    };

    ($func_name:ident, $options:ident, $payload:ident, $config:ident) => {
        pub async fn $func_name(
            options: String,
            payload: String,
            config: String,
        ) -> Result<Option<String>, String> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade.$func_name(&options, &payload).await.map_err(jsify)?;
            let name = stringify!($func_name);
            handle_results!(&name, &name, results);
        }
    };

    ($func_name:ident, $did_or_method:ident, $options:ident, $payload:ident, $config:ident) => {
        pub async fn $func_name(
            did_or_method: String,
            options: String,
            payload: String,
            config: String,
        ) -> Result<Option<String>, String> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade
                .$func_name(&did_or_method, &options, &payload)
                .await
                .map_err(jsify)?;
            handle_results!(stringify!($func_name), did_or_method, results);
        }
    };

    ($func_name:ident, $did_or_method:ident, $function:ident, $options:ident, $payload:ident, $config:ident) => {
        pub async fn $func_name(
            did_or_method: String,
            function: String,
            options: String,
            payload: String,
            config: String,
        ) -> Result<Option<String>, String> {
            let mut vade = get_vade(Some(&config)).map_err(jsify)?;
            let results = vade
                .$func_name(&did_or_method, &function, &options, &payload)
                .await
                .map_err(jsify)?;
            handle_results!(
                format!("{}: {}", stringify!($func_name), &function),
                did_or_method,
                results
            );
        }
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
    if #[cfg(feature = "didcomm")] {
        create_function!(didcomm_receive, options, payload, config);
        create_function!(didcomm_send, options, payload, config);
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
        create_function!(vc_zkp_finish_credential, did_or_method, options, payload, config);
        create_function!(vc_zkp_present_proof, did_or_method, options, payload, config);
        create_function!(vc_zkp_request_credential, did_or_method, options, payload, config);
        create_function!(vc_zkp_request_proof, did_or_method, options, payload, config);
        create_function!(vc_zkp_revoke_credential, did_or_method, options, payload, config);
        create_function!(vc_zkp_verify_proof, did_or_method, options, payload, config);
    } else {
    }
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

fn jsify(err: Box<dyn Error>) -> String {
    format!("{}", err)
}

#[allow(unused_variables)] // allow possibly unused variables due to feature mix
pub fn get_vade(config: Option<&String>) -> Result<Vade, Box<dyn Error>> {
    println!("get_vade");
    let config_values =
        get_config_values(config, vec!["signer".to_string(), "target".to_string()])?;

    println!(
        "config {}",
        config_values.clone().into_iter().collect::<String>()
    );

    let (signer_config, target) = match config_values.as_slice() {
        [signer_config, target, ..] => (signer_config, target),
        _ => {
            return Err(Box::from("invalid vade config"));
        }
    };

    println!("(target {} signer_config {}", target, signer_config);
    return get_vade_from_utils(target, signer_config);
}

fn get_config_values(
    config: Option<&String>,
    keys: Vec<String>,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut vec = Vec::new();
    let mut config_undefined = true;

    let config_hash_map: HashMap<String, String>;
    // let config_values =

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
    config: *const c_char,
) -> *const c_char {
    let func = unsafe { CStr::from_ptr(func_name).to_string_lossy().into_owned() };
    let args_array: &[*const c_char] =
        unsafe { slice::from_raw_parts(arguments, num_of_args as usize) };
    // convert each element to a Rust string
    let arguments_vec: Vec<_> = args_array
        .iter()
        .map(|&v| unsafe { CStr::from_ptr(v).to_string_lossy().into_owned() })
        .collect();

    let options = unsafe { CStr::from_ptr(options).to_string_lossy().into_owned() };
    let config = unsafe { CStr::from_ptr(config).to_string_lossy().into_owned() };

    println!("function {}", func);
    println!(
        "args {}",
        arguments_vec.clone().into_iter().collect::<String>()
    );

    let no_args = String::from("");

    let runtime = Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("Failed to create runtime");

    let result = match func.as_str() {
        "did_resolve" => runtime.block_on(did_resolve(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "did_create" => runtime.block_on(did_create(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "did_update" => runtime.block_on(did_update(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "didcomm_receive" => runtime.block_on(didcomm_receive(
            options,
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "didcomm_send" => runtime.block_on(didcomm_send(
            options,
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_create_credential_definition" => {
            runtime.block_on(vc_zkp_create_credential_definition(
                arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
                options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
                config,
            ))
        }
        "vc_zkp_create_credential_offer" => runtime.block_on(vc_zkp_create_credential_offer(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_create_credential_proposal" => runtime.block_on(vc_zkp_create_credential_proposal(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_create_credential_schema" => runtime.block_on(vc_zkp_create_credential_schema(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_create_revocation_registry_definition" => {
            runtime.block_on(vc_zkp_create_revocation_registry_definition(
                arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
                options,
                arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
                config,
            ))
        }
        "vc_zkp_update_revocation_registry" => runtime.block_on(vc_zkp_update_revocation_registry(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_issue_credential" => runtime.block_on(vc_zkp_issue_credential(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_finish_credential" => runtime.block_on(vc_zkp_finish_credential(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_present_proof" => runtime.block_on(vc_zkp_present_proof(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_request_credential" => runtime.block_on(vc_zkp_request_credential(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_request_proof" => runtime.block_on(vc_zkp_request_proof(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_revoke_credential" => runtime.block_on(vc_zkp_revoke_credential(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "vc_zkp_verify_proof" => runtime.block_on(vc_zkp_verify_proof(
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),
        "run_custom_function" => runtime.block_on(run_custom_function(
            arguments_vec.get(1).unwrap_or_else(|| &no_args).to_owned(),
            arguments_vec.get(0).unwrap_or_else(|| &no_args).to_owned(),
            options,
            arguments_vec.get(2).unwrap_or_else(|| &no_args).to_owned(),
            config,
        )),

        _ => Err("Function Not Supported By Vade".to_string()),
    };

    let response = match result.as_ref() {
        Ok(Some(value)) => value.to_string(),
        Ok(_) => "Unknown Result".to_string(),
        Err(e) => e.to_string(),
    };

    println!(" respond {}", response);

    return CString::new(response).unwrap().into_raw();
}
