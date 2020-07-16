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
use vade::Vade;
use wasm_bindgen::prelude::*;
// did
#[cfg(feature = "did")]
use crate::resolver::{ResolverConfig, SubstrateDidResolverEvan};
#[cfg(feature = "did")]
use std::env;
// vc-zkp
#[cfg(feature = "vc-zkp")]
use std::collections::HashMap;
#[cfg(feature = "vc-zkp")]
use crate::VadeEvan;
#[cfg(feature = "vc-zkp")]
use crate::{
    application::{
        datatypes::{
            Credential,
            CredentialDefinition,
            CredentialOffer,
            CredentialRequest,
            CredentialSchema,
            CredentialSecretsBlindingFactors,
            MasterSecret,
            ProofRequest,
            RevocationRegistryDefinition,
        },
        prover::Prover,
    },
    IssueCredentialResult,
};
#[cfg(feature = "vc-zkp")]
use serde_json::Value;
#[cfg(feature = "vc-zkp")]
use ursa::cl::Witness;

#[cfg(feature = "vc-zkp")]
const EVAN_METHOD: &str = "did:evan";

/// small drop-in replacement for asserts
/// if condition is false, will evaluate `create_msg` function and return an Err with it
fn ensure<F>(condition: bool, create_msg: F)
    -> Result<(), JsValue>
    where F: FnOnce() -> String
{
    if condition {
        Ok(())
    } else {
        Err(JsValue::from(&create_msg().to_string()))
    }
}

// shared
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

// did
#[cfg(feature = "did")]
#[wasm_bindgen]
pub async fn did_resolve(
    did: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;
    let results = vade
        .did_resolve(&did)
        .await
        .map_err(jsify)?;

    let err_msg = "could not get DID document";
    ensure(results.len() > 0, || format!("{}: '{}'", &err_msg, &did))?;

    Ok(results[0]
        .as_ref()
        .ok_or_else(|| err_msg.to_string())?
        .to_string())
}

// did
#[cfg(feature = "did")]
#[wasm_bindgen]
pub async fn did_update(
    did: String,
    options: String,
    payload: String,
) -> Result<(), JsValue> {
    let mut vade = get_vade().map_err(jsify)?;
    let results = vade
        .did_update(&did, &options, &payload)
        .await
        .map_err(jsify)?;

    let err_msg = "could not update DID document";
    ensure(results.len() > 0, || format!("{}: '{}'", &err_msg, &did))?;

    Ok(())
}

// vc-zkp
#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub async fn create_schema(
    issuer: String,
    schema_name: String,
    description: String,
    properties: String,
    required_properties: String,
    issuer_public_key_did: String,
    issuer_proving_key: String,
    private_key: String,
    identity: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;

    let options = get_options(private_key, identity);
    let payload = format!(
        r###"{{
            "issuer": "{}",
            "schemaName": "{}",
            "description": "{}",
            "properties": {},
            "requiredProperties": {},
            "allowAdditionalProperties": false,
            "issuerPublicKeyDid": "{}",
            "issuerProvingKey": "{}"
        }}"###,
        issuer,
        schema_name,
        description,
        properties,
        required_properties,
        issuer_public_key_did,
        issuer_proving_key,
    );
    let results = vade
        .vc_zkp_create_credential_schema(EVAN_METHOD, &options, &payload)
        .await
        .map_err(jsify)?;

    let err_msg = "could not create schema";
    ensure(results.len() > 0, || &err_msg)?;

    Ok(results[0]
        .as_ref()
        .ok_or(&err_msg)?
        .to_string())
}

#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub async fn create_credential_definition(
    schema_id: String,
    issuer_did: String,
    issuer_public_key_did_id: String,
    issuer_private_key: String,
    private_key: String,
    identity: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;

    let options = get_options(private_key, identity);
    let payload = format!(
        r###"{{
        "schemaDid": "{}",
        "issuerDid": "{}",
        "issuerPublicKeyDid": "{}",
        "issuerProvingKey": "{}"
    }}"###,
        schema_id, issuer_did, issuer_public_key_did_id, issuer_private_key
    );
    let results = vade
        .vc_zkp_create_credential_definition(EVAN_METHOD, &options, &payload)
        .await
        .map_err(jsify)?;

    let err_msg = "could not create credential definition";
    ensure(results.len() > 0, || &err_msg)?;

    Ok(results[0]
        .as_ref()
        .ok_or(&err_msg)?
        .to_string())
}

#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub async fn request_proof(
    schema_id: String,
    subject_did: String,
    issuer_did: String,
    revealed_attributes: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;

    let payload = format!(
        r###"{{
          "verifierDid": "{}",
          "proverDid": "{}",
          "subProofRequests": [{{
              "schema": "{}",
              "revealedAttributes": {}
          }}]
        }}"###,
        issuer_did, subject_did, schema_id, revealed_attributes,
    );
    let results = vade
        .vc_zkp_request_proof(EVAN_METHOD, "", &payload)
        .await
        .map_err(jsify)?;

    let err_msg = "could not create proof request";
    ensure(results.len() > 0, || &err_msg)?;

    Ok(results[0]
        .as_ref()
        .ok_or(&err_msg)?
        .to_string())
}

#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub fn create_master_secret() -> Result<String, JsValue> {
    serde_json::to_string(&ursa::cl::prover::Prover::new_master_secret()?)
        .map_err(|e| JsValue::from(format!("{}", e)))
}

#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub async fn create_credential_proposal(
    schema_id: String,
    subject_did: String,
    issuer_did: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;

    let payload = format!(
        r###"{{
          "issuer": "{}",
          "subject": "{}",
          "schema": "{}"
      }}"###,
        issuer_did, subject_did, schema_id
    );
    let results = vade
        .vc_zkp_create_credential_proposal(EVAN_METHOD, "", &payload)
        .await
        .map_err(jsify)?;

    let err_msg = "could not create credential proposal";
    ensure(results.len() > 0, || &err_msg)?;

    Ok(results[0]
        .as_ref()
        .ok_or(&err_msg)?
        .to_string())
}

#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub async fn create_credential_offer(
    proposal: String,
    credential_definition_id: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;
    let mut message_value: Value = serde_json::from_str(&proposal).map_err(jsify_serde)?;
    message_value["credentialDefinition"] = Value::from(credential_definition_id);
    let payload = serde_json::to_string(&message_value).map_err(jsify_serde)?;

    let results = vade
        .vc_zkp_create_credential_offer(EVAN_METHOD, "", &payload)
        .await
        .map_err(jsify)?;
    let err_msg = "could not create credential offer";
    ensure(results.len() > 0, || &err_msg)?;

    Ok(results[0]
        .as_ref()
        .ok_or(&err_msg)?
        .to_string())
}

#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub async fn create_credential_request(
    offer: String,
    master_secret: String,
    credential_values: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;
    let offer_object: CredentialOffer = serde_json::from_str(&offer).map_err(jsify_serde)?;
    let results = vade
        .did_resolve(&offer_object.schema)
        .await
        .map_err(jsify)?;
    let schema = results[0]
        .as_ref()
        .ok_or("could not get schema did document")?;
    let payload = format!(
        r###"{{
            "credentialOffering": {},
            "credentialSchema": {},
            "masterSecret": {},
            "credentialValues": {}
        }}"###,
        offer, schema, master_secret, credential_values,
    );
    let results = vade
        .vc_zkp_request_credential(EVAN_METHOD, "", &payload)
        .await
        .map_err(jsify)?;

    let err_msg = "could not create credential request";
    ensure(results.len() > 0, || &err_msg);

    Ok(results[0]
        .as_ref()
        .ok_or(&err_msg)?
        .to_string())
}

#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub async fn create_revocation_registry_definition(
    credential_definition_id: String,
    max_credential_count: u32,
    issuer_public_key_did: String,
    issuer_private_key: String,
    private_key: String,
    identity: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;

    let options = get_options(private_key, identity);
    let payload = format!(
        r###"{{
        "credentialDefinition": "{}",
        "issuerPublicKeyDid": "{}",
        "issuerProvingKey": "{}",
        "maximumCredentialCount": {}
    }}"###,
        credential_definition_id, issuer_public_key_did, issuer_private_key, max_credential_count
    );
    let results = vade
        .vc_zkp_create_revocation_registry_definition(EVAN_METHOD, &options, &payload)
        .await
        .map_err(jsify)?;

    let err_msg = "could not create revocation registry definition";
    ensure(results.len() > 0, || &err_msg);

    Ok(results[0]
        .as_ref()
        .ok_or(&err_msg)?
        .to_string())
}

#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub async fn issue_credential(
    definition: String,
    credential_private_key: String,
    request: String,
    revocation_key_private: String,
    revocation_info: String,
    revocation_definition: String,
    blinding_factors: String,
    master_secret: String,
    issuer_did: String,
    subject_did: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;
    debug!("get did {}", definition);
    let results = &vade.did_resolve(&definition).await.map_err(jsify)?;
    let credential_definition_doc = results[0]
        .as_ref()
        .ok_or("could not get credential definition did document")?;

    debug!("parse doc");
    let definition_parsed: CredentialDefinition =
        serde_json::from_str(&credential_definition_doc).map_err(jsify_serde)?;
    let request_parsed: CredentialRequest = serde_json::from_str(&request).map_err(jsify_serde)?;
    let blinding_factors_parsed: CredentialSecretsBlindingFactors =
        serde_json::from_str(&blinding_factors).map_err(jsify_serde)?;
    let master_secret_parsed: MasterSecret =
        serde_json::from_str(&master_secret).map_err(jsify_serde)?;
    let results = &vade
        .did_resolve(&revocation_definition)
        .await
        .map_err(jsify)?;
    let revocation_definition_doc = results[0]
        .as_ref()
        .ok_or("could not get revocation registry did document")?;
    let revocation_definition_parsed: RevocationRegistryDefinition =
        serde_json::from_str(&revocation_definition_doc).map_err(jsify_serde)?;

    let payload = format!(
        r###"{{
          "issuer": "{}",
          "subject": "{}",
          "credentialRequest": {},
          "credentialPrivateKey": {},
          "credentialRevocationDefinition": "{}",
          "revocationPrivateKey": {},
          "revocationInformation": {}
      }}"###,
        issuer_did,
        subject_did,
        request,
        credential_private_key,
        revocation_definition_parsed.id,
        revocation_key_private,
        revocation_info,
    );

    let results = vade
        .vc_zkp_issue_credential(EVAN_METHOD, "", &payload)
        .await
        .map_err(jsify)?;

    let err_msg = "could not issue credential";
    ensure(results.len() > 0, || &err_msg);
    let mut result: IssueCredentialResult =
        serde_json::from_str(
            results[0]
                .as_ref()
                .ok_or(err_msg)?
            )
            .map_err(jsify_serde)?;
    debug!("get did {}", result.credential.credential_schema.id);
    let results = vade
        .did_resolve(&result.credential.credential_schema.id)
        .await
        .map_err(jsify)?;

    let err_msg = "could not get schema did document";
    ensure(results.len() > 0, || &err_msg);

    let schema_doc = results[0]
        .as_ref()
        .ok_or(&err_msg)?;

    let schema: CredentialSchema = serde_json::from_str(&schema_doc).map_err(jsify_serde)?;
    Prover::post_process_credential_signature(
        &mut result.credential,
        &schema,
        &request_parsed,
        &definition_parsed,
        blinding_factors_parsed,
        &master_secret_parsed,
        &revocation_definition_parsed,
        &result.revocation_state.witness,
    )
    .map_err(jsify)?;

    Ok(serde_json::to_string(&result).map_err(jsify_serde)?)
}

#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub async fn present_proof(
    proof_request: String,
    credential: String,
    master_secret: String,
    witness: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;

    let proof_request_parsed: ProofRequest =
        serde_json::from_str(&proof_request).map_err(jsify_serde)?;
    let schema_did = &proof_request_parsed.sub_proof_requests[0].schema;
    let credential_parsed: Credential = serde_json::from_str(&credential).map_err(jsify_serde)?;
    let witness_parsed: Witness = serde_json::from_str(&witness).map_err(jsify_serde)?;
    let mut credentials: HashMap<String, Credential> = HashMap::new();
    credentials.insert(
        schema_did.clone(),
        serde_json::from_str(&credential).map_err(jsify_serde)?,
    );

    let mut witnesses: HashMap<String, Witness> = HashMap::new();
    witnesses.insert(credential_parsed.id.clone(), witness_parsed.clone());

    let payload = format!(
        r###"{{
            "proofRequest": {},
            "credentials": {},
            "witnesses": {},
            "masterSecret": {}
        }}"###,
        &proof_request,
        serde_json::to_string(&credentials).map_err(jsify_serde)?,
        serde_json::to_string(&witnesses).map_err(jsify_serde)?,
        &master_secret,
    );
    debug!("{}", &payload);
    let results = vade
        .vc_zkp_present_proof(EVAN_METHOD, "", &payload)
        .await
        .map_err(jsify)?;

    // check results
    let err_msg = "could not create proof presentation";
    ensure(results.len() > 0, || &err_msg);

    Ok(results[0]
        .as_ref()
        .ok_or(&err_msg)?
        .to_string())
}

#[cfg(feature = "vc-zkp")]
#[wasm_bindgen]
pub async fn verify_proof(
    presented_proof: String,
    proof_request: String,
) -> Result<String, JsValue> {
    let mut vade = get_vade().map_err(jsify)?;
    console_error_panic_hook::set_once();
    let payload = format!(
        r###"{{
              "presentedProof": {},
              "proofRequest": {}
          }}"###,
        presented_proof, proof_request
    );
    let results = vade
        .vc_zkp_verify_proof(EVAN_METHOD, "", &payload)
        .await
        .map_err(jsify)?;

    // check results
    let err_msg = "could not verify proof";
    ensure(results.len() > 0, || &err_msg);

    Ok(results[0]
        .as_ref()
        .ok_or(&err_msg)?
        .to_string())
}

/// Whitelists a specific evan did on substrate that this private key can create DIDs.
///
/// # Arguments
///
/// * `did` - Substrate identity to whitelist (e.g. did:evan:0x12345)
/// * `private_key` - private key (without '0x' prefix)
/// * `identity` - identity without prefix (e.g. 12345)
#[cfg(feature = "did")]
#[wasm_bindgen]
pub async fn whitelist_identity(
    did: String,
    private_key: String,
    identity: String,
) -> Result<(), JsValue> {
    let mut vade = get_vade().map_err(jsify)?;
    let payload = format!(
        r###"{{
            "privateKey": "{}",
            "identity": "{}",
            "operation": "whitelistIdentity"
        }}"###,
        private_key, identity,
    );

    let results = vade.did_update(&did, &payload, &"".to_string())
        .await
        .map_err(jsify)?;
    
    ensure(
        results.len() > 0,
        || format!("could not whitelist identity '{}', no response from plugins", &did)
    )?;

    Ok(())
}

#[cfg(feature = "vc-zkp")]
fn get_options(private_key: String, identity: String) -> String {
    format!(
        r###"{{
            "privateKey": "{}",
            "identity": "{}"
        }}"###,
        private_key, identity,
    )
}

fn get_vade() -> Result<Vade, Box<dyn std::error::Error>> {
    let mut vade = Vade::new();

    #[cfg(feature = "did")]
    vade.register_plugin(Box::from(SubstrateDidResolverEvan::new(ResolverConfig {
        signing_url: env::var("VADE_EVAN_SIGNING_URL").unwrap_or_else(
            |_| "https://tntkeyservices-e0ae.azurewebsites.net/api/key/sign".to_string()),
        target: env::var("VADE_EVAN_SUBSTRATE_IP").unwrap_or_else(|_| "13.69.59.185".to_string()),
    })));
    #[cfg(feature = "vc-zkp")]
    vade.register_plugin(Box::from(get_vade_evan()?));

    Ok(vade)
}

#[cfg(feature = "vc-zkp")]
fn get_vade_evan() -> Result<VadeEvan, Box<dyn std::error::Error>> {
    #[cfg(not(feature = "did"))]
    let internal_vade = Vade::new();
    #[cfg(feature = "did")]
    let mut internal_vade = Vade::new();
    internal_vade.register_plugin(Box::from(substrate_resolver));
    #[cfg(feature = "did")]
    internal_vade.register_plugin(Box::from(SubstrateDidResolverEvan::new(ResolverConfig {
        signing_url: env::var("VADE_EVAN_SIGNING_URL").unwrap_or_else(
            |_| "https://tntkeyservices-e0ae.azurewebsites.net/api/key/sign".to_string()),
        target: env::var("VADE_EVAN_SUBSTRATE_IP").unwrap_or_else(|_| "13.69.59.185".to_string()),
    })));

    Ok(VadeEvan::new(internal_vade, &signing_url))
}

fn jsify(err: Box<dyn std::error::Error>) -> JsValue {
    JsValue::from(format!("{}", err))
}

#[cfg(feature = "vc-zkp")]
fn jsify_serde(err: serde_json::error::Error) -> JsValue {
    JsValue::from(format!("{}", err))
}
