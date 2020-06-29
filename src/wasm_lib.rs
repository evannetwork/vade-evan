
extern crate ursa;
extern crate secp256k1;
extern crate sha3;
extern crate hex;
extern crate console_error_panic_hook;

use console_log;

extern crate vade;
extern crate uuid;

use std::collections::HashMap;
use vade::{
    Vade,
};

use crate::{
    VadeTnt,
    application::prover::Prover,
    application::datatypes::{
        Credential,
        CredentialDefinition,
        CredentialRequest,
        CredentialSchema,
        CredentialSecretsBlindingFactors,
        MasterSecret,
        ProofRequest,
        SchemaProperty,
        RevocationRegistryDefinition,
    },
    resolver::{
      SubstrateDidResolverEvan,
      ResolverConfig
    },
    IssueCredentialResult
};
use ursa::cl::{
  Witness
};
use wasm_bindgen::prelude::*;
use serde_json::Value;
use serde::{Serialize, Deserialize};

fn get_vade() -> Vade {
  // vade to work with
  // let substrate_resolver = SubstrateDidResolverEvan::new();
  let identity = hex::decode("9670f7974e7021e4940c56d47f6b31fdfdd37de8").unwrap();
  let substrate_resolver = SubstrateDidResolverEvan::new(ResolverConfig{
    target: "13.69.59.185".to_string(),
    private_key: "4ea724e22ede0b7bea88771612485205cfc344131a16b8ab23d4970132be8dab".to_string(),
    identity: identity.clone(),
  });
  let substrate_resolver2 = SubstrateDidResolverEvan::new(ResolverConfig{
    target: "13.69.59.185".to_string(),
    private_key: "4ea724e22ede0b7bea88771612485205cfc344131a16b8ab23d4970132be8dab".to_string(),
    identity: identity.clone(),
  });
  let substrate_message_handler = SubstrateDidResolverEvan::new(ResolverConfig{
    target: "13.69.59.185".to_string(),
    private_key: "4ea724e22ede0b7bea88771612485205cfc344131a16b8ab23d4970132be8dab".to_string(),
    identity: identity.clone(),
  });
  let mut internal_vade = Vade::new();
  internal_vade.register_did_resolver(Box::from(substrate_resolver));
  internal_vade.register_message_consumer(&vec!["generateDid".to_owned(), "whitelistIdentity".to_owned(), "setDidDocument".to_owned()], Box::from(substrate_message_handler));

  let tnt = VadeTnt::new(internal_vade);
  let mut vade = Vade::new();
  vade.register_did_resolver(Box::from(substrate_resolver2));
  vade.register_message_consumer(
    &vec![
      "createCredentialSchema",
      "createCredentialDefinition",
      "createCredentialProposal",
      "createCredentialOffer",
      "createRevocationRegistryDefinition",
      "requestCredential",
      "issueCredential",
      "requestProof",
      "presentProof",
      "verifyProof",
      "whitelistIdentity",
    ].iter().map(|&x| String::from(x)).collect(),
    Box::from(tnt),
  );

  return vade;
}

#[wasm_bindgen]
pub async fn create_schema(issuer: String, schema_name: String, description: String, properties: String, required_properties: String, issuer_public_key_did: String, issuer_proving_key: String, private_key: String, identity: String) -> Result<String, JsValue>{
  let mut vade = get_vade();

  let message_str = format!(r###"{{
    "type": "createCredentialSchema",
    "data": {{
      "issuer": "{}",
      "schemaName": "{}",
      "description": "{}",
      "properties": {},
      "requiredProperties": {},
      "allowAdditionalProperties": false,
      "issuerPublicKeyDid": "{}",
      "issuerProvingKey": "{}",
      "privateKey": "{}",
      "identity": "{}"
    }}
  }}"###,
    issuer,
    schema_name,
    description,
    properties,
    required_properties,
    issuer_public_key_did,
    issuer_proving_key,
    private_key,
    identity
  );
  let results = vade.send_message(&message_str).await.unwrap();

  // check results
  assert_eq!(results.len(), 1);

  Ok(results[0].as_ref().unwrap().to_string())

}

#[wasm_bindgen]
pub async fn create_credential_definition(schema_id: String, issuer_did: String, issuer_public_key_did_id: String, issuer_private_key: String, private_key: String, identity: String) -> Result<String, JsValue> {
  let mut vade = get_vade();

  let message_str = format!(r###"{{
    "type": "createCredentialDefinition",
    "data": {{
      "schemaDid": "{}",
      "issuerDid": "{}",
      "issuerPublicKeyDid": "{}",
      "issuerProvingKey": "{}",
      "privateKey": "{}",
      "identity": "{}"
    }}
  }}"###, schema_id, issuer_did, issuer_public_key_did_id, issuer_private_key, private_key, identity);
  let results = vade.send_message(&message_str).await.unwrap();

  // check results
  assert_eq!(results.len(), 1);
  Ok(results[0].as_ref().unwrap().to_string())
}

#[wasm_bindgen]
pub async fn request_proof(schema_id: String, subject_did: String, issuer_did: String, revealed_attributes: String) -> Result<String, JsValue> {
    let mut vade = get_vade();

    let message_str = format!(
    r###"{{
        "type": "requestProof",
        "data": {{
            "verifierDid": "{}",
            "proverDid": "{}",
            "subProofRequests": [{{
                "schema": "{}",
                "revealedAttributes": {}
            }}]
        }}
    }}"###,
    issuer_did,
    subject_did,
    schema_id,
    revealed_attributes
    );
    let results = vade.send_message(&message_str).await.unwrap();

    // check results
    assert_eq!(results.len(), 1);

    Ok(results[0].as_ref().unwrap().to_string())
}

#[wasm_bindgen]
pub fn create_master_secret() -> String {
    serde_json::to_string(&ursa::cl::prover::Prover::new_master_secret().unwrap()).unwrap()
}


#[wasm_bindgen]
pub async fn create_credential_proposal (schema_id: String, subject_did: String, issuer_did: String) -> Result<String, JsValue> {
    let mut vade = get_vade();

    let message_str = format!(r###"{{
      "type": "createCredentialProposal",
      "data": {{
        "issuer": "{}",
        "subject": "{}",
        "schema": "{}"
      }}
    }}"###, issuer_did, subject_did, schema_id);
    let results = vade.send_message(&message_str).await.unwrap();

    // check results
    assert_eq!(results.len(), 1);

    Ok(results[0].as_ref().unwrap().to_string())
}

#[wasm_bindgen]
pub async fn create_credential_offer(proposal: String, credential_definition_id: String) -> Result<String, JsValue> {
    let mut vade = get_vade();
    let message_str = format!(r###"{{
      "type": "createCredentialOffer",
      "data": {}
    }}"###, proposal);
    let mut message_value: Value = serde_json::from_str(&message_str).unwrap();
    message_value["data"]["credentialDefinition"] = Value::from(credential_definition_id);
    let message_str = serde_json::to_string(&message_value).unwrap();

    let results = vade.send_message(&message_str).await.unwrap();

    // check results
    assert_eq!(results.len(), 1);

    Ok(results[0].as_ref().unwrap().to_string())
}

#[wasm_bindgen]
pub async fn create_credential_request(
    offer: String,
    master_secret: String,
    credential_values: String,
  ) -> Result<String, JsValue> {
    let mut vade = get_vade();
    let message_str = format!(r###"{{
        "type": "requestCredential",
        "data": {{
            "credentialOffering": {},
            "masterSecret": {},
            "credentialValues": {}
        }}
    }}"###, offer, master_secret, credential_values);
    let results = vade.send_message(&message_str).await.unwrap();

    // check results
    assert_eq!(results.len(), 1);

    Ok(results[0].as_ref().unwrap().to_string())
}

#[wasm_bindgen]
pub async fn create_revocation_registry_definition(credential_definition_id: String, max_credential_count: u32, issuer_public_key_did: String, issuer_private_key: String, private_key: String, identity: String) -> Result<String, JsValue> {
  let mut vade = get_vade();
    let message_str = format!(r###"{{
      "type": "createRevocationRegistryDefinition",
      "data": {{
        "credentialDefinition": "{}",
        "issuerPublicKeyDid": "{}",
        "issuerProvingKey": "{}",
        "maximumCredentialCount": {},
        "privateKey": "{}",
        "identity": "{}"
      }}
    }}"###, credential_definition_id, issuer_public_key_did, issuer_private_key, max_credential_count, private_key, identity);
    let results = vade.send_message(&message_str).await.unwrap();

    // check results
    assert_eq!(results.len(), 1);
    Ok(results[0].as_ref().unwrap().to_string())
  }

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
    subject_did: String
    ) -> Result<String, JsValue> {
    let mut vade = get_vade();
    debug!("get did {}", definition);
    let credential_definition_doc = vade.get_did_document(
      &definition
    ).await.unwrap();

    debug!("parse doc");
    let definition_parsed: CredentialDefinition = serde_json::from_str(&credential_definition_doc).unwrap();
    let request_parsed: CredentialRequest = serde_json::from_str(&request).unwrap();
    let blinding_factors_parsed: CredentialSecretsBlindingFactors = serde_json::from_str(&blinding_factors).unwrap();
    let master_secret_parsed: MasterSecret = serde_json::from_str(&master_secret).unwrap();
    let revocation_definition_doc = vade.get_did_document(
      &revocation_definition
    ).await.unwrap();
    let revocation_definition_parsed: RevocationRegistryDefinition = serde_json::from_str(&revocation_definition_doc).unwrap();

    let message_str = format!(
      r###"{{
        "type": "issueCredential",
        "data": {{
          "issuer": "{}",
          "subject": "{}",
          "credentialRequest": {},
          "credentialPrivateKey": {},
          "credentialRevocationDefinition": "{}",
          "revocationPrivateKey": {},
          "revocationInformation": {}
        }}
    }}"###,
    issuer_did,
    subject_did,
    request,
    credential_private_key,
    revocation_definition_parsed.id,
    revocation_key_private,
    revocation_info,
  );

  let results = vade.send_message(&message_str).await.unwrap();

  // check results
  assert_eq!(results.len(), 1);

  let mut result: IssueCredentialResult = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

  debug!("get did {}", result.credential.credential_schema.id);
    let schema_doc = vade.get_did_document(
      &result.credential.credential_schema.id
    ).await.unwrap();

  let schema: CredentialSchema = serde_json::from_str(&schema_doc).unwrap();
  Prover::post_process_credential_signature(
    &mut result.credential,
    &schema,
    &request_parsed,
    &definition_parsed,
    blinding_factors_parsed,
    &master_secret_parsed,
    &revocation_definition_parsed,
    &result.revocation_state.witness
  );

  Ok(serde_json::to_string(&result).unwrap())
}

#[wasm_bindgen]
pub fn set_panic_hook() {
  console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn set_log_level(log_level: String) {
  let _ = match log_level.as_str() {
    "debug" => console_log::init_with_level(log::Level::Debug),
    "info" => console_log::init_with_level(log::Level::Info),
    "error" => console_log::init_with_level(log::Level::Error),
    _ =>  console_log::init_with_level(log::Level::Error),
  };
}


#[wasm_bindgen]
pub async fn present_proof(
    proof_request: String,
    credential: String,
    master_secret: String,
    witness: String
  ) -> Result<String, JsValue> {
    let mut vade = get_vade();

    let proof_request_parsed: ProofRequest = serde_json::from_str(&proof_request).unwrap();
    let schema_did = &proof_request_parsed.sub_proof_requests[0].schema;
    let credential_parsed: Credential = serde_json::from_str(&credential).unwrap();
    let witness_parsed: Witness = serde_json::from_str(&witness).unwrap();
    let mut credentials: HashMap<String, Credential> = HashMap::new();
    credentials.insert(
        schema_did.clone(),
        serde_json::from_str(&credential).unwrap(),
    );

    let mut witnesses: HashMap<String, Witness> = HashMap::new();
    witnesses.insert(credential_parsed.id.clone(), witness_parsed.clone());

    let message_str = format!(
        r###"{{
            "type": "presentProof",
            "data": {{
                "proofRequest": {},
                "credentials": {},
                "witnesses": {},
                "masterSecret": {}
            }}
        }}"###,
        &proof_request,
        serde_json::to_string(&credentials).unwrap(),
        serde_json::to_string(&witnesses).unwrap(),
        &master_secret,
    );
    debug!("{}", &message_str);
    let results = vade.send_message(&message_str).await.unwrap();

    // check results
    assert_eq!(results.len(), 1);

    Ok(results[0].as_ref().unwrap().to_string())
  }

  #[wasm_bindgen]
  pub async fn verify_proof(
      presented_proof: String,
      proof_request: String
  ) -> Result<String, JsValue>  {
    let mut vade = get_vade();
    console_error_panic_hook::set_once();
      let message_str = format!(
          r###"{{
              "type": "verifyProof",
              "data": {{
                  "presentedProof": {},
                  "proofRequest": {}
              }}
          }}"###,
          presented_proof,
          proof_request
      );
      let results = vade.send_message(&message_str).await.unwrap();

      // check results
      assert_eq!(results.len(), 1);

      Ok(results[0].as_ref().unwrap().to_string())
  }

  #[wasm_bindgen]
  pub async fn whitelist_identity(private_key: String, identity: String) -> Result<String, JsValue> {
    let mut vade = get_vade();
    let message_str = format!(r###"{{
      "type": "whitelistIdentity",
      "data": {{
        "privateKey": "{}",
        "identity": "{}"
      }}
    }}"###, private_key, identity);

    let result = vade.send_message(&message_str).await.unwrap();

    Ok("".to_string())
  }
