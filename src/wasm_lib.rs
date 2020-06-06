
extern crate ursa;
extern crate secp256k1;
extern crate sha3;
extern crate hex;

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
        RevocationRegistryDefinition
    },
    resolver::{
      SubstrateDidResolverEvan,
      ResolverConfig
    },
    IssueCredentialResult
};
use wasm_bindgen::prelude::*;
use serde_json::Value;

#[allow(dead_code)]
pub const SCHEMA_NAME: &'static str = "test_schema";

#[allow(dead_code)]
pub const SCHEMA_DESCRIPTION: &'static str = "Test description";

#[allow(dead_code)]
pub const SCHEMA_PROPERTIES: &'static str = r###"{
  "test_property_string": {
    "type": "string"
  }
}"###;

#[allow(dead_code)]
pub const SCHEMA_REQUIRED_PROPERTIES: &'static str = r###"[
  "test_property_string"
]"###;

#[allow(dead_code)]
pub const ISSUER_DID: &'static str = "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD1";
#[allow(dead_code)]
pub const ISSUER_PUBLIC_KEY_DID: &str =
    "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1";

#[allow(dead_code)]
pub const ISSUER_PRIVATE_KEY: &str =
    "d02f8a67f22ae7d1ffc5507ca9a4e6548024562a7b36881b7a29f66dd26c532e";

#[allow(dead_code)]
pub const SIGNER_PRIVATE_KEY: &str =
    "4ea724e22ede0b7bea88771612485205cfc344131a16b8ab23d4970132be8dab";

#[allow(dead_code)]
pub const SIGNER_IDENTITY: &str =
    "9670f7974e7021e4940c56d47f6b31fdfdd37de8";

#[allow(dead_code)]
pub const SUBJECT_DID: &'static str =
    "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD2";


fn get_vade() -> Vade {
  // vade to work with
  // let substrate_resolver = SubstrateDidResolverEvan::new();
  let identity = hex::decode("9670f7974e7021e4940c56d47f6b31fdfdd37de8").unwrap();
  let substrate_resolver = SubstrateDidResolverEvan::new(ResolverConfig{
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
pub async fn create_schema() -> Result<String, JsValue>{
  console_log::init_with_level(log::Level::Debug).unwrap();
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
  }}"###, ISSUER_DID, SCHEMA_NAME, SCHEMA_DESCRIPTION, SCHEMA_PROPERTIES, SCHEMA_REQUIRED_PROPERTIES, ISSUER_PUBLIC_KEY_DID, ISSUER_PRIVATE_KEY, SIGNER_PRIVATE_KEY, SIGNER_IDENTITY);
  let results = vade.send_message(&message_str).await.unwrap();

  // check results
  assert_eq!(results.len(), 1);

  Ok(results[0].as_ref().unwrap().to_string())

}

#[wasm_bindgen]
pub async fn create_credential_definition(schema_id: String) -> Result<String, JsValue> {
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
  }}"###, schema_id, ISSUER_DID, ISSUER_PUBLIC_KEY_DID, ISSUER_PRIVATE_KEY, SIGNER_PRIVATE_KEY, SIGNER_IDENTITY);
  let results = vade.send_message(&message_str).await.unwrap();

  // check results
  assert_eq!(results.len(), 1);
  Ok(results[0].as_ref().unwrap().to_string())
}

#[wasm_bindgen]
pub async fn request_proof(schema_id: String) -> Result<String, JsValue> {
    let mut vade = get_vade();

    let message_str = format!(
    r###"{{
        "type": "requestProof",
        "data": {{
            "verifierDid": "{}",
            "proverDid": "{}",
            "subProofRequests": [{{
                "schema": "{}",
                "revealedAttributes": ["test_property_string"]
            }}]
        }}
    }}"###,
    ISSUER_DID,
    SUBJECT_DID,
    schema_id,
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
pub async fn create_credential_proposal (schema_id: String) -> Result<String, JsValue> {
    let mut vade = get_vade();

    let message_str = format!(r###"{{
      "type": "createCredentialProposal",
      "data": {{
        "issuer": "{}",
        "subject": "{}",
        "schema": "{}"
      }}
    }}"###, ISSUER_DID, SUBJECT_DID, schema_id);
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
    definition: String,
    offer: String,
    master_secret: String,
  ) -> Result<String, JsValue> {
    let mut vade = get_vade();
    let message_str = format!(r###"{{
        "type": "requestCredential",
        "data": {{
            "credentialOffering": {},
            "credentialDefinition": {},
            "masterSecret": {},
            "credentialValues": {{
                "test_property_string": "test_property_string_value"
            }}
        }}
    }}"###, offer, definition, master_secret);
    let results = vade.send_message(&message_str).await.unwrap();

    // check results
    assert_eq!(results.len(), 1);

    Ok(results[0].as_ref().unwrap().to_string())
}

#[wasm_bindgen]
pub async fn create_revocation_registry_definition(credential_definition_id: String, max_credential_count: u32) -> Result<String, JsValue> {
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
    }}"###, credential_definition_id, ISSUER_PUBLIC_KEY_DID, ISSUER_PRIVATE_KEY, max_credential_count, SIGNER_PRIVATE_KEY, SIGNER_IDENTITY);
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
    master_secret: String
    ) -> Result<String, JsValue> {
    let mut vade = get_vade();

    let definition_parsed: CredentialDefinition = serde_json::from_str(&definition).unwrap();
    let request_parsed: CredentialRequest = serde_json::from_str(&request).unwrap();
    let blinding_factors_parsed: CredentialSecretsBlindingFactors = serde_json::from_str(&blinding_factors).unwrap();
    let master_secret_parsed: MasterSecret = serde_json::from_str(&master_secret).unwrap();
    let revocation_definition_parsed: RevocationRegistryDefinition = serde_json::from_str(&revocation_definition).unwrap();

    let message_str = format!(
      r###"{{
        "type": "issueCredential",
        "data": {{
          "issuer": "{}",
          "subject": "{}",
          "credentialRequest": {},
          "credentialDefinition": {},
          "credentialPrivateKey": {},
          "credentialRevocationDefinition": "{}",
          "revocationPrivateKey": {},
          "revocationInformation": {}
        }}
    }}"###,
    ISSUER_DID,
    SUBJECT_DID,
    request,
    definition,
    credential_private_key,
    revocation_definition_parsed.id,
    revocation_key_private,
    revocation_info,
  );
  info!("MESSAGE: {}", message_str);

  let results = vade.send_message(&message_str).await.unwrap();

  // check results
  assert_eq!(results.len(), 1);

  let mut result: IssueCredentialResult = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

  Prover::post_process_credential_signature(
    &mut result.credential,
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
pub async fn present_proof(
    proof_request: String,
    credential: String,
    definition: String,
    schema: String,
    revocation_registry: String,
    master_secret: String,
  ) -> Result<String, JsValue> {
    let mut vade = get_vade();
    let proof_request_parsed: ProofRequest = serde_json::from_str(&proof_request).unwrap();
    let schema_did = &proof_request_parsed.sub_proof_requests[0].schema;
    let mut credential_definitions: HashMap<String, CredentialDefinition> = HashMap::new();
    credential_definitions.insert(
        schema_did.clone(),
        serde_json::from_str(&definition).unwrap(),
    );
    let mut credentials: HashMap<String, Credential> = HashMap::new();
    credentials.insert(
        schema_did.clone(),
        serde_json::from_str(&credential).unwrap(),
    );
    let mut credential_schemas: HashMap<String, CredentialSchema> = HashMap::new();
    credential_schemas.insert(
        schema_did.clone(),
        serde_json::from_str(&schema).unwrap(),
    );
    let mut revocation_registries: HashMap<String, RevocationRegistryDefinition> = HashMap::new();
    revocation_registries.insert(
        schema_did.clone(),
        serde_json::from_str(&revocation_registry).unwrap(),
    );
    let message_str = format!(
        r###"{{
            "type": "presentProof",
            "data": {{
                "proofRequest": {},
                "credentials": {},
                "credentialDefinitions": {},
                "credentialSchemas": {},
                "revocationRegistries": {},
                "masterSecret": {}
            }}
        }}"###,
        proof_request,
        serde_json::to_string(&credentials).unwrap(),
        serde_json::to_string(&credential_definitions).unwrap(),
        serde_json::to_string(&credential_schemas).unwrap(),
        serde_json::to_string(&revocation_registries).unwrap(),
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
      proof_request: String,
      definition: String,
      schema: String,
      revocation_registry_definition: String
  ) -> Result<String, JsValue>  {
    let mut vade = get_vade();
      let message_str = format!(
          r###"{{
              "type": "verifyProof",
              "data": {{
                  "presentedProof": {},
                  "proofRequest": {},
                  "credentialDefinition": {},
                  "credentialSchema": {},
                  "revocationRegistryDefinition": {}
              }}
          }}"###,
          presented_proof,
          proof_request,
          definition,
          schema,
          revocation_registry_definition,
      );
      let results = vade.send_message(&message_str).await.unwrap();

      // check results
      assert_eq!(results.len(), 1);

      Ok(results[0].as_ref().unwrap().to_string())
  }
