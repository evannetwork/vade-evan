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

extern crate vade;
extern crate vade_evan;
extern crate vade_tnt;

mod test_data;

use std::collections::HashMap;
use vade::plugin::rust_storage_cache::RustStorageCache;
use vade_tnt::resolver::SubstrateDidResolverEvan;
use serde_json::Value;
use test_data::{
  ISSUER_DID,
  SCHEMA_DID,
  SUBJECT_DID,
  CREDENTIAL_DEFINITION_DID,
  EXAMPLE_CREDENTIAL_SCHEMA,
  EXAMPLE_CREDENTIAL_SCHEMA_DID,
  ISSUER_PUBLIC_KEY_DID,
  ISSUER_PRIVATE_KEY,
  EXAMPLE_GENERATED_DID,
  EXAMPLE_CREDENTIAL_DEFINITION,
  EXAMPLE_CREDENTIAL_DEFINITION_PRIVATE_KEY,
  EXAMPLE_REVOCATION_REGISTRY_DEFINITION_DID,
};
use ursa::bn::BigNumber;
use vade::{
    Vade,
};
use vade_tnt::{
    VadeTnt,
    IssueCredentialResult,
    application::issuer::Issuer,
    application::datatypes::{
        Credential,
        CredentialDefinition,
        CredentialOffer,
        CredentialPrivateKey,
        CredentialProposal,
        CredentialRequest,
        CredentialSchema,
        MasterSecret,
        ProofPresentation,
        ProofRequest,
        ProofVerification,
        RevocationKeyPrivate,
        RevocationRegistryDefinition,
        RevocationIdInformation
    },
};

#[tokio::test]
async fn vade_tnt_can_be_registered_as_plugin () -> Result<(), Box<dyn std::error::Error>>{
    let mut vade = get_vade();

    // run test
    let message_str = r###"{
        "type": "createCredentialProposal",
        "data": {}
    }"###;
    let results = vade.send_message(message_str).await;

    // check results
    match results {
      Ok(_) => panic!("test should have failed"),
      Err(_) => (),
    };

    Ok(())
}

#[tokio::test]
async fn vade_tnt_can_propose_credentials () -> Result<(), Box<dyn std::error::Error>>{
    let mut vade = get_vade();

    // run test
    let result: CredentialProposal = create_credential_proposal(&mut vade).await?;
    assert_eq!(result.issuer, ISSUER_DID);
    assert_eq!(result.subject, SUBJECT_DID);
    assert_eq!(result.schema, SCHEMA_DID);
    assert_eq!(result.r#type, "EvanZKPCredentialProposal");

    Ok(())
}

#[tokio::test]
async fn vade_tnt_can_offer_credentials () -> Result<(), Box<dyn std::error::Error>>{
    let mut vade = get_vade();

    let proposal: CredentialProposal = create_credential_proposal(&mut vade).await?;

    // run test
    let result: CredentialOffer = create_credential_offer(&mut vade, &proposal).await?;
    println!("{}", serde_json::to_string(&result).unwrap());

    assert_eq!(result.issuer, ISSUER_DID);
    assert_eq!(result.subject, SUBJECT_DID);
    assert_eq!(result.r#type, "EvanZKPCredentialOffering");
    assert_eq!(result.schema, SCHEMA_DID);
    assert_eq!(result.credential_definition, CREDENTIAL_DEFINITION_DID);
    assert_ne!(result.nonce, BigNumber::from_dec("0").unwrap());

    Ok(())
}

#[tokio::test]
async fn vade_tnt_can_request_credentials () -> Result<(), Box<dyn std::error::Error>>{
    let mut vade = get_vade();

    let proposal: CredentialProposal = create_credential_proposal(&mut vade).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal).await?;
    let (definition, _) = create_credential_definition(&mut vade).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();

    // run test
    let result: CredentialRequest = create_credential_request(&mut vade, &definition, &offer, &master_secret).await?;
    println!("{}", serde_json::to_string(&result).unwrap());

    // check results
    assert_eq!(result.subject, SUBJECT_DID);
    assert_eq!(result.credential_definition, "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD2");
    assert_eq!(result.schema, "did:evan:zkp:0x123451234512345123451234512345");
    assert_eq!(result.r#type, "EvanZKPCredentialRequest");

    Ok(())
}

#[tokio::test]
async fn vade_tnt_can_issue_credentials () -> Result<(), Box<dyn std::error::Error>>{
    let mut vade = get_vade();

    let proposal: CredentialProposal = create_credential_proposal(&mut vade).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal).await?;
    let (definition, credential_private_key) = create_credential_definition(&mut vade).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
    let request: CredentialRequest = create_credential_request(&mut vade, &definition, &offer, &master_secret).await?;
    let (_, revocation_key_private, revocation_info):
        (RevocationRegistryDefinition, RevocationKeyPrivate, RevocationIdInformation)
        = Issuer::create_revocation_registry_definition(
            EXAMPLE_GENERATED_DID,
            &definition,
            ISSUER_PUBLIC_KEY_DID,
            ISSUER_PRIVATE_KEY,
            42,
        );

    // run test
    let (result, _): (Credential, _) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &request,
        &revocation_key_private,
        &revocation_info,
    ).await?;
    println!("{}", serde_json::to_string(&result).unwrap());

    // check results
    assert_eq!(result.issuer, ISSUER_DID);

    Ok(())
}

#[tokio::test]
async fn vade_tnt_can_request_proof () -> Result<(), Box<dyn std::error::Error>>{
    let mut vade = get_vade();

    // run test
    let result: ProofRequest = request_proof(&mut vade).await?;
    println!("{}", serde_json::to_string(&result).unwrap());

    // check results
    assert_eq!(result.verifier, ISSUER_DID);
    assert_eq!(result.prover, SUBJECT_DID);
    assert_eq!(result.sub_proof_requests.len(), 1);
    assert_eq!(result.sub_proof_requests[0].schema, EXAMPLE_CREDENTIAL_SCHEMA_DID);
    assert_eq!(result.sub_proof_requests[0].revealed_attributes.len(), 1);
    assert_eq!(result.sub_proof_requests[0].revealed_attributes[0], "test_property_string");

    Ok(())
}

#[tokio::test]
async fn vade_tnt_can_present_proofs () -> Result<(), Box<dyn std::error::Error>>{
    let mut vade = get_vade();

    let (definition, credential_private_key) = create_credential_definition().unwrap();
    let proof_request: ProofRequest = request_proof(&mut vade).await?;
    let schema: CredentialSchema = serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA).unwrap();

    let proposal: CredentialProposal = create_credential_proposal(&mut vade).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
    let request: CredentialRequest = create_credential_request(&mut vade, &definition, &offer, &master_secret).await?;

    let (revocation_registry_definition, revocation_key_private, revocation_info):
        (RevocationRegistryDefinition, RevocationKeyPrivate, RevocationIdInformation)
        = Issuer::create_revocation_registry_definition(
            EXAMPLE_GENERATED_DID,
            &definition,
            ISSUER_PUBLIC_KEY_DID,
            ISSUER_PRIVATE_KEY,
            42,
        );
    let (credential, _) : (Credential, _) = issue_credential(&mut vade, &definition, &credential_private_key, &request, &revocation_key_private, &revocation_info).await?;

    // run test
    let result: ProofPresentation = present_proof(
        &mut vade,
        &proof_request,
        &credential,
        &definition,
        &schema,
        &revocation_registry_definition,
        &master_secret,
    ).await?;
    println!("{}", serde_json::to_string(&result).unwrap());

    // check result
    assert_eq!(result.r#type.len(), 1);
    assert_eq!(result.r#type[0], "VerifiablePresentation");
    assert_eq!(result.verifiable_credential.len(), 1);

    Ok(())
}

#[tokio::test]
async fn vade_tnt_can_verify_proof () -> Result<(), Box<dyn std::error::Error>>{
    let mut vade = get_vade();

    let (definition, credential_private_key) = create_credential_definition().unwrap();
    let proof_request: ProofRequest = request_proof(&mut vade).await?;
    let schema: CredentialSchema = serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
    let proposal: CredentialProposal = create_credential_proposal(&mut vade).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal).await?;
    let request: CredentialRequest = create_credential_request(&mut vade, &definition, &offer, &master_secret).await?;
    let (revocation_registry_definition, revocation_key_private, revocation_info):
        (RevocationRegistryDefinition, RevocationKeyPrivate, RevocationIdInformation)
        = Issuer::create_revocation_registry_definition(
            EXAMPLE_GENERATED_DID,
            &definition,
            ISSUER_PUBLIC_KEY_DID,
            ISSUER_PRIVATE_KEY,
            42,
        );
    let (credential, _): (Credential, _) = issue_credential(&mut vade, &definition, &credential_private_key, &request, &revocation_key_private, &revocation_info).await?;
    let presented_proof: ProofPresentation = present_proof(
        &mut vade,
        &proof_request,
        &credential,
        &definition,
        &schema,
        &revocation_registry_definition,
        &master_secret,
    ).await?;

    // run test
    let result: ProofVerification = verify_proof(
        &mut vade,
        &presented_proof,
        &proof_request,
        &definition,
        &schema,
    ).await?;
    println!("{}", serde_json::to_string(&result).unwrap());

    // check results
    assert_ne!(result.status, "rejected");

    Ok(())
}

async fn create_credential_offer(vade: &mut Vade, proposal: &CredentialProposal) -> Result<CredentialOffer, Box<dyn std::error::Error>> {
    let message_str = format!(r###"{{
      "type": "createCredentialOffer",
      "data": {}
    }}"###, serde_json::to_string(&proposal).unwrap());
    println!("{}", &message_str);
    let mut message_value: Value = serde_json::from_str(&message_str).unwrap();
    message_value["data"]["credentialDefinition"] = Value::from(CREDENTIAL_DEFINITION_DID);
    let message_str = serde_json::to_string(&message_value).unwrap();
    println!("{}", &message_str);

    let results = vade.send_message(&message_str).await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: CredentialOffer = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();
    // println!("{}", serde_json::to_string(&result).unwrap());

    Ok(result)
}

async fn create_credential_proposal (vade: &mut Vade) -> Result<CredentialProposal, Box<dyn std::error::Error>> {
    let message_str = format!(r###"{{
      "type": "createCredentialProposal",
      "data": {{
        "issuer": "{}",
        "subject": "{}",
        "schema": "{}"
      }}
    }}"###, ISSUER_DID, SUBJECT_DID, SCHEMA_DID);
    let results = vade.send_message(&message_str).await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: CredentialProposal = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok(result)
}

async fn create_credential_request(
    vade: &mut Vade,
    definition: &CredentialDefinition,
    offer: &CredentialOffer,
    master_secret: &MasterSecret,
  ) -> Result<CredentialRequest, Box<dyn std::error::Error>> {
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
    }}"###, serde_json::to_string(&offer).unwrap(), serde_json::to_string(&definition).unwrap(), serde_json::to_string(&master_secret).unwrap());
    println!("{}", &message_str);
    let results = vade.send_message(&message_str).await?;

    // check results
    assert_eq!(results.len(), 1);
    println!("{}", serde_json::to_string(&results[0]).unwrap());
    let (result, _): (CredentialRequest, Value) = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok(result)
}

async fn issue_credential(
    vade: &mut Vade,
    definition: &CredentialDefinition,
    credential_private_key: &CredentialPrivateKey,
    request: &CredentialRequest,
    revocation_key_private: &RevocationKeyPrivate,
    revocation_info: &RevocationIdInformation,
    ) -> Result<(Credential, RevocationIdInformation), Box<dyn std::error::Error>> {
    let message_str = format!(
      r###"{{
        "type": "issueCredential",
        "data": {{
          "issuer": "{}",
          "subject": "{}",
          "credentialRequest": {},
          "credentialDefinition": {},
          "credentialPrivateKey": {},
          "credentialSchema": {},
          "credentialRevocationDefinition": "{}",
          "revocationPrivateKey": {},
          "revocationInformation": {}
        }}
    }}"###,
    ISSUER_DID,
    SUBJECT_DID,
    serde_json::to_string(&request).unwrap(),
    serde_json::to_string(&definition).unwrap(),
    serde_json::to_string(&credential_private_key).unwrap(),
    EXAMPLE_CREDENTIAL_SCHEMA,
    EXAMPLE_REVOCATION_REGISTRY_DEFINITION_DID,
    serde_json::to_string(&revocation_key_private).unwrap(),
    serde_json::to_string(&revocation_info).unwrap(),
  );
  println!("{}", &message_str);
  let results = vade.send_message(&message_str).await?;

  // check results
  assert_eq!(results.len(), 1);
  println!("{}", serde_json::to_string(&results[0]).unwrap());
  let result: IssueCredentialResult = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

  Ok((result.credential, result.revocation_info))
}

async fn request_proof(vade: &mut Vade) -> Result<ProofRequest, Box<dyn std::error::Error>> {
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
    EXAMPLE_CREDENTIAL_SCHEMA_DID,
    );
    println!("{}", &message_str);
    let results = vade.send_message(&message_str).await?;

    // check results
    assert_eq!(results.len(), 1);
    println!("{}", serde_json::to_string(&results[0]).unwrap());
    let result: ProofRequest = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok(result)
}

async fn present_proof(
  vade: &mut Vade,
  proof_request: &ProofRequest,
  credential: &Credential,
  definition: &CredentialDefinition,
  schema: &CredentialSchema,
  revocation_registry: &RevocationRegistryDefinition,
  master_secret: &MasterSecret,
) -> Result<ProofPresentation, Box<dyn std::error::Error>> {
  let schema_did = &proof_request.sub_proof_requests[0].schema;
  let mut credential_definitions: HashMap<String, CredentialDefinition> = HashMap::new();
  credential_definitions.insert(
      schema_did.clone(),
      serde_json::from_str(&serde_json::to_string(&definition).unwrap()).unwrap(),
  );
  let mut credentials: HashMap<String, Credential> = HashMap::new();
  credentials.insert(
      schema_did.clone(),
      serde_json::from_str(&serde_json::to_string(&credential).unwrap()).unwrap(),
  );
  let mut credential_schemas: HashMap<String, CredentialSchema> = HashMap::new();
  credential_schemas.insert(
      schema_did.clone(),
      serde_json::from_str(&serde_json::to_string(&schema).unwrap()).unwrap(),
  );
  let mut revocation_registries: HashMap<String, RevocationRegistryDefinition> = HashMap::new();
  revocation_registries.insert(
      schema_did.clone(),
      serde_json::from_str(&serde_json::to_string(&revocation_registry).unwrap()).unwrap(),
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
      serde_json::to_string(&proof_request).unwrap(),
      serde_json::to_string(&credentials).unwrap(),
      serde_json::to_string(&credential_definitions).unwrap(),
      serde_json::to_string(&credential_schemas).unwrap(),
      serde_json::to_string(&revocation_registries).unwrap(),
      serde_json::to_string(&master_secret).unwrap(),
  );
  println!("{}", &message_str);
  let results = vade.send_message(&message_str).await?;

  // check results
  assert_eq!(results.len(), 1);
  println!("{}", serde_json::to_string(&results[0]).unwrap());
  let result: ProofPresentation = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

  Ok(result)
}

async fn verify_proof(
    vade: &mut Vade,
    presented_proof: &ProofPresentation,
    proof_request: &ProofRequest,
    definition: &CredentialDefinition,
    schema: &CredentialSchema,
) -> Result<ProofVerification, Box<dyn std::error::Error>> {
    let mut credential_definitions: HashMap<String, CredentialDefinition> = HashMap::new();
    credential_definitions.insert(
        "i want this".to_string(),
        serde_json::from_str(&serde_json::to_string(&definition).unwrap()).unwrap(),
    );
    let mut credential_schemas: HashMap<String, CredentialSchema> = HashMap::new();
    credential_schemas.insert(
        "i want this".to_string(),
        serde_json::from_str(&serde_json::to_string(&schema).unwrap()).unwrap(),
    );
    let message_str = format!(
        r###"{{
            "type": "verifyProof",
            "data": {{
                "presentedProof": {},
                "proofRequest": {}
            }}
        }}"###,
        serde_json::to_string(&presented_proof).unwrap(),
        serde_json::to_string(&proof_request).unwrap(),
    );
    println!("{}", &message_str);
    let results = vade.send_message(&message_str).await?;

    // check results
    assert_eq!(results.len(), 1);
    println!("{}", serde_json::to_string(&results[0]).unwrap());
    let result: ProofVerification = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok(result)
}

fn get_vade() -> Vade {
    // vade to work with
    // let substrate_resolver = SubstrateDidResolverEvan::new();
    let substrate_resolver = RustStorageCache::new();
    let substrate_message_handler = SubstrateDidResolverEvan::new();
    let mut internal_vade = Vade::new();
    internal_vade.register_did_resolver(Box::from(substrate_resolver));
    internal_vade.register_message_consumer(&vec!["generateDid".to_owned()], Box::from(substrate_message_handler));

    let tnt = VadeTnt::new(internal_vade);
    let mut vade = Vade::new();
    vade.register_message_consumer(
      &vec![
        "createCredentialDefinition",
        "createCredentialProposal",
        "createCredentialOffer",
        "requestCredential",
        "issueCredential",
        "requestProof",
        "presentProof",
        "verifyProof",
      ].iter().map(|&x| String::from(x)).collect(),
      Box::from(tnt),
    );

    return vade;
}

async fn create_credential_definition(vade: &mut Vade) -> Result<(CredentialDefinition, CredentialPrivateKey), Box<dyn std::error::Error>> {
    let message_str = format!(r###"{{
      "type": "createCredentialDefinition",
      "data": {{
        "schemaDid": "{}",
        "issuerDid": "{}",
        "issuerPublicKeyDid": "{}",
        "issuerProvingKey": "{}"
      }}
    }}"###, EXAMPLE_CREDENTIAL_SCHEMA_DID, ISSUER_DID, ISSUER_PUBLIC_KEY_DID, ISSUER_PRIVATE_KEY);
    let results = vade.send_message(&message_str).await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: (CredentialDefinition, CredentialPrivateKey) = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok(result)
    /*Ok(Issuer::create_credential_definition(
        EXAMPLE_GENERATED_DID,
        ISSUER_DID,
        &serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA).unwrap(),
        ISSUER_PUBLIC_KEY_DID,
        ISSUER_PRIVATE_KEY,
    ))*/
 }


 /*fn create_credential_schema() -> Result<(CredentialDefinition, CredentialPrivateKey), Box<dyn std::error::Error>> {
  let message_str = format!(r###"{{
    "type": "createCredentialSchema",
    "data": {{
      "issuer": "{}",
      "subject": "{}",
      "schema": "{}"
    }}
  }}"###, ISSUER_DID, SUBJECT_DID, SCHEMA_DID);
  let results = vade.send_message(&message_str).await?;

  // check results
  assert_eq!(results.len(), 1);
  let result: CredentialProposal = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

  Ok(result)
  Ok(Issuer::create_credential_definition(
      EXAMPLE_GENERATED_DID,
      ISSUER_DID,
      &serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA).unwrap(),
      ISSUER_PUBLIC_KEY_DID,
      ISSUER_PRIVATE_KEY,
  ))
}*/