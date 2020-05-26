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

use serde_json::Value;
use test_data::{
  ISSUER_DID,
  SCHEMA_DID,
  SUBJECT_DID,
  CREDENTIAL_DEFINITION_DID,
  ISSUER_DID_DOCUMENT_STR,
  EXAMPLE_CREDENTIAL_SCHEMA,
  EXAMPLE_CREDENTIAL_SCHEMA_DID,
  ISSUER_PUBLIC_KEY_DID,
  ISSUER_PRIVATE_KEY,
};
use ursa::bn::BigNumber;
use vade::{
    Vade,
};
use vade_evan::plugin::rust_didresolver_evan::RustDidResolverEvan;
use vade_tnt::{
    VadeTnt,
    application::issuer::Issuer,
    application::prover::Prover,
    application::verifier::Verifier,
    application::datatypes::{
        Credential,
        CredentialDefinition,
        CredentialOffer,
        CredentialPrivateKey,
        CredentialProposal,
        CredentialRequest,
        CredentialSchema,
        CredentialSecretsBlindingFactors,
        MasterSecret,
        ProofPresentation,
        ProofRequest,
        ProofVerification,
        RevocationKeyPrivate,
        RevocationRegistryDefinition,
        SchemaProperty,
        SubProofRequest,
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
    let (definition, _) = create_credential_definition().unwrap();

    // run test
    let result: CredentialRequest = create_credential_request(&mut vade, &definition, &offer).await?;
    println!("{}", serde_json::to_string(&result).unwrap());

    // check results
    assert_eq!(result.subject, SUBJECT_DID);
    assert_eq!(result.credential_definition, "did:evan:zkp:0x123451234512345123451234512345");
    assert_eq!(result.schema, "did:evan:zkp:0x123451234512345123451234512345");
    assert_eq!(result.r#type, "EvanZKPCredentialRequest");

    Ok(())
}

#[tokio::test]
async fn vade_tnt_can_issue_credentials () -> Result<(), Box<dyn std::error::Error>>{
    let mut vade = get_vade();

    let proposal: CredentialProposal = create_credential_proposal(&mut vade).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal).await?;
    let (definition, credential_private_key) = create_credential_definition().unwrap();
    let request: CredentialRequest = create_credential_request(&mut vade, &definition, &offer).await?;

    // run test
    let result: Credential = issue_credential(&mut vade, &definition, &credential_private_key, &request).await?;
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

// #[tokio::test]
async fn vade_tnt_can_verify_proof () -> Result<(), Box<dyn std::error::Error>>{
    let mut vade = get_vade();

    // run test
    let message_str = r###"{
        "type": "verifyProof",
        "data": {
        }
    }"###;
    let _results = vade.send_message(message_str).await;

    // check results
    Err(Box::from("test not implemented"))
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

async fn create_credential_request(vade: &mut Vade, definition: &CredentialDefinition, offer: &CredentialOffer) -> Result<CredentialRequest, Box<dyn std::error::Error>> {
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
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

async fn issue_credential(vade: &mut Vade, definition: &CredentialDefinition, credential_private_key: &CredentialPrivateKey, request: &CredentialRequest) -> Result<Credential, Box<dyn std::error::Error>> {
    let (revocation_registry_definition, revocation_key_private):
        (RevocationRegistryDefinition, RevocationKeyPrivate)
        = Issuer::create_revocation_registry_definition(
            &definition,
            ISSUER_PUBLIC_KEY_DID,
            ISSUER_PRIVATE_KEY,
            42,
        );
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
          "revocationRegistryDefinition": {},
          "revocationPrivateKey": {}
        }}
    }}"###,
    ISSUER_DID,
    SUBJECT_DID,
    serde_json::to_string(&request).unwrap(),
    serde_json::to_string(&definition).unwrap(),
    serde_json::to_string(&credential_private_key).unwrap(), 
    EXAMPLE_CREDENTIAL_SCHEMA,
    serde_json::to_string(&revocation_registry_definition).unwrap(),
    serde_json::to_string(&revocation_key_private).unwrap(),
  );
  println!("{}", &message_str);
  let results = vade.send_message(&message_str).await?;

  // check results
  assert_eq!(results.len(), 1);
  println!("{}", serde_json::to_string(&results[0]).unwrap());
  let result: Credential = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

  Ok(result)
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

fn get_vade() -> Vade {
    // vade to work with
    let tnt = VadeTnt::new();
    let mut vade = Vade::new();
    vade.register_message_consumer(
      &vec![
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

fn create_credential_definition() -> Result<(CredentialDefinition, CredentialPrivateKey), Box<dyn std::error::Error>> {
    Ok(Issuer::create_credential_definition(
        &ISSUER_DID,
        &serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA).unwrap(),
        ISSUER_PUBLIC_KEY_DID,
        ISSUER_PRIVATE_KEY,
    ))
 }