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

mod test_data;

use serde_json::Value;
use std::collections::HashMap;
use test_data::{
    ISSUER_DID,
    ISSUER_PRIVATE_KEY,
    ISSUER_PUBLIC_KEY_DID,
    SCHEMA_DESCRIPTION,
    SCHEMA_EXTENDED_PROPERTIES,
    SCHEMA_MORE_EXTENDED_PROPERTIES,
    SCHEMA_NAME,
    SCHEMA_PROPERTIES,
    SCHEMA_REQUIRED_PROPERTIES,
    SIGNER_IDENTITY,
    SIGNER_PRIVATE_KEY,
    SUBJECT_DID,
};
use ursa::bn::BigNumber;
use ursa::cl::{CredentialSecretsBlindingFactors, Witness};
use vade::Vade;
use vade_evan::resolver::SubstrateDidResolverEvan;
use vade_evan::{
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
        RevocationIdInformation,
        RevocationKeyPrivate,
        RevocationRegistryDefinition,
        RevocationState,
    },
    application::prover::Prover,
    resolver::ResolverConfig,
    CreateRevocationRegistryDefinitionResult,
    IssueCredentialResult,
    VadeEvan,
};

const EVAN_METHOD: &str = "did:evan";

// TODO: Test multi-proof presentations
// TODO: Test revocation
// TODO: Test multiple sequential proofs of same credential
// TODO: Test proving after revoking another credential of the same registry

#[tokio::test]
async fn vade_evan_can_be_registered_as_plugin() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    // run test
    let results = vade
        .vc_zkp_create_credential_proposal(EVAN_METHOD, "", "")
        .await;

    // check results
    if results.is_ok() {
        // test is supposed to fail
        panic!("test should have failed")
    }

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_whitelist_identity() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade_evan = get_vade_evan();

    // run test
    whitelist_identity(&mut vade_evan).await?;

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_create_schema() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    // run test
    let _result: CredentialSchema = create_credential_schema(&mut vade).await?;

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_propose_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();
    let schema: CredentialSchema = create_credential_schema(&mut vade).await?;

    // run test
    let result: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    assert_eq!(result.issuer, ISSUER_DID);
    assert_eq!(result.subject, SUBJECT_DID);
    assert_eq!(result.schema, schema.id.clone());
    assert_eq!(result.r#type, "EvanZKPCredentialProposal");

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_offer_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    let schema: CredentialSchema = create_credential_schema(&mut vade).await?;
    let (definition, _) = create_credential_definition(&mut vade, &schema).await?;
    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;

    // run test
    let result: CredentialOffer =
        create_credential_offer(&mut vade, &proposal, &definition).await?;

    assert_eq!(result.issuer, ISSUER_DID);
    assert_eq!(result.subject, SUBJECT_DID);
    assert_eq!(result.r#type, "EvanZKPCredentialOffering");
    assert_eq!(result.schema, schema.id.clone());
    assert_eq!(result.credential_definition, definition.id.clone());
    assert_ne!(result.nonce, BigNumber::from_dec("0").unwrap());

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_request_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    let schema: CredentialSchema = create_credential_schema(&mut vade).await?;
    let (definition, _) = create_credential_definition(&mut vade, &schema).await?;
    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();

    // run test
    let (result, _) = create_credential_request(&mut vade, &schema, &offer, &master_secret).await?;

    // check results
    assert_eq!(result.subject, SUBJECT_DID);
    assert_eq!(result.credential_definition, definition.id.clone());
    assert_eq!(result.schema, schema.id.clone());
    assert_eq!(result.r#type, "EvanZKPCredentialRequest");

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_issue_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    let schema: CredentialSchema = create_credential_schema(&mut vade).await?;

    let (definition, credential_private_key) =
        create_credential_definition(&mut vade, &schema).await?;

    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;

    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;

    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
    let (request, _) =
        create_credential_request(&mut vade, &schema, &offer, &master_secret).await?;

    let rev_reg_def: CreateRevocationRegistryDefinitionResult =
        create_revocation_registry_definition(&mut vade, &definition, 42).await?;

    // run test
    let (result, _, _): (Credential, _, _) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &request,
        &rev_reg_def.private_key,
        &rev_reg_def.revocation_info,
        &rev_reg_def.revocation_registry_definition,
    )
    .await?;

    // check results
    assert_eq!(result.issuer, ISSUER_DID);

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_request_proof() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    let schema: CredentialSchema = create_credential_schema(&mut vade).await?;

    // run test
    let result: ProofRequest = request_proof(&mut vade, &schema).await?;

    // check results
    assert_eq!(result.verifier, ISSUER_DID);
    assert_eq!(result.prover, SUBJECT_DID);
    assert_eq!(result.sub_proof_requests.len(), 1);
    assert_eq!(result.sub_proof_requests[0].schema, schema.id.clone());
    assert_eq!(result.sub_proof_requests[0].revealed_attributes.len(), 1);
    assert_eq!(
        result.sub_proof_requests[0].revealed_attributes[0],
        "test_property_string"
    );

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_present_proofs() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    let schema: CredentialSchema = create_credential_schema(&mut vade).await?;
    let (definition, credential_private_key) =
        create_credential_definition(&mut vade, &schema).await?;
    let proof_request: ProofRequest = request_proof(&mut vade, &schema).await?;
    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
    let (request, blinding_factors) =
        create_credential_request(&mut vade, &schema, &offer, &master_secret).await?;

    let rev_reg_def: CreateRevocationRegistryDefinitionResult =
        create_revocation_registry_definition(&mut vade, &definition, 42).await?;

    let (mut credential, revocation_state, _): (Credential, RevocationState, _) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &request,
        &rev_reg_def.private_key,
        &rev_reg_def.revocation_info,
        &rev_reg_def.revocation_registry_definition,
    )
    .await?;

    Prover::post_process_credential_signature(
        &mut credential,
        &schema,
        &request,
        &definition,
        blinding_factors,
        &master_secret,
        &rev_reg_def.revocation_registry_definition,
        &revocation_state.witness,
    );

    // run test
    let result: ProofPresentation = present_proof(
        &mut vade,
        &proof_request,
        &credential,
        &revocation_state.witness,
        &master_secret,
    )
    .await?;

    // check result
    assert_eq!(result.r#type.len(), 1);
    assert_eq!(result.r#type[0], "VerifiablePresentation");
    assert_eq!(result.verifiable_credential.len(), 1);

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_present_proofs_with_less_properties(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    let schema: CredentialSchema = create_extended_credential_schema(&mut vade).await?;
    let (definition, credential_private_key) =
        create_credential_definition(&mut vade, &schema).await?;
    let proof_request: ProofRequest = request_proof(&mut vade, &schema).await?;
    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
    let (request, blinding_factors) =
        create_two_property_credential_request(&mut vade, &schema, &offer, &master_secret).await?;

    let rev_reg_def: CreateRevocationRegistryDefinitionResult =
        create_revocation_registry_definition(&mut vade, &definition, 42).await?;

    let (mut credential, revocation_state, _): (Credential, RevocationState, _) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &request,
        &rev_reg_def.private_key,
        &rev_reg_def.revocation_info,
        &rev_reg_def.revocation_registry_definition,
    )
    .await?;

    Prover::post_process_credential_signature(
        &mut credential,
        &schema,
        &request,
        &definition,
        blinding_factors,
        &master_secret,
        &rev_reg_def.revocation_registry_definition,
        &revocation_state.witness,
    );

    // run test
    let result: ProofPresentation = present_proof(
        &mut vade,
        &proof_request,
        &credential,
        &revocation_state.witness,
        &master_secret,
    )
    .await?;

    // check result
    assert_eq!(result.r#type.len(), 1);
    assert_eq!(result.r#type[0], "VerifiablePresentation");
    assert_eq!(result.verifiable_credential.len(), 1);

    Ok(())
}

#[tokio::test]
async fn vade_tnt_can_present_proofs_with_selective_revealed_attributes_and_omitted_optional_properties(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    let schema: CredentialSchema = create_three_property_credential_request(&mut vade).await?;
    let (definition, credential_private_key) =
        create_credential_definition(&mut vade, &schema).await?;
    let proof_request: ProofRequest = request_proof(&mut vade, &schema).await?;
    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
    let (request, blinding_factors) =
        create_two_property_credential_request(&mut vade, &schema, &offer, &master_secret).await?;

    let rev_reg_def: CreateRevocationRegistryDefinitionResult =
        create_revocation_registry_definition(&mut vade, &definition, 42).await?;

    let (mut credential, revocation_state, _): (Credential, RevocationState, _) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &request,
        &rev_reg_def.private_key,
        &rev_reg_def.revocation_info,
        &rev_reg_def.revocation_registry_definition,
    )
    .await?;

    Prover::post_process_credential_signature(
        &mut credential,
        &schema,
        &request,
        &definition,
        blinding_factors,
        &master_secret,
        &rev_reg_def.revocation_registry_definition,
        &revocation_state.witness,
    );

    // run test
    let presented_proof: ProofPresentation = present_proof(
        &mut vade,
        &proof_request,
        &credential,
        &revocation_state.witness,
        &master_secret,
    )
    .await?;

    // check result
    assert_eq!(presented_proof.r#type.len(), 1);
    assert_eq!(presented_proof.r#type[0], "VerifiablePresentation");
    assert_eq!(presented_proof.verifiable_credential.len(), 1);

    // run test
    let result: ProofVerification =
        verify_proof(&mut vade, &presented_proof, &proof_request).await?;

    // check results
    assert_ne!(result.status, "rejected");
    Ok(())
}

#[tokio::test]
async fn vade_tnt_cannot_request_credential_with_missing_required_properties(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    let schema: CredentialSchema = create_three_property_credential_request(&mut vade).await?;
    let (definition, _) = create_credential_definition(&mut vade, &schema).await?;
    request_proof(&mut vade, &schema).await?;
    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();

    match create_credential_request_with_missing_required_property(
        &mut vade,
        &schema,
        &offer,
        &master_secret,
    )
    .await
    {
        Ok(_) => panic!("test should have failed"),
        Err(err) => assert_eq!(
            format!("{}", err).contains("Missing required schema property"),
            true
        ),
    };

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_verify_proof() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    let schema: CredentialSchema = create_credential_schema(&mut vade).await?;
    let (definition, credential_private_key) =
        create_credential_definition(&mut vade, &schema).await?;
    let proof_request: ProofRequest = request_proof(&mut vade, &schema).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();
    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
    let (request, blinding_factors) =
        create_credential_request(&mut vade, &schema, &offer, &master_secret).await?;

    //let (revocation_registry_definition, revocation_key_private, revocation_info):
    //(RevocationRegistryDefinition, RevocationKeyPrivate, RevocationIdInformation)
    let rev_reg_def: CreateRevocationRegistryDefinitionResult =
        create_revocation_registry_definition(&mut vade, &definition, 42).await?;
    let (mut credential, revocation_state, _): (Credential, RevocationState, _) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &request,
        &rev_reg_def.private_key,
        &rev_reg_def.revocation_info,
        &rev_reg_def.revocation_registry_definition,
    )
    .await?;

    Prover::post_process_credential_signature(
        &mut credential,
        &schema,
        &request,
        &definition,
        blinding_factors,
        &master_secret,
        &rev_reg_def.revocation_registry_definition,
        &revocation_state.witness,
    );

    let presented_proof: ProofPresentation = present_proof(
        &mut vade,
        &proof_request,
        &credential,
        &revocation_state.witness,
        &master_secret,
    )
    .await?;

    // run test
    let result: ProofVerification =
        verify_proof(&mut vade, &presented_proof, &proof_request).await?;

    // check results
    assert_ne!(result.status, "rejected");

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_revoke_credential() -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    // Issue credential
    let schema: CredentialSchema = create_credential_schema(&mut vade).await?;
    let (definition, credential_private_key) =
        create_credential_definition(&mut vade, &schema).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();

    let proof_request: ProofRequest = request_proof(&mut vade, &schema).await?;

    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
    let (request, blinding_factors) =
        create_credential_request(&mut vade, &schema, &offer, &master_secret).await?;

    let rev_result: CreateRevocationRegistryDefinitionResult =
        create_revocation_registry_definition(&mut vade, &definition, 42).await?;

    let revocation_registry_definition = rev_result.revocation_registry_definition;
    let revocation_key_private = rev_result.private_key;
    let revocation_info = rev_result.revocation_info;

    let (mut credential, revocation_state, _): (Credential, RevocationState, _) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &request,
        &revocation_key_private,
        &revocation_info,
        &revocation_registry_definition,
    )
    .await?;

    Prover::post_process_credential_signature(
        &mut credential,
        &schema,
        &request,
        &definition,
        blinding_factors,
        &master_secret,
        &revocation_registry_definition,
        &revocation_state.witness,
    );

    let updated_registry =
        revoke_credential(&mut vade, &credential, &revocation_registry_definition).await?;

    let updated_revocation_state =
        Prover::update_revocation_state_for_credential(revocation_state.clone(), updated_registry);

    // Verify proof for credential, using the updated revocation registry
    let presented_proof: ProofPresentation = present_proof(
        &mut vade,
        &proof_request,
        &credential,
        &updated_revocation_state.witness,
        &master_secret,
    )
    .await?;

    let result: ProofVerification =
        verify_proof(&mut vade, &presented_proof, &proof_request).await?;

    // check results
    assert_eq!(result.status, "rejected");

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_verify_proof_after_revocation_update(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    // Issue main credential
    let schema: CredentialSchema = create_credential_schema(&mut vade).await?;
    let (definition, credential_private_key) =
        create_credential_definition(&mut vade, &schema).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();

    let proof_request: ProofRequest = request_proof(&mut vade, &schema).await?;

    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
    let (request, blinding_factors) =
        create_credential_request(&mut vade, &schema, &offer, &master_secret).await?;

    let rev_result: CreateRevocationRegistryDefinitionResult =
        create_revocation_registry_definition(&mut vade, &definition, 42).await?;

    let revocation_registry_definition = rev_result.revocation_registry_definition;
    let revocation_key_private = rev_result.private_key;
    let revocation_info = rev_result.revocation_info;

    let (mut credential, revocation_state, revocation_info): (
        Credential,
        RevocationState,
        RevocationIdInformation,
    ) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &request,
        &revocation_key_private,
        &revocation_info,
        &revocation_registry_definition,
    )
    .await?;

    Prover::post_process_credential_signature(
        &mut credential,
        &schema,
        &request,
        &definition,
        blinding_factors,
        &master_secret,
        &revocation_registry_definition,
        &revocation_state.witness,
    );

    // Issue different credential & revoke it
    let other_proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let other_offer: CredentialOffer =
        create_credential_offer(&mut vade, &other_proposal, &definition).await?;
    let (other_request, other_blinding_factors) =
        create_credential_request(&mut vade, &schema, &other_offer, &master_secret).await?;

    let (mut other_credential, other_revocation_state, _): (
        Credential,
        RevocationState,
        RevocationIdInformation,
    ) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &other_request,
        &revocation_key_private,
        &revocation_info,
        &revocation_registry_definition,
    )
    .await?;

    Prover::post_process_credential_signature(
        &mut other_credential,
        &schema,
        &other_request,
        &definition,
        other_blinding_factors,
        &master_secret,
        &revocation_registry_definition,
        &other_revocation_state.witness,
    );

    let updated_registry = revoke_credential(
        &mut vade,
        &other_credential,
        &revocation_registry_definition,
    )
    .await?;

    let updated_revocation_state =
        Prover::update_revocation_state_for_credential(revocation_state.clone(), updated_registry);

    // Verify proof for main credential, using the updated revocation registry
    let presented_proof: ProofPresentation = present_proof(
        &mut vade,
        &proof_request,
        &credential,
        &updated_revocation_state.witness,
        &master_secret,
    )
    .await?;

    // run test
    let result: ProofVerification =
        verify_proof(&mut vade, &presented_proof, &proof_request).await?;

    // check results
    assert_ne!(result.status, "rejected");

    Ok(())
}

#[tokio::test]
async fn vade_evan_can_verify_proof_after_multiple_revocation_updates(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut vade = get_vade();

    // Issue main credential
    let schema: CredentialSchema = create_credential_schema(&mut vade).await?;
    let (definition, credential_private_key) =
        create_credential_definition(&mut vade, &schema).await?;
    let master_secret = ursa::cl::prover::Prover::new_master_secret().unwrap();

    let proof_request: ProofRequest = request_proof(&mut vade, &schema).await?;

    let proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let offer: CredentialOffer = create_credential_offer(&mut vade, &proposal, &definition).await?;
    let (request, blinding_factors) =
        create_credential_request(&mut vade, &schema, &offer, &master_secret).await?;

    let rev_result: CreateRevocationRegistryDefinitionResult =
        create_revocation_registry_definition(&mut vade, &definition, 42).await?;

    let revocation_registry_definition = rev_result.revocation_registry_definition;
    let revocation_key_private = rev_result.private_key;
    let revocation_info = rev_result.revocation_info;

    let (mut credential, revocation_state, revocation_info): (
        Credential,
        RevocationState,
        RevocationIdInformation,
    ) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &request,
        &revocation_key_private,
        &revocation_info,
        &revocation_registry_definition,
    )
    .await?;

    Prover::post_process_credential_signature(
        &mut credential,
        &schema,
        &request,
        &definition,
        blinding_factors,
        &master_secret,
        &revocation_registry_definition,
        &revocation_state.witness,
    );

    let updated_registry =
        revoke_credential(&mut vade, &credential, &revocation_registry_definition).await?;

    // Issue another credential & revoke it
    let other_proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let other_offer: CredentialOffer =
        create_credential_offer(&mut vade, &other_proposal, &definition).await?;
    let (other_request, other_blinding_factors) =
        create_credential_request(&mut vade, &schema, &other_offer, &master_secret).await?;

    let (mut other_credential, other_revocation_state, revocation_info): (
        Credential,
        RevocationState,
        RevocationIdInformation,
    ) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &other_request,
        &revocation_key_private,
        &revocation_info,
        &updated_registry,
    )
    .await?;

    Prover::post_process_credential_signature(
        &mut other_credential,
        &schema,
        &other_request,
        &definition,
        other_blinding_factors,
        &master_secret,
        &updated_registry,
        &other_revocation_state.witness,
    );

    // Issue third credential & revoke it
    let third_proposal: CredentialProposal = create_credential_proposal(&mut vade, &schema).await?;
    let third_offer: CredentialOffer =
        create_credential_offer(&mut vade, &third_proposal, &definition).await?;
    let (third_request, third_blinding_factors) =
        create_credential_request(&mut vade, &schema, &third_offer, &master_secret).await?;

    let (mut third_credential, third_revocation_state, _): (
        Credential,
        RevocationState,
        RevocationIdInformation,
    ) = issue_credential(
        &mut vade,
        &definition,
        &credential_private_key,
        &third_request,
        &revocation_key_private,
        &revocation_info,
        &updated_registry,
    )
    .await?;

    Prover::post_process_credential_signature(
        &mut third_credential,
        &schema,
        &third_request,
        &definition,
        third_blinding_factors,
        &master_secret,
        &updated_registry,
        &third_revocation_state.witness,
    );

    let updated_registry =
        revoke_credential(&mut vade, &third_credential, &updated_registry).await?;

    // We need the second credential's witness to be up to date before creating proofs
    let updated_second_revocation_state = Prover::update_revocation_state_for_credential(
        other_revocation_state.clone(),
        updated_registry,
    );

    // Verify proof for main credential, using the updated revocation registry
    let presented_proof = present_proof(
        &mut vade,
        &proof_request,
        &other_credential,
        &updated_second_revocation_state.witness,
        &master_secret,
    )
    .await?;

    // run test
    let result: ProofVerification =
        verify_proof(&mut vade, &presented_proof, &proof_request).await?;

    // check results
    assert_ne!(result.status, "rejected");

    Ok(())
}

async fn create_credential_definition(
    vade: &mut Vade,
    schema: &CredentialSchema,
) -> Result<(CredentialDefinition, CredentialPrivateKey), Box<dyn std::error::Error>> {
    let payload = format!(
        r###"{{
            "schemaDid": "{}",
            "issuerDid": "{}",
            "issuerPublicKeyDid": "{}",
            "issuerProvingKey": "{}"
        }}"###,
        schema.id, ISSUER_DID, ISSUER_PUBLIC_KEY_DID, ISSUER_PRIVATE_KEY
    );
    let results = vade
        .vc_zkp_create_credential_definition(EVAN_METHOD, &get_options(), &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: (CredentialDefinition, CredentialPrivateKey) =
        serde_json::from_str(&results[0].as_ref().unwrap()).unwrap();
    Ok(result)
}

async fn create_credential_offer(
    vade: &mut Vade,
    proposal: &CredentialProposal,
    credential_definition: &CredentialDefinition,
) -> Result<CredentialOffer, Box<dyn std::error::Error>> {
    let payload = serde_json::to_string(&proposal).unwrap();
    let mut message_value: Value = serde_json::from_str(&payload).unwrap();
    message_value["credentialDefinition"] = Value::from(credential_definition.id.clone());
    let payload = serde_json::to_string(&message_value).unwrap();

    let results = vade
        .vc_zkp_create_credential_offer(EVAN_METHOD, "", &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: CredentialOffer = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok(result)
}

async fn create_credential_proposal(
    vade: &mut Vade,
    schema: &CredentialSchema,
) -> Result<CredentialProposal, Box<dyn std::error::Error>> {
    let payload = format!(
        r###"{{
            "issuer": "{}",
            "subject": "{}",
            "schema": "{}"
        }}"###,
        ISSUER_DID, SUBJECT_DID, schema.id
    );
    let results = vade
        .vc_zkp_create_credential_proposal(EVAN_METHOD, "", &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: CredentialProposal = serde_json::from_str(&results[0].as_ref().unwrap()).unwrap();

    Ok(result)
}

async fn create_credential_request(
    vade: &mut Vade,
    schema: &CredentialSchema,
    offer: &CredentialOffer,
    master_secret: &MasterSecret,
) -> Result<(CredentialRequest, CredentialSecretsBlindingFactors), Box<dyn std::error::Error>> {
    let payload = format!(
        r###"{{
            "credentialOffering": {},
            "credentialSchema": {},
            "masterSecret": {},
            "credentialValues": {{
                "test_property_string": "test_property_string_value"
            }}
        }}
        "###,
        serde_json::to_string(&offer).unwrap(),
        serde_json::to_string(&schema).unwrap(),
        serde_json::to_string(&master_secret).unwrap()
    );
    let results = vade
        .vc_zkp_request_credential(EVAN_METHOD, "", &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);
    let (result, blinding_factors): (CredentialRequest, CredentialSecretsBlindingFactors) =
        serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok((result, blinding_factors))
}

async fn create_two_property_credential_request(
    vade: &mut Vade,
    schema: &CredentialSchema,
    offer: &CredentialOffer,
    master_secret: &MasterSecret,
) -> Result<(CredentialRequest, CredentialSecretsBlindingFactors), Box<dyn std::error::Error>> {
    let payload = format!(
        r###"{{
    "credentialOffering": {},
    "credentialSchema": {},
    "masterSecret": {},
    "credentialValues": {{
        "test_property_string": "test_property_string_value",
        "test_property_string2": "test_property_string_value2"
    }}
  }}"###,
        serde_json::to_string(&offer).unwrap(),
        serde_json::to_string(&schema).unwrap(),
        serde_json::to_string(&master_secret).unwrap()
    );
    let results = vade
        .vc_zkp_request_credential(EVAN_METHOD, "", &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);
    let (result, blinding_factors): (CredentialRequest, CredentialSecretsBlindingFactors) =
        serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok((result, blinding_factors))
}

async fn create_credential_request_with_missing_required_property(
    vade: &mut Vade,
    schema: &CredentialSchema,
    offer: &CredentialOffer,
    master_secret: &MasterSecret,
) -> Result<(CredentialRequest, CredentialSecretsBlindingFactors), Box<dyn std::error::Error>> {
    let payload = format!(
        r###"{{
    "credentialOffering": {},
    "credentialSchema": {},
    "masterSecret": {},
    "credentialValues": {{
        "test_property_string2": "test_property_string_value2"
    }}
  }}"###,
        serde_json::to_string(&offer).unwrap(),
        serde_json::to_string(&schema).unwrap(),
        serde_json::to_string(&master_secret).unwrap()
    );
    let results = vade
        .vc_zkp_request_credential(EVAN_METHOD, "", &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);
    let (result, blinding_factors): (CredentialRequest, CredentialSecretsBlindingFactors) =
        serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok((result, blinding_factors))
}

async fn create_extended_credential_schema(
    vade: &mut Vade,
) -> Result<CredentialSchema, Box<dyn std::error::Error>> {
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
        ISSUER_DID,
        SCHEMA_NAME,
        SCHEMA_DESCRIPTION,
        SCHEMA_EXTENDED_PROPERTIES,
        SCHEMA_REQUIRED_PROPERTIES,
        ISSUER_PUBLIC_KEY_DID,
        ISSUER_PRIVATE_KEY
    );
    let results = vade
        .vc_zkp_create_credential_schema(EVAN_METHOD, &get_options(), &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);

    let result: CredentialSchema = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();
    Ok(result)
}

async fn create_revocation_registry_definition(
    vade: &mut Vade,
    credential_definition: &CredentialDefinition,
    max_credential_count: u32,
) -> Result<CreateRevocationRegistryDefinitionResult, Box<dyn std::error::Error>> {
    let payload = format!(
        r###"{{
        "credentialDefinition": "{}",
        "issuerPublicKeyDid": "{}",
        "issuerProvingKey": "{}",
        "maximumCredentialCount": {}
    }}"###,
        credential_definition.id, ISSUER_PUBLIC_KEY_DID, ISSUER_PRIVATE_KEY, max_credential_count
    );
    let results = vade
        .vc_zkp_create_revocation_registry_definition(EVAN_METHOD, &get_options(), &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);

    let result: CreateRevocationRegistryDefinitionResult =
        serde_json::from_str(results[0].as_ref().unwrap()).unwrap();
    Ok(result)
}

fn get_options() -> String {
    format!(
        r###"{{
            "privateKey": "{}",
            "identity": "{}"
        }}"###,
        SIGNER_PRIVATE_KEY, SIGNER_IDENTITY,
    )
}

fn get_vade() -> Vade {
    let evan = get_vade_evan();
    let mut vade = Vade::new();
    vade.register_plugin(Box::from(evan));

    vade
}

fn get_vade_evan() -> VadeEvan {
    // vade to work with
    // let substrate_resolver = SubstrateDidResolverEvan::new();
    let identity = hex::decode("9670f7974e7021e4940c56d47f6b31fdfdd37de8").unwrap();
    let substrate_resolver = SubstrateDidResolverEvan::new(ResolverConfig {
        target: "13.69.59.185".to_string(),
        private_key: "4ea724e22ede0b7bea88771612485205cfc344131a16b8ab23d4970132be8dab".to_string(),
        identity,
    });
    let mut internal_vade = Vade::new();
    internal_vade.register_plugin(Box::from(substrate_resolver));

    VadeEvan::new(internal_vade)
}

async fn issue_credential(
    vade: &mut Vade,
    definition: &CredentialDefinition,
    credential_private_key: &CredentialPrivateKey,
    request: &CredentialRequest,
    revocation_key_private: &RevocationKeyPrivate,
    revocation_info: &RevocationIdInformation,
    revocation_definition: &RevocationRegistryDefinition,
) -> Result<(Credential, RevocationState, RevocationIdInformation), Box<dyn std::error::Error>> {
    let payload = format!(
        r###"{{
            "issuer": "{}",
            "subject": "{}",
            "credentialRequest": {},
            "credentialDefinition": {},
            "credentialPrivateKey": {},
            "credentialRevocationDefinition": "{}",
            "revocationPrivateKey": {},
            "revocationInformation": {}
        }}"###,
        ISSUER_DID,
        SUBJECT_DID,
        serde_json::to_string(&request).unwrap(),
        serde_json::to_string(&definition).unwrap(),
        serde_json::to_string(&credential_private_key).unwrap(),
        &revocation_definition.id,
        serde_json::to_string(&revocation_key_private).unwrap(),
        serde_json::to_string(&revocation_info).unwrap(),
    );
    let results = vade
        .vc_zkp_issue_credential(EVAN_METHOD, "", &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: IssueCredentialResult = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok((
        result.credential,
        result.revocation_state,
        result.revocation_info,
    ))
}

async fn request_proof(
    vade: &mut Vade,
    schema: &CredentialSchema,
) -> Result<ProofRequest, Box<dyn std::error::Error>> {
    let payload = format!(
        r###"{{
            "verifierDid": "{}",
            "proverDid": "{}",
            "subProofRequests": [{{
                "schema": "{}",
                "revealedAttributes": ["test_property_string"]
            }}]
        }}"###,
        ISSUER_DID, SUBJECT_DID, schema.id,
    );
    let results = vade.vc_zkp_request_proof(EVAN_METHOD, "", &payload).await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: ProofRequest = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok(result)
}

async fn revoke_credential(
    vade: &mut Vade,
    credential: &Credential,
    revocation_registry_definition: &RevocationRegistryDefinition,
) -> Result<RevocationRegistryDefinition, Box<dyn std::error::Error>> {
    let payload = format!(
        r###"{{
            "issuer": "{}",
            "revocationRegistryDefinition": "{}",
            "credentialRevocationId": {},
            "issuerPublicKeyDid": "{}",
            "issuerProvingKey" : "{}"
        }}"###,
        ISSUER_DID,
        revocation_registry_definition.id.clone(),
        credential.signature.revocation_id.clone(),
        ISSUER_PUBLIC_KEY_DID,
        ISSUER_PRIVATE_KEY
    );
    let results = vade
        .vc_zkp_revoke_credential(EVAN_METHOD, &get_options(), &payload)
        .await?;

    assert_eq!(results.len(), 1);

    let updated_registry: RevocationRegistryDefinition =
        serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok(updated_registry)
}

async fn present_proof(
    vade: &mut Vade,
    proof_request: &ProofRequest,
    credential: &Credential,
    witness: &Witness,
    master_secret: &MasterSecret,
) -> Result<ProofPresentation, Box<dyn std::error::Error>> {
    let schema_did = &proof_request.sub_proof_requests[0].schema;
    let mut credentials: HashMap<String, Credential> = HashMap::new();
    credentials.insert(
        schema_did.clone(),
        serde_json::from_str(&serde_json::to_string(&credential).unwrap()).unwrap(),
    );

    let mut witnesses: HashMap<String, Witness> = HashMap::new();
    witnesses.insert(credential.id.clone(), witness.clone());

    let payload = format!(
        r###"{{
        "proofRequest": {},
        "credentials": {},
        "witnesses": {},
        "masterSecret": {}
      }}"###,
        serde_json::to_string(&proof_request).unwrap(),
        serde_json::to_string(&credentials).unwrap(),
        serde_json::to_string(&witnesses).unwrap(),
        serde_json::to_string(&master_secret).unwrap(),
    );
    let results = vade.vc_zkp_present_proof(EVAN_METHOD, "", &payload).await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: ProofPresentation = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok(result)
}

async fn verify_proof(
    vade: &mut Vade,
    presented_proof: &ProofPresentation,
    proof_request: &ProofRequest,
) -> Result<ProofVerification, Box<dyn std::error::Error>> {
    let payload = format!(
        r###"{{
            "presentedProof": {},
            "proofRequest": {}
        }}"###,
        serde_json::to_string(presented_proof).unwrap(),
        serde_json::to_string(proof_request).unwrap()
    );
    let results = vade.vc_zkp_verify_proof(EVAN_METHOD, "", &payload).await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: ProofVerification = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();

    Ok(result)
}

async fn whitelist_identity(vade_evan: &mut VadeEvan) -> Result<(), Box<dyn std::error::Error>> {
    let results = vade_evan.whitelist_identity(&get_options()).await;

    if results.is_err() {
        // test is not supposed to fail
        panic!("could not whitelist identity")
    }

    Ok(())
}

async fn create_credential_schema(
    vade: &mut Vade,
) -> Result<CredentialSchema, Box<dyn std::error::Error>> {
    let message_str = format!(
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
        ISSUER_DID,
        SCHEMA_NAME,
        SCHEMA_DESCRIPTION,
        SCHEMA_PROPERTIES,
        SCHEMA_REQUIRED_PROPERTIES,
        ISSUER_PUBLIC_KEY_DID,
        ISSUER_PRIVATE_KEY
    );
    let results = vade
        .vc_zkp_create_credential_schema(EVAN_METHOD, &get_options(), &message_str)
        .await?;

    // check results
    assert_eq!(results.len(), 1);

    let result: CredentialSchema = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();
    Ok(result)
}

async fn create_three_property_credential_request(
    vade: &mut Vade,
) -> Result<CredentialSchema, Box<dyn std::error::Error>> {
    let message_str = format!(
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
        ISSUER_DID,
        SCHEMA_NAME,
        SCHEMA_DESCRIPTION,
        SCHEMA_MORE_EXTENDED_PROPERTIES,
        SCHEMA_REQUIRED_PROPERTIES,
        ISSUER_PUBLIC_KEY_DID,
        ISSUER_PRIVATE_KEY
    );
    let results = vade
        .vc_zkp_create_credential_schema(EVAN_METHOD, &get_options(), &message_str)
        .await?;

    // check results
    assert_eq!(results.len(), 1);

    let result: CredentialSchema = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();
    Ok(result)
}
