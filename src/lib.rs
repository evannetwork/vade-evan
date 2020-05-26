extern crate ursa;
extern crate secp256k1;
extern crate sha3;
extern crate hex;
#[macro_use]
extern crate log;
extern crate vade;

pub mod application;
pub mod crypto;
pub mod utils;

use async_trait::async_trait;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use vade::{
    Vade,
    //traits::MessageConsumer,
};
use crate::{
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateCredentialSchemaArguments {
    pub issuer: String,
    pub schema_name: String,
    pub description: String,
    pub properties: HashMap<String, SchemaProperty>,
    pub required_properties: Vec<String>,
    pub allow_additional_properties: bool,
    pub issuer_public_key_did: String,
    pub issuer_proving_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssueCredentialArguments {
    pub issuer: String,
    pub subject: String,
    pub credential_request: CredentialRequest,
    pub credential_definition: CredentialDefinition,
    pub credential_private_key: CredentialPrivateKey,
    pub credential_schema: CredentialSchema,
    pub revocation_registry_definition: RevocationRegistryDefinition,
    pub revocation_private_key: RevocationKeyPrivate,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OfferCredentialArguments {
    pub issuer: String,
    pub subject: String,
    pub schema: String,
    pub credential_definition: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PresentProofArguments {
    pub proof_request: ProofRequest,
    pub credentials: HashMap<String, Credential>,
    pub credential_definitions: HashMap<String, CredentialDefinition>,
    pub credential_schemas: HashMap<String, CredentialSchema>,
    pub revocation_registries: HashMap<String, RevocationRegistryDefinition> // RevDef ID to RevDef
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateCredentialProposalArguments {
    pub issuer: String,
    pub subject: String,
    pub schema: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestCredentialArguments {
    pub credential_offering: CredentialOffer,
    pub credential_definition: CredentialDefinition,
    pub master_secret: MasterSecret,
    pub credential_values: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestProofArguments {
    pub verifier_did: String,
    pub prover_did: String,
    pub sub_proof_requests: Vec<SubProofRequest>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidateProofArguments {
    pub presented_proof: ProofPresentation,
    pub proof_request: ProofRequest,
    pub credential_definitions: HashMap<String, CredentialDefinition>,
    pub credential_schemas: HashMap<String, CredentialSchema>,
}

pub struct VadeTnt {
}

impl VadeTnt {
    /// Creates new instance of `VadeTnt`.
    pub fn new() -> VadeTnt {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        VadeTnt {
        }
    }
}

#[async_trait(?Send)]
impl MessageConsumer for VadeTnt {
    /// Reacts to `Vade` messages.
    /// 
    /// # Arguments
    /// 
    /// * `message_data` - arbitrary data for plugin, e.g. a JSON
    async fn handle_message(
        &mut self,
        message_type: &str,
        message_data: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        match message_type {
            "createCredentialProposal" => self.create_credential_proposal(message_data).await,
            "createCredentialOffer" => self.create_credential_offer(message_data).await,
            "requestCredential" => self.request_credential(message_data).await,
            "issueCredential" => self.issue_credential(message_data).await,
            "requestProof" => self.request_proof(message_data).await,
            "presentProof" => self.present_proof(message_data).await,
            "verifyProof" => self.verify_proof(message_data).await,
            _ => Err(Box::from(format!("message type '{}' not implemented", message_type)))
        }
    }
}

impl VadeTnt {
    async fn issue_credential(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let mut input: IssueCredentialArguments = serde_json::from_str(&data)?;
        let result: Credential = Issuer::issue_credential(
            &input.issuer,
            &input.subject,
            input.credential_request,
            input.credential_definition,
            input.credential_private_key,
            input.credential_schema,
            &mut input.revocation_registry_definition,
            input.revocation_private_key,
        );

        Ok(Some(serde_json::to_string(&result).unwrap()))
    }

    async fn create_credential_offer(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: OfferCredentialArguments = serde_json::from_str(&data)?;
        let result: CredentialOffer = Issuer::offer_credential(
            &input.issuer,
            &input.subject,
            &input.schema,
            &input.credential_definition,
        );

        Ok(Some(serde_json::to_string(&result).unwrap()))
    }

    async fn present_proof(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: PresentProofArguments = serde_json::from_str(&data)?;
        let result: ProofPresentation = Prover::present_proof(
            input.proof_request,
            input.credentials,
            input.credential_definitions,
            input.credential_schemas,
            input.revocation_registries,
        );

        Ok(Some(serde_json::to_string(&result).unwrap()))
    }

    async fn create_credential_proposal(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: CreateCredentialProposalArguments = serde_json::from_str(&data)?;
        let result: CredentialProposal = Prover::propose_credential(
            &input.issuer,
            &input.subject,
            &input.schema,
        );

        Ok(Some(serde_json::to_string(&result).unwrap()))
    }

    async fn request_credential(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: RequestCredentialArguments = serde_json::from_str(&data)?;
        let result: (CredentialRequest, CredentialSecretsBlindingFactors) = Prover::request_credential(
            input.credential_offering,
            input.credential_definition,
            input.master_secret,
            input.credential_values,
        );

        Ok(Some(serde_json::to_string(&result).unwrap()))
    }

    async fn request_proof(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: RequestProofArguments = serde_json::from_str(&data)?;
        let result: ProofRequest = Verifier::request_proof(
            &input.verifier_did,
            &input.prover_did,
            input.sub_proof_requests,
        );

        Ok(Some(serde_json::to_string(&result).unwrap()))
    }

    async fn verify_proof(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: ValidateProofArguments = serde_json::from_str(&data)?;
        let result: ProofVerification = Verifier::validate_proof(
            input.presented_proof,
            input.proof_request,
            input.credential_definitions,
            input.credential_schemas,
        );

        Ok(Some(serde_json::to_string(&result).unwrap()))
    }
}
