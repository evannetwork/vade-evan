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
    traits::MessageConsumer,
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
    pub credential_revocation_definition: String,
    pub credential_private_key: CredentialPrivateKey,
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
    pub credentials: HashMap<String, Credential>
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
    pub proof_request: ProofRequest
}

pub struct VadeTnt {
  vade: Vade
}

impl VadeTnt {
    /// Creates new instance of `VadeTnt`.
    pub fn new(vade: Vade) -> VadeTnt {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        VadeTnt {
          vade
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

        // Resolve credential definition
        let definition: CredentialDefinition = serde_json::from_str(
          &self.vade.get_did_document(
            &input.credential_request.credential_definition
          ).await?
        ).unwrap();

        // Resolve schema
        let schema: CredentialSchema = serde_json::from_str(
          &self.vade.get_did_document(
            &definition.schema
          ).await?
        ).unwrap();

        // Resolve revocation definition
        let mut revocation_definition: RevocationRegistryDefinition = serde_json::from_str(
          &self.vade.get_did_document(
            &input.credential_revocation_definition
          ).await?
        ).unwrap();

        let result: Credential = Issuer::issue_credential(
            &input.issuer,
            &input.subject,
            input.credential_request,
            definition,
            input.credential_private_key,
            schema,
            &mut revocation_definition,
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

        // Resolve all necessary credential definitions, schemas and registries
        let mut definitions: HashMap<String, CredentialDefinition> = HashMap::new();
        let mut schemas: HashMap<String, CredentialSchema> = HashMap::new();
        let mut revocation_definitions: HashMap<String, RevocationRegistryDefinition> = HashMap::new();
        for req in &input.proof_request.sub_proof_requests {
          // Resolve schema
          let schema_did = &req.schema;
          schemas.insert(schema_did.clone(), serde_json::from_str(
            &self.vade.get_did_document(
              &schema_did
            ).await?
          ).unwrap());

          // Resolve credential definition
          let definition_did = input.credentials.get(schema_did).unwrap().signature.credential_definition.clone();
          definitions.insert(schema_did.clone(), serde_json::from_str(
            &self.vade.get_did_document(
              &definition_did
            ).await?
          ).unwrap());

          // Resolve revocation definition
          let rev_definition_did = input.credentials.get(schema_did).unwrap().signature.revocation_registry_definition.clone();
          revocation_definitions.insert(schema_did.clone(), serde_json::from_str(
            &self.vade.get_did_document(
              &rev_definition_did
            ).await?
          ).unwrap());
        }

        let result: ProofPresentation = Prover::present_proof(
            input.proof_request,
            input.credentials,
            definitions,
            schemas,
            revocation_definitions
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

        // Resolve credential definition
        let definition: CredentialDefinition = serde_json::from_str(
          &self.vade.get_did_document(
            &input.credential_offering.credential_definition
          ).await?
        ).unwrap();

        let result: (CredentialRequest, CredentialSecretsBlindingFactors) = Prover::request_credential(
            input.credential_offering,
            definition,
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

        // Resolve all necessary credential definitions, schemas and registries
        let mut definitions: HashMap<String, CredentialDefinition> = HashMap::new();
        let mut schemas: HashMap<String, CredentialSchema> = HashMap::new();
        for req in &input.proof_request.sub_proof_requests {
          // Resolve schema
          let schema_did = &req.schema;
          schemas.insert(schema_did.clone(), serde_json::from_str(
            &self.vade.get_did_document(
              &schema_did
            ).await?
          ).unwrap());
        }

        for credential in &input.presented_proof.verifiable_credential {
          // Resolve credential definition
          let definition_did = credential.proof.credential_definition.clone();
          definitions.insert(credential.credential_schema.id.clone(), serde_json::from_str(
            &self.vade.get_did_document(
              &definition_did
            ).await?
          ).unwrap());
        }

        let result: ProofVerification = Verifier::validate_proof(
            input.presented_proof,
            input.proof_request,
            definitions,
            schemas,
        );

        Ok(Some(serde_json::to_string(&result).unwrap()))
    }
}
