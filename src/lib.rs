extern crate ursa;
extern crate secp256k1;
extern crate sha3;
extern crate hex;
#[macro_use]
extern crate log;
extern crate vade;
extern crate uuid;

pub mod application;
pub mod crypto;
pub mod utils;
pub mod resolver;

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
use simple_error::SimpleError;

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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateCredentialDefinitionArguments {
  pub issuer_did: String,
  pub schema_did: String,
  pub issuer_public_key_did: String,
  pub issuer_proving_key: String
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRevocationRegistryDefinitionArguments {
  pub credential_definition: String,
  pub issuer_did: String,
  pub issuer_public_key_did: String,
  pub issuer_proving_key: String,
  pub maximum_credential_count: u32
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeCredentialArguments {
  issuer: String,
  revocation_registry_definition_id: String,
  credential_revocation_id: u32,
  issuer_public_key_did: String,
  issuer_proving_key: String
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
            "createCredentialDefinition" => self.create_credential_definition(message_data).await,
            "createCredentialOffer" => self.create_credential_offer(message_data).await,
            "createCredentialProposal" => self.create_credential_proposal(message_data).await,
            "createCredentialSchema" => self.create_credential_schema(message_data).await,
            "createRevocationRegistryDefinition" => self.create_revocation_registry_definition(message_data).await,
            "issueCredential" => self.issue_credential(message_data).await,
            "presentProof" => self.present_proof(message_data).await,
            "requestCredential" => self.request_credential(message_data).await,
            "requestProof" => self.request_proof(message_data).await,
            "revokeCredential" => self.revoke_credential(message_data).await,
            "verifyProof" => self.verify_proof(message_data).await,
            _ => Err(Box::from(format!("message type '{}' not implemented", message_type)))
        }
    }
}

impl VadeTnt {
    async fn create_credential_definition(&mut self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
      let input: CreateCredentialDefinitionArguments = serde_json::from_str(&data)?;

      let schema: CredentialSchema = serde_json::from_str(
        &self.vade.get_did_document(
          &input.schema_did
        ).await?
      ).unwrap();

      let generated_did = self.generate_did().await?;

      let definition = Issuer::create_credential_definition(
        &generated_did,
        &input.issuer_did,
        &schema,
        &input.issuer_public_key_did,
        &input.issuer_proving_key
      );

      let serialized = serde_json::to_string(&definition).unwrap();

      self.vade.set_did_document(&generated_did, &serialized).await?;

      Ok(Some(serialized))
    }

    async fn create_credential_schema(&mut self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
      let input: CreateCredentialSchemaArguments = serde_json::from_str(&data)?;

      let generated_did = self.generate_did().await?;

      let schema = Issuer::create_credential_schema(
        &generated_did,
        &input.issuer,
        &input.schema_name,
        &input.description,
        input.properties,
        input.required_properties,
        input.allow_additional_properties,
        &input.issuer_public_key_did,
        &input.issuer_proving_key
      );

      let serialized = serde_json::to_string(&schema).unwrap();

      self.vade.set_did_document(&generated_did, &serialized).await?;

      Ok(Some(serialized))
    }

    async fn create_revocation_registry_definition(&mut self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
      let input: CreateRevocationRegistryDefinitionArguments = serde_json::from_str(&data)?;

      // Resolve credential definition
      let definition: CredentialDefinition = serde_json::from_str(
        &self.vade.get_did_document(
          &input.credential_definition
        ).await?
      ).unwrap();

      let generated_did = self.generate_did().await?;

      let (definition, private_key) = Issuer::create_revocation_registry_definition(
        &generated_did,
        &definition,
        &input.issuer_public_key_did,
        &input.issuer_proving_key,
        input.maximum_credential_count
      );

      let serialised_key = serde_json::to_string(&private_key).unwrap();
      let serialised_def = serde_json::to_string(&definition).unwrap();

      self.vade.set_did_document(&generated_did, &serialised_def).await?;

      Ok(Some(serialised_key))
    }


    async fn issue_credential(&self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: IssueCredentialArguments = serde_json::from_str(&data)?;

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

    async fn revoke_credential(&mut self, data: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let input: RevokeCredentialArguments = serde_json::from_str(&data)?;

        // Resolve revocation definition
        let mut revocation_definition: RevocationRegistryDefinition = serde_json::from_str(
          &self.vade.get_did_document(
            &input.revocation_registry_definition_id
          ).await?
        ).unwrap();

        let max_cred_count: u32 = revocation_definition.maximum_credential_count;

        let updated_registry = Issuer::revoke_credential(
          &input.issuer,
          &mut revocation_definition,
          max_cred_count,
          &input.issuer_public_key_did,
          &input.issuer_proving_key
        );

        let serialized = serde_json::to_string(&updated_registry).unwrap();

        self.vade.set_did_document(&revocation_definition.id, &serialized).await?;

        Ok(Some(serialized))
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

    async fn generate_did(&mut self) -> Result<String, Box<dyn std::error::Error>> {
      let generate_did_message = r###"{
        "type": "generateDid",
        "data": {}
      }"###;
      let result = self.vade.send_message(generate_did_message).await?;
      if result.len() == 0 {
        return Err(Box::new(SimpleError::new(format!("Could not generate DID as no listeners were registered for this method"))));
      }

      let generated_did = result[0].as_ref().unwrap().to_owned();

      Ok(generated_did)
    }
}
