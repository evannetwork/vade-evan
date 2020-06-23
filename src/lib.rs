extern crate ursa;
extern crate secp256k1;
extern crate sha3;
extern crate hex;
#[macro_use]
pub extern crate log;

extern crate vade;
extern crate uuid;

pub mod application;
pub mod crypto;

#[macro_use]
pub mod utils;
pub mod resolver;

pub mod wasm_lib;

use async_trait::async_trait;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use vade::{Vade, VadePlugin, VadePluginResultValue};
use ursa::cl::Witness;
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
        RevocationIdInformation,
        RevocationState
    },
};
use simple_error::SimpleError;

const EVAN_METHOD: &str = "did:evan";
const EVAN_METHOD_PREFIX: &str = "did:evan:zkp:";

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
    pub private_key: String,
    pub identity: String,
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
    pub revocation_information: RevocationIdInformation
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
    pub witnesses: HashMap<String, Witness>,
    pub master_secret: MasterSecret
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
struct WhitelistIdentityArguments {
  pub private_key: String,
  pub identity: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateCredentialDefinitionArguments {
  pub issuer_did: String,
  pub schema_did: String,
  pub issuer_public_key_did: String,
  pub issuer_proving_key: String,
  pub private_key: String,
  pub identity: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateRevocationRegistryDefinitionArguments {
  pub credential_definition: String,
  pub issuer_public_key_did: String,
  pub issuer_proving_key: String,
  pub maximum_credential_count: u32,
  pub private_key: String,
  pub identity: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RevokeCredentialArguments {
  issuer: String,
  revocation_registry_definition: String,
  credential_revocation_id: u32,
  issuer_public_key_did: String,
  issuer_proving_key: String,
  pub private_key: String,
  pub identity: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRevocationRegistryDefinitionResult {
  pub private_key: RevocationKeyPrivate,
  pub revocation_info: RevocationIdInformation,
  pub revocation_registry_definition: RevocationRegistryDefinition
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialResult {
  pub credential: Credential,
  pub revocation_info: RevocationIdInformation,
  pub revocation_state: RevocationState
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

impl VadeTnt {
    pub async fn whitelist_identity(&mut self, data: &str) -> Result<(), Box<dyn std::error::Error>> {
        let input: WhitelistIdentityArguments = serde_json::from_str(&data)?;
        let options = format!(r###"{{
            "privateKey": "{}",
            "identity": "{}",
            "operation": "whitelistIdentity"
        }}"###, input.private_key, input.identity);
        let identity_did = format!("{}{}", EVAN_METHOD_PREFIX, &input.identity);

        let result = self.vade.did_update(&identity_did, &options, &"".to_string()).await?;

        if result.is_empty() {
            return Err(Box::from(
                "Could not generate DID as no listeners were registered for this method"));
        }

        Ok(())
    }

    async fn generate_did(&mut self, private_key: &str, identity: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let options = format!(r###"{{
            "privateKey": "{}",
            "identity": "{}"
        }}"###, private_key, identity);
        let result = self.vade.did_create(EVAN_METHOD, &options, &"".to_string()).await?;
        if result.is_empty() {
            return Err(Box::from(
                "Could not generate DID as no listeners were registered for this method"));
        }

        let generated_did = format!("{}{}", EVAN_METHOD_PREFIX, &result[0].to_owned());

        Ok(generated_did)
    }

    async fn set_did_document(&mut self, did: &str, payload: &str, private_key: &str, identity: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let options = format!(r###"{{
            "privateKey": "{}",
            "identity": "{}",
            "operation": "setDidDocument"
        }}"###, &private_key, &identity);
        let result = self.vade.did_update(&did, &options, &payload).await?;

        if result.is_empty() {
            return Err(Box::from(
                "Could not set did document as no listeners were registered for this method"));
        }

        Ok(Some("".to_string()))
    }
}

#[async_trait(?Send)]
impl VadePlugin for VadeTnt {
    /// Creates a new credential definition and stores it on-chain.
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `CreateCredentialDefinitionArguments`
    ///
    /// # Returns
    /// * `Option<String>` - The created definition as a JSON object
    async fn vc_zkp_create_credential_definition(
      &mut self,
      method: &str,
      _options: &str,
      payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: CreateCredentialDefinitionArguments = serde_json::from_str(&payload)?;
        
        let results = &self.vade.did_resolve(&input.schema_did).await?;
        if results.is_empty() {
          return Err(Box::from(format!("could not get schema \"{}\"", &input.schema_did)));
        }
        let schema: CredentialSchema = serde_json::from_str(&results[0]).unwrap();

        let generated_did = self.generate_did(&input.private_key, &input.identity).await?;

        let (definition, pk) = Issuer::create_credential_definition(
            &generated_did,
            &input.issuer_did,
            &schema,
            &input.issuer_public_key_did,
            &input.issuer_proving_key
        );

        let serialized = serde_json::to_string(&(&definition, &pk)).unwrap();
        let serialized_definition = serde_json::to_string(&definition).unwrap();
        self.set_did_document(&generated_did, &serialized_definition, &input.private_key, &input.identity).await?;

        Ok(VadePluginResultValue::Success(serialized))
    }

    /// Creates a new credential schema and stores it on-chain.
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `CreateCredentialSchemaArguments`
    ///
    /// # Returns
    /// * `Option<String>` - The created schema as a JSON object
    async fn vc_zkp_create_credential_schema(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: CreateCredentialSchemaArguments = serde_json::from_str(&payload)?;

        let generated_did = self.generate_did(&input.private_key, &input.identity).await?;
  
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
        self.set_did_document(&generated_did, &serialized, &input.private_key, &input.identity).await?;
  
        Ok(VadePluginResultValue::Success(serialized))
    }

    /// Creates a new revocation registry definition and stores it on-chain.
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `CreateRevocationRegistryDefinitionArguments`
    ///
    /// # Returns
    /// * `Option<String>` - The created revocation registry definition as a JSON object
    async fn vc_zkp_create_revocation_registry_definition(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: CreateRevocationRegistryDefinitionArguments = serde_json::from_str(&payload)?;

        debug!("fetching credential definition with did: {}", &input.credential_definition);
        let definition: CredentialDefinition = serde_json::from_str(
          &self.vade.did_resolve(&input.credential_definition).await?[0]
        ).unwrap();
  
        let generated_did = self.generate_did(&input.private_key, &input.identity).await?;
  
        let (definition, private_key, revocation_info) = Issuer::create_revocation_registry_definition(
          &generated_did,
          &definition,
          &input.issuer_public_key_did,
          &input.issuer_proving_key,
          input.maximum_credential_count
        );
  
        let serialised_def = serde_json::to_string(&definition).unwrap();
  
        self.set_did_document(&generated_did, &serialised_def, &input.private_key, &input.identity).await?;
  
        let serialised_result = serde_json::to_string(
          &CreateRevocationRegistryDefinitionResult {
            private_key,
            revocation_info,
            revocation_registry_definition: definition
          }
        ).unwrap();
  
        Ok(VadePluginResultValue::Success(serialised_result))
    }

    /// Issues a new credential.
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `CreateRevocationRegistryDefinitionArguments`
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object consisting of the credential, this credential's initial revocation state and
    /// the updated revocation info, only interesting for the issuer (needs to be stored privately)
    async fn vc_zkp_issue_credential(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: IssueCredentialArguments = serde_json::from_str(&payload)?;

        debug!(
          "fetching credential definition with did: {}",
          &input.credential_request.credential_definition,
        );
        let definition: CredentialDefinition = serde_json::from_str(
           &self.vade.did_resolve(&input.credential_request.credential_definition).await?[0]
        ).unwrap();

        debug!("fetching schema with did: {}", &definition.schema);
        let schema: CredentialSchema = serde_json::from_str(
           &self.vade.did_resolve(&definition.schema).await?[0]
        ).unwrap();

        debug!(
          "fetching revocation definition with did: {}",
          &input.credential_revocation_definition,
        );
        let mut revocation_definition: RevocationRegistryDefinition = serde_json::from_str(
           &self.vade.did_resolve(&input.credential_revocation_definition).await?[0]
        ).unwrap();

        let (credential, revocation_state, revocation_info) = Issuer::issue_credential(
            &input.issuer,
            &input.subject,
            input.credential_request,
            definition,
            input.credential_private_key,
            schema,
            &mut revocation_definition,
            input.revocation_private_key,
            &input.revocation_information
        ).unwrap();

        Ok(
            VadePluginResultValue::Success(
            serde_json::to_string(
              &IssueCredentialResult {
                credential,
                revocation_state,
                revocation_info
              }
            ).unwrap()
          )
        )
    }
    
    /// Creates a `CredentialOffer` message.
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `OfferCredentialArguments` type
    ///
    /// # Returns
    /// * `Option<String>` - The offer as a JSON object
    async fn vc_zkp_create_credential_offer(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: OfferCredentialArguments = serde_json::from_str(&payload)?;
        let result: CredentialOffer = Issuer::offer_credential(
            &input.issuer,
            &input.subject,
            &input.schema,
            &input.credential_definition,
        );
        Ok(VadePluginResultValue::Success(serde_json::to_string(&result).unwrap()))
    }

    /// Creates a `CredentialProof` message.
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `PresentProofArguments` type
    ///
    /// # Returns
    /// * `Option<String>` - The offer as a JSON object
    async fn vc_zkp_present_proof(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: PresentProofArguments = serde_json::from_str(&payload)?;

        // Resolve all necessary credential definitions, schemas and registries
        let mut definitions: HashMap<String, CredentialDefinition> = HashMap::new();
        let mut schemas: HashMap<String, CredentialSchema> = HashMap::new();
        let mut revocation_definitions: HashMap<String, RevocationRegistryDefinition> = HashMap::new();
        for req in &input.proof_request.sub_proof_requests {
          let schema_did = &req.schema;
          debug!("fetching schema with did: {}", &schema_did);
          schemas.insert(schema_did.clone(), serde_json::from_str(
             &self.vade.did_resolve(&schema_did).await?[0]
          ).unwrap());

          let definition_did = input.credentials.get(schema_did).unwrap().signature.credential_definition.clone();
          debug!("fetching credential definition with did: {}", &definition_did);
          definitions.insert(schema_did.clone(), serde_json::from_str(
             &self.vade.did_resolve(&definition_did).await?[0]
          ).unwrap());

          // Resolve revocation definition
          let rev_definition_did = input.credentials.get(schema_did).unwrap().signature.revocation_registry_definition.clone();
          debug!("fetching revocation definition with did: {}", &rev_definition_did);
          revocation_definitions.insert(schema_did.clone(), serde_json::from_str(
             &self.vade.did_resolve(&rev_definition_did).await?[0]
          ).unwrap());
        }

        let result: ProofPresentation = Prover::present_proof(
            input.proof_request,
            input.credentials,
            definitions,
            schemas,
            revocation_definitions,
            input.witnesses,
            &input.master_secret,
        );

        Ok(VadePluginResultValue::Success(serde_json::to_string(&result).unwrap()))
    }

    /// Creates a `CredentialProposal` message.
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `CreateCredentialProposalArguments` type
    ///
    /// # Returns
    /// * `Option<String>` - The proposal as a JSON object
    async fn vc_zkp_create_credential_proposal(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: CreateCredentialProposalArguments = serde_json::from_str(&payload)?;
        let result: CredentialProposal = Prover::propose_credential(
            &input.issuer,
            &input.subject,
            &input.schema,
        );

        Ok(VadePluginResultValue::Success(serde_json::to_string(&result).unwrap()))
    }

    /// Creates a `CredentialRequest` message.
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `RequestCredentialArguments` type
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object consisting of the `CredentialRequest` and `CredentialSecretsBlindingFactors` (to be stored at the prover's site in a private manner)
    async fn vc_zkp_request_credential(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: RequestCredentialArguments = serde_json::from_str(&payload)?;

        debug!(
          "fetching credential definition with did: {}",
          &input.credential_offering.credential_definition,
        );
        let definition: CredentialDefinition = serde_json::from_str(
          &self.vade.did_resolve(&input.credential_offering.credential_definition).await?[0]
        ).unwrap();

        let result: (CredentialRequest, CredentialSecretsBlindingFactors) = Prover::request_credential(
            input.credential_offering,
            definition,
            input.master_secret,
            input.credential_values,
        );

        Ok(VadePluginResultValue::Success(serde_json::to_string(&result).unwrap()))
    }

    /// Creates a `ProofRequest` message.
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `RequestProofArguments` type
    ///
    /// # Returns
    /// * `Option<String>` - A `ProofRequest` as JSON
    async fn vc_zkp_request_proof(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: RequestProofArguments = serde_json::from_str(&payload)?;
        let result: ProofRequest = Verifier::request_proof(
            &input.verifier_did,
            &input.prover_did,
            input.sub_proof_requests,
        );

        Ok(VadePluginResultValue::Success(serde_json::to_string(&result).unwrap()))
    }

    /// Revokes a credential and updates the revocation registry definition.
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `RevokeCredentialArguments` type
    ///
    /// # Returns
    /// * `Option<String>` - The updated revocation registry definition as a JSON object
    async fn vc_zkp_revoke_credential(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: RevokeCredentialArguments = serde_json::from_str(&payload)?;

        debug!(
          "fetching revocation definition with did: {}",
          &input.revocation_registry_definition,
        );
        let rev_def: RevocationRegistryDefinition = serde_json::from_str(
          &self.vade.did_resolve(&input.revocation_registry_definition).await?[0]
        ).unwrap();

        let updated_registry = Issuer::revoke_credential(
          &input.issuer,
          &rev_def,
          input.credential_revocation_id,
          &input.issuer_public_key_did,
          &input.issuer_proving_key
        );

        let serialized = serde_json::to_string(&updated_registry).unwrap();

        self.set_did_document(&rev_def.id, &serialized, &input.private_key, &input.identity).await?;

        Ok(VadePluginResultValue::Success(serialized))
    }

    /// Verifies a given `ProofPresentation` in accordance to the specified `ProofRequest`
    ///
    /// # Arguments
    /// * `data` - Expects a JSON object representing a `ValidateProofArguments` type
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object representing a `ProofVerification` type, specifying whether verification was successful
    async fn vc_zkp_verify_proof(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<String>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let input: ValidateProofArguments = serde_json::from_str(&payload)?;

        // Resolve all necessary credential definitions, schemas and registries
        let mut definitions: HashMap<String, CredentialDefinition> = HashMap::new();
        let mut rev_definitions: HashMap<String, Option<RevocationRegistryDefinition>> = HashMap::new();
        let mut schemas: HashMap<String, CredentialSchema> = HashMap::new();
        for req in &input.proof_request.sub_proof_requests {
          let schema_did = &req.schema;
          debug!("fetching schema with did: {}", &schema_did);
          schemas.insert(schema_did.clone(), serde_json::from_str(
              &self.vade.did_resolve(&schema_did).await?[0]
          ).unwrap());
        }

        for credential in &input.presented_proof.verifiable_credential {
          let definition_did = &credential.proof.credential_definition.clone();
          debug!("fetching credential definition with did: {}", &definition_did);
          definitions.insert(credential.credential_schema.id.clone(), serde_json::from_str(
              &self.vade.did_resolve(&definition_did).await?[0]
          ).unwrap());

          let rev_definition_did = &credential.proof.revocation_registry_definition.clone();
          debug!(
              "fetching revocation definition with did: {}",
              &rev_definition_did
          );
          rev_definitions.insert(credential.credential_schema.id.clone(), Some(serde_json::from_str(
            &self.vade.did_resolve(&rev_definition_did).await?[0]
          ).unwrap()));
        }

        let result: ProofVerification = Verifier::verify_proof(
            input.presented_proof,
            input.proof_request,
            definitions,
            schemas,
            rev_definitions
        );

        Ok(VadePluginResultValue::Success(serde_json::to_string(&result).unwrap()))
    }
}
