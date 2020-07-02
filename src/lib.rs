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

//! This crate allows you to use to work with DIDs and zero knowledge proof VCs on Trust and Trace.
//! For this purpose two [`VadePlugin`] implementations are exported: [`VadeEvan`] and [`SubstrateDidResolverEvan`].
//!
//! ## VadeEvan
//!
//! Responsible for working with zero knowledge proof VCs on Trust and Trace.
//!
//! Implements the following [`VadePlugin`] functions:
//!
//! - [`vc_zkp_create_credential_schema`]
//! - [`vc_zkp_create_credential_definition`]
//! - [`vc_zkp_create_credential_proposal`]
//! - [`vc_zkp_create_credential_offer`]
//! - [`vc_zkp_request_credential`]
//! - [`vc_zkp_create_revocation_registry_definition`]
//! - [`vc_zkp_update_revocation_registry`]
//! - [`vc_zkp_issue_credential`]
//! - [`vc_zkp_revoke_credential`]
//! - [`vc_zkp_request_proof`]
//! - [`vc_zkp_present_proof`]
//! - [`vc_zkp_verify_proof`]
//!
//! ## SubstrateDidResolverEvan
//!
//! Supports creating, updating and getting DIDs and DID documents on substrate, therefore supports:
//!
//! - [`did_create`]
//! - [`did_resolve`]
//! - [`did_update`]
//!
//! [`did_create`]: https://docs.rs/vade_evan/*/vade_evan/resolver/struct.SubstrateDidResolverEvan.html#method.did_create
//! [`did_resolve`]: https://docs.rs/vade_evan/*/vade_evan/resolver/struct.SubstrateDidResolverEvan.html#method.did_resolve
//! [`did_update`]: https://docs.rs/vade_evan/*/vade_evan/resolver/struct.SubstrateDidResolverEvan.html#method.did_update
//! [`SubstrateDidResolverEvan`]: https://docs.rs/vade_evan/*/vade_evan/resolver/struct.SubstrateDidResolverEvan.html
//! [`Vade`]: https://docs.rs/vade_evan/*/vade/struct.Vade.html
//! [`VadePlugin`]: https://docs.rs/vade_evan/*/vade/trait.VadePlugin.html
//! [`VadeEvan`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html
//! [`vc_zkp_create_credential_definition`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_credential_definition
//! [`vc_zkp_create_credential_offer`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_credential_offer
//! [`vc_zkp_create_credential_proposal`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_credential_proposal
//! [`vc_zkp_create_credential_schema`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_credential_schema
//! [`vc_zkp_create_revocation_registry_definition`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_revocation_registry_definition
//! [`vc_zkp_issue_credential`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_issue_credential
//! [`vc_zkp_present_proof`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_present_proof
//! [`vc_zkp_request_credential`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_request_credential
//! [`vc_zkp_request_proof`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_request_proof
//! [`vc_zkp_revoke_credential`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_revoke_credential
//! [`vc_zkp_update_revocation_registry`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_update_revocation_registry
//! [`vc_zkp_verify_proof`]: https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_verify_proof

extern crate hex;
extern crate secp256k1;
extern crate sha3;
extern crate ursa;
#[macro_use]
pub extern crate log;

extern crate uuid;
extern crate vade;

pub mod application;
pub mod crypto;

#[macro_use]
pub mod utils;
pub mod resolver;

pub mod wasm_lib;

use crate::{
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
        SchemaProperty,
        SubProofRequest,
    },
    application::issuer::Issuer,
    application::prover::Prover,
    application::verifier::Verifier,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ursa::cl::Witness;
use vade::{Vade, VadePlugin, VadePluginResultValue};

const EVAN_METHOD: &str = "did:evan";
const EVAN_METHOD_PREFIX: &str = "did:evan:";
const EVAN_METHOD_ZKP_PREFIX: &str = "did:evan:zkp:";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationOptions {
    pub private_key: String,
    pub identity: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialDefinitionPayload {
    pub issuer_did: String,
    pub schema_did: String,
    pub issuer_public_key_did: String,
    pub issuer_proving_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialSchemaPayload {
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
pub struct CreateRevocationRegistryDefinitionPayload {
    pub credential_definition: String,
    pub issuer_public_key_did: String,
    pub issuer_proving_key: String,
    pub maximum_credential_count: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRevocationRegistryDefinitionResult {
    pub private_key: RevocationKeyPrivate,
    pub revocation_info: RevocationIdInformation,
    pub revocation_registry_definition: RevocationRegistryDefinition,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialPayload {
    pub issuer: String,
    pub subject: String,
    pub credential_request: CredentialRequest,
    pub credential_revocation_definition: String,
    pub credential_private_key: CredentialPrivateKey,
    pub revocation_private_key: RevocationKeyPrivate,
    pub revocation_information: RevocationIdInformation,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialResult {
    pub credential: Credential,
    pub revocation_info: RevocationIdInformation,
    pub revocation_state: RevocationState,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfferCredentialPayload {
    pub issuer: String,
    pub subject: String,
    pub schema: String,
    pub credential_definition: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentProofPayload {
    pub proof_request: ProofRequest,
    pub credentials: HashMap<String, Credential>,
    pub witnesses: HashMap<String, Witness>,
    pub master_secret: MasterSecret,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialProposalPayload {
    pub issuer: String,
    pub subject: String,
    pub schema: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCredentialPayload {
    pub credential_offering: CredentialOffer,
    pub credential_schema: CredentialSchema,
    pub master_secret: MasterSecret,
    pub credential_values: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestProofPayload {
    pub verifier_did: String,
    pub prover_did: String,
    pub sub_proof_requests: Vec<SubProofRequest>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCredentialPayload {
    pub issuer: String,
    pub revocation_registry_definition: String,
    pub credential_revocation_id: u32,
    pub issuer_public_key_did: String,
    pub issuer_proving_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateProofPayload {
    pub presented_proof: ProofPresentation,
    pub proof_request: ProofRequest,
}

pub struct VadeEvan {
    vade: Vade,
}

impl VadeEvan {
    /// Creates new instance of `VadeEvan`.
    pub fn new(vade: Vade) -> VadeEvan {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        VadeEvan { vade }
    }
}

impl VadeEvan {
    /// Whitelists an identity on substrate, which is required to perform transactions.
    ///
    /// # Arguments
    ///
    /// * `data` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan/*/vade_evan/struct.AuthenticationOptions.html)
    pub async fn whitelist_identity(
        &mut self,
        data: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let input: AuthenticationOptions = serde_json::from_str(&data)?;
        let options = format!(
            r###"{{
            "privateKey": "{}",
            "identity": "{}",
            "operation": "whitelistIdentity"
        }}"###,
            input.private_key, input.identity
        );
        let identity_did = format!("{}0x{}", EVAN_METHOD_PREFIX, &input.identity);

        let result = self
            .vade
            .did_update(&identity_did, &options, &"".to_string())
            .await?;

        if result.is_empty() {
            return Err(Box::from(
                "Could not generate DID as no listeners were registered for this method",
            ));
        }

        Ok(())
    }

    async fn generate_did(
        &mut self,
        private_key: &str,
        identity: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let options = format!(
            r###"{{
            "privateKey": "{}",
            "identity": "{}"
        }}"###,
            private_key, identity
        );
        let result = self
            .vade
            .did_create(EVAN_METHOD, &options, &"".to_string())
            .await?;
        if result.is_empty() {
            return Err(Box::from(
                "Could not generate DID as no listeners were registered for this method",
            ));
        }

        let generated_did = format!(
            "{}{}",
            EVAN_METHOD_ZKP_PREFIX,
            &result[0].as_ref().unwrap().to_owned(),
        );

        Ok(generated_did)
    }

    async fn set_did_document(
        &mut self,
        did: &str,
        payload: &str,
        private_key: &str,
        identity: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let options = format!(
            r###"{{
            "privateKey": "{}",
            "identity": "{}",
            "operation": "setDidDocument"
        }}"###,
            &private_key, &identity
        );
        let result = self.vade.did_update(&did, &options, &payload).await?;

        if result.is_empty() {
            return Err(Box::from(
                "Could not set did document as no listeners were registered for this method",
            ));
        }

        Ok(Some("".to_string()))
    }
}

#[async_trait(?Send)]
impl VadePlugin for VadeEvan {
    /// Creates a new credential definition and stores the public part on-chain. The private part (key) needs
    /// to be stored in a safe way and must not be shared. A credential definition holds cryptographic material
    /// needed to verify proofs. Every definition is bound to one credential schema.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential definition for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan/*/vade_evan/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`CreateCredentialDefinitionPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.CreateCredentialDefinitionPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The created definition as a JSON object
    async fn vc_zkp_create_credential_definition(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let options: AuthenticationOptions = serde_json::from_str(&options)?;
        let payload: CreateCredentialDefinitionPayload = serde_json::from_str(&payload)?;

        let results = &self.vade.did_resolve(&payload.schema_did).await?;
        if results.is_empty() {
            return Err(Box::from(format!(
                "could not get schema \"{}\"",
                &payload.schema_did
            )));
        }
        let schema: CredentialSchema = serde_json::from_str(&results[0].as_ref().unwrap()).unwrap();

        let generated_did = self
            .generate_did(&options.private_key, &options.identity)
            .await?;

        let (definition, pk) = Issuer::create_credential_definition(
            &generated_did,
            &payload.issuer_did,
            &schema,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
        );

        let serialized = serde_json::to_string(&(&definition, &pk)).unwrap();
        let serialized_definition = serde_json::to_string(&definition).unwrap();
        self.set_did_document(
            &generated_did,
            &serialized_definition,
            &options.private_key,
            &options.identity,
        )
        .await?;

        Ok(VadePluginResultValue::Success(Some(serialized)))
    }

    /// Creates a new zero-knowledge proof credential schema.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential schema for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan/*/vade_evan/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`CreateCredentialSchemaPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.CreateCredentialSchemaPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The created schema as a JSON object
    async fn vc_zkp_create_credential_schema(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let options: AuthenticationOptions = serde_json::from_str(&options)?;
        let payload: CreateCredentialSchemaPayload = serde_json::from_str(&payload)?;

        let generated_did = self
            .generate_did(&options.private_key, &options.identity)
            .await?;

        let schema = Issuer::create_credential_schema(
            &generated_did,
            &payload.issuer,
            &payload.schema_name,
            &payload.description,
            payload.properties,
            payload.required_properties,
            payload.allow_additional_properties,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
        );

        let serialized = serde_json::to_string(&schema).unwrap();
        self.set_did_document(
            &generated_did,
            &serialized,
            &options.private_key,
            &options.identity,
        )
        .await?;

        Ok(VadePluginResultValue::Success(Some(serialized)))
    }

    /// Creates a new revocation registry definition and stores it on-chain. The definition consists of a public
    /// and a private part. The public part holds the cryptographic material needed to create non-revocation proofs.
    /// The private part needs to reside with the registry owner and is used to revoke credentials.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a revocation registry definition for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan/*/vade_evan/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`CreateRevocationRegistryDefinitionPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.CreateRevocationRegistryDefinitionPayload.html)
    ///
    /// # Returns
    /// * created revocation registry definition as a JSON object as serialized [`CreateRevocationRegistryDefinitionResult`](https://docs.rs/vade_evan/*/vade_evan/struct.CreateRevocationRegistryDefinitionResult.html)
    async fn vc_zkp_create_revocation_registry_definition(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let options: AuthenticationOptions = serde_json::from_str(&options)?;
        let payload: CreateRevocationRegistryDefinitionPayload = serde_json::from_str(&payload)?;

        debug!(
            "fetching credential definition with did: {}",
            &payload.credential_definition
        );
        let definition: CredentialDefinition = serde_json::from_str(
            &self
                .vade
                .did_resolve(&payload.credential_definition)
                .await?[0]
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        let generated_did = self
            .generate_did(&options.private_key, &options.identity)
            .await?;

        let (definition, private_key, revocation_info) =
            Issuer::create_revocation_registry_definition(
                &generated_did,
                &definition,
                &payload.issuer_public_key_did,
                &payload.issuer_proving_key,
                payload.maximum_credential_count,
            );

        let serialized_def = serde_json::to_string(&definition).unwrap();

        self.set_did_document(
            &generated_did,
            &serialized_def,
            &options.private_key,
            &options.identity,
        )
        .await?;

        let serialized_result = serde_json::to_string(&CreateRevocationRegistryDefinitionResult {
            private_key,
            revocation_info,
            revocation_registry_definition: definition,
        })
        .unwrap();

        Ok(VadePluginResultValue::Success(Some(serialized_result)))
    }

    /// Issues a new credential. This requires an issued schema, credential definition, an active revocation
    /// registry and a credential request message.
    ///
    /// # Arguments
    ///
    /// * `method` - method to issue a credential for (e.g. "did:example")
    /// * `_options` - no authenticated request required, so can be left empty
    /// * `payload` - serialized [`IssueCredentialPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.IssueCredentialPayload.html)
    ///
    /// # Returns
    /// * serialized [`IssueCredentialResult`](https://docs.rs/vade_evan/*/vade_evan/struct.IssueCredentialResult.html) consisting of the credential, this credential's initial revocation state and
    /// the updated revocation info, only interesting for the issuer (needs to be stored privately)
    async fn vc_zkp_issue_credential(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: IssueCredentialPayload = serde_json::from_str(&payload)?;

        debug!(
            "fetching credential definition with did: {}",
            &payload.credential_request.credential_definition,
        );
        let definition: CredentialDefinition = serde_json::from_str(
            &self
                .vade
                .did_resolve(&payload.credential_request.credential_definition)
                .await?[0]
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        debug!("fetching schema with did: {}", &definition.schema);
        let schema: CredentialSchema = serde_json::from_str(
            &self.vade.did_resolve(&definition.schema).await?[0]
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        debug!(
            "fetching revocation definition with did: {}",
            &payload.credential_revocation_definition,
        );
        let mut revocation_definition: RevocationRegistryDefinition = serde_json::from_str(
            &self
                .vade
                .did_resolve(&payload.credential_revocation_definition)
                .await?[0]
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        let (credential, revocation_state, revocation_info) = Issuer::issue_credential(
            &payload.issuer,
            &payload.subject,
            payload.credential_request,
            definition,
            payload.credential_private_key,
            schema,
            &mut revocation_definition,
            payload.revocation_private_key,
            &payload.revocation_information,
        )
        .unwrap();

        Ok(VadePluginResultValue::Success(Some(
            serde_json::to_string(&IssueCredentialResult {
                credential,
                revocation_state,
                revocation_info,
            })
            .unwrap(),
        )))
    }

    /// Creates a `CredentialOffer` message. A `CredentialOffer` is sent by an issuer and is the response
    /// to a `CredentialProposal`. The `CredentialOffer` specifies which schema and definition the issuer
    /// is capable and willing to use for credential issuance.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential offer for (e.g. "did:example")
    /// * `_options` - no authenticated request required, so can be left empty
    /// * `payload` - serialized [`OfferCredentialPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.OfferCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The offer as a JSON object
    async fn vc_zkp_create_credential_offer(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: OfferCredentialPayload = serde_json::from_str(&payload)?;
        let result: CredentialOffer = Issuer::offer_credential(
            &payload.issuer,
            &payload.subject,
            &payload.schema,
            &payload.credential_definition,
        );
        Ok(VadePluginResultValue::Success(Some(
            serde_json::to_string(&result).unwrap(),
        )))
    }

    /// Presents a proof for one or more credentials. A proof presentation is the response to a
    /// proof request. The proof needs to incorporate all required fields from all required schemas
    /// requested in the proof request.
    ///
    /// # Arguments
    ///
    /// * `method` - method to presents a proof for (e.g. "did:example")
    /// * `_options` - no authenticated request required, so can be left empty
    /// * `payload` - serialized [`PresentProofPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.PresentProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The offer as a JSON object
    async fn vc_zkp_present_proof(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: PresentProofPayload = serde_json::from_str(&payload)?;

        // Resolve all necessary credential definitions, schemas and registries
        let mut definitions: HashMap<String, CredentialDefinition> = HashMap::new();
        let mut schemas: HashMap<String, CredentialSchema> = HashMap::new();
        let mut revocation_definitions: HashMap<String, RevocationRegistryDefinition> =
            HashMap::new();
        for req in &payload.proof_request.sub_proof_requests {
            let schema_did = &req.schema;
            debug!("fetching schema with did: {}", &schema_did);
            schemas.insert(
                schema_did.clone(),
                serde_json::from_str(
                    &self.vade.did_resolve(&schema_did).await?[0]
                        .as_ref()
                        .unwrap(),
                )
                .unwrap(),
            );

            let definition_did = payload
                .credentials
                .get(schema_did)
                .unwrap()
                .signature
                .credential_definition
                .clone();
            debug!(
                "fetching credential definition with did: {}",
                &definition_did
            );
            definitions.insert(
                schema_did.clone(),
                serde_json::from_str(
                    &self.vade.did_resolve(&definition_did).await?[0]
                        .as_ref()
                        .unwrap(),
                )
                .unwrap(),
            );

            // Resolve revocation definition
            let rev_definition_did = payload
                .credentials
                .get(schema_did)
                .unwrap()
                .signature
                .revocation_registry_definition
                .clone();
            debug!(
                "fetching revocation definition with did: {}",
                &rev_definition_did
            );
            revocation_definitions.insert(
                schema_did.clone(),
                serde_json::from_str(
                    &self.vade.did_resolve(&rev_definition_did).await?[0]
                        .as_ref()
                        .unwrap(),
                )
                .unwrap(),
            );
        }

        let result: ProofPresentation = Prover::present_proof(
            payload.proof_request,
            payload.credentials,
            definitions,
            schemas,
            revocation_definitions,
            payload.witnesses,
            &payload.master_secret,
        );

        Ok(VadePluginResultValue::Success(Some(
            serde_json::to_string(&result).unwrap(),
        )))
    }

    /// Creates a new zero-knowledge proof credential proposal. This message is the first in the
    /// credential issuance flow and is sent by the potential credential holder to the credential issuer.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential proposal for (e.g. "did:example")
    /// * `_options` - no authenticated request required, so can be left empty
    /// * `payload` - serialized [`CreateCredentialProposalPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.CreateCredentialProposalPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The proposal as a JSON object
    async fn vc_zkp_create_credential_proposal(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: CreateCredentialProposalPayload = serde_json::from_str(&payload)?;
        let result: CredentialProposal =
            Prover::propose_credential(&payload.issuer, &payload.subject, &payload.schema);

        Ok(VadePluginResultValue::Success(Some(
            serde_json::to_string(&result).unwrap(),
        )))
    }

    /// Requests a credential. This message is the response to a credential offering and is sent by the potential
    /// credential holder. It incorporates the target schema, credential definition offered by the issuer, and
    /// the encoded values the holder wants to get signed. The credential is not stored on-chain and needs to be
    /// kept private.
    ///
    /// # Arguments
    ///
    /// * `method` - method to request a credential for (e.g. "did:example")
    /// * `_options` - no authenticated request required, so can be left empty
    /// * `payload` - serialized [`RequestCredentialPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.RequestCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object consisting of the `CredentialRequest` and `CredentialSecretsBlindingFactors` (to be stored at the proofer's site in a private manner)
    async fn vc_zkp_request_credential(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: RequestCredentialPayload = serde_json::from_str(&payload)?;

        debug!(
            "fetching credential definition with did: {}",
            &payload.credential_offering.credential_definition,
        );
        let definition: CredentialDefinition = serde_json::from_str(
            &self
                .vade
                .did_resolve(&payload.credential_offering.credential_definition)
                .await?[0]
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        let result = Prover::request_credential(
            payload.credential_offering,
            definition,
            payload.credential_schema,
            payload.master_secret,
            payload.credential_values,
        )?;

        Ok(VadePluginResultValue::Success(Some(
            serde_json::to_string(&result).unwrap(),
        )))
    }

    /// Requests a zero-knowledge proof for one or more credentials issued under one or more specific schemas and
    /// is sent by a verifier to a prover.
    /// The proof request consists of the fields the verifier wants to be revealed per schema.
    ///
    /// # Arguments
    ///
    /// * `method` - method to request a proof for (e.g. "did:example")
    /// * `_options` - no authenticated request required, so can be left empty
    /// * `payload` - serialized [`RequestProofPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.RequestProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A `ProofRequest` as JSON
    async fn vc_zkp_request_proof(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: RequestProofPayload = serde_json::from_str(&payload)?;
        let result: ProofRequest = Verifier::request_proof(
            &payload.verifier_did,
            &payload.prover_did,
            payload.sub_proof_requests,
        );

        Ok(VadePluginResultValue::Success(Some(
            serde_json::to_string(&result).unwrap(),
        )))
    }

    /// Revokes a credential. After revocation the published revocation registry needs to be updated with information
    /// returned by this function. To revoke a credential, tbe revoker must be in posession of the private key associated
    /// with the credential's revocation registry. After revocation, the published revocation registry must be updated.
    /// Only then is the credential truly revoked.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to revoke a credential for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan/*/vade_evan/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`RevokeCredentialPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.RevokeCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The updated revocation registry definition as a JSON object. Contains information
    /// needed to update the respective revocation registry.
    async fn vc_zkp_revoke_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let options: AuthenticationOptions = serde_json::from_str(&options)?;
        let payload: RevokeCredentialPayload = serde_json::from_str(&payload)?;

        debug!(
            "fetching revocation definition with did: {}",
            &payload.revocation_registry_definition,
        );
        let rev_def: RevocationRegistryDefinition = serde_json::from_str(
            &self
                .vade
                .did_resolve(&payload.revocation_registry_definition)
                .await?[0]
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        let updated_registry = Issuer::revoke_credential(
            &payload.issuer,
            &rev_def,
            payload.credential_revocation_id,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
        );

        let serialized = serde_json::to_string(&updated_registry).unwrap();

        self.set_did_document(
            &rev_def.id,
            &serialized,
            &options.private_key,
            &options.identity,
        )
        .await?;

        Ok(VadePluginResultValue::Success(Some(serialized)))
    }

    /// Verifies a one or multiple proofs sent in a proof presentation.
    ///
    /// # Arguments
    ///
    /// * `method` - method to verify a proof for (e.g. "did:example")
    /// * `_options` - no authenticated request required, so can be left empty
    /// * `payload` - serialized [`ValidateProofPayload`](https://docs.rs/vade_evan/*/vade_evan/struct.ValidateProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object representing a `ProofVerification` type, specifying whether verification was successful
    async fn vc_zkp_verify_proof(
        &mut self,
        method: &str,
        _options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: ValidateProofPayload = serde_json::from_str(&payload)?;

        // Resolve all necessary credential definitions, schemas and registries
        let mut definitions: HashMap<String, CredentialDefinition> = HashMap::new();
        let mut rev_definitions: HashMap<String, Option<RevocationRegistryDefinition>> =
            HashMap::new();
        let mut schemas: HashMap<String, CredentialSchema> = HashMap::new();
        for req in &payload.proof_request.sub_proof_requests {
            let schema_did = &req.schema;
            debug!("fetching schema with did: {}", &schema_did);
            schemas.insert(
                schema_did.clone(),
                serde_json::from_str(
                    &self.vade.did_resolve(&schema_did).await?[0]
                        .as_ref()
                        .unwrap(),
                )
                .unwrap(),
            );
        }

        for credential in &payload.presented_proof.verifiable_credential {
            let definition_did = &credential.proof.credential_definition.clone();
            debug!(
                "fetching credential definition with did: {}",
                &definition_did
            );
            definitions.insert(
                credential.credential_schema.id.clone(),
                serde_json::from_str(
                    &self.vade.did_resolve(&definition_did).await?[0]
                        .as_ref()
                        .unwrap(),
                )
                .unwrap(),
            );

            let rev_definition_did = &credential.proof.revocation_registry_definition.clone();
            debug!(
                "fetching revocation definition with did: {}",
                &rev_definition_did
            );
            rev_definitions.insert(
                credential.credential_schema.id.clone(),
                Some(
                    serde_json::from_str(
                        &self.vade.did_resolve(&rev_definition_did).await?[0]
                            .as_ref()
                            .unwrap(),
                    )
                    .unwrap(),
                ),
            );
        }

        let result: ProofVerification = Verifier::verify_proof(
            payload.presented_proof,
            payload.proof_request,
            definitions,
            schemas,
            rev_definitions,
        );

        Ok(VadePluginResultValue::Success(Some(
            serde_json::to_string(&result).unwrap(),
        )))
    }
}
