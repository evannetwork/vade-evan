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

use crate::{
    application::{
        datatypes::{
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
            RevocationIdInformation,
            RevocationKeyPrivate,
            RevocationRegistryDefinition,
            RevocationState,
            SchemaProperty,
            SubProofRequest,
        },
        issuer::Issuer,
        prover::Prover,
        verifier::Verifier,
    },
    signing::Signer,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error};
use ursa::{
    bn::BigNumber,
    cl::{constants::LARGE_PRIME, helpers::generate_safe_prime, Witness},
};
use vade::{Vade, VadePlugin, VadePluginResultValue};

const EVAN_METHOD: &str = "did:evan";
const EVAN_METHOD_ZKP: &str = "did:evan:zkp";

macro_rules! parse {
    ($data:expr, $type_name:expr) => {{
        serde_json::from_str($data)
            .map_err(|e| format!("{} when parsing {} {}", &e, $type_name, $data))?
    }};
}

macro_rules! get_document {
    ($vade:expr, $did:expr, $type_name:expr) => {{
        debug!("fetching {} with did; {}", $type_name, $did);
        let resolve_result = $vade.did_resolve($did).await?;
        let result_str = resolve_result[0]
            .as_ref()
            .ok_or_else(|| format!("could not get {} did document", $type_name))?;
        parse!(&result_str, &$type_name)
    }};
}

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
    pub p_safe: Option<BigNumber>,
    pub q_safe: Option<BigNumber>,
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
    pub blinding_factors: CredentialSecretsBlindingFactors,
    pub master_secret: MasterSecret,
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
    pub credential_schema: String,
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
    signer: Box<dyn Signer>,
    vade: Vade,
}

impl VadeEvan {
    /// Creates new instance of `VadeEvan`.
    pub fn new(vade: Vade, signer: Box<dyn Signer>) -> VadeEvan {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        VadeEvan { signer, vade }
    }
}

impl VadeEvan {
    /// Generate new safe prime number with `ursa`'s configured default size.
    /// Can be used to generate values for:
    ///
    /// - payload.p_safe
    /// - payload.q_safe
    ///
    /// for [`vc_zkp_create_credential_definition`](https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_credential_definition).
    pub fn generate_safe_prime() -> Result<String, Box<dyn Error>> {
        let bn = generate_safe_prime(LARGE_PRIME)
            .map_err(|err| format!("could not generate safe prime number; {}", &err))?;
        serde_json::to_string(&bn)
            .map_err(|err| Box::from(format!("could not serialize big number; {}", &err)))
    }

    async fn generate_did(
        &mut self,
        private_key: &str,
        identity: &str,
    ) -> Result<String, Box<dyn Error>> {
        let options = format!(
            r###"{{
            "privateKey": "{}",
            "identity": "{}"
        }}"###,
            private_key, identity
        );
        let result = self
            .vade
            .did_create(EVAN_METHOD_ZKP, &options, &"".to_string())
            .await?;
        if result.is_empty() {
            return Err(Box::from(
                "Could not generate DID as no listeners were registered for this method",
            ));
        }

        let generated_did = result[0]
            .as_ref()
            .ok_or("could not generate DID")?
            .to_owned();

        Ok(generated_did)
    }

    async fn set_did_document(
        &mut self,
        did: &str,
        payload: &str,
        private_key: &str,
        identity: &str,
    ) -> Result<Option<String>, Box<dyn Error>> {
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
    /// Runs a custom function, currently supports
    ///
    /// - `generate_safe_prime` to generate safe prime numbers for [`vc_zkp_create_credential_definition`](https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.vc_zkp_create_credential_definition)
    ///
    /// # Arguments
    ///
    /// * `method` - method to call a function for (e.g. "did:example")
    /// * `function` - currently only supports `generate_safe_prime`
    /// * `_options` - currently not used, so can be left empty
    /// * `_payload` - currently not used, so can be left empty
    async fn run_custom_function(
        &mut self,
        method: &str,
        function: &str,
        _options: &str,
        _payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        match function {
            "generate_safe_prime" => Ok(VadePluginResultValue::Success(Some(
                VadeEvan::generate_safe_prime()?,
            ))),
            _ => Ok(VadePluginResultValue::Ignored),
        }
    }

    /// Creates a new credential definition and stores the public part on-chain. The private part (key) needs
    /// to be stored in a safe way and must not be shared. A credential definition holds cryptographic material
    /// needed to verify proofs. Every definition is bound to one credential schema.
    ///
    /// To improve performance, safe prime numbers that are used to derive keys from **can** be
    /// pre-generated with custom function `generate_safe_prime` which can be called with
    /// [`run_custom_function`](https://docs.rs/vade_evan/*/vade_evan/struct.VadeEvan.html#method.run_custom_function).
    /// For these numbers two calls have to be made to create two distinct numbers. They can then
    /// be provided as [`payload.p_safe`](https://docs.rs/vade_evan/*/vade_evan/struct.CreateCredentialDefinitionPayload.html#structfield.p_safe)
    /// and [`payload.q_safe`](https://docs.rs/vade_evan/*/vade_evan/struct.CreateCredentialDefinitionPayload.html#structfield.q_safe).
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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: CreateCredentialDefinitionPayload = parse!(&payload, "payload");
        let schema: CredentialSchema = get_document!(&mut self.vade, &payload.schema_did, "schema");

        let generated_did = self
            .generate_did(&options.private_key, &options.identity)
            .await?;

        let (definition, pk) = Issuer::create_credential_definition(
            &generated_did,
            &payload.issuer_did,
            &schema,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
            payload.p_safe.as_ref(),
            payload.q_safe.as_ref(),
        )
        .await?;

        let serialized = serde_json::to_string(&(&definition, &pk))?;
        let serialized_definition = serde_json::to_string(&definition)?;
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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: CreateCredentialSchemaPayload = parse!(&payload, "payload");

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
            &self.signer,
        )
        .await?;

        let serialized = serde_json::to_string(&schema)?;
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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: CreateRevocationRegistryDefinitionPayload = parse!(&payload, "payload");
        let definition: CredentialDefinition = get_document!(
            &mut self.vade,
            &payload.credential_definition,
            "credential definition"
        );

        let generated_did = self
            .generate_did(&options.private_key, &options.identity)
            .await?;

        let (definition, private_key, revocation_info) =
            Issuer::create_revocation_registry_definition(
                &generated_did,
                &definition,
                &payload.issuer_public_key_did,
                &payload.issuer_proving_key,
                &self.signer,
                payload.maximum_credential_count,
            )
            .await?;

        let serialized_def = serde_json::to_string(&definition)?;

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
        })?;

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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: IssueCredentialPayload = parse!(&payload, "payload");
        let definition: CredentialDefinition = get_document!(
            &mut self.vade,
            &payload.credential_request.credential_definition,
            "credential definition"
        );
        let schema: CredentialSchema = get_document!(&mut self.vade, &definition.schema, "schema");
        let mut revocation_definition: RevocationRegistryDefinition = get_document!(
            &mut self.vade,
            &payload.credential_revocation_definition,
            "revocation definition"
        );

        let schema_copy: CredentialSchema = serde_json::from_str(&serde_json::to_string(&schema)?)?;
        let request_copy: CredentialRequest =
            serde_json::from_str(&serde_json::to_string(&payload.credential_request)?)?;
        let definition_copy: CredentialDefinition =
            serde_json::from_str(&serde_json::to_string(&definition)?)?;
        let (mut credential, revocation_state, revocation_info) = Issuer::issue_credential(
            &payload.issuer,
            &payload.subject,
            payload.credential_request,
            definition,
            payload.credential_private_key,
            schema,
            &mut revocation_definition,
            payload.revocation_private_key,
            &payload.revocation_information,
        )?;

        Prover::post_process_credential_signature(
            &mut credential,
            &schema_copy,
            &request_copy,
            &definition_copy,
            payload.blinding_factors,
            &payload.master_secret,
            &revocation_definition,
            &revocation_state.witness,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &IssueCredentialResult {
                credential,
                revocation_state,
                revocation_info,
            },
        )?)))
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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: OfferCredentialPayload = parse!(&payload, "payload");
        let result: CredentialOffer = Issuer::offer_credential(
            &payload.issuer,
            &payload.subject,
            &payload.schema,
            &payload.credential_definition,
        )?;
        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: PresentProofPayload = parse!(&payload, "payload");

        // Resolve all necessary credential definitions, schemas and registries
        let mut definitions: HashMap<String, CredentialDefinition> = HashMap::new();
        let mut schemas: HashMap<String, CredentialSchema> = HashMap::new();
        let mut revocation_definitions: HashMap<String, RevocationRegistryDefinition> =
            HashMap::new();
        for req in &payload.proof_request.sub_proof_requests {
            let schema_did = &req.schema;
            schemas.insert(
                schema_did.clone(),
                get_document!(&mut self.vade, &schema_did, "schema"),
            );

            let definition_did = payload
                .credentials
                .get(schema_did)
                .ok_or("invalid schema")?
                .signature
                .credential_definition
                .clone();
            definitions.insert(
                schema_did.clone(),
                get_document!(&mut self.vade, &definition_did, "credential definition"),
            );

            // Resolve revocation definition
            let rev_definition_did = payload
                .credentials
                .get(schema_did)
                .ok_or("invalid schema")?
                .signature
                .revocation_registry_definition
                .clone();
            revocation_definitions.insert(
                schema_did.clone(),
                get_document!(&mut self.vade, &rev_definition_did, "revocation definition"),
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
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: CreateCredentialProposalPayload = parse!(&payload, "payload");
        let result: CredentialProposal =
            Prover::propose_credential(&payload.issuer, &payload.subject, &payload.schema);

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: RequestCredentialPayload = serde_json::from_str(&payload)
            .map_err(|e| format!("{} when parsing payload {}", &e, &payload))?;
        let definition: CredentialDefinition = get_document!(
            &mut self.vade,
            &payload.credential_offering.credential_definition,
            "credential definition"
        );
        let schema: CredentialSchema =
            get_document!(&mut self.vade, &payload.credential_schema, "schema");

        let result = Prover::request_credential(
            payload.credential_offering,
            definition,
            schema,
            payload.master_secret,
            payload.credential_values,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: RequestProofPayload = parse!(&payload, "payload");
        let result: ProofRequest = Verifier::request_proof(
            &payload.verifier_did,
            &payload.prover_did,
            payload.sub_proof_requests,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Revokes a credential. After revocation the published revocation registry needs to be updated with information
    /// returned by this function. To revoke a credential, tbe revoker must be in possession of the private key associated
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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: RevokeCredentialPayload = parse!(&payload, "payload");
        let rev_def: RevocationRegistryDefinition = get_document!(
            &mut self.vade,
            &payload.revocation_registry_definition,
            "revocation registry definition"
        );

        let updated_registry = Issuer::revoke_credential(
            &payload.issuer,
            &rev_def,
            payload.credential_revocation_id,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized = serde_json::to_string(&updated_registry)?;

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
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        if method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let payload: ValidateProofPayload = parse!(&payload, "payload");

        // Resolve all necessary credential definitions, schemas and registries
        let mut definitions: HashMap<String, CredentialDefinition> = HashMap::new();
        let mut rev_definitions: HashMap<String, Option<RevocationRegistryDefinition>> =
            HashMap::new();
        let mut schemas: HashMap<String, CredentialSchema> = HashMap::new();
        for req in &payload.proof_request.sub_proof_requests {
            let schema_did = &req.schema;
            schemas.insert(
                schema_did.clone(),
                get_document!(&mut self.vade, &schema_did, "schema"),
            );
        }

        for credential in &payload.presented_proof.verifiable_credential {
            let definition_did = &credential.proof.credential_definition.clone();
            definitions.insert(
                credential.credential_schema.id.clone(),
                get_document!(&mut self.vade, definition_did, "credential definition"),
            );

            let rev_definition_did = &credential.proof.revocation_registry_definition.clone();
            rev_definitions.insert(
                credential.credential_schema.id.clone(),
                get_document!(&mut self.vade, &rev_definition_did, "revocation definition"),
            );
        }

        let result: ProofVerification = Verifier::verify_proof(
            payload.presented_proof,
            payload.proof_request,
            definitions,
            schemas,
            rev_definitions,
        );

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }
}
