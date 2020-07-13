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

use crate::application::datatypes::{
    Credential,
    CredentialDefinition,
    CredentialOffer,
    CredentialRequest,
    CredentialSchema,
    CredentialSchemaReference,
    CredentialSignature,
    CredentialSubject,
    DeltaHistory,
    EncodedCredentialValue,
    RevocationIdInformation,
    RevocationRegistryDefinition,
    RevocationState,
    SchemaProperty,
};
use crate::application::prover::Prover;
use crate::crypto::crypto_issuer::Issuer as CryptoIssuer;
use crate::crypto::crypto_utils::create_assertion_proof;
use crate::utils::utils::{generate_uuid, get_now_as_iso_string};
use std::collections::{HashMap, HashSet};
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};
use ursa::cl::RevocationTailsGenerator;
use ursa::cl::{
    new_nonce,
    CredentialPrivateKey,
    RevocationKeyPrivate,
    RevocationRegistry,
    RevocationRegistryDelta,
};
#[cfg(target_arch = "wasm32")]
use wasm_timer::{SystemTime, UNIX_EPOCH};

/// Holds the logic needed to issue and revoke credentials.
pub struct Issuer {}

impl Issuer {
    pub fn new() -> Issuer {
        Issuer {}
    }

    /// Creates a new credential definition for a `CredentialSchema`. The definition needs to be stored
    /// in a publicly available and temper-proof way.
    ///
    /// # Arguments
    /// * `assigned_did` - DID to be used to revole this credential definition
    /// * `issuer_did` - DID of the issuer
    /// * `schema` - The `CredentialSchema` this definition belongs to
    /// * `issuer_public_key_did` - DID of the public key to check the assertion proof of the definition document
    /// * `issuer_proving_key` - Private key used to create the assertion proof
    ///
    /// # Returns
    /// * `CredentialDefinition` - The definition object to be saved in a publicly available and temper-proof way
    /// * `CredentialPrivateKey` - The private key used to sign credentials. Needs to be stored privately & securely
    pub fn create_credential_definition(
        assigned_did: &str,
        issuer_did: &str,
        schema: &CredentialSchema,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
    ) -> Result<(CredentialDefinition, CredentialPrivateKey), Box<dyn std::error::Error>> {
        let created_at = get_now_as_iso_string();
        let (credential_private_key, crypto_credential_def) =
            CryptoIssuer::create_credential_definition(&schema)?;
        let mut definition = CredentialDefinition {
            id: assigned_did.to_owned(),
            r#type: "EvanZKPCredentialDefinition".to_string(),
            issuer: issuer_did.to_owned(),
            schema: schema.id.to_owned(),
            created_at,
            public_key: crypto_credential_def.public_key,
            public_key_correctness_proof: crypto_credential_def.credential_key_correctness_proof,
            proof: None,
        };

        let document_to_sign = serde_json::to_value(&definition)?;

        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            &issuer_did,
            &issuer_proving_key,
        )?;

        definition.proof = Some(proof);

        Ok((definition, credential_private_key))
    }

    /// Creates a new credential schema specifying properties credentials issued under this schema need to incorporate.
    /// The schema needs to be stored in a publicly available and temper-proof way.
    ///
    /// # Arguments
    /// * `assigned_did` - DID to be used to revole this credential definition
    /// * `issuer_did` - DID of the issuer
    /// * `schema_name` - Name of the schema
    /// * `description` - Description for the schema. Can be left blank
    /// * `properties` - The properties of the schema as Key-Object pairs#
    /// * `required_properties` - The keys of properties that need to be provided when issuing a credential under this schema.
    /// * `allow_additional_properties` - Specifies whether a credential under this schema is considered valid if it specifies more properties than the schema specifies.
    /// * `issuer_public_key_did` - DID of the public key to check the assertion proof of the definition document
    /// * `issuer_proving_key` - Private key used to create the assertion proof
    ///
    /// # Returns
    /// * `CredentialSchema` - The schema object to be saved in a publicly available and temper-proof way
    pub fn create_credential_schema(
        assigned_did: &str,
        issuer_did: &str,
        schema_name: &str,
        description: &str,
        properties: HashMap<String, SchemaProperty>,
        required_properties: Vec<String>,
        allow_additional_properties: bool,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
    ) -> Result<CredentialSchema, Box<dyn std::error::Error>> {
        let created_at = get_now_as_iso_string();

        let mut schema = CredentialSchema {
            id: assigned_did.to_owned(),
            r#type: "EvanVCSchema".to_string(), //TODO: Make enum
            name: schema_name.to_owned(),
            author: issuer_did.to_owned(),
            created_at,
            description: description.to_owned(),
            properties,
            required: required_properties,
            additional_properties: allow_additional_properties,
            proof: None,
        };

        let document_to_sign = serde_json::to_value(&schema)?;

        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            &issuer_did,
            &issuer_proving_key,
        )?;

        schema.proof = Some(proof);

        Ok(schema)
    }

    /// Creates a new revocation registry definition. This definition is used to prove the non-revocation state of a credential.
    /// It needs to be publicly published and updated after every revocation. The definition is signed by the issuer.
    ///
    /// # Arguments
    /// * `assigned_did` - DID that will point to the registry definition
    /// * `credential_definition` - Credential definition this revocation registry definition will be associated with
    /// * `issuer_public_key_did` - DID of the public key that will be associated with the created signature
    /// * `issuer_proving_key` - Private key of the issuer used for signing the definition
    /// * `maximum_credential_count` - Capacity of the revocation registry in terms of issuable credentials
    ///
    /// # Returns
    /// A 3-tuple consisting
    /// * `RevocationRegistryDefinition` - the definition
    /// * `RevocationKeyPrivate` - the according revocation private key, and an revocation
    /// * `RevocationIdInformation` - object used for keeping track of issued revocation IDs
    pub fn create_revocation_registry_definition(
        assigned_did: &str,
        credential_definition: &CredentialDefinition,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        maximum_credential_count: u32,
    ) -> Result<
        (
            RevocationRegistryDefinition,
            RevocationKeyPrivate,
            RevocationIdInformation,
        ),
        Box<dyn std::error::Error>,
    > {
        let (crypto_rev_def, rev_key_private) = CryptoIssuer::create_revocation_registry(
            &credential_definition.public_key,
            maximum_credential_count,
        )?;

        let updated_at = get_now_as_iso_string();

        let delta_history = DeltaHistory {
            created: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "Error generating unix timestamp for delta history")?
                .as_secs(),
            delta: crypto_rev_def.registry_delta.clone(),
        };

        let mut rev_reg_def = RevocationRegistryDefinition {
            id: assigned_did.to_string(),
            credential_definition: credential_definition.id.to_string(),
            registry: crypto_rev_def.registry,
            registry_delta: crypto_rev_def.registry_delta,
            delta_history: vec![delta_history],
            maximum_credential_count,
            revocation_public_key: crypto_rev_def.revocation_public_key,
            tails: crypto_rev_def.tails,
            updated_at,
            proof: None,
        };

        let revoc_info = RevocationIdInformation {
            definition_id: assigned_did.to_string(),
            next_unused_id: 1, // needs to start at 1
            used_ids: HashSet::new(),
        };

        let document_to_sign = serde_json::to_value(&rev_reg_def)?;
        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            &credential_definition.issuer,
            &issuer_proving_key,
        )?;

        rev_reg_def.proof = Some(proof);

        Ok((rev_reg_def, rev_key_private, revoc_info))
    }

    /// Issue a new credential, based on a credential request received by the credential subject
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer
    /// * `subject_did` - DID of the subject
    /// * `credential_request` - Credential request object sent by the subject
    /// * `credential_definition` - Credential definition to use for issuance as specified by the credential request
    /// * `credential_private_key` - Issuer's private key associated with the credential definition
    /// * `credential_schema` - Credential schema to be used as specified by the credential request
    /// * `revocation_registry_definition` - Revocation registry definition to be used for issuance
    /// * `revocation_private_key` - Private key associated to the revocation registry definition
    /// * `revocation_info` - Revocation info containing ID counter. Hold by credential definition owner
    ///
    /// # Returns
    /// Tuple containing
    /// * `Credential` - Issued credential
    /// * `RevocationIdInformation` - Updated `revocation_info` object that needs to be persisted
    pub fn issue_credential(
        issuer_did: &str,
        subject_did: &str,
        credential_request: CredentialRequest,
        credential_definition: CredentialDefinition,
        credential_private_key: CredentialPrivateKey,
        credential_schema: CredentialSchema,
        revocation_registry_definition: &mut RevocationRegistryDefinition,
        revocation_private_key: RevocationKeyPrivate,
        revocation_info: &RevocationIdInformation,
    ) -> Result<(Credential, RevocationState, RevocationIdInformation), Box<dyn std::error::Error>>
    {
        let mut data: HashMap<String, EncodedCredentialValue> = HashMap::new();
        //
        // Optional value handling
        //
        let mut processed_credential_request: CredentialRequest =
            serde_json::from_str(&serde_json::to_string(&credential_request)?)?;
        let mut null_values: HashMap<String, String> = HashMap::new();
        for field in &credential_schema.properties {
            if credential_request.credential_values.get(field.0).is_none() {
                for required in &credential_schema.required {
                    if required.eq(field.0) {
                        // No value provided for required schema property
                        let error = format!("Missing required schema property; {}", field.0);
                        return Err(Box::from(error));
                    }
                }
                null_values.insert(field.0.clone(), "null".to_owned()); // ommtted property is optional, encode it with 'null'
            } else {
                // Add value to credentialSubject part of VC
                let val = credential_request
                    .credential_values
                    .get(field.0)
                    .ok_or("could not get credential subject from request")?
                    .clone();
                data.insert(field.0.to_owned(), val);
            }
        }

        processed_credential_request
            .credential_values
            .extend(Prover::encode_values(null_values)?);

        let credential_subject = CredentialSubject {
            id: subject_did.to_owned(),
            data,
        };

        let schema_reference = CredentialSchemaReference {
            id: credential_schema.id,
            r#type: "EvanZKPSchema".to_string(),
        };

        // Get next unused revocation ID for credential, mark as used & increment counter
        if revocation_info.next_unused_id == revocation_registry_definition.maximum_credential_count
        {
        }
        let rev_idx = revocation_info.next_unused_id;
        let mut used_ids: HashSet<u32> = revocation_info.used_ids.clone();
        if !used_ids.insert(rev_idx) {
            return Err(Box::from("Could not use next revocation ID as it has already been used - Counter information seems to be corrupted"));
        }

        let new_rev_info = RevocationIdInformation {
            definition_id: revocation_registry_definition.id.clone(),
            next_unused_id: rev_idx + 1,
            used_ids,
        };

        let (signature, signature_correctness_proof, issuance_nonce, witness) =
            CryptoIssuer::sign_credential_with_revocation(
                &processed_credential_request,
                &credential_private_key,
                &credential_definition.public_key,
                revocation_registry_definition,
                rev_idx,
                &revocation_private_key,
            )?;

        let credential_id = generate_uuid();

        let delta: RevocationRegistryDelta = serde_json::from_str(&serde_json::to_string(
            &revocation_registry_definition.registry,
        )?)?;

        let revocation_state = RevocationState {
            credential_id: credential_id.clone(),
            revocation_id: rev_idx,
            delta: delta.clone(),
            updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "Error generating unix timestamp for delta history")?
                .as_secs(),
            witness,
        };

        let cred_signature = CredentialSignature {
            r#type: "CLSignature2019".to_string(),
            credential_definition: credential_definition.id,
            issuance_nonce,
            signature,
            signature_correctness_proof,
            revocation_id: rev_idx,
            revocation_registry_definition: revocation_registry_definition.id.clone(),
        };

        let credential = Credential {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            id: credential_id.clone(),
            r#type: vec!["VerifiableCredential".to_string()],
            issuer: issuer_did.to_owned(),
            credential_subject,
            credential_schema: schema_reference,
            signature: cred_signature,
        };
        Ok((credential, revocation_state, new_rev_info))
    }

    /// Creates a new credential offer, as a response to a `CredentialProposal` sent by a prover.
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer
    /// * `subject_did` - DID of the subject
    /// * `schema_did` - DID of the `CredentialSchema` to be offered
    /// * `credential_definition_did` - DID of the `CredentialDefinition` to be offered
    ///
    /// # Returns
    /// * `CredentialOffer` - The message to be sent to the prover.
    pub fn offer_credential(
        issuer_did: &str,
        subject_did: &str,
        schema_did: &str,
        credential_definition_did: &str,
    ) -> Result<CredentialOffer, Box<dyn std::error::Error>> {
        let nonce = new_nonce().map_err(|e| format!("could not get nonce; {}", &e))?;

        Ok(CredentialOffer {
            issuer: issuer_did.to_owned(),
            subject: subject_did.to_owned(),
            r#type: "EvanZKPCredentialOffering".to_string(),
            schema: schema_did.to_owned(),
            credential_definition: credential_definition_did.to_owned(),
            nonce,
        })
    }

    /// Revokes a credential.
    ///
    /// # Arguments
    /// * `issuer` - DID of the issuer
    /// * `revocation_registry_definition` - Revocation registry definition the credential belongs to
    /// * `revocation_id` - Revocation ID of the credential
    /// * `issuer_public_key_did` - DID of the public key that will be associated with the created signature
    /// * `issuer_proving_key` - Private key of the issuer used for signing the definition
    ///
    /// # Returns
    /// * `RevocationRegistryDefinition` - The updated revocation registry definition that needs to be stored in the original revocation registry definition's place.
    pub fn revoke_credential(
        issuer: &str,
        revocation_registry_definition: &RevocationRegistryDefinition,
        revocation_id: u32,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
    ) -> Result<RevocationRegistryDefinition, Box<dyn std::error::Error>> {
        let updated_at = get_now_as_iso_string();

        let delta = CryptoIssuer::revoke_credential(revocation_registry_definition, revocation_id)?;

        let mut full_delta: RevocationRegistryDelta =
            revocation_registry_definition.registry_delta.clone();
        full_delta
            .merge(&delta)
            .map_err(|e| format!("could not create revocation registry delta; {}", &e))?;

        let unix_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Error generating unix timestamp for delta history")?
            .as_secs();
        let delta_history = DeltaHistory {
            created: unix_timestamp,
            delta: delta.clone(),
        };

        let mut history_vec = revocation_registry_definition.delta_history.clone();
        history_vec.push(delta_history);

        let tails: RevocationTailsGenerator =
            revocation_registry_definition.tails.clone().to_owned();
        let mut rev_reg_def = RevocationRegistryDefinition {
            id: revocation_registry_definition.id.to_owned(),
            credential_definition: revocation_registry_definition
                .credential_definition
                .to_owned(),
            registry: RevocationRegistry::from(full_delta.clone()),
            registry_delta: full_delta,
            delta_history: history_vec,
            maximum_credential_count: revocation_registry_definition.maximum_credential_count,
            revocation_public_key: revocation_registry_definition
                .revocation_public_key
                .clone()
                .to_owned(),
            tails,
            updated_at,
            proof: None,
        };

        let document_to_sign = serde_json::to_value(&rev_reg_def)?;
        let proof = create_assertion_proof(
            &document_to_sign,
            issuer_public_key_did,
            issuer,
            issuer_proving_key,
        )?;

        rev_reg_def.proof = Some(proof);

        Ok(rev_reg_def)
    }
}
