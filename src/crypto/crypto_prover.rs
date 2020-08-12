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

extern crate ursa;

use crate::{
    application::{
        datatypes::{
            Credential,
            CredentialDefinition,
            CredentialRequest,
            CredentialSchema,
            CredentialSignature,
            EncodedCredentialValue,
            ProofRequest,
            RevocationRegistryDefinition,
        },
        prover::Prover as ApplicationProver,
    },
    crypto::crypto_datatypes::{CryptoCredentialDefinition, CryptoCredentialRequest},
};
use std::{collections::HashMap, error::Error};
use ursa::{
    cl::{
        issuer::Issuer as CryptoIssuer,
        prover::Prover as CryptoProver,
        verifier::Verifier as CryptoVerifier,
        CredentialPublicKey,
        CredentialSecretsBlindingFactors,
        MasterSecret,
        Nonce,
        Proof,
        RevocationKeyPublic,
        RevocationRegistry,
        Witness,
    },
    errors::UrsaCryptoResult,
};

// Mediator class to broker between the high-level vade-evan application prover and the Ursa prover class
pub struct Prover {}

impl Prover {
    pub fn new() -> Prover {
        Prover {}
    }

    pub fn request_credential(
        requester_did: &str,
        encoded_credential_values: &HashMap<String, EncodedCredentialValue>,
        master_secret: MasterSecret,
        credential_definition: CryptoCredentialDefinition,
        credential_nonce: Nonce,
    ) -> Result<(CryptoCredentialRequest, CredentialSecretsBlindingFactors), Box<dyn Error>> {
        // Master secret will be used to prove that each proof was really issued to the holder/subject/prover
        // Needs to stay secret
        let mut credential_values_builder = CryptoIssuer::new_credential_values_builder()
            .map_err(|e| format!("could not create credential values builder; {}", &e))?;
        for value in encoded_credential_values {
            credential_values_builder
                .add_dec_known(value.0, &value.1.encoded)
                .map_err(|e| format!("could not add credential value; {}", &e))?;
        }
        credential_values_builder
            .add_value_hidden(
                "master_secret",
                &master_secret
                    .value()
                    .map_err(|e| format!("could not get value of master secret; {}", &e))?,
            )
            .map_err(|e| format!("could not add master secret as hidden value; {}", &e))?;
        let credential_values = credential_values_builder
            .finalize()
            .map_err(|e| format!("could not finalize credential values; {}", &e))?;

        let (
            blinded_credential_secrets,
            blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = CryptoProver::blind_credential_secrets(
            &credential_definition.public_key,
            &credential_definition.credential_key_correctness_proof,
            &credential_values,
            &credential_nonce,
        )
        .map_err(|e| format!("could not blind credential secrets; {}", &e))?;

        let req = CryptoCredentialRequest {
            subject: requester_did.to_owned(),
            blinded_credential_secrets,
            blinded_credential_secrets_correctness_proof,
            credential_nonce,
        };

        Ok((req, blinding_factors))
    }

    pub fn create_master_secret() -> UrsaCryptoResult<MasterSecret> {
        return CryptoProver::new_master_secret();
    }

    pub fn create_proof_with_revoc(
        proof_request: &ProofRequest,
        credentials: &HashMap<String, Credential>,
        credential_definitions: &HashMap<String, CredentialDefinition>,
        credential_schemas: &HashMap<String, CredentialSchema>,
        revocation_registries: &HashMap<String, RevocationRegistryDefinition>,
        master_secret: &MasterSecret,
        witnesses: &HashMap<String, Witness>,
    ) -> Result<Proof, Box<dyn Error>> {
        let mut non_credential_schema_builder =
            CryptoIssuer::new_non_credential_schema_builder()
                .map_err(|e| format!("could not create non credential schema builder; {}", &e))?;
        non_credential_schema_builder
            .add_attr("master_secret")
            .map_err(|e| {
                format!(
                    "could not add master secret to non credential schema; {}",
                    &e
                )
            })?;
        let non_credential_schema = non_credential_schema_builder
            .finalize()
            .map_err(|e| format!("could not finalize credential schema; {}", &e))?;

        let mut proof_builder = CryptoProver::new_proof_builder()
            .map_err(|e| format!("could not create proof builder; {}", &e))?;
        proof_builder
            .add_common_attribute("master_secret")
            .map_err(|e| format!("could not add master secret to proof; {}", &e))?;

        let mut credential_schema_builder;
        let mut sub_proof_request_builder;
        let mut credential_values_builder;

        for sub_proof in &proof_request.sub_proof_requests {
            // Build Ursa credential schema & proof requests
            credential_schema_builder = CryptoIssuer::new_credential_schema_builder()
                .map_err(|e| format!("could not create credential schema builder; {}", &e))?;
            sub_proof_request_builder = CryptoVerifier::new_sub_proof_request_builder()
                .map_err(|e| format!("could not create sub proof request builder; {}", &e))?;
            credential_values_builder = CryptoIssuer::new_credential_values_builder()
                .map_err(|e| format!("could not create credential values builder; {}", &e))?;
            for property in &credential_schemas
                .get(&sub_proof.schema)
                .ok_or("Credentials missing for schema")?
                .properties
            {
                credential_schema_builder
                    .add_attr(&property.0)
                    .map_err(|e| format!("could not add schema to credentials; {}", &e))?;

                if credentials
                    .get(&sub_proof.schema)
                    .ok_or("could not get sub proof schema from credential")?
                    .credential_subject
                    .data
                    .get(property.0)
                    .is_none()
                {
                    // Property is not specified in credential, need to encode it with null
                    let mut to_encode: HashMap<String, String> = HashMap::new();
                    to_encode.insert(property.0.clone(), "null".to_owned());
                    let val = ApplicationProver::encode_values(to_encode)?
                        .get(property.0)
                        .ok_or("could not get encoded credential")?
                        .clone();
                    credential_values_builder
                        .add_dec_known(property.0, &val.encoded)
                        .map_err(|e| format!("could not add credential; {}", &e))?;
                }
            }

            for property in &sub_proof.revealed_attributes {
                sub_proof_request_builder
                    .add_revealed_attr(&property)
                    .map_err(|e| format!("could not add revealed attribute; {}", &e))?;
            }
            // Build ursa credential values
            for values in &credentials
                .get(&sub_proof.schema)
                .ok_or("Credentials missing for schema")?
                .credential_subject
                .data
            {
                credential_values_builder
                    .add_dec_known(&values.0, &values.1.encoded)
                    .map_err(|e| format!("could not add credential; {}", &e))?;
            }

            credential_values_builder
                .add_value_hidden(
                    "master_secret",
                    &master_secret
                        .value()
                        .map_err(|e| format!("could not get master secret value; {}", &e))?,
                )
                .map_err(|e| format!("could not add master secret to credentials; {}", &e))?;

            let witness = witnesses
                .get(
                    &credentials
                        .get(&sub_proof.schema)
                        .ok_or("could not get sub proof schema from credentials")?
                        .id,
                )
                .ok_or("could not get witness by sub proof schema")?;

            // Build proof for requested schema & attributes
            proof_builder
                .add_sub_proof_request(
                    &sub_proof_request_builder
                        .finalize()
                        .map_err(|e| format!("could not finalize sub proof request; {}", &e))?,
                    &credential_schema_builder
                        .finalize()
                        .map_err(|e| format!("could not finalize credential schema; {}", &e))?,
                    &non_credential_schema,
                    &credentials
                        .get(&sub_proof.schema)
                        .ok_or("could not get sub proof schema from credentials")?
                        .signature
                        .signature,
                    &credential_values_builder
                        .finalize()
                        .map_err(|e| format!("could not finalize credential values; {}", &e))?,
                    &credential_definitions
                        .get(&sub_proof.schema)
                        .ok_or("could not get sub proof schema from credential definitions")?
                        .public_key,
                    Some(
                        &revocation_registries
                            .get(&sub_proof.schema)
                            .ok_or("could not get sub proof schema from revocation registries")?
                            .registry,
                    ),
                    Some(&witness),
                )
                .map_err(|e| format!("could not add sub proof request; {}", &e))?;
        }

        let proof = proof_builder
            .finalize(&proof_request.nonce)
            .map_err(|e| format!("could not finalize proof; {}", &e))?;

        Ok(proof)
    }

    pub fn process_credential(
        credential: &mut CredentialSignature,
        credential_request: &CredentialRequest,
        credential_public_key: &CredentialPublicKey,
        credential_blinding_factors: &CredentialSecretsBlindingFactors,
        master_secret: &MasterSecret,
        revocation_registry_definition: Option<RevocationRegistryDefinition>,
        witness: &Witness,
    ) -> Result<(), Box<dyn Error>> {
        let mut revocation_key_public: Option<RevocationKeyPublic> = None;
        let mut revocation_registry: Option<RevocationRegistry> = None;
        if let Some(rrd_value) = revocation_registry_definition {
            let rev_def = rrd_value;
            revocation_key_public = Some(rev_def.revocation_public_key);
            revocation_registry = Some(rev_def.registry);
        }

        let mut credential_values_builder = CryptoIssuer::new_credential_values_builder()
            .map_err(|e| format!("could not create credential values builder; {}", &e))?;
        for value in &credential_request.credential_values {
            credential_values_builder
                .add_dec_known(value.0, &value.1.encoded)
                .map_err(|e| format!("could not add credential value; {}", &e))?;
        }
        credential_values_builder
            .add_value_hidden(
                "master_secret",
                &master_secret
                    .value()
                    .map_err(|e| format!("could not get master secret value; {}", &e))?,
            )
            .map_err(|e| format!("could not add master secret to credential values; {}", &e))?;
        let values = credential_values_builder
            .finalize()
            .map_err(|e| format!("could not finalize credential values; {}", &e))?;

        CryptoProver::process_credential_signature(
            &mut credential.signature,
            &values,
            &credential.signature_correctness_proof,
            credential_blinding_factors,
            &credential_public_key,
            &credential.issuance_nonce,
            revocation_key_public.as_ref(),
            revocation_registry.as_ref(),
            Some(witness),
        )
        .map_err(|e| format!("could not process credential signature; {}", &e))?;

        Ok(())
    }
}
