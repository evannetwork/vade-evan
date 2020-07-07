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

pub mod verifier {
    extern crate ursa;

    use ursa::cl::issuer::Issuer as CryptoIssuer;
    use ursa::cl::verifier::Verifier as CryptoVerifier;
    use ursa::cl::Proof as CryptoProof;
    use ursa::cl::RevocationKeyPublic;
    use ursa::cl::RevocationRegistry;
    use ursa::cl::SubProof;
    use ursa::cl::SubProofRequest;

    use crate::application::datatypes::{
        CredentialDefinition,
        CredentialSchema,
        ProofPresentation,
        ProofRequest,
        RevocationRegistryDefinition,
    };
    use std::collections::HashMap;

    // Mediator class to broker between the high-level vade-evan application verifier and the Ursa verifier class
    pub struct CredVerifier {}

    impl CredVerifier {
        pub fn new() -> CredVerifier {
            CredVerifier {}
        }

        pub fn request_proof(attributes: Vec<&str>
        ) -> Result<SubProofRequest, Box<dyn std::error::Error>> {
            let mut sub_proof_request_builder =
                CryptoVerifier::new_sub_proof_request_builder()
                    .map_err(|e| format!("could not create sub proof request builder: {}", &e))?;
            for i in 0..attributes.len() {
                sub_proof_request_builder
                    .add_revealed_attr(&attributes[i])
                    .map_err(|e| format!("could not add revealed attribute: {}", &e))?;
            }
            let sub_proof_request = sub_proof_request_builder
                .finalize()
                .map_err(|e| format!("could not finalize sub proof request: {}", &e))?;

            Ok(sub_proof_request)
        }

        pub fn verify_proof(
            presented_proof: &ProofPresentation,
            proof_request: &ProofRequest,
            credential_definitions: &HashMap<String, CredentialDefinition>,
            credential_schemas: &HashMap<String, CredentialSchema>,
            revocation_registiry_definition: &HashMap<String, Option<RevocationRegistryDefinition>>,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let mut proof_verifier = CryptoVerifier::new_proof_verifier()
                .map_err(|e| format!("could not create proof verifier: {}", &e))?;

            let mut non_credential_schema_builder =
                CryptoIssuer::new_non_credential_schema_builder()
                    .map_err(|e| format!("could not create non credential schema builder: {}", &e))?;
            non_credential_schema_builder
                .add_attr("master_secret")
                .map_err(|e| format!("could not add master secret to non credential schema: {}", &e))?;
            let non_credential_schema = non_credential_schema_builder
                .finalize()
                .map_err(|e| format!("could not finalize non credential schema: {}", &e))?;

            let mut pub_key;
            let mut credential_schema_builder;
            let mut sub_proof_request_builder;
            for sub_proof_request in &proof_request.sub_proof_requests {
                credential_schema_builder = CryptoIssuer::new_credential_schema_builder()
                    .map_err(|e| format!("could not create new credential schema builder: {}", &e))?;
                for property in credential_schemas
                    .get(&sub_proof_request.schema)
                    .ok_or("could not get credential schema for sub proof request")?
                    .properties
                    .keys()
                {
                    credential_schema_builder
                        .add_attr(property)
                        .map_err(|e| format!("could not add credential schema: {}", &e))?;
                }

                sub_proof_request_builder =
                    CryptoVerifier::new_sub_proof_request_builder()
                        .map_err(|e| format!("could not create proof request builder: {}", &e))?;
                for property in &sub_proof_request.revealed_attributes {
                    sub_proof_request_builder
                        .add_revealed_attr(&property)
                        .map_err(|e| format!("could not add revealed attribute to sub proof request: {}", &e))?;
                    credential_schema_builder
                        .add_attr(property)
                        .map_err(|e| format!("could not add attribute to credential schema: {}", &e))?;
                }

                let mut key: Option<RevocationKeyPublic> = None;
                let mut registry: Option<RevocationRegistry> = None;
                let reg_def = revocation_registiry_definition
                    .get(&sub_proof_request.schema)
                    .ok_or("could not get sub proof request schema from revocation registry def")?;
                if reg_def.is_some() {
                    key = Some(
                        reg_def
                            .as_ref()
                            .ok_or("could not get registry registry definition reference")?
                            .revocation_public_key
                            .clone(),
                    );
                    registry = Some(
                        serde_json::from_str(
                            &serde_json::to_string(
                                &reg_def
                                    .as_ref()
                                    .ok_or("could not get registry definition as reference")?
                                    .registry,
                            )?,
                        )?,
                    );
                }

                pub_key = &credential_definitions
                    .get(&sub_proof_request.schema)
                    .ok_or("could not get sub proof request schema")?
                    .public_key;
                proof_verifier
                    .add_sub_proof_request(
                        &sub_proof_request_builder
                            .finalize()
                            .map_err(|e| format!("could not finalize sub proof request: {}", &e))?,
                        &credential_schema_builder
                            .finalize()
                            .map_err(|e| format!("could not finalize credential schema: {}", &e))?,
                        &non_credential_schema,
                        &pub_key,
                        key.as_ref(),
                        registry.as_ref(),
                    )
                    .map_err(|e| format!("could not add sub proof request: {}", &e))?;
            }

            // Create Ursa proof object
            let mut sub_proofs: Vec<SubProof> = Vec::new();
            for vc in &presented_proof.verifiable_credential {
                sub_proofs.push(serde_json::from_str(&vc.proof.proof)?);
            }
            let serialized = format!(
                r###"{{
              "proofs": {},
              "aggregated_proof": {}
          }}"###,
                serde_json::to_string(&sub_proofs)?,
                &presented_proof.proof.aggregated_proof
            );
            let ursa_proof: CryptoProof = serde_json::from_str(&serialized)?;

            if proof_verifier
                .verify(&ursa_proof, &presented_proof.proof.nonce)
                .map_err(|e| format!("could not verify proof: {}", &e))?
            {
                Ok(())
            } else {
                Err(From::from("Proof verification failed"))
            }
        }
    }
}
