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
    application::datatypes::{CredentialRequest, CredentialSchema, RevocationRegistryDefinition},
    crypto::crypto_datatypes::{CryptoCredentialDefinition, CryptoRevocationRegistryDefinition},
};
use std::{collections::HashSet, error::Error};
use ursa::{
    bn::BigNumber,
    cl::{
        issuer::Issuer as CryptoIssuer,
        new_nonce,
        CredentialPrivateKey,
        CredentialPublicKey,
        CredentialSignature,
        Nonce,
        RevocationKeyPrivate,
        RevocationRegistry,
        RevocationRegistryDelta,
        SignatureCorrectnessProof,
        SimpleTailsAccessor,
        Witness,
    },
};

// Mediator class to broker between the high-level vade-evan application issuer and the Ursa issuer class
pub struct Issuer {}

impl Issuer {
    pub fn new() -> Issuer {
        Issuer {}
    }

    pub fn create_credential_definition(
        credential_schema: &CredentialSchema,
        _p_safe: Option<&BigNumber>,
        _q_safe: Option<&BigNumber>,
    ) -> Result<(CredentialPrivateKey, CryptoCredentialDefinition), Box<dyn Error>> {
        let mut non_credential_schema_builder =
            CryptoIssuer::new_non_credential_schema_builder()
                .map_err(|e| format!("could not get new non credential schema builder; {}", &e))?;
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
            .map_err(|e| format!("could not finalize non credential schema; {}", &e))?;

        // Retrieve property names from schema
        // TODO: Object handling, how to handle nested object properties?
        let mut credential_schema_builder = CryptoIssuer::new_credential_schema_builder()
            .map_err(|e| format!("could not create credential schema builder; {}", &e))?;
        for property in &credential_schema.properties {
            credential_schema_builder
                .add_attr(&property.0)
                .map_err(|e| format!("could not add attribute to credential schema; {}", &e))?;
        }
        let crypto_schema = credential_schema_builder
            .finalize()
            .map_err(|e| format!("could not finalize credential schema; {}", &e))?;

        let (public_key, credential_private_key, credential_key_correctness_proof) = {
            // if p_safe.is_none() || q_safe.is_none() {
            CryptoIssuer::new_credential_def(&crypto_schema, &non_credential_schema, true)
                .map_err(|e| format!("could not create credential definition; {}", &e))?
            // } else {
            //     CryptoIssuer::new_credential_def_with_primes(
            //         &crypto_schema,
            //         &non_credential_schema,
            //         true,
            //         p_safe.ok_or("could not get prime number p_safe")?,
            //         q_safe.ok_or("could not get prime number q_safe")?,
            //     )
            //     .map_err(|e| format!("could not create credential definition; {}", &e))?
            // }
        };

        let definition = CryptoCredentialDefinition {
            public_key,
            credential_key_correctness_proof,
        };

        Ok((credential_private_key, definition))
    }

    pub fn sign_credential(
        credential_request: &CredentialRequest,
        credential_private_key: &CredentialPrivateKey,
        credential_public_key: &CredentialPublicKey,
    ) -> Result<(CredentialSignature, SignatureCorrectnessProof, Nonce), Box<dyn Error>> {
        let credential_issuance_nonce =
            new_nonce().map_err(|e| format!("could not get new nonce; {}", &e))?;

        let mut value_builder = CryptoIssuer::new_credential_values_builder()
            .map_err(|e| format!("could not create credential values builder; {}", &e))?;
        for pair in &credential_request.credential_values {
            value_builder
                .add_dec_known(&pair.0, &pair.1.encoded)
                .map_err(|e| format!("could not add credential value; {}", &e))?;
        }
        let values = value_builder
            .finalize()
            .map_err(|e| format!("could not finalize credential values; {}", &e))?;

        let (cred, proof) = CryptoIssuer::sign_credential(
            &credential_request.subject,
            &credential_request.blinded_credential_secrets,
            &credential_request.blinded_credential_secrets_correctness_proof,
            &credential_request.credential_nonce,
            &credential_issuance_nonce,
            &values,
            &credential_public_key,
            &credential_private_key,
        )
        .map_err(|e| format!("could not sign credential; {}", &e))?;

        Ok((cred, proof, credential_issuance_nonce))
    }

    pub fn sign_credential_with_revocation(
        credential_request: &CredentialRequest,
        credential_private_key: &CredentialPrivateKey,
        credential_public_key: &CredentialPublicKey,
        credential_revocation_definition: &mut RevocationRegistryDefinition,
        credential_revocation_id: u32,
        revocation_private_key: &RevocationKeyPrivate,
    ) -> Result<
        (
            CredentialSignature,
            SignatureCorrectnessProof,
            Nonce,
            Witness,
        ),
        Box<dyn Error>,
    > {
        let credential_issuance_nonce =
            new_nonce().map_err(|e| format!("could not get new nonce; {}", &e))?;

        let tails_accessor = SimpleTailsAccessor::new(&mut credential_revocation_definition.tails)
            .map_err(|e| format!("could not create SimpleTailsAccessor; {}", &e))?;

        let mut value_builder = CryptoIssuer::new_credential_values_builder()
            .map_err(|e| format!("could not create credential values builder; {}", &e))?;
        for pair in &credential_request.credential_values {
            value_builder
                .add_dec_known(&pair.0, &pair.1.encoded)
                .map_err(|e| format!("could not add credential value; {}", &e))?;
        }
        let values = value_builder
            .finalize()
            .map_err(|e| format!("could not finalize credential values; {}", &e))?;

        // no delta because we assume issuance_by_default == true
        let (cred, proof, _) = CryptoIssuer::sign_credential_with_revoc(
            &credential_request.subject,
            &credential_request.blinded_credential_secrets,
            &credential_request.blinded_credential_secrets_correctness_proof,
            &credential_request.credential_nonce,
            &credential_issuance_nonce,
            &values,
            credential_public_key,
            credential_private_key,
            credential_revocation_id,
            credential_revocation_definition.maximum_credential_count,
            true, // TODO: Make global var
            &mut credential_revocation_definition.registry,
            &revocation_private_key,
            &tails_accessor,
        )
        .map_err(|e| format!("could not sign credential with revoc; {}", &e))?;

        let witness = Witness::new(
            credential_revocation_id,
            credential_revocation_definition.maximum_credential_count,
            true, // TODO: Global const
            &credential_revocation_definition.registry_delta,
            &tails_accessor,
        )
        .map_err(|e| format!("could not create witness; {}", &e))?;

        Ok((cred, proof, credential_issuance_nonce, witness))
    }

    pub fn create_revocation_registry(
        credential_public_key: &CredentialPublicKey,
        maximum_credential_count: u32,
    ) -> Result<(CryptoRevocationRegistryDefinition, RevocationKeyPrivate), Box<dyn Error>> {
        let (rev_key_pub, rev_key_priv, rev_registry, rev_tails_gen) =
            CryptoIssuer::new_revocation_registry_def(
                credential_public_key,
                maximum_credential_count,
                true,
            )
            .map_err(|e| format!("could not create revocation registry definition; {}", &e))?;

        let revoked = HashSet::new();
        let issued = HashSet::new();
        let rev_reg_delta =
            RevocationRegistryDelta::from_parts(None, &rev_registry, &issued, &revoked);

        let rev_def = CryptoRevocationRegistryDefinition {
            registry: rev_registry,
            registry_delta: rev_reg_delta,
            tails: rev_tails_gen,
            revocation_public_key: rev_key_pub,
            maximum_credential_count,
        };

        Ok((rev_def, rev_key_priv))
    }

    pub fn revoke_credential(
        revocation_registry_definition: &RevocationRegistryDefinition,
        revocation_id: u32,
    ) -> Result<RevocationRegistryDelta, Box<dyn Error>> {
        let mut registry = revocation_registry_definition.registry.clone();
        let mut tails_gen = revocation_registry_definition.tails.clone();
        let max_cred_num = revocation_registry_definition.maximum_credential_count;
        let tails = SimpleTailsAccessor::new(&mut tails_gen)
            .map_err(|e| format!("could not create SimpleTailsAccessor; {}", &e))?;
        match CryptoIssuer::revoke_credential(&mut registry, max_cred_num, revocation_id, &tails) {
            Ok(delta) => Ok(delta),
            Err(_) => return Err(Box::from("Unable to revoke credential")),
        }
    }

    pub fn update_revocation_registry(
        revocation_registry_delta: RevocationRegistryDelta,
    ) -> RevocationRegistry {
        let new_registry = RevocationRegistry::from(revocation_registry_delta);
        return new_registry;
    }
}

impl Default for Issuer {
    fn default() -> Self {
        Self::new()
    }
}
