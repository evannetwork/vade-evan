use regex::Regex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{value::Value, Map};
use std::collections::HashMap;
use thiserror::Error;
use vade_evan_bbs::{
    recover_address_and_data,
    BbsCredential,
    BbsProofRequest,
    BbsSubProofRequest,
    CredentialSchema,
    PresentProofPayload,
    ProofPresentation,
    RequestProofPayload,
    UnsignedBbsCredential,
    VerifyProofPayload,
};

use super::{
    datatypes::DidDocumentResult,
    shared::{
        check_for_optional_empty_params,
        convert_to_nquads,
        create_draft_credential_from_schema,
        SharedError,
    },
};
use crate::api::VadeEvan;
use crate::helpers::credential::Credential;
use crate::helpers::datatypes::EVAN_METHOD;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum PresentationError {
    #[error("internal VadeEvan call failed; {0}")]
    VadeEvanError(String),
    #[error("{0}")]
    JsonLdHandling(#[from] SharedError), // for now only one type of error from shared helper, so just re-package it
    #[error("could not find revealed attributes in nquads: {0}")]
    InvalidRevealedAttributes(String),
    #[error("internal error occurred; {0}")]
    InternalError(String),
    #[error("invalid presentation provided; {0}")]
    InvalidPresentationError(String),
    #[error(r#"JSON serialization of {0} failed due to "{1}""#)]
    JsonSerialization(String, String),
    #[error(r#"JSON deserialization of {0} failed due to "{1}" on: {2}"#)]
    JsonDeserialization(String, String, String),
    #[error(r#"schema with DID "{0}" does not seem to be a valid schema: {1}"#)]
    SchemaInvalid(String, String),
    #[error(r#"schema with DID "{0}" could not be found"#)]
    SchemaNotFound(String),
    #[error(r#"SelfIssuedCredential are unsigned and can not contain proof"#)]
    SelfIssuedCredentialWithProof(),
}

/// A
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SelfIssuedPresentation {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub verifiable_credential: Vec<UnsignedBbsCredential>,
}

impl PresentationError {
    fn to_serialization_error(
        parsed_object: &str,
    ) -> impl Fn(serde_json::Error) -> PresentationError + '_ {
        move |err| PresentationError::JsonSerialization(parsed_object.to_string(), err.to_string())
    }

    fn to_deserialization_error<'a>(
        to_parse_name: &'a str,
        to_parse_value: &'a str,
    ) -> impl Fn(serde_json::Error) -> PresentationError + 'a {
        move |err| {
            PresentationError::JsonDeserialization(
                to_parse_name.to_string(),
                err.to_string(),
                to_parse_value.to_string(),
            )
        }
    }
}

// Master secret is always incorporated, without being mentioned in the credential schema
const ADDITIONAL_HIDDEN_MESSAGES_COUNT: usize = 1;
const NQUAD_REGEX: &str = r"^_:c14n[0-9]* <http://schema.org/([^>]+?)>";
const TYPE_OPTIONS: &str = r#"{ "type": "bbs" }"#;

pub struct Presentation<'a> {
    vade_evan: &'a mut VadeEvan,
}

impl<'a> Presentation<'a> {
    pub fn new(vade_evan: &'a mut VadeEvan) -> Result<Self, PresentationError> {
        Ok(Self { vade_evan })
    }

    /// Requests a proof for a credential.
    /// The proof request consists of the fields the verifier wants to be revealed per schema.
    ///
    /// # Arguments
    ///
    /// * `schema_did` - DID of schema to request proof for
    /// * `revealed_attributes` - list of names of revealed attributes in specified schema, reveals all if omitted
    ///
    /// # Returns
    /// * `Option<String>` - A `ProofRequest` as JSON
    pub async fn create_proof_request(
        &mut self,
        schema_did: &str,
        revealed_attributes: Option<&str>,
    ) -> Result<String, PresentationError> {
        let revealed_attributes = check_for_optional_empty_params(revealed_attributes);
        let revealed_attributes_parsed: Option<Vec<String>> = revealed_attributes
            .map(|ras| {
                serde_json::from_str(ras).map_err(PresentationError::to_deserialization_error(
                    "revealed attributes",
                    ras,
                ))
            })
            .transpose()?;
        let proof_request_payload = RequestProofPayload {
            verifier_did: None,
            schemas: vec![schema_did.to_string()],
            reveal_attributes: self
                .get_reveal_attributes_indices_map(schema_did, revealed_attributes_parsed)
                .await?,
        };

        let proof_request_json = serde_json::to_string(&proof_request_payload).map_err(
            PresentationError::to_serialization_error("RequestProofPayload"),
        )?;

        self.vade_evan
            .vc_zkp_request_proof(EVAN_METHOD, TYPE_OPTIONS, &proof_request_json)
            .await
            .map_err(|err| PresentationError::VadeEvanError(err.to_string()))
    }

    /// Verifies a presentation.
    ///
    /// The function checks if the presentation is valid against the provided proof request.
    ///
    /// # Arguments
    ///
    /// * `presentation_str` - verifiable presentation from the holder as JSON string
    /// * `proof_request_str` - proof request from the verifier as JSON string
    ///
    /// # Returns
    /// * `Result<String, PresentationError>` - A `BbsProofVerification` as JSON
    ///   wrapped in a `Result` along with a potential `PresentationError`
    pub async fn verify_presentation(
        &mut self,
        presentation_str: &str,
        proof_request_str: &str,
    ) -> Result<String, PresentationError> {
        let presentation: ProofPresentation = serde_json::from_str(presentation_str).map_err(
            PresentationError::to_deserialization_error("presentation", presentation_str),
        )?;
        let proof_request: BbsProofRequest = serde_json::from_str(proof_request_str).map_err(
            PresentationError::to_deserialization_error("proof request", proof_request_str),
        )?;

        let credential = presentation.verifiable_credential.get(0).ok_or_else(|| {
            PresentationError::InvalidPresentationError(
                "Credentail not found in presentation".to_owned(),
            )
        })?;

        let schema_did = &credential.credential_schema.id;

        let mut map_for_nquads: Map<String, Value> = Map::new();
        map_for_nquads.insert("@context".to_owned(), credential.context.to_owned().into());

        for (k, v) in credential.credential_subject.data.to_owned() {
            map_for_nquads.insert(k, serde_json::Value::String(v));
        }

        let mut helper_credential = Credential::new(self.vade_evan)
            .map_err(|err| PresentationError::InternalError(err.to_string()))?;

        let public_key_issuer = helper_credential
            .get_issuer_public_key(&credential.issuer, "#bbs-key-1")
            .await
            .map_err(|err| PresentationError::InternalError(err.to_string()))?;
        let mut keys_to_schema_map = HashMap::new();
        keys_to_schema_map.insert(schema_did.to_owned(), public_key_issuer);

        let mut revocation_list = None;
        if credential.credential_status.is_some() {
            let credential_status = &credential.clone().credential_status.ok_or_else(|| {
                PresentationError::InternalError("Error in parsing credential_status".to_string())
            })?;
            revocation_list = helper_credential
                .get_did_document(&credential_status.revocation_list_credential)
                .await
                .map_err(|err| PresentationError::InternalError(err.to_string()))?;
        }

        // extract signing address
        let mut presentation_value: Value = serde_json::from_str(presentation_str).map_err(
            PresentationError::to_deserialization_error("presentation", &presentation_str),
        )?;

        let presentation_value_with_proof =
            presentation_value.as_object_mut().ok_or_else(|| {
                PresentationError::InternalError("Error in parsing presentation proof".to_string())
            })?;

        let presentation_value_without_proof = presentation_value_with_proof
            .remove("proof")
            .ok_or_else(|| {
                PresentationError::InternalError("Error in parsing presentation proof".to_string())
            })?;

        let (signer_address, _) = recover_address_and_data(
            presentation_value_without_proof["jws"]
                .as_str()
                .ok_or_else(|| {
                    PresentationError::InternalError(
                        "Error in parsing presentation proof".to_string(),
                    )
                })?,
        )
        .map_err(|err| PresentationError::InternalError(err.to_string()))?;
        let signer_address = format!("0x{}", signer_address);
        let proof_request = VerifyProofPayload {
            presentation: presentation.clone(),
            proof_request,
            keys_to_schema_map,
            signer_address,
            revocation_list,
        };
        let payload = serde_json::to_string(&proof_request).map_err(
            PresentationError::to_serialization_error("VerifyProofPayload"),
        )?;
        self.vade_evan
            .vc_zkp_verify_proof(EVAN_METHOD, TYPE_OPTIONS, &payload)
            .await
            .map_err(|err| PresentationError::VadeEvanError(err.to_string()))
    }

    /// Creates a presentation.
    /// The presentation has proof and requested credentials.
    ///
    /// # Arguments
    ///
    /// * `proof_request` - proof request for presentation
    /// * `credential` - credential to be shared in presentation
    /// * `master_secret` - user's master secret
    /// * `signing_key` - users secp256k1 private signing key
    /// * `prover_did` - did of prover/holder
    /// * `revealed_attributes` - list of names of revealed attributes in specified schema,
    ///
    /// # Returns
    /// * `Option<String>` - A `Presentation` as JSON
    pub async fn create_presentation(
        &mut self,
        proof_request_str: &str,
        credential_str: &str,
        master_secret: &str,
        signing_key: &str,
        prover_did: &str,
        revealed_attributes: Option<&str>,
    ) -> Result<String, PresentationError> {
        let revealed_attributes = check_for_optional_empty_params(revealed_attributes);
        let credential: BbsCredential = serde_json::from_str(credential_str).map_err(
            PresentationError::to_deserialization_error("credential", credential_str),
        )?;
        let schema_did = &credential.credential_schema.id;

        let mut proof_request: BbsProofRequest = serde_json::from_str(proof_request_str).map_err(
            PresentationError::to_deserialization_error("proof request", proof_request_str),
        )?;
        let matched_schema = proof_request
            .sub_proof_requests
            .clone()
            .into_iter()
            .filter(|sub_proof| &sub_proof.schema == schema_did)
            .collect::<Vec<BbsSubProofRequest>>();

        if matched_schema.is_empty() {
            return Err(PresentationError::SchemaInvalid(
                schema_did.to_string(),
                "Proof request schema doesn't match with Credential schema".to_owned(),
            ));
        }
        if revealed_attributes.is_some() {
            let revealed_attributes_parsed: Option<Vec<String>> = revealed_attributes
                .map(|ras| {
                    serde_json::from_str(ras).map_err(PresentationError::to_deserialization_error(
                        "revealed attributes",
                        ras,
                    ))
                })
                .transpose()?;
            let reveal_attributes = self
                .get_reveal_attributes_indices_map(schema_did, revealed_attributes_parsed)
                .await?;
            for sub_proof in proof_request.sub_proof_requests.iter_mut() {
                if &sub_proof.schema == schema_did {
                    sub_proof.revealed_attributes = reveal_attributes
                        .get(schema_did)
                        .ok_or_else(|| {
                            PresentationError::InternalError(format!(
                                "RevealedAttributes not found for schema {}",
                                schema_did
                            ))
                        })?
                        .to_owned()
                }
            }
        }
        // get nquads
        let mut parsed_credential: Map<String, Value> =
            serde_json::from_str(credential_str).map_err(
                PresentationError::to_deserialization_error("credential", credential_str),
            )?;
        parsed_credential.remove("proof");

        // credential_schema_map
        let mut credential_schema_map = HashMap::new();
        credential_schema_map.insert(schema_did.to_owned(), credential.clone());

        // revealed_properties_schema_map
        let mut revealed_properties_schema_map = HashMap::new();
        let revealed = credential.credential_subject.clone();
        revealed_properties_schema_map.insert(schema_did.to_owned(), revealed);

        let mut helper_credential = Credential::new(self.vade_evan)
            .map_err(|err| PresentationError::InternalError(err.to_string()))?;
        let public_key_issuer = helper_credential
            .get_issuer_public_key(&credential.issuer, "#bbs-key-1")
            .await
            .map_err(|err| PresentationError::InternalError(err.to_string()))?;
        let mut public_key_schema_map = HashMap::new();

        public_key_schema_map.insert(schema_did.to_owned(), public_key_issuer);

        let present_proof_payload = PresentProofPayload {
            proof_request,
            credential_schema_map,
            revealed_properties_schema_map,
            public_key_schema_map,
            master_secret: master_secret.to_owned(),
            prover_did: prover_did.to_owned(),
            prover_public_key_did: format!("{}#key-1", prover_did.to_owned()),
            prover_proving_key: signing_key.to_owned(),
        };

        let payload = serde_json::to_string(&present_proof_payload).map_err(|err| {
            PresentationError::JsonSerialization("PresentProofPayload".to_owned(), err.to_string())
        })?;
        self.vade_evan
            .vc_zkp_present_proof(EVAN_METHOD, TYPE_OPTIONS, &payload)
            .await
            .map_err(|err| PresentationError::VadeEvanError(err.to_string()))
    }

    /// Creates a self issued presentation.
    /// The presentation has no proof.
    ///
    /// # Arguments
    ///
    /// * `unsigned_credential` - self issued credential (without proof) to be shared in presentation
    ///
    /// # Returns
    /// * `Option<String>` - A `SelfIssuedPresentation` as JSON
    pub async fn create_self_issued_presentation(
        &mut self,
        unsigned_credential_str: &str,
    ) -> Result<String, PresentationError> {
        if unsigned_credential_str.contains("proof") {
            return Err(PresentationError::SelfIssuedCredentialWithProof());
        }
        let unsigned_credential: UnsignedBbsCredential = serde_json::from_str(
            unsigned_credential_str,
        )
        .map_err(PresentationError::to_deserialization_error(
            "UnsignedCredential",
            unsigned_credential_str,
        ))?;

        let self_issued_presentation = SelfIssuedPresentation {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_owned(),
                "https://schema.org/".to_owned(),
                "https://w3id.org/vc-revocation-list-2020/v1".to_owned(),
            ],
            id: format!("{}", Uuid::new_v4()),
            r#type: vec!["VerifiablePresentation".to_owned()],
            verifiable_credential: vec![unsigned_credential],
        };
        let self_issued_presentation_str = serde_json::to_string(&self_issued_presentation)
            .map_err(|err| {
                PresentationError::JsonSerialization(
                    "SelfIssuedPresentation".to_owned(),
                    err.to_string(),
                )
            })?;
        Ok(self_issued_presentation_str)
    }

    async fn get_did_document<T>(&mut self, did: &str) -> Result<T, PresentationError>
    where
        T: DeserializeOwned,
    {
        let did_result_str = self
            .vade_evan
            .did_resolve(did)
            .await
            .map_err(|err| PresentationError::VadeEvanError(err.to_string()))?;

        if did_result_str == "Not Found" {
            return Err(PresentationError::SchemaNotFound(did.to_string()));
        }

        let did_result_value: DidDocumentResult<T> = serde_json::from_str(&did_result_str)
            .map_err(|err| {
                PresentationError::SchemaInvalid(
                    did.to_string(),
                    PresentationError::to_deserialization_error("DID document", &did_result_str)(
                        err,
                    )
                    .to_string(),
                )
            })?;

        Ok(did_result_value.did_document)
    }

    async fn get_reveal_attributes_indices_map(
        &mut self,
        schema_did: &str,
        revealed_attributes: Option<Vec<String>>,
    ) -> Result<HashMap<String, Vec<usize>>, PresentationError> {
        let regex = Regex::new(NQUAD_REGEX).map_err(|err| {
            PresentationError::InternalError(format!("regex for nquads invalid; {0}", &err))
        })?;

        // get parsed schema and "clone" it due to move occurring below
        let schema: CredentialSchema = self.get_did_document(schema_did).await?;
        // get nquads for schema
        let credential_draft = create_draft_credential_from_schema(false, &schema);
        let credential_draft_str = serde_json::to_string(&credential_draft).map_err(
            PresentationError::to_serialization_error("UnsignedBbsCredential"),
        )?;
        let nquads = convert_to_nquads(&credential_draft_str).await?;

        // avoid duplicated regex applications, so build property to index map beforehand
        let mut name_to_index_map: HashMap<&str, usize> = HashMap::new();
        for (index, nquad) in nquads.iter().enumerate() {
            if let Some(captures) = regex.captures(nquad) {
                if let Some(name_match) = captures.get(1) {
                    name_to_index_map.insert(name_match.as_str(), index);
                }
            }
        }

        let attribute_names = revealed_attributes
            .unwrap_or_else(|| schema.properties.keys().map(|p| p.to_string()).collect());

        // collect indices for attributes we have and collect missing ones
        let mut attribute_indices: Vec<usize> = vec![];
        let mut missing_attributes: Vec<&str> = vec![];
        for attribute_name in attribute_names.iter() {
            if let Some(index) = name_to_index_map.get(attribute_name.as_str()) {
                attribute_indices.push(*index + ADDITIONAL_HIDDEN_MESSAGES_COUNT);
            } else {
                missing_attributes.push(attribute_name);
            }
        }

        if missing_attributes.len() > 0 {
            return Err(PresentationError::InvalidRevealedAttributes(
                missing_attributes
                    .iter()
                    .map(|ma| format!(r#""{}""#, &ma))
                    .collect::<Vec<String>>()
                    .join(", "),
            ));
        }

        Ok(HashMap::from([(schema_did.to_string(), attribute_indices)]))
    }
}

#[cfg(test)]
#[cfg(not(all(feature = "c-lib", feature = "target-c-sdk")))]
mod tests_proof_request {

    use anyhow::Result;
    use vade_evan_bbs::{BbsProofRequest, BbsProofVerification};

    use crate::{VadeEvan, DEFAULT_SIGNER, DEFAULT_TARGET};

    use super::Presentation;

    const SIGNER_PRIVATE_KEY: &str =
        "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106";
    const MASTER_SECRET: &str = "XSAzKjR1cNdvtew13KqfynP2tUEuJ+VkKLHVnrnB0Ig=";
    const NOT_A_SCHEMA_DID: &str = "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA"; // some identity DID
    const NOT_FOUND_DID: &str = "did:evan:EiBrPL8Yif5NWHOzbKvyh1PX1wKVlWvIa6nTG1v8PXytvgfoobar";
    const SCHEMA_DID: &str = "did:evan:EiBrPL8Yif5NWHOzbKvyh1PX1wKVlWvIa6nTG1v8PXytvg"; // evan.address
    const SCHEMA_DID_2: &str = "did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg";
    const SUBJECT_DID: &str = "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA";
    const CREDENTIAL: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https://schema.org/",
           "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id":"uuid:4ea2335a-a558-4bd4-b1d5-566838ff1e3a",
        "type":[
           "VerifiableCredential"
        ],
        "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "issuanceDate":"2023-05-03T15:21:42.000Z",
        "credentialSubject":{
           "data":{
              "test_property_string":"value"
           }
        },
        "credentialSchema":{
           "id":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
           "type":"EvanVCSchema"
        },
        "credentialStatus":{
           "id":"did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA#0",
           "type":"RevocationList2021Status",
           "revocationListIndex":"0",
           "revocationListCredential":"did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA"
        },
        "proof":{
           "type":"BbsBlsSignature2020",
           "created":"2023-05-03T15:21:42.000Z",
           "proofPurpose":"assertionMethod",
           "verificationMethod":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
           "credentialMessageCount":13,
           "requiredRevealStatements":[
              1
           ],
           "signature":"sZTYWUrmYaVDUGs1L2UM/7f7UlVLSQS2vPQQG1YWU3TQRlcviNXFDx054zztzG8rWc1lw5e+SJNo4c1x+rpOFiXBjjK6IukN3a0zG5c/ayFbIQ6OVjxV7noWX8aTdNXNO5eyVV2Upd1YB4WGAuUO0w=="
        }
    }"###;
    const UNSIGNED_CREDENTIAL: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https://schema.org/",
           "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id":"uuid:4ea2335a-a558-4bd4-b1d5-566838ff1e3a",
        "type":[
           "VerifiableCredential"
        ],
        "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "issuanceDate":"2023-05-03T15:21:42.000Z",
        "credentialSubject":{
           "data":{
              "test_property_string":"value"
           }
        },
        "credentialSchema":{
           "id":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
           "type":"EvanVCSchema"
        },
        "credentialStatus":{
           "id":"did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA#0",
           "type":"RevocationList2021Status",
           "revocationListIndex":"0",
           "revocationListCredential":"did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA"
        }
    }"###;
    #[tokio::test]
    async fn helper_can_create_proof_request() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut presentation = Presentation::new(&mut vade_evan)?;

        let result = presentation
            .create_proof_request(SCHEMA_DID, Some(r#"["zip", "country"]"#))
            .await;

        assert!(result.is_ok());
        let mut parsed: BbsProofRequest = serde_json::from_str(&result?)?;
        assert_eq!(parsed.r#type, "BBS");
        assert_eq!(parsed.sub_proof_requests[0].schema, SCHEMA_DID);
        parsed.sub_proof_requests[0].revealed_attributes.sort();
        assert_eq!(parsed.sub_proof_requests[0].revealed_attributes, [13, 15],);

        Ok(())
    }

    #[tokio::test]
    async fn helper_returns_an_error_if_schema_did_cannot_be_resolved() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut presentation = Presentation::new(&mut vade_evan)?;

        let result = presentation
            .create_proof_request(NOT_FOUND_DID, Some(r#"["zip", "country"]"#))
            .await;

        match result {
            Ok(_) => assert!(false, "got unexpected result instead of error"),
            Err(err) => assert_eq!(
                err.to_string(),
                format!("schema with DID \"{}\" could not be found", &NOT_FOUND_DID),
            ),
        };

        Ok(())
    }

    #[tokio::test]
    async fn helper_returns_an_error_if_schema_did_resolves_to_non_schema() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut presentation = Presentation::new(&mut vade_evan)?;

        let result = presentation
            .create_proof_request(NOT_A_SCHEMA_DID, Some(r#"["zip", "country"]"#))
            .await;

        match result {
            Ok(_) => assert!(false, "got unexpected result instead of error"),
            Err(err) => assert!(
                err.to_string().starts_with(&format!(r#"schema with DID "{}" does not seem to be a valid schema: JSON deserialization of DID document failed due to "#, NOT_A_SCHEMA_DID)),
            ),
        };

        Ok(())
    }

    #[tokio::test]
    async fn helper_can_detect_invalid_properties() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut presentation = Presentation::new(&mut vade_evan)?;

        let result = presentation
            .create_proof_request(SCHEMA_DID, Some(r#"["zip", "country", "foo", "bar"]"#))
            .await;

        match result {
            Ok(_) => assert!(false, "got unexpected result instead of error"),
            Err(err) => assert_eq!(
                err.to_string(),
                r#"could not find revealed attributes in nquads: "foo", "bar""#
            ),
        };

        Ok(())
    }

    #[tokio::test]
    async fn helper_requests_all_attributes_if_none_are_specified() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut presentation = Presentation::new(&mut vade_evan)?;

        let result = presentation.create_proof_request(SCHEMA_DID, None).await;

        assert!(result.is_ok());
        let mut parsed: BbsProofRequest = serde_json::from_str(&result?)?;
        assert_eq!(parsed.r#type, "BBS");
        assert_eq!(parsed.sub_proof_requests[0].schema, SCHEMA_DID);
        parsed.sub_proof_requests[0].revealed_attributes.sort();
        assert_eq!(
            parsed.sub_proof_requests[0].revealed_attributes,
            [11, 12, 13, 14, 15],
        );

        Ok(())
    }

    #[tokio::test]
    async fn helper_can_create_presentation() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut presentation = Presentation::new(&mut vade_evan)?;

        let proof_request_result = presentation
            .create_proof_request(SCHEMA_DID_2, Some(r#"["test_property_string2"]"#))
            .await;

        assert!(proof_request_result.is_ok());
        let proof_request_str = &proof_request_result?;
        let mut parsed: BbsProofRequest = serde_json::from_str(proof_request_str)?;
        assert_eq!(parsed.r#type, "BBS");
        assert_eq!(parsed.sub_proof_requests[0].schema, SCHEMA_DID_2);
        parsed.sub_proof_requests[0].revealed_attributes.sort();
        assert_eq!(parsed.sub_proof_requests[0].revealed_attributes, [12],);

        let presentation_result = presentation
            .create_presentation(
                proof_request_str,
                CREDENTIAL,
                MASTER_SECRET,
                SIGNER_PRIVATE_KEY,
                SUBJECT_DID,
                None,
            )
            .await;
        assert!(presentation_result.is_ok());

        Ok(())
    }

    #[tokio::test]
    async fn helper_can_create_self_issued_presentation() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut presentation = Presentation::new(&mut vade_evan)?;

        let self_presentation_result = presentation
            .create_self_issued_presentation(UNSIGNED_CREDENTIAL)
            .await;
        assert!(self_presentation_result.is_ok());
        let self_presentation_result_str = self_presentation_result?;
        assert!(
            !self_presentation_result_str.contains("proof"),
            "Self Issued Presentation can not contain proof"
        );
        Ok(())
    }

    #[tokio::test]
    async fn helper_returns_error_if_self_issued_credential_contains_proof() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut presentation = Presentation::new(&mut vade_evan)?;

        let self_presentation_result = presentation
            .create_self_issued_presentation(CREDENTIAL)
            .await;
        match self_presentation_result {
            Ok(_) => assert!(false, "got unexpected result instead of error"),
            Err(err) => assert!(err
                .to_string()
                .ends_with(r#"SelfIssuedCredential are unsigned and can not contain proof"#)),
        };

        Ok(())
    }

    #[tokio::test]
    async fn helper_can_verify_presentation() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut presentation = Presentation::new(&mut vade_evan)?;

        let proof_request_result = presentation
            .create_proof_request(SCHEMA_DID_2, Some(r#"["test_property_string2"]"#))
            .await;

        assert!(proof_request_result.is_ok());
        let proof_request_str = &proof_request_result?;
        let mut parsed: BbsProofRequest = serde_json::from_str(proof_request_str)?;
        assert_eq!(parsed.r#type, "BBS");
        assert_eq!(parsed.sub_proof_requests[0].schema, SCHEMA_DID_2);
        parsed.sub_proof_requests[0].revealed_attributes.sort();

        let presentation_result = presentation
            .create_presentation(
                proof_request_str,
                CREDENTIAL,
                MASTER_SECRET,
                SIGNER_PRIVATE_KEY,
                SUBJECT_DID,
                None,
            )
            .await;
        assert!(presentation_result.is_ok());
        let presentation_str = &presentation_result?;

        let verify_result = presentation
            .verify_presentation(presentation_str, proof_request_str)
            .await;

        assert!(verify_result.is_ok());
        let proof_verification: BbsProofVerification = serde_json::from_str(&verify_result?)?;

        assert_eq!(proof_verification.status, "verified".to_string());
        Ok(())
    }

    #[tokio::test]
    async fn helper_returns_an_error_if_credential_schema_and_proof_request_schema_mismatch(
    ) -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut presentation = Presentation::new(&mut vade_evan)?;
        let proof_request_result = presentation
            .create_proof_request(SCHEMA_DID, Some(r#"["zip", "country"]"#))
            .await;
        assert!(proof_request_result.is_ok());
        let presentation_result = presentation
            .create_presentation(
                &proof_request_result?,
                CREDENTIAL,
                MASTER_SECRET,
                SIGNER_PRIVATE_KEY,
                SUBJECT_DID,
                None,
            )
            .await;

        match presentation_result {
            Ok(_) => assert!(false, "got unexpected result instead of error"),
            Err(err) => assert!(err
                .to_string()
                .ends_with(r#"Proof request schema doesn't match with Credential schema"#)),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests_create_presentation {
    // will be added with further updates
}

#[cfg(test)]
mod tests_verify_presentation {
    // will be added with further updates
}
