use regex::Regex;
use serde::de::DeserializeOwned;
use serde_json::{value::Value, Map};
use std::collections::HashMap;
use thiserror::Error;
use vade_evan_bbs::{
    BbsCredential,
    BbsProofRequest,
    BbsSubProofRequest,
    CredentialSchema,
    PresentProofPayload,
    RequestProofPayload,
};

use super::{
    datatypes::DidDocumentResult,
    shared::{convert_to_nquads, create_draft_credential_from_schema, SharedError},
};
use crate::api::VadeEvan;
use crate::helpers::credential::Credential;
use crate::helpers::datatypes::EVAN_METHOD;

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
    #[error(r#"JSON serialization of {0} failed due to "{1}""#)]
    JsonSerialization(String, String),
    #[error(r#"JSON deserialization of {0} failed due to "{1}" on: {2}"#)]
    JsonDeserialization(String, String, String),
    #[error(r#"schema with DID "{0}" does not seem to be a valid schema: {1}"#)]
    SchemaInvalid(String, String),
    #[error(r#"schema with DID "{0}" could not be found"#)]
    SchemaNotFound(String),
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
const NQUAD_REGEX: &str = r"^_:c14n0 <http://schema.org/([^>]+?)>";
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

    /// Creates a presentation.
    /// The presentation has proof and requested credentials.
    ///
    /// # Arguments
    ///
    /// * `proof_request` - proof request for presentation
    /// * `credential` - credential to be shared in presentation
    /// * `master_secret` - user's master secret
    /// * `signing_key` - users secp256k1 private signing key
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
        revealed_attributes: Option<&str>,
    ) -> Result<String, PresentationError> {
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
        let credential_without_proof =
            serde_json::to_string(&parsed_credential).map_err(|err| {
                PresentationError::JsonSerialization(
                    "credential_without_proof".to_owned(),
                    err.to_string(),
                )
            })?;
        let nquads = convert_to_nquads(&credential_without_proof).await?;

        let mut nquads_schema_map = HashMap::new();
        nquads_schema_map.insert(schema_did.to_owned(), nquads);

        // credential_schema_map
        let mut credential_schema_map = HashMap::new();
        credential_schema_map.insert(schema_did.to_owned(), credential.clone());

        // revealed_properties_schema_map
        let mut revealed_properties_schema_map = HashMap::new();
        let revealed = credential.credential_subject.clone();
        revealed_properties_schema_map.insert(schema_did.to_owned(), revealed);

        // get prover did
        let prover = credential.credential_subject.id.clone().ok_or_else(|| {
            PresentationError::InternalError("CredentialSubject doesn't contain did".to_owned())
        })?;

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
            prover_did: prover.clone(),
            prover_public_key_did: format!("{}#key-1", prover),
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
        let credential_draft =
            create_draft_credential_from_schema(false, Some("did:placeholder"), &schema);
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
#[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
mod tests_proof_request {

    use anyhow::Result;
    use vade_evan_bbs::BbsProofRequest;

    use crate::{VadeEvan, DEFAULT_SIGNER, DEFAULT_TARGET};

    use super::Presentation;

    const SIGNER_PRIVATE_KEY: &str =
        "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106";
    const MASTER_SECRET: &str = "QyRmu33oIQFNW+dSI5wex3u858Ra7yx5O1tsxJgQvu8=";
    const NOT_A_SCHEMA_DID: &str = "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA"; // some identity DID
    const NOT_FOUND_DID: &str = "did:evan:EiBrPL8Yif5NWHOzbKvyh1PX1wKVlWvIa6nTG1v8PXytvgfoobar";
    const SCHEMA_DID: &str = "did:evan:EiBrPL8Yif5NWHOzbKvyh1PX1wKVlWvIa6nTG1v8PXytvg"; // evan.address
    const SCHEMA_DID_2: &str = "did:evan:EiCimsy3uWJ7PivWK0QUYSCkImQnjrx6fGr6nK8XIg26Kg";
    const CREDENTIAL: &str = r###"{
        "id": "uuid:70b7ec4e-f035-493e-93d3-2cf5be4c7f88",
        "type": [
            "VerifiableCredential"
        ],
        "proof": {
            "type": "BbsBlsSignature2020",
            "created": "2023-02-01T14:08:17.000Z",
            "signature": "kvSyi40dnZ5S3/mSxbSUQGKLpyMXDQNLCPtwDGM9GsnNNKF7MtaFHXIbvXaVXku0EY/n2uNMQ2bmK2P0KEmzgbjRHtzUOWVdfAnXnVRy8/UHHIyJR471X6benfZk8KG0qVqy+w67z9g628xRkFGA5Q==",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA#bbs-key-1",
            "credentialMessageCount": 13,
            "requiredRevealStatements": []
        },
        "issuer": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA",
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.org/",
            "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "issuanceDate": "2023-02-01T14:08:09.849Z",
        "credentialSchema": {
            "id": "did:evan:EiCimsy3uWJ7PivWK0QUYSCkImQnjrx6fGr6nK8XIg26Kg",
            "type": "EvanVCSchema"
        },
        "credentialStatus": {
            "id": "did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA#4",
            "type": "RevocationList2020Status",
            "revocationListIndex": "4",
            "revocationListCredential": "did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA"
        },
        "credentialSubject": {
            "id": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA",
            "data": {
                "bio": "biography"
            }
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
        assert_eq!(parsed.sub_proof_requests[0].revealed_attributes, [14, 16],);

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
            [12, 13, 14, 15, 16],
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
            .create_proof_request(SCHEMA_DID_2, Some(r#"["bio"]"#))
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
                None,
            )
            .await;
        dbg!(&presentation_result);
        assert!(presentation_result.is_ok());

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
