use regex::Regex;
use serde::de::DeserializeOwned;
use std::collections::HashMap;

use thiserror::Error;
use vade_evan_bbs::{CredentialSchema, RequestProofPayload};

use super::{
    datatypes::DidDocumentResult,
    shared::{convert_to_nquads, create_draft_credential_from_schema, SharedError},
};
use crate::api::VadeEvan;
use crate::helpers::datatypes::EVAN_METHOD;

#[derive(Error, Debug)]
pub enum PresentationError {
    #[error("internal VadeEvan call failed; {0}")]
    VadeEvanError(String),
    #[error("{0}")]
    JsonLdHandling(#[from] SharedError), // for now only one type of error from shared helper, so just re-package it
    #[error("could not find revealed attributes in nquads; {0}")]
    InvalidRevealedAttributes(String),
    #[error("internal error occurred; {0}")]
    InternalError(String),
    #[error("JSON (de)serialization failed")]
    JsonDeSerialization(#[from] serde_json::Error),
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

    pub async fn create_proof_request(
        &mut self,
        schema_did: &str,
        revealed_attributes: &[&str],
    ) -> Result<String, PresentationError> {
        let mut reveal_attributes = HashMap::new();
        reveal_attributes.insert(schema_did.to_string(), revealed_attributes.to_vec());
        let proof_request_payload = RequestProofPayload {
            verifier_did: None,
            schemas: vec![schema_did.to_string()],
            reveal_attributes: self
                .get_reveal_attributes_map(schema_did, revealed_attributes)
                .await?,
        };

        let proof_request_json = serde_json::to_string(&proof_request_payload)?;

        self.vade_evan
            .vc_zkp_request_proof(EVAN_METHOD, TYPE_OPTIONS, &proof_request_json)
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
        let did_result_value: DidDocumentResult<T> = serde_json::from_str(&did_result_str)?;

        Ok(did_result_value.did_document)
    }

    async fn get_reveal_attributes_map(
        &mut self,
        schema_did: &str,
        revealed_attributes: &[&str],
    ) -> Result<HashMap<String, Vec<usize>>, PresentationError> {
        let regex = Regex::new(NQUAD_REGEX).map_err(|err| {
            PresentationError::InternalError(format!("regex for nquads invalid; {0}", &err))
        })?;

        // get nquads for schema
        let schema: CredentialSchema = self.get_did_document(schema_did).await?;
        let credential_draft =
            create_draft_credential_from_schema(false, Some("did:placeholder"), schema);
        let credential_draft_str = serde_json::to_string(&credential_draft)?;
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

        // collect indices for attributes we have and collect missing ones
        let mut attribute_indices: Vec<usize> = vec![];
        let mut missing_attributes: Vec<&str> = vec![];
        for attribute_name in revealed_attributes.iter() {
            if let Some(index) = name_to_index_map.get(attribute_name) {
                attribute_indices.push(*index + ADDITIONAL_HIDDEN_MESSAGES_COUNT);
            } else {
                missing_attributes.push(attribute_name);
            }
        }

        if missing_attributes.len() > 0 {
            return Err(PresentationError::InvalidRevealedAttributes(
                missing_attributes.join(", "),
            ));
        }

        Ok(HashMap::from([(schema_did.to_string(), attribute_indices)]))
    }
}

#[cfg(test)]
mod tests_proof_request {

    use anyhow::Result;
    use vade_evan_bbs::BbsProofRequest;

    use crate::{VadeEvan, DEFAULT_SIGNER, DEFAULT_TARGET};

    // evan.address
    const SCHEMA_DID: &str = "did:evan:EiBrPL8Yif5NWHOzbKvyh1PX1wKVlWvIa6nTG1v8PXytvg";

    #[tokio::test]

    async fn helper_can_create_proof_request() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let result = vade_evan
            .helper_create_proof_request(SCHEMA_DID, &["zip", "country"])
            .await;

        assert!(result.is_ok());
        let parsed: BbsProofRequest = serde_json::from_str(&result?)?;
        assert_eq!(parsed.r#type, "BBS");
        assert_eq!(parsed.sub_proof_requests[0].schema, SCHEMA_DID);
        assert_eq!(parsed.sub_proof_requests[0].revealed_attributes, [16, 14]);

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
