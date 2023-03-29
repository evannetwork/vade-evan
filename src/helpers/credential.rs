use crate::api::VadeEvan;
use crate::helpers::datatypes::EVAN_METHOD;
use std::time::SystemTime;
use std::{io::Read, panic};

use super::datatypes::{DidDocumentResult, IdentityDidDocument};
use super::shared::{convert_to_nquads, create_draft_credential_from_schema, SharedError};
use bbs::{
    prelude::{DeterministicPublicKey, PublicKey},
    signature::Signature,
    HashElem,
    SignatureMessage,
};
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use serde::de::DeserializeOwned;
use serde_json::{value::Value, Map};
use thiserror::Error;
use uuid::Uuid;
use vade_evan_bbs::{
    BbsCredential,
    BbsCredentialOffer,
    BbsCredentialRequest,
    CredentialSchema,
    CredentialSchemaReference,
    CredentialStatus,
    CredentialSubject,
    FinishCredentialPayload,
    IssueCredentialPayload,
    OfferCredentialPayload,
    RevocationListCredential,
    RevokeCredentialPayload,
    UnfinishedBbsCredential,
    UnsignedBbsCredential,
};

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("internal VadeEvan call failed; {0}")]
    VadeEvanError(String),
    #[error("invalid did document")]
    InvalidDidDocument(String),
    #[error("pubkey for verification method not found, {0}")]
    InvalidVerificationMethod(String),
    #[error("credential_status is invalid, {0}")]
    InvalidCredentialStatus(String),
    #[error("JSON (de)serialization failed")]
    JsonDeSerialization(#[from] serde_json::Error),
    #[error("{0}")]
    JsonLdHandling(#[from] SharedError), // for now only one type of error from shared helper, so just re-package it
    #[error("base64 decoding failed")]
    Base64DecodingFailed(#[from] base64::DecodeError),
    #[error("an error has occurred during bbs signature validation: {0}")]
    BbsValidationError(String),
    #[error("could not parse public key: {0}")]
    PublicKeyParsingError(String),
    #[error("revocation list invalid; {0}")]
    RevocationListInvalid(String),
    #[error("credential has been revoked")]
    CredentialRevoked,
    #[error("wrong number of messages in credential, got {0} but proof was created for {1}")]
    MessageCountMismatch(usize, usize),
}

// Master secret is always incorporated, without being mentioned in the credential schema
const ADDITIONAL_HIDDEN_MESSAGES_COUNT: usize = 1;
const TYPE_OPTIONS: &str = r#"{ "type": "bbs" }"#;

fn get_public_key_generator(
    public_key: &str,
    message_count: usize,
) -> Result<PublicKey, CredentialError> {
    let public_key: DeterministicPublicKey =
        DeterministicPublicKey::from(base64::decode(public_key)?.into_boxed_slice());
    let public_key_generator = public_key.to_public_key(message_count).map_err(|e| {
        CredentialError::PublicKeyParsingError(format!(
            "public key invalid, generate public key generator; {}",
            e
        ))
    })?;

    Ok(public_key_generator)
}

pub fn is_revoked(
    credential_status: &CredentialStatus,
    revocation_list: &RevocationListCredential,
) -> Result<bool, CredentialError> {
    let encoded_list = base64::decode_config(
        revocation_list.credential_subject.encoded_list.to_string(),
        base64::URL_SAFE,
    )?;
    let mut decoder = GzDecoder::new(&encoded_list[..]);
    let mut decoded_list = Vec::new();
    decoder
        .read_to_end(&mut decoded_list)
        .map_err(|e| CredentialError::RevocationListInvalid(e.to_string()))?;

    let revocation_list_index_number = credential_status
        .revocation_list_index
        .parse::<usize>()
        .map_err(|e| {
            CredentialError::RevocationListInvalid(format!(
                "Error parsing revocation_list_id: {}",
                e
            ))
        })?;

    let byte_index_float: f32 = (revocation_list_index_number / 8) as f32;
    let byte_index: usize = byte_index_float.floor() as usize;
    let revoked = decoded_list[byte_index] & (1 << (revocation_list_index_number % 8)) != 0;

    Ok(revoked)
}

pub struct Credential<'a> {
    vade_evan: &'a mut VadeEvan,
}

impl<'a> Credential<'a> {
    pub fn new(vade_evan: &'a mut VadeEvan) -> Result<Credential, CredentialError> {
        Ok(Credential { vade_evan })
    }

    pub async fn create_credential_offer(
        &mut self,
        schema_did: &str,
        use_valid_until: bool,
        issuer_did: &str,
        subject_did: Option<&str>,
    ) -> Result<String, CredentialError> {
        let credential_draft = self
            .create_empty_unsigned_credential(schema_did, subject_did.as_deref(), use_valid_until)
            .await?;
        let credential_draft_str = serde_json::to_string(&credential_draft)?;
        let nquads = convert_to_nquads(&credential_draft_str).await?;

        let payload = OfferCredentialPayload {
            issuer: issuer_did.to_string(),
            subject: subject_did.map(|v| v.to_string()),
            nquad_count: nquads.len(),
        };
        let result = self
            .vade_evan
            .vc_zkp_create_credential_offer(
                EVAN_METHOD,
                TYPE_OPTIONS,
                &serde_json::to_string(&payload)?,
            )
            .await
            .map_err(|err| CredentialError::VadeEvanError(err.to_string()))?;

        Ok(result)
    }

    pub async fn create_credential_request(
        &mut self,
        issuer_public_key: &str,
        bbs_secret: &str,
        credential_values: &str,
        credential_offer: &str,
        credential_schema_did: &str,
    ) -> Result<String, CredentialError> {
        let credential_schema: CredentialSchema =
            self.get_did_document(credential_schema_did).await?;

        let payload = format!(
            r#"{{
                "credentialOffering": {},
                "masterSecret": "{}",
                "credentialValues": {},
                "issuerPubKey": "{}",
                "credentialSchema": {}
            }}"#,
            credential_offer,
            bbs_secret,
            credential_values,
            issuer_public_key,
            serde_json::to_string(&credential_schema)?
        );
        let result = self
            .vade_evan
            .vc_zkp_request_credential(EVAN_METHOD, TYPE_OPTIONS, &payload)
            .await
            .map_err(|err| CredentialError::VadeEvanError(err.to_string()))?;

        Ok(result)
    }

    pub async fn verify_credential(
        &mut self,
        credential_str: &str,
        master_secret: &str,
    ) -> Result<(), CredentialError> {
        let credential: BbsCredential = serde_json::from_str(credential_str)?;

        // get nquads
        let mut parsed_credential: Map<String, Value> = serde_json::from_str(credential_str)?;
        parsed_credential.remove("proof");
        let credential_without_proof = serde_json::to_string(&parsed_credential)?;
        let did_doc_nquads = convert_to_nquads(&credential_without_proof).await?;

        if (did_doc_nquads.len() + ADDITIONAL_HIDDEN_MESSAGES_COUNT)
            != credential.proof.credential_message_count
        {
            return Err(CredentialError::MessageCountMismatch(
                credential.proof.credential_message_count,
                did_doc_nquads.len() + ADDITIONAL_HIDDEN_MESSAGES_COUNT,
            ));
        }

        // get public key suitable for messages
        let verification_method_id = credential
            .proof
            .verification_method
            .rsplit_once('#')
            .ok_or_else(|| {
                CredentialError::InvalidVerificationMethod(
                    "invalid verification method in proof".to_string(),
                )
            })?
            .1;
        let issuer_pub_key = self
            .get_issuer_public_key(&credential.issuer, &format!("#{}", verification_method_id))
            .await?;
        let public_key_generator = get_public_key_generator(
            &issuer_pub_key,
            did_doc_nquads.len() + ADDITIONAL_HIDDEN_MESSAGES_COUNT,
        )?;

        // verify signature
        self.verify_proof_signature(
            &credential.proof.signature,
            &did_doc_nquads,
            master_secret,
            &public_key_generator,
        )
        .await?;

        if credential.credential_status.is_some() {
            let credential_status = &credential.credential_status.ok_or_else(|| {
                CredentialError::InvalidCredentialStatus(
                    "Error in parsing credential_status".to_string(),
                )
            })?;
            // resolve the did and extract the did document out of it
            let revocation_list: RevocationListCredential = self
                .get_did_document(&credential_status.revocation_list_credential)
                .await?;
            let credential_revoked = is_revoked(credential_status, &revocation_list)?;
            if credential_revoked {
                return Err(CredentialError::CredentialRevoked);
            }
        }

        Ok(())
    }

    /// Revokes a given credential with the help of vade and updates revocation list credential
    ///
    /// # Arguments
    /// * `credential_str` - credential to be revoked in seralized string format
    /// * `updated_key_jwk` - public key in jwk format to sign did update
    /// * `private_key` - bbs private key to sign revocaton request
    ///
    /// # Returns
    /// * `String` - the result of updated revocation list doc after credential revocation
    #[cfg(feature = "plugin-did-sidetree")]
    pub async fn revoke_credential(
        &mut self,
        credential_str: &str,
        update_key_jwk: &str,
        private_key: &str,
    ) -> Result<String, CredentialError> {
        let credential: BbsCredential = serde_json::from_str(credential_str)?;
        let credential_status = &credential.credential_status.ok_or_else(|| {
            CredentialError::InvalidCredentialStatus(
                "Error in parsing credential_status".to_string(),
            )
        })?;

        let revocation_list: RevocationListCredential = self
            .get_did_document(&credential_status.revocation_list_credential)
            .await?;

        let proving_key = private_key;
        let payload = RevokeCredentialPayload {
            issuer: credential.issuer.clone(),
            revocation_list: revocation_list.clone(),
            revocation_id: credential_status.revocation_list_index.to_owned(),
            issuer_public_key_did: credential.issuer.clone(),
            issuer_proving_key: proving_key.to_owned(),
        };

        let payload = serde_json::to_string(&payload)?;
        let updated_revocation_list = self
            .vade_evan
            .vc_zkp_revoke_credential(EVAN_METHOD, TYPE_OPTIONS, &payload)
            .await
            .map_err(|err| CredentialError::VadeEvanError(err.to_string()))?;

        let update_result = self
            .vade_evan
            .helper_did_update(
                &revocation_list.id,
                "ReplaceDidDoc",
                update_key_jwk,
                &updated_revocation_list,
            )
            .await
            .map_err(|err| CredentialError::VadeEvanError(err.to_string()))?;
        Ok(update_result)
    }

    /// Creates a new zero-knowledge proof self issued credential.
    /// `create_self_issued_credential` function combines `vc_zkp_create_credential_offer`,
    /// `vc_zkp_create_credential_request`, `vc_zkp_issue_credential` and `vc_zkp_finish_credential`
    /// and produces self-issued credential with blind signature.
    ///
    /// # Arguments
    ///
    /// * `schema_did` - schema to create the credential
    /// * `credential_subject_str` - JSON string of CredentialSubject structure
    /// * `bbs_secret` - BBS secret
    /// * `bbs_private_key` - BBS private key
    /// * `credential_revocation_did` - revocation list DID (or `None` if no revocation is used)
    /// * `credential_revocation_id` - index in revocation list (or `None` if no revocation is used)
    /// * `exp_date` - expiration date, string, e.g. "1722-12-03T14:23:42.120Z" (or `None` if no expiration date is used)
    ///
    /// # Returns
    /// * credential as JSON serialized [`BbsCredential`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.BbsCredential.html)
    pub async fn create_self_issued_credential(
        &mut self,
        schema_did: &str,
        credential_subject_str: &str,
        bbs_secret: &str,
        bbs_private_key: &str,
        credential_revocation_did: &str,
        credential_revocation_id: &str,
        exp_date: Option<&str>,
    ) -> Result<String, CredentialError> {
        let credential_subject: CredentialSubject = serde_json::from_str(credential_subject_str)?;
        let subject_did = credential_subject
            .clone()
            .id
            .unwrap_or_else(|| "no subject did found".to_string());
        let schema: CredentialSchema = self.get_did_document(schema_did).await?;
        let issuer_public_key = self
            .get_issuer_public_key(&subject_did, "#bbs-key-1")
            .await?;
        let use_valid_until = exp_date.is_some();
        let credential_values_str = serde_json::to_string(&credential_subject.clone().data)?;

        // create credential offer
        let context = vec![
            "https://www.w3.org/2018/credentials/v1".to_string(),
            "https://schema.org/".to_string(),
            "https://w3id.org/vc-revocation-list-2020/v1".to_string(),
        ];
        let id = Uuid::new_v4().to_string();
        let r#type = vec!["VerifiableCredential".to_string()];
        let issuer = subject_did.clone();
        let valid_until = if use_valid_until {
            Some(exp_date.unwrap_or("").to_string())
        } else {
            None
        };
        let date_now = SystemTime::now();
        let datetime: DateTime<Utc> = date_now.into();
        let issuance_date = datetime.format("%Y-%m-%dT%TZ").to_string();
        let credential_subject = CredentialSubject {
            id: Some(subject_did.clone()), // subject.id stays optional, defined by create_offer call
            data: schema // fill ALL subject data fields with empty string (mandatory and optional ones)
                .properties
                .into_iter()
                .map(|(name, _schema_property)| {
                    (
                        name.clone(),
                        credential_subject
                            .data
                            .get(&(name.clone()))
                            .unwrap_or(&"invalid credential value".to_string())
                            .to_string(),
                    )
                })
                .collect(),
        };
        let credential_schema = CredentialSchemaReference {
            id: schema.id,
            r#type: schema.r#type,
        };
        let credential_status = CredentialStatus {
            id: format!("{}#{}", credential_revocation_did, credential_revocation_id),
            r#type: "RevocationList2020Status".to_string(),
            revocation_list_index: credential_revocation_id.to_string(),
            revocation_list_credential: credential_revocation_did.to_string(),
        };
        let unsigned_credential = UnsignedBbsCredential {
            context,
            id,
            r#type,
            issuer,
            valid_until,
            issuance_date,
            credential_subject,
            credential_schema,
            credential_status: Some(credential_status),
        };

        let unsigned_credential_str = serde_json::to_string(&unsigned_credential)?;
        let nquads_vc = convert_to_nquads(&unsigned_credential_str).await?;

        let payload = OfferCredentialPayload {
            issuer: subject_did.clone(),
            subject: Some(subject_did.clone()),
            nquad_count: nquads_vc.len(),
        };
        let offer_str = self
            .vade_evan
            .vc_zkp_create_credential_offer(
                EVAN_METHOD,
                TYPE_OPTIONS,
                &serde_json::to_string(&payload)?,
            )
            .await
            .map_err(|err| CredentialError::VadeEvanError(err.to_string()))?;

        // Create credential request
        let request_str = self
            .create_credential_request(
                &issuer_public_key,
                &bbs_secret,
                &credential_values_str,
                &offer_str,
                schema_did,
            )
            .await?;
        let (request, blinding_key): (BbsCredentialRequest, String) =
            serde_json::from_str(request_str.as_str())?;
        let indices = vec![0, 1];

        // Issue credentials
        let offer: BbsCredentialOffer = serde_json::from_str(&offer_str)?;
        let payload = IssueCredentialPayload {
            unsigned_vc: unsigned_credential,
            nquads: nquads_vc,
            issuer_public_key_id: "#bbs-key-1".to_string(),
            issuer_public_key: issuer_public_key.clone(),
            issuer_secret_key: bbs_private_key.to_string(),
            credential_request: request.clone(),
            credential_offer: offer,
            required_indices: indices,
        };
        let payload_str = serde_json::to_string(&payload)?;
        let credential_str = self
            .vade_evan
            .vc_zkp_issue_credential(EVAN_METHOD, TYPE_OPTIONS, &payload_str)
            .await
            .map_err(|err| CredentialError::VadeEvanError(err.to_string()))?;

        // Finish credentials
        let mut parsed_credential: Map<String, Value> = serde_json::from_str(&credential_str)?;
        parsed_credential.remove("proof");
        let _credential_without_proof = serde_json::to_string(&parsed_credential)?;
        let did_doc_nquads = convert_to_nquads(&_credential_without_proof).await?;
        let credential: UnfinishedBbsCredential = serde_json::from_str(credential_str.as_str())?;
        let payload_finish = FinishCredentialPayload {
            credential,
            master_secret: bbs_secret.to_string(),
            nquads: did_doc_nquads,
            issuer_public_key: issuer_public_key.clone(),
            blinding: blinding_key,
        };
        let payload_finish_str = serde_json::to_string(&payload_finish)?;
        let result = self
            .vade_evan
            .vc_zkp_finish_credential(EVAN_METHOD, TYPE_OPTIONS, payload_finish_str.as_str())
            .await
            .map_err(|err| CredentialError::VadeEvanError(err.to_string()))?;

        Ok(result)
    }

    async fn create_empty_unsigned_credential(
        &mut self,
        schema_did: &str,
        subject_did: Option<&str>,
        use_valid_until: bool,
    ) -> Result<UnsignedBbsCredential, CredentialError> {
        let schema: CredentialSchema = self.get_did_document(schema_did).await?;

        Ok(create_draft_credential_from_schema(
            use_valid_until,
            subject_did,
            &schema,
        ))
    }

    async fn get_did_document<T>(&mut self, did: &str) -> Result<T, CredentialError>
    where
        T: DeserializeOwned,
    {
        let did_result_str = self
            .vade_evan
            .did_resolve(did)
            .await
            .map_err(|err| CredentialError::VadeEvanError(err.to_string()))?;
        let did_result_value: DidDocumentResult<T> = serde_json::from_str(&did_result_str)?;

        Ok(did_result_value.did_document)
    }

    /// Resolve a issuer did, get the did document and extract the public key out of the
    /// verification methods
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer to load the pub key from
    /// * `verification_method_id` - id of verification method to extract the pub key
    ///
    /// # Returns
    /// * `publicKey` - pub key of the issuer
    pub async fn get_issuer_public_key(
        &mut self,
        issuer_did: &str,
        verification_method_id: &str,
    ) -> Result<String, CredentialError> {
        let did_document: IdentityDidDocument = self.get_did_document(issuer_did).await?;

        let mut public_key: &str = "";
        let verification_methods = did_document
            .verification_method
            .ok_or("no verification method found")
            .map_err(|err| CredentialError::PublicKeyParsingError(err.to_string()))?;
        for method in verification_methods.iter() {
            if method.id == verification_method_id {
                public_key = &method.public_key_jwk.x;
                break;
            }
        }

        if public_key == "" {
            return Err(CredentialError::InvalidVerificationMethod(format!(
                "no public key found for verification id {}",
                &verification_method_id
            )));
        }

        Ok(public_key.to_string())
    }

    async fn verify_proof_signature(
        &self,
        signature: &str,
        did_doc_nquads: &Vec<String>,
        master_secret: &str,
        pk: &PublicKey,
    ) -> Result<(), CredentialError> {
        let mut signature_messages: Vec<SignatureMessage> = Vec::new();
        let master_secret_message: SignatureMessage =
            SignatureMessage::from(base64::decode(master_secret)?.into_boxed_slice());
        signature_messages.insert(0, master_secret_message);
        let mut i = 1;
        for message in did_doc_nquads {
            signature_messages.insert(i, SignatureMessage::hash(message));
            i += 1;
        }
        let decoded_proof = base64::decode(signature)?;
        let signature = panic::catch_unwind(|| Signature::from(decoded_proof.into_boxed_slice()))
            .map_err(|_| {
            CredentialError::BbsValidationError("Error parsing signature".to_string())
        })?;
        let is_valid = signature
            .verify(&signature_messages, &pk)
            .map_err(|err| CredentialError::BbsValidationError(err.to_string()))?;

        match is_valid {
            true => Ok(()),
            false => Err(CredentialError::BbsValidationError(
                "signature invalid".to_string(),
            )),
        }
    }
}

#[cfg(test)]
#[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
mod tests {
    use crate::helpers::credential::is_revoked;

    cfg_if::cfg_if! {
        if #[cfg(feature = "plugin-did-sidetree")] {
            use anyhow::Result;
            use vade_evan_bbs::{BbsCredential, BbsCredentialOffer};
            use crate::{VadeEvan, DEFAULT_SIGNER, DEFAULT_TARGET};
            use vade_sidetree::datatypes::DidCreateResponse;
            use vade_evan_bbs::RevocationListCredential;
            use crate::helpers::datatypes::DidDocumentResult;
            use super::{Credential, CredentialError};

            const CREDENTIAL_ACTIVE: &str = r###"{
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
            const CREDENTIAL_INVALID_PROOF_SIGNATURE: &str = r###"{
                "id": "uuid:70b7ec4e-f035-493e-93d3-2cf5be4c7f88",
                "type": [
                    "VerifiableCredential"
                ],
                "proof": {
                    "type": "BbsBlsSignature2020",
                    "created": "2023-02-01T14:08:17.000Z",
                    "signature": "Zm9vYmFy",
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
            const CREDENTIAL_MESSAGE_COUNT: usize = 13;
            const CREDENTIAL_REVOKED: &str = r###"{
                "id": "uuid:19b1e481-8743-4c27-8934-45d682714ccc",
                "type": [
                    "VerifiableCredential"
                ],
                "proof": {
                    "type": "BbsBlsSignature2020",
                    "created": "2023-02-02T14:23:43.000Z",
                    "signature": "lqKrWCzOaeL4qRRyhN4555I5/A/TmKQ9iJUvA+34pwNfh4rBLFxKlLwJK5dfuQjrDZ+0EWSK8X+e7Jv9cWjOZ+v/t3lgT3nFczMtfPjgFe4a3iWKCRUi1HM6h1+c6HY+C0j0QOB606TTXe2EInb+WQ==",
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
                "issuanceDate": "2023-02-02T14:23:42.120Z",
                "credentialSchema": {
                    "id": "did:evan:EiCimsy3uWJ7PivWK0QUYSCkImQnjrx6fGr6nK8XIg26Kg",
                    "type": "EvanVCSchema"
                },
                "credentialStatus": {
                    "id": "did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA#6",
                    "type": "RevocationList2020Status",
                    "revocationListIndex": "6",
                    "revocationListCredential": "did:evan:EiA0Ns-jiPwu2Pl4GQZpkTKBjvFeRXxwGgXRTfG1Lyi8aA"
                },
                "credentialSubject": {
                    "id": "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA",
                    "data": {
                        "bio": "biography"
                    }
                }
            }"###;
            const ISSUER_DID: &str = "did:evan:EiAee4ixDnSP0eWyp0YFV7Wt9yrZ3w841FNuv9NSLFSCVA";
            const PUBLIC_KEY: &str = "qWZ7EGhzYsSlBq4mLhNal6cHXBD88ZfncdbEWQoue6SaAbZ7k56IxsjcvuXD6LGYDgMgtjTHnBraaMRiwJVBJenXgOT8nto7ZUTO/TvCXwtyPMzGrLM5JNJdEaPP4QJN";
            const MASTER_SECRET: &str = "QyRmu33oIQFNW+dSI5wex3u858Ra7yx5O1tsxJgQvu8=";
            const SCHEMA_DID: &str = "did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw";
            const SUBJECT_DID: &str = "did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f";
            const VERIFICATION_METHOD_ID: &str = "#bbs-key-1";
        } else {
        }
    }

    #[tokio::test]
    #[cfg(all(
        feature = "plugin-did-sidetree",
        not(all(feature = "target-c-lib", feature = "capability-sdk"))
    ))]
    async fn helper_can_create_credential_offer() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut credential = Credential::new(&mut vade_evan)?;

        let offer_str = credential
            .create_credential_offer(SCHEMA_DID, false, ISSUER_DID, Some(SUBJECT_DID))
            .await?;

        let offer_obj: BbsCredentialOffer = serde_json::from_str(&offer_str)?;
        assert_eq!(offer_obj.issuer, ISSUER_DID);
        assert_eq!(offer_obj.subject, Some(SUBJECT_DID.to_string()));
        assert_eq!(offer_obj.credential_message_count, CREDENTIAL_MESSAGE_COUNT);
        assert!(!offer_obj.nonce.is_empty());

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "plugin-did-sidetree")]
    async fn helper_can_create_credential_request() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: "test",
            signer: "remote|http://127.0.0.1:7070/key/sign",
        })?;
        let credential_offer = r#"{
        "issuer": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906",
        "subject": "did:any:abc",
        "nonce": "QqJR4o6joiApYVXX7JLbRIZBQ9QprlFpewo8GbojIKY=",
        "credentialMessageCount": 2
    }"#;
        let bbs_secret = r#"OASkVMA8q6b3qJuabvgaN9K1mKoqptCv4SCNvRmnWuI="#;
        let credential_values = r#"{
        "email": "value@x.com"
    }"#;
        let issuer_pub_key = r#"jCv7l26izalfcsFe6j/IqtVlDolo2Y3lNld7xOG63GjSNHBVWrvZQe2O859q9JeVEV4yXtfYofGQSWrMVfgH5ySbuHpQj4fSgLu4xXyFgMidUO1sIe0NHRcXpOorP01o"#;

        let credential_request = vade_evan
            .helper_create_credential_request(
                issuer_pub_key,
                bbs_secret,
                credential_values,
                credential_offer,
                SCHEMA_DID,
            )
            .await?;

        assert!(credential_request.contains("blindSignatureContext"));

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "plugin-did-sidetree")]
    async fn can_get_issuer_pub_key() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let mut credential = Credential::new(&mut vade_evan)?;
        let pub_key = credential
            .get_issuer_public_key(ISSUER_DID, VERIFICATION_METHOD_ID)
            .await?;

        assert_eq!(pub_key, PUBLIC_KEY);

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "plugin-did-sidetree")]
    async fn will_throw_when_pub_key_not_found() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let mut credential = Credential::new(&mut vade_evan)?;
        let pub_key = credential
            .get_issuer_public_key(ISSUER_DID, "#random-id")
            .await;

        match pub_key {
            Ok(_) => assert!(false, "pub key should not be there"),
            Err(_) => assert!(true, "pub key not found"),
        }

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "plugin-did-sidetree")]
    async fn helper_can_verify_valid_credential() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let mut credential = Credential::new(&mut vade_evan)?;

        // verify the credential issuer
        credential
            .verify_credential(CREDENTIAL_ACTIVE, MASTER_SECRET)
            .await?;

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "plugin-did-sidetree")]
    async fn helper_rejects_credentials_with_invalid_message_count() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let mut credential = Credential::new(&mut vade_evan)?;

        let mut credential_parsed: BbsCredential = serde_json::from_str(&CREDENTIAL_ACTIVE)?;
        credential_parsed.proof.credential_message_count = 3;
        let credential_with_invalid_msg_count = serde_json::to_string(&credential_parsed)?;

        match credential
            .verify_credential(&credential_with_invalid_msg_count, MASTER_SECRET)
            .await
        {
            Ok(_) => assert!(false, "credential should have been detected as revoked"),
            Err(CredentialError::MessageCountMismatch(got, expected)) => {
                assert_eq!(3, got);
                assert_eq!(13, expected);
                assert!(true, "credential revoked as expected")
            }
            _ => assert!(false, "revocation check failed with unexpected error"),
        };

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "plugin-did-sidetree")]
    async fn helper_can_detect_a_broken_credential() -> Result<()> {
        use super::CredentialError;

        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let mut credential = Credential::new(&mut vade_evan)?;

        match credential
            .verify_credential(CREDENTIAL_REVOKED, MASTER_SECRET)
            .await
        {
            Ok(_) => assert!(false, "credential should have been detected as revoked"),
            Err(CredentialError::CredentialRevoked) => {
                assert!(true, "credential revoked as expected")
            }
            _ => assert!(false, "revocation check failed with unexpected error"),
        };

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "plugin-did-sidetree")]
    async fn helper_can_revoke_credential() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: "test",
            signer: "local",
        })?;
        // create did
        let did_create_result = vade_evan
            .helper_did_create(None, None, None, None, None)
            .await?;
        let did_create_result: DidCreateResponse = serde_json::from_str(&did_create_result)?;
        let mut credential: BbsCredential = serde_json::from_str(CREDENTIAL_ACTIVE)?;
        let mut credential_status = &mut credential.credential_status.ok_or_else(|| {
            CredentialError::InvalidCredentialStatus(
                "Error in parsing credential_status".to_string(),
            )
        })?;

        let did_result_str = vade_evan
            .did_resolve(&credential_status.revocation_list_credential)
            .await?;
        let did_result_value: DidDocumentResult<RevocationListCredential> =
            serde_json::from_str(&did_result_str)?;
        let mut revocation_list = did_result_value.did_document;
        revocation_list.id = did_create_result.did.did_document.id.clone();

        credential_status.revocation_list_credential = revocation_list.id.clone();
        credential.credential_status = Some(credential_status.to_owned());
        // Replace did doc with revocation list
        let did_update_result = vade_evan
            .helper_did_update(
                &did_create_result.did.did_document.id,
                "ReplaceDidDoc",
                &serde_json::to_string(&did_create_result.update_key)?,
                &serde_json::to_string(&revocation_list)?,
            )
            .await;
        assert!(did_update_result.is_ok());

        // check is credential is not revoked
        match is_revoked(credential_status, &revocation_list)? {
            false => assert!(true, "credential is active and not revoked as expected"),
            true => assert!(
                false,
                "credential should be active and not revoked at this stage"
            ),
        };
        // Get update key for next update to remove key
        let mut update_key = did_create_result.update_key.clone();
        let mut nonce = update_key
            .nonce
            .unwrap_or_else(|| "0".to_string())
            .parse::<u32>()?;
        nonce += 1;
        update_key.nonce = Some(nonce.to_string());

        // call revoke credential
        let revoke_result = vade_evan
            .helper_revoke_credential(
                &serde_json::to_string(&credential)?,
                &serde_json::to_string(&update_key)?,
                "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106",
            )
            .await;
        assert!(revoke_result.is_ok());

        //fetch revocation list after revocation
        let did_result_str = vade_evan
            .did_resolve(credential_status.revocation_list_credential.as_str())
            .await?;
        let did_result_value: DidDocumentResult<RevocationListCredential> =
            serde_json::from_str(&did_result_str)?;
        revocation_list = did_result_value.did_document;

        // verify credential
        match is_revoked(credential_status, &revocation_list)? {
            false => assert!(false, "credential should have been detected as revoked"),
            true => assert!(true, "credential revoked as expected"),
        };

        Ok(())
    }
    #[tokio::test]
    #[cfg(feature = "plugin-did-sidetree")]
    async fn helper_can_detect_a_credential_with_an_invalid_proof_signature() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let mut credential = Credential::new(&mut vade_evan)?;

        // verify the credential issuer
        match credential
            .verify_credential(CREDENTIAL_INVALID_PROOF_SIGNATURE, MASTER_SECRET)
            .await
        {
            Ok(_) => assert!(false, "credential should have been detected as revoked"),
            Err(credential_error) => {
                assert_eq!(
                    credential_error.to_string(),
                    "an error has occurred during bbs signature validation: signature invalid"
                        .to_string()
                );
            }
        };

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "plugin-did-sidetree")]
    async fn helper_can_create_self_issued_credential() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: "test",
            signer: "remote|http://127.0.0.1:7070/key/sign",
        })?;
        let credential_subject_str = r#"{
            "id": "did:evan:EiAOD3RUcQrRXNZIR8BIEXuGvixcUj667_5fdeX-Sp3PpA",
            "data": {
                "email": "value@x.com"
            }
        }"#;
        let bbs_secret = "GRsdzRB0pf/8MKP/ZBOM2BEV1A8DIDfmLh8T3b1hPKc=";
        let bbs_private_key = "WWTZW8pkz35UnvsUCEsof2CJmNHaJQ/X+B5xjWcHr/I=";
        let schema_did = "did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw";

        let mut credential = Credential::new(&mut vade_evan)?;

        match credential
            .create_self_issued_credential(
                schema_did,
                credential_subject_str,
                bbs_secret,
                bbs_private_key,
                "did:revoc:12345",
                "1",
                None,
            )
            .await
        {
            Ok(_) => assert!(true, "credential should have been successfully self issued"),
            Err(_) => assert!(
                false,
                "error occured when creating the self issued credential"
            ),
        };

        Ok(())
    }
}
