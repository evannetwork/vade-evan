use crate::api::VadeEvan;
use crate::helpers::datatypes::EVAN_METHOD;
use std::{io::Read, panic};

use super::datatypes::{DidDocumentResult, IdentityDidDocument};
use super::shared::{check_for_optional_empty_params, convert_to_nquads, is_did, SharedError};
use bbs::{
    prelude::{DeterministicPublicKey, PublicKey},
    signature::Signature,
    HashElem,
    SignatureMessage,
};
use flate2::read::GzDecoder;
use serde::de::DeserializeOwned;
use serde_json::{value::Value, Map};
use thiserror::Error;
use vade_evan_bbs::{
    BbsCredential,
    CredentialDraftOptions,
    CredentialSchema,
    CredentialStatus,
    CredentialSubject,
    LdProofVcDetailOptionsCredentialStatusType,
    OfferCredentialPayload,
    RevocationListCredential,
    RevokeCredentialPayload,
};

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("internal VadeEvan call failed; {0}")]
    VadeEvanError(String),
    #[error("invalid did document")]
    InvalidDidDocument(String),
    #[error("pubkey for verification method not found, {0}")]
    InvalidVerificationMethod(String),
    #[error("invalid credential schema, {0}")]
    InvalidCredentialSchema(String),
    #[error("credential_status is invalid, {0}")]
    InvalidCredentialStatus(String),
    #[error("JSON (de)serialization failed")]
    JsonDeSerialization(#[from] serde_json::Error),
    #[error(r#"JSON serialization of {0} failed due to "{1}""#)]
    JsonSerialization(String, String),
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
    #[error("revocation index invalid; {0}")]
    RevocationIndexInvalid(String),
    #[error("credential has been revoked")]
    CredentialRevoked,
    #[error("wrong number of messages in credential, got {0} but proof was created for {1}")]
    MessageCountMismatch(usize, usize),
    #[error(r#"value "{0}" given for "{1} is not a DID""#)]
    NotADid(String, String),
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

/// Checks if input is a DID and returns a `CredentialError::NotADid` if not.
///
/// # Arguments
///
/// * `to_check` - input value to check
/// * `name` - name of the input to check, used for log message
///
/// # Returns
/// `()` or `CredentialError::NotADid`
pub fn fail_if_not_a_did(to_check: &str, name: &str) -> Result<(), CredentialError> {
    if !is_did(to_check) {
        return Err(CredentialError::NotADid(
            to_check.to_owned(),
            name.to_owned(),
        ));
    }
    Ok(())
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
        is_credential_status_included: bool,
        required_reveal_statements: &str,
    ) -> Result<String, CredentialError> {
        fail_if_not_a_did(schema_did, "schema_did")?;
        fail_if_not_a_did(issuer_did, "issuer_did")?;
        let schema: CredentialSchema = self.get_did_document(schema_did).await?;
        let required_reveal_statements: Vec<u32> = serde_json::from_str(required_reveal_statements)
            .map_err(|err| CredentialError::JsonDeSerialization(err))?;
        let payload = OfferCredentialPayload {
            draft_credential: schema.to_draft_credential(CredentialDraftOptions {
                issuer_did: issuer_did.to_string(),
                id: None,
                issuance_date: None,
                valid_until: match use_valid_until {
                    true => Some("".to_owned()),
                    false => None,
                },
            }),
            credential_status_type: match is_credential_status_included {
                true => LdProofVcDetailOptionsCredentialStatusType::RevocationList2021Status,
                false => LdProofVcDetailOptionsCredentialStatusType::None,
            },
            required_reveal_statements,
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
        fail_if_not_a_did(credential_schema_did, "credential_schema_did")?;
        let credential_schema: CredentialSchema =
            self.get_did_document(credential_schema_did).await?;

        let payload = format!(
            r#"{{
                "credentialOffer": {},
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
    #[cfg(feature = "did-sidetree")]
    pub async fn revoke_credential(
        &mut self,
        credential_str: &str,
        update_key_jwk: &str,
        private_key: &str,
    ) -> Result<String, CredentialError> {
        let credential: BbsCredential = serde_json::from_str(credential_str)?;
        let credential_status = &credential.credential_status.ok_or_else(|| {
            CredentialError::InvalidCredentialStatus(
                "credentialStatus is required for revocation".to_string(),
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

    /// Creates an unsigned self issued credential.
    /// `create_self_issued_credential` function produces self-issued credential without proof.
    ///
    /// # Arguments
    ///
    /// * `schema_did` - schema to create the credential
    /// * `credential_subject_str` - JSON string of CredentialSubject structure
    /// * `exp_date` - expiration date, string, e.g. "1722-12-03T14:23:42.120Z" (or `None` if no expiration date is used)
    /// * `subject_did` - subject did for self issued credential
    ///
    /// # Returns
    /// * credential as JSON serialized [`UnsignedBbsCredential`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.UnsignedBbsCredential.html)
    pub async fn create_self_issued_credential(
        &mut self,
        schema_did: &str,
        credential_subject_str: &str,
        exp_date: Option<&str>,
        subject_did: &str,
    ) -> Result<String, CredentialError> {
        fail_if_not_a_did(schema_did, "schema_did")?;
        fail_if_not_a_did(subject_did, "subject_did")?;
        let exp_date = check_for_optional_empty_params(exp_date);
        let credential_subject: CredentialSubject = serde_json::from_str(credential_subject_str)?;

        let use_valid_until: bool = exp_date.is_some();

        let valid_until = if use_valid_until {
            Some(exp_date.unwrap_or("").to_string())
        } else {
            None
        };

        let schema: CredentialSchema = self.get_did_document(schema_did).await?;
        let draft_credential = schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: subject_did.to_owned(),
            id: None,
            issuance_date: None,
            valid_until,
        });

        let mut unsigned_credential = draft_credential.to_unsigned_credential(None);
        unsigned_credential.credential_subject = credential_subject;
        let result = serde_json::to_string(&unsigned_credential).map_err(|err| {
            CredentialError::JsonSerialization("unsigned_credential".to_owned(), err.to_string())
        })?;

        Ok(result)
    }

    pub async fn get_did_document<T>(&mut self, did: &str) -> Result<T, CredentialError>
    where
        T: DeserializeOwned,
    {
        fail_if_not_a_did(did, "did for did document")?;
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
        fail_if_not_a_did(issuer_did, "issuer_did")?;
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
#[cfg(not(all(feature = "c-lib", feature = "target-c-sdk")))]
mod tests {
    use crate::helpers::credential::is_revoked;

    cfg_if::cfg_if! {
        if #[cfg(feature = "did-sidetree")] {
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
            const VERIFICATION_METHOD_ID: &str = "#bbs-key-1";
        } else {
        }
    }

    #[tokio::test]
    async fn helper_cannot_create_proof_request_with_invalid_did() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut credential = Credential::new(&mut vade_evan)?;

        let result = credential
            .create_credential_offer("not a did", false, ISSUER_DID, true, "[1]")
            .await;

        assert!(result.is_err());
        match result {
            Ok(_) => assert!(false, "expected error but got result"),
            Err(error) => assert_eq!(
                error.to_string(),
                r#"value "not a did" given for "schema_did is not a DID""#.to_string()
            ),
        };

        Ok(())
    }

    #[tokio::test]
    #[cfg(all(
        feature = "did-sidetree",
        not(all(feature = "c-lib", feature = "target-c-sdk"))
    ))]
    async fn helper_can_create_credential_offer() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let mut credential = Credential::new(&mut vade_evan)?;

        let offer_str = credential
            .create_credential_offer(SCHEMA_DID, false, ISSUER_DID, true, "[1]")
            .await?;

        let offer_obj: BbsCredentialOffer = serde_json::from_str(&offer_str)?;
        assert_eq!(
            offer_obj
                .ld_proof_vc_detail
                .options
                .required_reveal_statements,
            vec![1]
        );
        assert_eq!(offer_obj.ld_proof_vc_detail.credential.issuer, ISSUER_DID);
        assert!(!offer_obj.nonce.is_empty());

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "did-sidetree")]
    async fn helper_can_create_credential_request() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: "test",
            signer: "remote|http://127.0.0.1:7070/key/sign",
        })?;
        let credential_offer = vade_evan
            .helper_create_credential_offer(SCHEMA_DID, false, ISSUER_DID, true, "[1]")
            .await?;

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
                &credential_offer,
                SCHEMA_DID,
            )
            .await?;

        assert!(credential_request.contains("blindSignatureContext"));

        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "did-sidetree")]
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
    #[cfg(feature = "did-sidetree")]
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
    #[cfg(feature = "did-sidetree")]
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
    #[cfg(feature = "did-sidetree")]
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
    #[cfg(feature = "did-sidetree")]
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
    #[cfg(feature = "did-sidetree")]
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
        let credential_status = &mut credential.credential_status.ok_or_else(|| {
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
        match is_revoked(&credential_status, &revocation_list)? {
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
        match is_revoked(&credential_status, &revocation_list)? {
            false => assert!(false, "credential should have been detected as revoked"),
            true => assert!(true, "credential revoked as expected"),
        };

        Ok(())
    }
    #[tokio::test]
    #[cfg(feature = "did-sidetree")]
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
    #[cfg(feature = "did-sidetree")]
    async fn helper_can_create_self_issued_credential() -> Result<()> {
        use vade_evan_bbs::UnsignedBbsCredential;

        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: "test",
            signer: "remote|http://127.0.0.1:7070/key/sign",
        })?;
        let credential_subject_str = r#"{"data":{"email":"value@x.com"}}"#;
        let subject_id = "did:evan:EiAOD3RUcQrRXNZIR8BIEXuGvixcUj667_5fdeX-Sp3PpA";
        let schema_did = "did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw";

        let mut credential = Credential::new(&mut vade_evan)?;

        match credential
            .create_self_issued_credential(schema_did, credential_subject_str, None, subject_id)
            .await
        {
            Ok(issued_credential) => {
                assert!(true, "credential should have been successfully self issued");
                let unsigned_credential: UnsignedBbsCredential =
                    serde_json::from_str(&issued_credential)?;
                let credential_subject =
                    serde_json::to_string(&unsigned_credential.credential_subject)?;
                assert_eq!(credential_subject_str, credential_subject.as_str());
                assert_eq!(unsigned_credential.issuer, subject_id);
            }
            Err(_) => assert!(
                false,
                "error occured when creating the self issued credential"
            ),
        };

        Ok(())
    }
}
