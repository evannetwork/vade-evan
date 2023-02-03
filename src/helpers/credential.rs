use std::{io::Read, panic};

use bbs::{
    prelude::{DeterministicPublicKey, PublicKey},
    signature::Signature,
    HashElem,
    SignatureMessage,
};
use flate2::read::GzDecoder;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{value::Value, Map};
use ssi::{
    jsonld::{json_to_dataset, JsonLdOptions, StaticLoader},
    urdna2015::normalize,
};
use vade_evan_bbs::{
    BbsCredential,
    CredentialSchema,
    CredentialSchemaReference,
    CredentialStatus,
    CredentialSubject,
    OfferCredentialPayload,
    RevocationListCredential,
    UnsignedBbsCredential,
};

use crate::api::{VadeEvan, VadeEvanError};
use crate::datatypes::DidDocument;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidDocumentResult<T> {
    did_document: T,
}

// Master secret is always incorporated, without being mentioned in the credential schema
const ADDITIONAL_HIDDEN_MESSAGES_COUNT: usize = 1;
const EVAN_METHOD: &str = "did:evan";
const TYPE_OPTIONS: &str = r#"{ "type": "bbs" }"#;

// fn create_empty_unsigned_credential(
//     schema_did_doc_str: &str,
//     subject_did: Option<&str>,
//     use_valid_until: bool,
// ) -> Result<UnsignedBbsCredential, VadeEvanError> {
//     let response_obj: Value = serde_json::from_str(&schema_did_doc_str)?;
//     let did_document_obj = response_obj.get("didDocument").ok_or_else(|| {
//         VadeEvanError::InvalidDidDocument("missing 'didDocument' in response".to_string())
//     });
//     let did_document_str = serde_json::to_string(&did_document_obj?)?;
//     let schema_obj: CredentialSchema = serde_json::from_str(&did_document_str)?;

//     let credential = UnsignedBbsCredential {
//         context: vec![
//             "https://www.w3.org/2018/credentials/v1".to_string(),
//             "https://schema.org/".to_string(),
//             "https://w3id.org/vc-revocation-list-2020/v1".to_string(),
//         ],
//         id: "uuid:834ca9da-9f09-4359-8264-c890de13cdc8".to_string(),
//         r#type: vec!["VerifiableCredential".to_string()],
//         issuer: "did:evan:testcore:placeholder_issuer".to_string(),
//         valid_until: if use_valid_until {
//             Some("2031-01-01T00:00:00.000Z".to_string())
//         } else {
//             None
//         },
//         issuance_date: "2021-01-01T00:00:00.000Z".to_string(),
//         credential_subject: CredentialSubject {
//             id: subject_did.map(|s| s.to_owned()), // subject.id stays optional, defined by create_offer call
//             data: schema_obj // fill ALL subject data fields with empty string (mandatory and optional ones)
//                 .properties
//                 .into_iter()
//                 .map(|(name, _schema_property)| (name, String::new()))
//                 .collect(),
//         },
//         credential_schema: CredentialSchemaReference {
//             id: schema_obj.id,
//             r#type: schema_obj.r#type,
//         },
//         credential_status: CredentialStatus {
//             id: "did:evan:zkp:placeholder_status#0".to_string(),
//             r#type: "RevocationList2020Status".to_string(),
//             revocation_list_index: "0".to_string(),
//             revocation_list_credential: "did:evan:zkp:placeholder_status".to_string(),
//         },
//     };

//     Ok(credential)
// }

async fn convert_to_nquads(document_string: &str) -> Result<Vec<String>, VadeEvanError> {
    let mut loader = StaticLoader;
    let options = JsonLdOptions {
        base: None,           // -b, Base IRI
        expand_context: None, // -c, IRI for expandContext option
        ..Default::default()
    };
    let dataset = json_to_dataset(
        &document_string,
        None, // will be patched into @context, e.g. Some(&r#"["https://schema.org/"]"#.to_string()),
        false,
        Some(&options),
        &mut loader,
    )
    .await
    .map_err(|err| VadeEvanError::JsonLdHandling(err.to_string()))?;
    let dataset_normalized = normalize(&dataset).unwrap();
    let normalized = dataset_normalized.to_nquads().unwrap();
    let non_empty_lines = normalized
        .split("\n")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    Ok(non_empty_lines)
}

fn get_public_key_generator(
    public_key: &str,
    message_count: usize,
) -> Result<PublicKey, VadeEvanError> {
    let public_key: DeterministicPublicKey =
        DeterministicPublicKey::from(base64::decode(public_key)?.into_boxed_slice());
    let public_key_generator = public_key.to_public_key(message_count).map_err(|e| {
        VadeEvanError::PublicKeyParsingError(format!(
            "public key invalid, generate public key generator; {}",
            e
        ))
    })?;

    Ok(public_key_generator)
}

pub fn is_revoked(
    credential_status: &CredentialStatus,
    revocation_list: &RevocationListCredential,
) -> Result<bool, VadeEvanError> {
    let encoded_list = base64::decode_config(
        revocation_list.credential_subject.encoded_list.to_string(),
        base64::URL_SAFE,
    )?;
    let mut decoder = GzDecoder::new(&encoded_list[..]);
    let mut decoded_list = Vec::new();
    decoder
        .read_to_end(&mut decoded_list)
        .map_err(|e| VadeEvanError::RevocationListInvalid(e.to_string()))?;

    let revocation_list_index_number = credential_status
        .revocation_list_index
        .parse::<usize>()
        .map_err(|e| {
            VadeEvanError::RevocationListInvalid(format!("Error parsing revocation_list_id: {}", e))
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
    pub fn new(vade_evan: &'a mut VadeEvan) -> Result<Credential, VadeEvanError> {
        Ok(Credential { vade_evan })
    }

    pub async fn create_credential_offer(
        &mut self,
        schema_did: &str,
        use_valid_until: bool,
        issuer_did: &str,
        subject_did: Option<&str>,
    ) -> Result<String, VadeEvanError> {
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
            .await?;

        Ok(result)
    }

    pub async fn create_credential_request(
        self,
        issuer_public_key: &str,
        bbs_secret: &str,
        credential_values: &str,
        credential_offer: &str,
        credential_schema_did: &str,
    ) -> Result<String, VadeEvanError> {
        let schema_did_doc_str = self.vade_evan.did_resolve(credential_schema_did).await?;
        let response_obj: Value = serde_json::from_str(&schema_did_doc_str).map_err(|err| {
            VadeEvanError::InternalError {
                source_message: err.to_string(),
            }
        })?;
        let did_document_obj =
            response_obj
                .get("didDocument")
                .ok_or_else(|| VadeEvanError::InternalError {
                    source_message: "missing 'didDocument' in response".to_string(),
                });
        let credential_schema = serde_json::to_string(&did_document_obj?).map_err(|err| {
            VadeEvanError::InternalError {
                source_message: err.to_string(),
            }
        })?;

        let payload = format!(
            r#"{{
                "credentialOffering": {},
                "masterSecret": {},
                "credentialValues": {},
                "issuerPubKey": {},
                "credentialSchema": {}
            }}"#,
            credential_offer, bbs_secret, credential_values, issuer_public_key, credential_schema
        );
        let result = self
            .vade_evan
            .vc_zkp_request_credential(EVAN_METHOD, TYPE_OPTIONS, &payload)
            .await?;

        Ok(result)
    }

    pub async fn verify_credential(
        &mut self,
        credential_str: &str,
        verification_method_id: &str,
        master_secret: &str,
    ) -> Result<(), VadeEvanError> {
        let credential: BbsCredential = serde_json::from_str(credential_str)?;

        // get nquads
        let mut parsed_credential: Map<String, Value> = serde_json::from_str(credential_str)?;
        parsed_credential.remove("proof");
        let credential_without_proof = serde_json::to_string(&parsed_credential)?;
        let did_doc_nquads = convert_to_nquads(&credential_without_proof).await?;

        if (did_doc_nquads.len() + ADDITIONAL_HIDDEN_MESSAGES_COUNT)
            != credential.proof.credential_message_count
        {
            return Err(VadeEvanError::MessageCountMismatch(
                credential.proof.credential_message_count,
                did_doc_nquads.len() + ADDITIONAL_HIDDEN_MESSAGES_COUNT,
            ));
        }

        // get public key suitable for messages
        let issuer_pub_key = self
            .get_issuer_public_key(&credential.issuer, verification_method_id)
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

        // check if credential has been revoked
        // let revocation_list =  getDidDocument(context, cred.credentialStatus.revocationListCredential);
        // resolve the did and extract the did document out of it
        let revocation_list: RevocationListCredential = self
            .get_did_document(&credential.credential_status.revocation_list_credential)
            .await?;
        let credential_revoked = is_revoked(&credential.credential_status, &revocation_list)?;
        if credential_revoked {
            return Err(VadeEvanError::CredentialRevoked);
        }

        Ok(())
    }

    async fn create_empty_unsigned_credential(
        &mut self,
        schema_did: &str,
        subject_did: Option<&str>,
        use_valid_until: bool,
    ) -> Result<UnsignedBbsCredential, VadeEvanError> {
        let schema: CredentialSchema = self.get_did_document(schema_did).await?;

        let credential = UnsignedBbsCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://schema.org/".to_string(),
                "https://w3id.org/vc-revocation-list-2020/v1".to_string(),
            ],
            id: "uuid:834ca9da-9f09-4359-8264-c890de13cdc8".to_string(),
            r#type: vec!["VerifiableCredential".to_string()],
            issuer: "did:evan:testcore:placeholder_issuer".to_string(),
            valid_until: if use_valid_until {
                Some("2031-01-01T00:00:00.000Z".to_string())
            } else {
                None
            },
            issuance_date: "2021-01-01T00:00:00.000Z".to_string(),
            credential_subject: CredentialSubject {
                id: subject_did.map(|s| s.to_owned()), // subject.id stays optional, defined by create_offer call
                data: schema // fill ALL subject data fields with empty string (mandatory and optional ones)
                    .properties
                    .into_iter()
                    .map(|(name, _schema_property)| (name, String::new()))
                    .collect(),
            },
            credential_schema: CredentialSchemaReference {
                id: schema.id,
                r#type: schema.r#type,
            },
            credential_status: CredentialStatus {
                id: "did:evan:zkp:placeholder_status#0".to_string(),
                r#type: "RevocationList2020Status".to_string(),
                revocation_list_index: "0".to_string(),
                revocation_list_credential: "did:evan:zkp:placeholder_status".to_string(),
            },
        };

        Ok(credential)
    }

    async fn get_did_document<T>(&mut self, did: &str) -> Result<T, VadeEvanError>
    where
        T: DeserializeOwned,
    {
        let did_result_str = self.vade_evan.did_resolve(did).await?;
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
    /// * `CredentialProposal` - The message to be sent to an issuer
    async fn get_issuer_public_key(
        &mut self,
        issuer_did: &str,
        verification_method_id: &str,
    ) -> Result<String, VadeEvanError> {
        let did_document: DidDocument = self.get_did_document(issuer_did).await?;

        // get the verification methods
        let verification_methods =
            did_document
                .verification_method
                .ok_or(VadeEvanError::InvalidVerificationMethod(
                    "missing 'verification_method' property in did_document".to_string(),
                ))?;

        let mut public_key: &str = "";
        for method in verification_methods.iter() {
            if method.id == verification_method_id {
                public_key = &method.public_key_jwk.x;
                break;
            }
        }

        if public_key == "" {
            return Err(VadeEvanError::InvalidVerificationMethod(format!(
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
    ) -> Result<(), VadeEvanError> {
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
            VadeEvanError::BbsValidationError("Error parsing signature".to_string())
        })?;
        let is_valid = signature
            .verify(&signature_messages, &pk)
            .map_err(|err| VadeEvanError::BbsValidationError(err.to_string()))?;

        dbg!(&is_valid);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use vade_evan_bbs::{BbsCredential, BbsCredentialOffer};

    use crate::{VadeEvan, VadeEvanError, DEFAULT_SIGNER, DEFAULT_TARGET};

    use super::Credential;

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

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
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
        let bbs_secret = r#""OASkVMA8q6b3qJuabvgaN9K1mKoqptCv4SCNvRmnWuI=""#;
        let credential_values = r#"{
        "email": "value@x.com"
    }"#;
        let issuer_pub_key = r#""jCv7l26izalfcsFe6j/IqtVlDolo2Y3lNld7xOG63GjSNHBVWrvZQe2O859q9JeVEV4yXtfYofGQSWrMVfgH5ySbuHpQj4fSgLu4xXyFgMidUO1sIe0NHRcXpOorP01o""#;

        let credential_request = vade_evan
            .helper_create_credential_request(
                issuer_pub_key,
                bbs_secret,
                credential_values,
                credential_offer,
                SCHEMA_DID,
            )
            .await?;

        println!("{}", credential_request);
        assert!(credential_request.contains("blindSignatureContext"));

        Ok(())
    }

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
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
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
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
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_can_verify_valid_credential() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let mut credential = Credential::new(&mut vade_evan)?;

        // verify the credential issuer
        credential
            .verify_credential(CREDENTIAL_ACTIVE, VERIFICATION_METHOD_ID, MASTER_SECRET)
            .await?;

        Ok(())
    }

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
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
            .verify_credential(
                &credential_with_invalid_msg_count,
                VERIFICATION_METHOD_ID,
                MASTER_SECRET,
            )
            .await
        {
            Ok(_) => assert!(false, "credential should have been detected as revoked"),
            Err(VadeEvanError::MessageCountMismatch(got, expected)) => {
                assert_eq!(3, got);
                assert_eq!(13, expected);
                assert!(true, "credential revoked as expected")
            }
            _ => assert!(false, "revocation check failed with unexpected error"),
        };

        Ok(())
    }

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_can_detect_a_broken_credential() -> Result<()> {
        use crate::VadeEvanError;

        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let mut credential = Credential::new(&mut vade_evan)?;

        match credential
            .verify_credential(CREDENTIAL_REVOKED, VERIFICATION_METHOD_ID, MASTER_SECRET)
            .await
        {
            Ok(_) => assert!(false, "credential should have been detected as revoked"),
            Err(VadeEvanError::CredentialRevoked) => {
                assert!(true, "credential revoked as expected")
            }
            _ => assert!(false, "revocation check failed with unexpected error"),
        };

        Ok(())
    }
}
