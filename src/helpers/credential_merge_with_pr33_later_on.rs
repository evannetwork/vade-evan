use serde_json::value::Value;
use ssi::{
    jsonld::{json_to_dataset, JsonLdOptions, StaticLoader},
    urdna2015::normalize,
};
use vade_evan_bbs::{
    CredentialSchema, CredentialSchemaReference, CredentialStatus, CredentialSubject,
    OfferCredentialPayload, UnsignedBbsCredential,
};

use crate::api::{VadeEvan, VadeEvanError};
use crate::datatypes::DidDocument;

const EVAN_METHOD: &str = "did:evan";
const TYPE_OPTIONS: &str = r#"{ "type": "bbs" }"#;

fn create_empty_unsigned_credential(
    schema_did_doc_str: &str,
    subject_did: Option<&str>,
    use_valid_until: bool,
) -> Result<UnsignedBbsCredential, VadeEvanError> {
    let response_obj: Value = serde_json::from_str(&schema_did_doc_str)?;
    let did_document_obj = response_obj.get("didDocument").ok_or_else(|| {
        VadeEvanError::InvalidDidDocument("missing 'didDocument' in response".to_string())
    });
    let did_document_str = serde_json::to_string(&did_document_obj?)?;
    let schema_obj: CredentialSchema = serde_json::from_str(&did_document_str)?;

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
            data: schema_obj // fill ALL subject data fields with empty string (mandatory and optional ones)
                .properties
                .into_iter()
                .map(|(name, _schema_property)| (name, String::new()))
                .collect(),
        },
        credential_schema: CredentialSchemaReference {
            id: schema_obj.id,
            r#type: schema_obj.r#type,
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
pub struct Credential<'a> {
    vade_evan: &'a mut VadeEvan,
}

impl<'a> Credential<'a> {
    pub fn new(vade_evan: &'a mut VadeEvan) -> Result<Credential, VadeEvanError> {
        Ok(Credential { vade_evan })
    }

    pub async fn create_credential_offer(
        self,
        schema_did: &str,
        use_valid_until: bool,
        issuer_did: &str,
        subject_did: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        let schema_did_doc_str = self.vade_evan.did_resolve(schema_did).await?;

        let credential_draft = create_empty_unsigned_credential(
            &schema_did_doc_str,
            subject_did.as_deref(),
            use_valid_until,
        )?;
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

    /// Resolve a issuer did, get the did document and extract the public key out of the
    /// verification methods
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer to load the pub key from
    /// * `verification_method_id` - id of verification method to extract the pub key
    ///
    /// # Returns
    /// * `CredentialProposal` - The message to be sent to an issuer
    async fn get_issuer_pub_key(
        self,
        issuer_did: &str,
        verification_method_id: &str,
    ) -> Result<String, VadeEvanError> {
        // resolve the did and extract the did document out of it
        let did_result_str = self.vade_evan.did_resolve(issuer_did).await?;
        let did_result_value: Value = serde_json::from_str(&did_result_str)?;
        let did_document_result = did_result_value.get("didDocument").ok_or_else(|| {
            VadeEvanError::InvalidDidDocument(
                "missing 'didDocument' property in resolved did".to_string(),
            )
        });
        let did_document_str = serde_json::to_string(&did_document_result?)?;
        let did_document: DidDocument = serde_json::from_str(&did_document_str)?;

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
            return Err(VadeEvanError::InvalidVerificationMethod(
                "no public key found for verification id {verification_method_id}".to_string(),
            ));
        }

        Ok(public_key.to_string())
    }

    pub async fn verify(
        self,
        issuer_did: &str,
        verification_method_id: &str,
    ) -> Result<(), VadeEvanError> {
        let issuer_pub_key = self
            .get_issuer_pub_key(issuer_did, verification_method_id)
            .await?;

        // TODO: add bbs_secret: &str,
        // TODO: add credential: BbsCredential

        println!("found issuer pub key: {}", issuer_pub_key);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use vade_evan_bbs::BbsCredentialOffer;

    use crate::{VadeEvan, DEFAULT_SIGNER, DEFAULT_TARGET};

    use super::Credential;

    const CREDENTIAL_MESSAGE_COUNT: usize = 13;
    const VALID_ISSUER_DID: &str = "did:evan:EiBtSZwjyrwiMfUUOU5o0CKdavUi36l7lYKszccZyvl84A";
    const SCHEMA_DID: &str = "did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw";
    const SUBJECT_DID: &str = "did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f";
    const VERIFICATION_METHOD_ID: &str = "#publicKey";
    const JSON_WEB_PUB_KEY: &str = "0ya7nOYpfP6joriZg0tjSl4uyN992Lqk3Ef-bzzhuC4";

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_can_create_credential_offer() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let credential = Credential::new(&mut vade_evan)?;

        let offer_str = credential
            .create_credential_offer(SCHEMA_DID, false, VALID_ISSUER_DID, Some(SUBJECT_DID))
            .await?;

        let offer_obj: BbsCredentialOffer = serde_json::from_str(&offer_str)?;
        assert_eq!(offer_obj.issuer, VALID_ISSUER_DID);
        assert_eq!(offer_obj.subject, Some(SUBJECT_DID.to_string()));
        assert_eq!(offer_obj.credential_message_count, CREDENTIAL_MESSAGE_COUNT);
        assert!(!offer_obj.nonce.is_empty());

        Ok(())
    }

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_can_verify_credential() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let credential = Credential::new(&mut vade_evan)?;

        // TODO: verify credential nquads

        // verify the credential issuer
        credential
            .verify(VALID_ISSUER_DID, VERIFICATION_METHOD_ID)
            .await?;

        Ok(())
    }

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn can_get_issuer_pub_key() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let credential = Credential::new(&mut vade_evan)?;
        let pub_key = credential
            .get_issuer_pub_key(VALID_ISSUER_DID, VERIFICATION_METHOD_ID)
            .await?;

        assert_eq!(pub_key, JSON_WEB_PUB_KEY);

        Ok(())
    }

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn will_throw_when_pubkey_not_found() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let credential = Credential::new(&mut vade_evan)?;
        let pub_key = credential
            .get_issuer_pub_key(VALID_ISSUER_DID, "#random-id")
            .await;

        match pub_key {
            Ok(_) => assert!(false, "pub key should not be there"),
            Err(_) => assert!(true, "pub key not found"),
        }

        Ok(())
    }
}
