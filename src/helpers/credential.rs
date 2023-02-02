use crate::api::{VadeEvan, VadeEvanError};
use crate::helpers::datatypes::{EVAN_METHOD, TYPE_BBS_OPTIONS};
use serde_json::Value;
use ssi::{
    jsonld::{json_to_dataset, JsonLdOptions, StaticLoader},
    urdna2015::normalize,
};
use vade_evan_bbs::{
    CredentialSchema,
    CredentialSchemaReference,
    CredentialStatus,
    CredentialSubject,
    OfferCredentialPayload,
    UnsignedBbsCredential,
};

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
                TYPE_BBS_OPTIONS,
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
            .vc_zkp_request_credential(EVAN_METHOD, TYPE_BBS_OPTIONS, &payload)
            .await?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use vade_evan_bbs::BbsCredentialOffer;

    use crate::{VadeEvan, DEFAULT_SIGNER, DEFAULT_TARGET};

    use super::Credential;

    const CREDENTIAL_MESSAGE_COUNT: usize = 13;
    const ISSUER_DID: &str = "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6";
    const SCHEMA_DID: &str = "did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw";
    const SUBJECT_DID: &str = "did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f";

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_can_create_credential_offer() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let credential = Credential::new(&mut vade_evan)?;

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
}
