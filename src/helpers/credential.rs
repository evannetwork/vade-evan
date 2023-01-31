use serde_json::value::Value;

use crate::api::{VadeEvan, VadeEvanError};
const EVAN_METHOD: &str = "did:evan";
const TYPE_OPTIONS: &str = r#"{ "type": "bbs" }"#;

pub struct Credential<'a> {
    vade_evan: &'a mut VadeEvan,
}

impl<'a> Credential<'a> {
    pub fn new(vade_evan: &'a mut VadeEvan) -> Result<Credential, VadeEvanError> {
        Ok(Credential { vade_evan })
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
}
