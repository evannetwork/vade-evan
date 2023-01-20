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
        credential_schema: &str,
    ) -> Result<String, VadeEvanError> {
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
