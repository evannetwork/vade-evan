use crate::api::{VadeEvan, VadeEvanError};
use crate::helpers::datatypes::{DIDType, EVAN_METHOD};
pub struct DID<'a> {
    vade_evan: &'a mut VadeEvan,
}

impl<'a> DID<'a> {
    pub fn new(vade_evan: &'a mut VadeEvan) -> Result<DID, VadeEvanError> {
        Ok(DID { vade_evan })
    }

    pub async fn create(
        self,
        did_type: DIDType,
        private_key: Option<&str>,
        identity: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        // let payload = format!(
        //     r#"{{
        //         "credentialOffering": {},
        //         "masterSecret": {},
        //         "credentialValues": {},
        //         "issuerPubKey": {},
        //         "credentialSchema": {}
        //     }}"#,
        //     credential_offer, bbs_secret, credential_values, issuer_public_key, credential_schema
        // );
        // let result = self
        //     .vade_evan
        //     .vc_zkp_request_credential(EVAN_METHOD, TYPE_OPTIONS, &payload)
        //     .await?;

        Ok("".to_string())
    }
    pub async fn update(
        self,
        did_type: DIDType,
        did: Option<&str>,        
        private_key: Option<&str>,
        identity: Option<&str>,
        operation: Option<&str>,
        payload: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        Ok("".to_string())
    }
}
