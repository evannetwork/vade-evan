use crate::api::{VadeEvan, VadeEvanError};
use crate::helpers::datatypes::{
    DIDOperationType,
    PublicKeyModel,
    PublicKeyPurpose,
    Service,
    EVAN_METHOD,
    TYPE_BBS_KEY,
    TYPE_JSONWEB_KEY,
    TYPE_SIDETREE_OPTIONS,
};
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};

use super::datatypes::PublicKeyJWK;
pub struct DID<'a> {
    vade_evan: &'a mut VadeEvan,
}

impl<'a> DID<'a> {
    pub fn new(vade_evan: &'a mut VadeEvan) -> Result<DID, VadeEvanError> {
        Ok(DID { vade_evan })
    }

    pub async fn create(
        self,
        bbs_key: Option<&str>,
        signing_key: Option<&str>,
        service_endpoint: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        let mut public_keys: Vec<PublicKeyModel> = vec![];
        match bbs_key {
            Some(val) => public_keys.push(PublicKeyModel {
                id: "#bbs-key-1".to_owned(),
                r#type: TYPE_BBS_KEY.to_owned(),
                public_key_jwk: PublicKeyJWK {
                    kty: "EC".to_owned(),
                    crv: "BLS12381_G2".to_owned(),
                    x: val.to_owned(),
                    y: None,
                },
                purposes: vec![
                    PublicKeyPurpose::Authentication,
                    PublicKeyPurpose::AssertionMethod,
                    PublicKeyPurpose::CapabilityInvocation,
                    PublicKeyPurpose::CapabilityDelegation,
                    PublicKeyPurpose::KeyAgreement,
                ],
            }),
            None => {}
        };
        match signing_key {
            Some(val) => {
                let pub_key = decode_config(val, URL_SAFE_NO_PAD).map_err(|err| {
                    VadeEvanError::InternalError {
                        source_message: err.to_string(),
                    }
                })?;
                public_keys.push(PublicKeyModel {
                    id: "#signing-key-1".to_owned(),
                    r#type: TYPE_JSONWEB_KEY.to_owned(),
                    public_key_jwk: PublicKeyJWK {
                        kty: "EC".to_owned(),
                        crv: "secp256k1".to_owned(),
                        x: encode_config(pub_key[1..33].as_ref(), URL_SAFE_NO_PAD),
                        y: Some(encode_config(pub_key[33..65].as_ref(), URL_SAFE_NO_PAD)),
                    },
                    purposes: vec![
                        PublicKeyPurpose::Authentication,
                        PublicKeyPurpose::AssertionMethod,
                        PublicKeyPurpose::CapabilityInvocation,
                        PublicKeyPurpose::CapabilityDelegation,
                        PublicKeyPurpose::KeyAgreement,
                    ],
                })
            }
            None => {}
        };

        let mut services: Vec<Service> = vec![];
        match service_endpoint {
            Some(val) => services.push(Service {
                id: "service#1".to_owned(),
                r#type: "CustomService".to_owned(),
                service_endpoint: val.to_owned(),
            }),
            None => {}
        }

        let payload = format!(
            r#"{{
                "public_keys": {},
                "services": {},
            }}"#,
            serde_json::to_string(&public_keys).map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string()
            })?,
            serde_json::to_string(&services).map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string()
            })?
        );
        let result = self
            .vade_evan
            .did_create(EVAN_METHOD, TYPE_SIDETREE_OPTIONS, &payload)
            .await?;
        Ok(result)
    }
    pub async fn update(
        self,
        did: &str,
        operation: DIDOperationType,
        identity: Option<&str>,
        payload: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        Ok("".to_string())
    }
}
