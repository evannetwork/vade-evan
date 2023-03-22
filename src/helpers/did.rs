use std::str::FromStr;

use crate::api::{VadeEvan, VadeEvanError};
use crate::helpers::datatypes::{DIDOperationType, EVAN_METHOD, TYPE_SIDETREE_OPTIONS};
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use uuid::Uuid;

use vade_sidetree::{
    datatypes::{
        AddPublicKeys,
        AddServices,
        DidUpdatePayload,
        IetfJsonPatch,
        JsonPatch,
        JsonWebKey,
        JsonWebKeyPublic,
        Patch,
        PublicKey,
        Purpose,
        RemovePublicKeys,
        RemoveServices,
        Service,
        UpdateType,
    },
    CreateDidPayload,
};

pub const TYPE_BBS_KEY: &str = "Bls12381G2Key2020";
pub const TYPE_JSONWEB_KEY: &str = "JsonWebKey2020";

pub struct Did<'a> {
    vade_evan: &'a mut VadeEvan,
}

impl<'a> Did<'a> {
    pub fn new(vade_evan: &'a mut VadeEvan) -> Result<Did, VadeEvanError> {
        Ok(Did { vade_evan })
    }

    pub async fn create(
        self,
        bbs_public_key: Option<&str>,
        signing_key: Option<&str>,
        service_endpoint: Option<&str>,
        update_key: Option<&str>,
        recovery_key: Option<&str>,
    ) -> Result<String, VadeEvanError> {
        let mut public_keys: Vec<PublicKey> = vec![];
        let update_key: Option<JsonWebKey> = match update_key {
            None => None,
            Some(json_web_key) => {
                serde_json::from_str(json_web_key).map_err(|err| VadeEvanError::InternalError {
                    source_message: err.to_string(),
                })?
            }
        };
        let recovery_key: Option<JsonWebKey> = match recovery_key {
            None => None,
            Some(json_web_key) => {
                serde_json::from_str(json_web_key).map_err(|err| VadeEvanError::InternalError {
                    source_message: err.to_string(),
                })?
            }
        };

        match bbs_public_key {
            Some(val) => public_keys.push(PublicKey {
                id: format!("bbs-key#{}", Uuid::new_v4().to_simple().to_string()),
                key_type: TYPE_BBS_KEY.to_owned(),
                public_key_jwk: Some(JsonWebKey {
                    key_type: "EC".to_owned(),
                    curve: "BLS12381_G2".to_owned(),
                    x: val.to_owned(),
                    y: None,
                    d: None,
                    nonce: None,
                }),
                purposes: Some(vec![
                    Purpose::Authentication,
                    Purpose::AssertionMethod,
                    Purpose::CapabilityInvocation,
                    Purpose::CapabilityDelegation,
                    Purpose::KeyAgreement,
                ]),
                controller: None,
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
                public_keys.push(PublicKey {
                    id: format!("signing-key-1#{}", Uuid::new_v4().to_simple().to_string()),
                    key_type: TYPE_JSONWEB_KEY.to_owned(),
                    public_key_jwk: Some(JsonWebKey {
                        key_type: "EC".to_owned(),
                        curve: "secp256k1".to_owned(),
                        x: encode_config(pub_key[1..33].as_ref(), URL_SAFE_NO_PAD),
                        y: Some(encode_config(pub_key[33..65].as_ref(), URL_SAFE_NO_PAD)),
                        d: None,
                        nonce: None,
                    }),
                    purposes: Some(vec![
                        Purpose::Authentication,
                        Purpose::AssertionMethod,
                        Purpose::CapabilityInvocation,
                        Purpose::CapabilityDelegation,
                        Purpose::KeyAgreement,
                    ]),
                    controller: None,
                })
            }
            None => {}
        };

        let mut services: Vec<Service> = vec![];
        match service_endpoint {
            Some(val) => services.push(Service {
                id: "service#1".to_owned(),
                service_endpoint: val.to_owned(),
                service_type: "CustomService".to_owned(),
            }),
            None => {}
        }

        let mut create_payload: CreateDidPayload = CreateDidPayload {
            update_key,
            recovery_key,
            public_keys: None,
            services: None,
        };
        if public_keys.len() > 0 {
            create_payload.public_keys = Some(public_keys);
        }
        if services.len() > 0 {
            create_payload.services = Some(services);
        }
        let payload =
            serde_json::to_string(&create_payload).map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string(),
            })?;

        let result = self
            .vade_evan
            .did_create(EVAN_METHOD, TYPE_SIDETREE_OPTIONS, &payload)
            .await?;
        Ok(result)
    }

    pub async fn update(
        self,
        did: &str,
        operation: &str,
        update_key: &str,
        payload: &str,
    ) -> Result<String, VadeEvanError> {
        let patch: Patch;
        let operation =
            DIDOperationType::from_str(operation).map_err(|_| VadeEvanError::InternalError {
                source_message: "Unsupported update operation".to_owned(),
            })?;
        let update_key: JsonWebKey =
            serde_json::from_str(update_key).map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string(),
            })?;
        let mut next_update_key: JsonWebKeyPublic =
            serde_json::from_value(serde_json::to_value(update_key.clone()).map_err(|err| {
                VadeEvanError::InternalError {
                    source_message: err.to_string(),
                }
            })?)
            .map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string(),
            })?;
        let mut nonce = next_update_key
            .nonce
            .unwrap_or_else(|| "0".to_string())
            .parse::<u32>()
            .map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string(),
            })?;
        nonce += 1;
        next_update_key.nonce = Some(nonce.to_string());

        match operation {
            DIDOperationType::AddKey => {
                let new_key_to_add: JsonWebKey =
                    serde_json::from_str(payload).map_err(|err| VadeEvanError::InternalError {
                        source_message: err.to_string(),
                    })?;
                let id = format!("key#{}", Uuid::new_v4().to_simple().to_string());

                let public_key_to_add = PublicKey {
                    id,
                    key_type: "EcdsaSecp256k1VerificationKey2019".to_string(),
                    purposes: Some([Purpose::KeyAgreement].to_vec()),
                    public_key_jwk: Some(new_key_to_add),
                    controller: None,
                };

                patch = Patch::AddPublicKeys(AddPublicKeys {
                    public_keys: vec![public_key_to_add],
                });
            }
            DIDOperationType::RemoveKey => {
                let key_id_to_remove = payload.to_owned();
                patch = Patch::RemovePublicKeys(RemovePublicKeys {
                    ids: vec![key_id_to_remove],
                });
            }
            DIDOperationType::AddServiceEndpoint => {
                let service: Service =
                    serde_json::from_str(payload).map_err(|err| VadeEvanError::InternalError {
                        source_message: err.to_string(),
                    })?;

                patch = Patch::AddServices(AddServices {
                    services: vec![service],
                });
            }

            DIDOperationType::RemoveServiceEndpoint => {
                let service_id_to_remove = payload.to_owned();

                patch = Patch::RemoveServices(RemoveServices {
                    ids: vec![service_id_to_remove],
                });
            }
            DIDOperationType::ReplaceDidDoc => {
                let updated_did_doc =
                    serde_json::from_str(payload).map_err(|err| VadeEvanError::InternalError {
                        source_message: err.to_string(),
                    })?;
                let ietf_json_patch = IetfJsonPatch {
                    op: "replace".to_owned(),
                    path: "".to_owned(),
                    value: updated_did_doc,
                };
                patch = Patch::IetfJsonPatch(JsonPatch {
                    patches: vec![ietf_json_patch],
                })
            }
        };

        let update_payload = DidUpdatePayload {
            update_type: UpdateType::Update,
            update_key: Some(update_key),
            next_update_key: Some(next_update_key),
            patches: Some(vec![patch]),
            next_recovery_key: None,
            recovery_key: None,
        };

        let payload = &serde_json::to_string(&update_payload).map_err(|err| {
            VadeEvanError::InternalError {
                source_message: err.to_string(),
            }
        })?;

        let result = self
            .vade_evan
            .did_update(did, TYPE_SIDETREE_OPTIONS, payload)
            .await?;

        Ok(result)
    }
}

#[cfg(test)]
#[cfg(feature = "plugin-did-sidetree")]
#[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
mod tests {
    use crate::{VadeEvan, VadeEvanError, DEFAULT_SIGNER, DEFAULT_TARGET};
    use anyhow::Result;
    use serial_test::serial;
    use vade_sidetree::datatypes::{DidCreateResponse, JsonWebKey, Service, SidetreeDidDocument};

    #[tokio::test]
    #[serial]
    async fn helper_did_can_create_did_with_update_and_recovery_keys() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let did_create_result = vade_evan
            .helper_did_create(None, None, None, None, None)
            .await;

        assert!(did_create_result.is_ok());
        let did_create_result: DidCreateResponse = serde_json::from_str(&did_create_result?)?;

        let did_create_result = vade_evan
            .helper_did_create(
                None,
                None,
                None,
                Some(&serde_json::to_string(&did_create_result.update_key)?),
                Some(&serde_json::to_string(&did_create_result.recovery_key)?),
            )
            .await;
        assert!(did_create_result.is_ok());
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn helper_did_can_create_did_with_bbs_public_key() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let base64_encoded_bbs_public_key = "LwDjc3acetrEsbccFI4zSy1+AFqUbkEUf6Sm0OxIdhU=";

        let did_create_result = vade_evan
            .helper_did_create(Some(base64_encoded_bbs_public_key), None, None, None, None)
            .await;

        assert!(did_create_result.is_ok());
        assert!(did_create_result?.contains(base64_encoded_bbs_public_key));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn helper_did_can_create_did_with_service_endpoint() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let service_endpoint = "www.example.service";

        let did_create_result = vade_evan
            .helper_did_create(None, None, Some(service_endpoint), None, None)
            .await;
        assert!(did_create_result.is_ok());
        assert!(did_create_result?.contains(service_endpoint));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn helper_did_can_update_did_add_key() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let did_create_result = vade_evan
            .helper_did_create(None, None, None, None, None)
            .await?;
        let did_create_result: DidCreateResponse = serde_json::from_str(&did_create_result)?;

        let base64_encoded_bbs_public_key = "LwDjc3acetrEsbccFI4zSy1+AFqUbkEUf6Sm0OxIdhU=";

        let public_key = JsonWebKey {
            key_type: "EC".to_owned(),
            curve: "BLS12381_G2".to_owned(),
            x: base64_encoded_bbs_public_key.to_owned(),
            y: None,
            d: None,
            nonce: None,
        };

        let did_update_result = vade_evan
            .helper_did_update(
                &did_create_result.did.did_document.id,
                "AddKey",
                &serde_json::to_string(&did_create_result.update_key)?,
                &serde_json::to_string(&public_key)?,
            )
            .await;

        assert!(did_update_result.is_ok());

        let did_resolve_result = vade_evan
            .did_resolve(&did_create_result.did.did_document.id)
            .await?;
        assert!(did_resolve_result.contains(&base64_encoded_bbs_public_key));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn helper_did_can_update_did_add_service() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let did_create_result = vade_evan
            .helper_did_create(None, None, None, None, None)
            .await?;
        let did_create_result: DidCreateResponse = serde_json::from_str(&did_create_result)?;

        let service_endpoint = "https://w3id.org/did-resolution/v1".to_string();

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            service_endpoint: service_endpoint.clone(),
        };

        let did_update_result = vade_evan
            .helper_did_update(
                &did_create_result.did.did_document.id,
                "AddServiceEndpoint",
                &serde_json::to_string(&did_create_result.update_key)?,
                &serde_json::to_string(&service)?,
            )
            .await;

        assert!(did_update_result.is_ok());

        let did_resolve_result = vade_evan
            .did_resolve(&did_create_result.did.did_document.id)
            .await?;
        assert!(did_resolve_result.contains(&service_endpoint));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn helper_did_can_update_did_add_remove_service() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let did_create_result = vade_evan
            .helper_did_create(None, None, None, None, None)
            .await?;
        let did_create_result: DidCreateResponse = serde_json::from_str(&did_create_result)?;

        let service_endpoint = "https://www.google.de".to_string();

        let service = Service {
            id: "sds".to_string(),
            service_type: "SecureDataStrore".to_string(),
            service_endpoint: service_endpoint.clone(),
        };

        let did_update_result = vade_evan
            .helper_did_update(
                &did_create_result.did.did_document.id,
                "AddServiceEndpoint",
                &serde_json::to_string(&did_create_result.update_key)?,
                &serde_json::to_string(&service)?,
            )
            .await;

        assert!(did_update_result.is_ok());

        let did_resolve_result = vade_evan
            .did_resolve(&did_create_result.did.did_document.id)
            .await?;
        assert!(did_resolve_result.contains(&service_endpoint));

        // Get update key for next update to remove service
        let mut update_key = did_create_result.update_key.clone();
        let mut nonce = update_key
            .nonce
            .unwrap_or_else(|| "0".to_string())
            .parse::<u32>()
            .map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string(),
            })?;
        nonce += 1;
        update_key.nonce = Some(nonce.to_string());

        let did_update_result = vade_evan
            .helper_did_update(
                &did_create_result.did.did_document.id,
                "RemoveServiceEndpoint",
                &serde_json::to_string(&update_key)?,
                "sds",
            )
            .await;

        assert!(did_update_result.is_ok());

        // resolve and see if the service is removed
        let did_resolve_result = vade_evan
            .did_resolve(&did_create_result.did.did_document.id)
            .await?;

        assert!(!did_resolve_result.contains(&service_endpoint));

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn helper_did_can_update_did_add_remove_key() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let did_create_result = vade_evan
            .helper_did_create(None, None, None, None, None)
            .await?;
        let did_create_result: DidCreateResponse = serde_json::from_str(&did_create_result)?;

        let base64_encoded_bbs_public_key = "LwDjc3acetrEsbccFI4zSy1+AFqUbkEUf6Sm0OxIdhU=";

        let public_key = JsonWebKey {
            key_type: "EC".to_owned(),
            curve: "BLS12381_G2".to_owned(),
            x: base64_encoded_bbs_public_key.to_owned(),
            y: None,
            d: None,
            nonce: None,
        };

        let did_update_result = vade_evan
            .helper_did_update(
                &did_create_result.did.did_document.id,
                "AddKey",
                &serde_json::to_string(&did_create_result.update_key)?,
                &serde_json::to_string(&public_key)?,
            )
            .await;

        assert!(did_update_result.is_ok());

        let did_resolve_result = vade_evan
            .did_resolve(&did_create_result.did.did_document.id)
            .await?;
        assert!(did_resolve_result.contains(&base64_encoded_bbs_public_key));

        let did_resolve_result: SidetreeDidDocument = serde_json::from_str(&did_resolve_result)?;

        // Get update key for next update to remove key
        let mut update_key = did_create_result.update_key.clone();
        let mut nonce = update_key
            .nonce
            .unwrap_or_else(|| "0".to_string())
            .parse::<u32>()
            .map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string(),
            })?;
        nonce += 1;
        update_key.nonce = Some(nonce.to_string());

        let verification_method = &did_resolve_result
            .did_document
            .verification_method
            .ok_or("verification method not found")
            .map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string(),
            })?;

        let key_id = &verification_method
            .get(0)
            .ok_or("invalid key")
            .map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string(),
            })?
            .id;
        let key_id = &key_id[1..key_id.len()]; // remove # symbol from key id
        let did_update_result = vade_evan
            .helper_did_update(
                &did_create_result.did.did_document.id,
                "RemoveKey",
                &serde_json::to_string(&update_key)?,
                key_id,
            )
            .await;

        assert!(did_update_result.is_ok());

        // resolve and see if the key is removed
        let did_resolve_result = vade_evan
            .did_resolve(&did_create_result.did.did_document.id)
            .await?;
        assert!(!did_resolve_result.contains(&base64_encoded_bbs_public_key));
        Ok(())
    }
}
