use std::str::FromStr;

use crate::api::{VadeEvan, VadeEvanError};
use crate::helpers::datatypes::{
    AddPublicKeys,
    AddServices,
    CreateDidPayload,
    DIDOperationType,
    DidUpdatePayload,
    Patch,
    PublicKeyJWK,
    PublicKeyModel,
    PublicKeyPurpose,
    RemovePublicKeys,
    RemoveServices,
    Service,
    EVAN_METHOD,
    TYPE_BBS_KEY,
    TYPE_JSONWEB_KEY,
    TYPE_SIDETREE_OPTIONS,
};
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use uuid::Uuid;

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
                    d: None,
                    nonce: None,
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
                        d: None,
                        nonce: None,
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

        let mut create_payload: CreateDidPayload = CreateDidPayload {
            update_key: None,
            recovery_key: None,
            public_keys: None,
            services: None,
        };
        if public_keys.len() > 0 {
            create_payload.public_keys = Some(public_keys);
        }
        if services.len() > 0 {
            create_payload.services = Some(services);
        }
        let payload = serde_json::to_string(&create_payload)?;

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
        let update_key: PublicKeyJWK =
            serde_json::from_str(update_key).map_err(|err| VadeEvanError::InternalError {
                source_message: err.to_string(),
            })?;
        let mut next_update_key = update_key.clone();
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
                let new_key_to_add: PublicKeyJWK =
                    serde_json::from_str(payload).map_err(|err| VadeEvanError::InternalError {
                        source_message: err.to_string(),
                    })?;
                let id = format!("key#{}", Uuid::new_v4().to_simple().to_string());

                let public_key_to_add = PublicKeyModel {
                    id,
                    r#type: "EcdsaSecp256k1VerificationKey2019".to_string(),
                    purposes: [PublicKeyPurpose::KeyAgreement].to_vec(),
                    public_key_jwk: new_key_to_add,
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
            DIDOperationType::AddServiceEnpoint => {
                let service: Service =
                    serde_json::from_str(payload).map_err(|err| VadeEvanError::InternalError {
                        source_message: err.to_string(),
                    })?;

                patch = Patch::AddServices(AddServices {
                    services: vec![service],
                });
            }

            DIDOperationType::RemoveServiceEnpoint => {
                let service_id_to_remove = payload.to_owned();

                patch = Patch::RemoveServices(RemoveServices {
                    ids: vec![service_id_to_remove],
                });
            }
        };

        let update_payload = DidUpdatePayload {
            update_type: "update".to_string(),
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

        println!("{}\n", payload);

        let result = self
            .vade_evan
            .did_update(did, TYPE_SIDETREE_OPTIONS, payload)
            .await?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::datatypes::{PublicKeyJWK, Service};
    use crate::{VadeEvan, VadeEvanError, DEFAULT_SIGNER, DEFAULT_TARGET};
    use anyhow::Result;
    use serde::{Deserialize, Serialize};
    use serial_test::serial;

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SidetreeDidDocument {
        did_document: DidDoc,
    }

    #[derive(Default, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct KeyAgreement {
        id: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CreateDIDResponse {
        did: Did,
        update_key: PublicKeyJWK,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Did {
        did_document: DidDoc,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct DidDoc {
        id: String,
        pub verification_method: Option<Vec<KeyAgreement>>,
    }

    #[tokio::test]
    #[serial]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_did_can_create_did_with_bbs_keys() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let base64_encoded_bbs_key = "LwDjc3acetrEsbccFI4zSy1+AFqUbkEUf6Sm0OxIdhU=";

        let did_create_result = vade_evan
            .helper_did_create(Some(base64_encoded_bbs_key), None, None)
            .await;

        assert!(did_create_result.is_ok());
        assert!(did_create_result?.contains(base64_encoded_bbs_key));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_did_can_create_did_with_service_endpoint() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let service_endpoint = "www.example.service";

        let did_create_result = vade_evan
            .helper_did_create(None, None, Some(service_endpoint))
            .await;
        assert!(did_create_result.is_ok());
        assert!(did_create_result?.contains(service_endpoint));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_did_can_update_did_add_key() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let did_create_result = vade_evan.helper_did_create(None, None, None).await?;

        let did_create_result: CreateDIDResponse = serde_json::from_str(&did_create_result)?;

        let base64_encoded_bbs_key = "LwDjc3acetrEsbccFI4zSy1+AFqUbkEUf6Sm0OxIdhU=";

        let public_key = PublicKeyJWK {
            kty: "EC".to_owned(),
            crv: "BLS12381_G2".to_owned(),
            x: base64_encoded_bbs_key.to_owned(),
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
        assert!(did_resolve_result.contains(&base64_encoded_bbs_key));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_did_can_update_did_add_service() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let did_create_result = vade_evan.helper_did_create(None, None, None).await?;

        let did_create_result: CreateDIDResponse = serde_json::from_str(&did_create_result)?;

        let service_endpoint = "https://w3id.org/did-resolution/v1".to_string();

        let service = Service {
            id: "sds".to_string(),
            r#type: "SecureDataStrore".to_string(),
            service_endpoint: service_endpoint.clone(),
        };

        let did_update_result = vade_evan
            .helper_did_update(
                &did_create_result.did.did_document.id,
                "AddServiceEnpoint",
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
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_did_can_update_did_add_remove_service() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let did_create_result = vade_evan.helper_did_create(None, None, None).await?;

        let did_create_result: CreateDIDResponse = serde_json::from_str(&did_create_result)?;

        let service_endpoint = "https://www.google.de".to_string();

        let service = Service {
            id: "sds".to_string(),
            r#type: "SecureDataStrore".to_string(),
            service_endpoint: service_endpoint.clone(),
        };

        let did_update_result = vade_evan
            .helper_did_update(
                &did_create_result.did.did_document.id,
                "AddServiceEnpoint",
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
                "RemoveServiceEnpoint",
                &serde_json::to_string(&update_key)?,
                "sds",
            )
            .await;

        assert!(did_update_result.is_ok());

        // resolve and see if the service is removed
        let did_resolve_result = vade_evan
            .did_resolve(&did_create_result.did.did_document.id)
            .await?;

        println!("{}\n", did_resolve_result);
        assert!(!did_resolve_result.contains(&service_endpoint));

        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_did_can_update_did_add_remove_key() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;

        let did_create_result = vade_evan.helper_did_create(None, None, None).await?;

        let did_create_result: CreateDIDResponse = serde_json::from_str(&did_create_result)?;

        let base64_encoded_bbs_key = "LwDjc3acetrEsbccFI4zSy1+AFqUbkEUf6Sm0OxIdhU=";

        let public_key = PublicKeyJWK {
            kty: "EC".to_owned(),
            crv: "BLS12381_G2".to_owned(),
            x: base64_encoded_bbs_key.to_owned(),
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
        assert!(did_resolve_result.contains(&base64_encoded_bbs_key));

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
            .ok_or("updated key not found")
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

        println!("{}", did_resolve_result);
        assert!(!did_resolve_result.contains(&base64_encoded_bbs_key));
        Ok(())
    }
}
