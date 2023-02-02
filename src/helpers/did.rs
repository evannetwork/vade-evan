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
        println!("create payload{}", payload);
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
                let public_key_to_add = PublicKeyModel {
                    id: "update_key".to_owned(),
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

        let result = self
            .vade_evan
            .did_update(
                did,
                TYPE_SIDETREE_OPTIONS,
                &serde_json::to_string(&update_payload).map_err(|err| {
                    VadeEvanError::InternalError {
                        source_message: err.to_string(),
                    }
                })?,
            )
            .await?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::{VadeEvan, DEFAULT_SIGNER, DEFAULT_TARGET};
    use anyhow::Result;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CreateDIDResponse {
        did: Did,
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
    }

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_can_create_did_with_bbs_keys() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let base64_encoded_bbs_key = "LwDjc3acetrEsbccFI4zSy1+AFqUbkEUf6Sm0OxIdhU=";

        let did_create_result = vade_evan
            .helper_did_create(Some(base64_encoded_bbs_key), None, None)
            .await;

        assert!(did_create_result.is_ok());
        // println!("{}", did_create_result?);
        let create_response: CreateDIDResponse = serde_json::from_str(&did_create_result?)?;

        let did_resolve = vade_evan
            .did_resolve(&create_response.did.did_document.id)
            .await?;
        println!("{}", did_resolve);
        assert!(did_resolve.contains(base64_encoded_bbs_key));
        Ok(())
    }

    #[tokio::test]
    #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    async fn helper_can_create_did_with_service_endpoint() -> Result<()> {
        let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
            target: DEFAULT_TARGET,
            signer: DEFAULT_SIGNER,
        })?;
        let service_endpoint = "www.example.service";

        let did_create_result = vade_evan
            .helper_did_create(None, None, Some(service_endpoint))
            .await;

        assert!(did_create_result.is_ok());
        // println!("{}", did_create_result?);
        let create_response: CreateDIDResponse = serde_json::from_str(&did_create_result?)?;

        let did_resolve = vade_evan
            .did_resolve(&create_response.did.did_document.id)
            .await?;
        println!("{}", did_resolve);
        assert!(did_resolve.contains(service_endpoint));
        Ok(())
    }

    // #[tokio::test]
    // #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    // async fn helper_can_update_did_with_service_endpoint() -> Result<()> {
    //     let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
    //         target: DEFAULT_TARGET,
    //         signer: DEFAULT_SIGNER,
    //     })?;

    //     let did_create_result = vade_evan
    //         .helper_did_create(None, None, Some(service_endpoint))
    //         .await;

    //     assert!(did_create_result.is_ok());
    //     println!("{}", did_create_result?);
    //     Ok(())
    // }

    // #[tokio::test]
    // #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    // async fn helper_can_update_did_with_public_key() -> Result<()> {
    //     let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
    //         target: DEFAULT_TARGET,
    //         signer: DEFAULT_SIGNER,
    //     })?;
    //     let service_endpoint = "www.example.service";

    //     let did_create_result = vade_evan
    //         .helper_did_create(None, None, Some(service_endpoint))
    //         .await;

    //     assert!(did_create_result.is_ok());
    //     println!("{}", did_create_result?);
    //     Ok(())
    // }

    // #[tokio::test]
    // #[cfg(not(all(feature = "target-c-lib", feature = "capability-sdk")))]
    // async fn helper_can_update_did_with_public_key() -> Result<()> {
    //     let mut vade_evan = VadeEvan::new(crate::VadeEvanConfig {
    //         target: DEFAULT_TARGET,
    //         signer: DEFAULT_SIGNER,
    //     })?;
    //     let service_endpoint = "www.example.service";

    //     let did_create_result = vade_evan
    //         .helper_did_create(None, None, Some(service_endpoint))
    //         .await;

    //     assert!(did_create_result.is_ok());
    //     println!("{}", did_create_result?);
    //     Ok(())
    // }
}
