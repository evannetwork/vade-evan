use serde::{Deserialize, Serialize};

pub const EVAN_METHOD: &str = "did:evan";
pub const TYPE_BBS_OPTIONS: &str = r#"{ "type": "bbs" }"#;
pub const TYPE_SIDETREE_OPTIONS: &str = r#"{ "type": "sidetree" }"#;

pub const TYPE_BBS_KEY: &str = "Bls12381G2Key2020";
pub const TYPE_JSONWEB_KEY: &str = "JsonWebKey2020";

pub enum DIDOperationType{
    AddKey,
    RemoveKey,
    AddServiceEnpoint
}
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum PublicKeyPurpose {
    Authentication,
    AssertionMethod,
    CapabilityInvocation,
    CapabilityDelegation,
    KeyAgreement
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyModel {
    pub id: String,
    pub r#type: String,
    pub public_key_jwk: PublicKeyJWK,
    pub purposes: Vec<PublicKeyPurpose>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJWK{
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Service{
    pub id: String,
    pub r#type: String,
    pub service_endpoint: String,
}