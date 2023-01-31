use serde::{Deserialize, Serialize};

pub const EVAN_METHOD: &str = "did:evan";
pub const TYPE_BBS_OPTIONS: &str = r#"{ "type": "bbs" }"#;
pub const TYPE_SIDETREE_OPTIONS: &str = r#"{ "type": "sidetree", \"waitForCompletion\":true }"#;

pub const TYPE_BBS_KEY: &str = "Bls12381G2Key2020";
pub const TYPE_JSONWEB_KEY: &str = "JsonWebKey2020";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePublicKeys {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPublicKeys {
    pub public_keys: Vec<PublicKeyModel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveServices {
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddServices {
    pub services: Vec<Service>,
}

pub enum DIDOperationType {
    AddKey,
    RemoveKey,
    AddServiceEnpoint,
    RemoveServiceEnpoint,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum PublicKeyPurpose {
    Authentication,
    AssertionMethod,
    CapabilityInvocation,
    CapabilityDelegation,
    KeyAgreement,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyModel {
    pub id: String,
    pub r#type: String,
    pub public_key_jwk: PublicKeyJWK,
    pub purposes: Vec<PublicKeyPurpose>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyJWK {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    pub r#type: String,
    pub service_endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "action")]
#[serde(rename_all(serialize = "kebab-case", deserialize = "kebab-case"))]
pub enum Patch {
    AddPublicKeys(AddPublicKeys),
    RemovePublicKeys(RemovePublicKeys),
    AddServices(AddServices),
    RemoveServices(RemoveServices),
    Default,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DidUpdatePayload {
    pub update_type: String,
    pub update_key: Option<PublicKeyJWK>,
    pub recovery_key: Option<PublicKeyJWK>,
    pub next_update_key: Option<PublicKeyJWK>,
    pub next_recovery_key: Option<PublicKeyJWK>,
    pub patches: Option<Vec<Patch>>,
}
