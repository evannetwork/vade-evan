use ursa::cl::{
  CredentialPublicKey,
  CredentialKeyCorrectnessProof
};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::crypto::crypto_datatypes::AssertionProof;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDefinition {
  pub id: String,
  pub r#type: String,
  pub issuer: String,
  pub schema: String,
  pub created_at: String,
  pub public_key: CredentialPublicKey,
  pub public_key_correctness_proof: CredentialKeyCorrectnessProof,
  pub proof: Option<AssertionProof>
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
  pub id: String,
  pub r#type: String,
  pub name: String,
  pub author: String,
  pub created_at: String,
  pub description: String,
  pub properties: HashMap<String, SchemaProperty>,
  pub required: Vec<String>,
  pub additional_properties: bool,
  pub proof: Option<AssertionProof>
}

// TODO: More supported fields?
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaProperty {
  pub r#type: String,
  pub format: Option<String>,
  pub items: Option<Vec<String>>
}
