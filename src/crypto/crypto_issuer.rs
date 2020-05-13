use ursa::cl::{
  CredentialPublicKey,
  CredentialPrivateKey,
  new_nonce,
  RevocationKeyPrivate,
  SimpleTailsAccessor
};
use ursa::cl::issuer::Issuer as CryptoIssuer;
use serde_json::{Value};
use chrono::{DateTime, Utc};
use data_encoding::BASE64URL;
use sha2::{Digest, Sha256};
use secp256k1::{Message, Signature, SecretKey, sign};
use std::convert::TryInto;
use crate::datatypes::datatypes::{
  CryptoCredentialRequest,
  CryptoCredentialDefinition,
  CredentialSchema,
  AssertionProof,
  SignedCredential,
  RevocationRegistryDefinition
};


pub struct Issuer {
}

impl Issuer {

  pub fn new() -> Issuer {
    Issuer {
    }
  }

  pub fn create_credential_definition(
    definition_issuer: String,
    credential_schema: CredentialSchema,
    include_master_secret: bool,
    issuer_private_key: String
  ) -> (CredentialPrivateKey, CryptoCredentialDefinition) {
    let mut non_credential_schema_builder = CryptoIssuer::new_non_credential_schema_builder().unwrap();
    if include_master_secret {
      non_credential_schema_builder.add_attr("master_secret").unwrap();
    }
    let non_credential_schema = non_credential_schema_builder.finalize().unwrap();

    // Retrieve property names from schema
    // TODO: Object handling, how to handle nested object properties?
    let mut credential_schema_builder = CryptoIssuer::new_credential_schema_builder().unwrap();
    for property in &credential_schema.properties {
      credential_schema_builder.add_attr(property.0).unwrap();
    }
    let crypto_schema = credential_schema_builder.finalize().unwrap();

    let (public_key, credential_private_key, credential_key_correctness_proof) =
      CryptoIssuer::new_credential_def(&crypto_schema, &non_credential_schema, false).unwrap();

    let mut definition = CryptoCredentialDefinition {
      public_key,
      credential_key_correctness_proof,
      proof: None
    };

    let doc_to_sign: Value = serde_json::to_value(&definition).unwrap();
    let proof_val = Issuer::create_proof(&doc_to_sign, "?", &issuer_private_key, &definition_issuer).unwrap();
    let proof: AssertionProof = serde_json::from_value(proof_val).unwrap();
    definition.proof = Some(proof);

    return (credential_private_key, definition);
  }

  /**
   * Creates a new ISO credential schema and stores it in the registry.
   * Returns the ID of the schema in the registry.
   */
  // pub fn create_credential_schema(
  //   schema_name: String,
  //   author: String,
  //   description: String,
  //   properties: HashMap<String, SchemaProperty>,
  //   required: Vec<String>,
  //   allow_additional_properties: bool,
  //   author_private_key: String
  // ) -> Result<CredentialSchema, Box<dyn std::error::Error>> {
  //   let created_at = Issuer::get_timestamp_now();
  //   let did = Issuer::get_new_did();
  //   let schema_type = "EvanVCSchema".to_string();
  //   let mut schema = CredentialSchema {
  //     id: did,
  //     name: schema_name,
  //     author,
  //     created_at,
  //     description,
  //     properties,
  //     required,
  //     r#type: schema_type,
  //     additional_properties: allow_additional_properties,
  //     proof: None
  //   };

  //   let doc_to_sign = serde_json::to_value(schema).unwrap();
  //   let proof_val = Issuer::create_proof(&doc_to_sign, "?", &author, &author_private_key).unwrap();
  //   let proof : AssertionProof = serde_json::from_value(proof_val).unwrap();
  //   schema.proof = Some(proof);

  //   return Ok(schema);
  // }


  pub fn sign_credential(
    credential_request: &CryptoCredentialRequest,
    credential_private_key: CredentialPrivateKey,
    credential_public_key: CredentialPublicKey
  ) -> SignedCredential {
    let credential_issuance_nonce = new_nonce().unwrap();

    let (cred, proof) = CryptoIssuer::sign_credential(&credential_request.subject,
                              &credential_request.blinded_credential_secrets,
                              &credential_request.blinded_credential_secrets_correctness_proof,
                              &credential_request.credential_nonce,
                              &credential_issuance_nonce,
                              &credential_request.credential_values,
                              &credential_public_key,
                              &credential_private_key).unwrap();
    return SignedCredential {
      signature: cred,
      correctness_proof: proof,
      issuance_nonce: credential_issuance_nonce
    }
  }

  pub fn sign_credential_with_revocation(
    credential_request: &CryptoCredentialRequest,
    credential_private_key: &CredentialPrivateKey,
    credential_public_key: &CredentialPublicKey,
    credential_revocation_definition: &mut RevocationRegistryDefinition,
    credential_revocation_id: u32,
    revocation_private_key: &RevocationKeyPrivate
  ) -> SignedCredential {
    let credential_issuance_nonce = new_nonce().unwrap();

    let tails_accessor = SimpleTailsAccessor::new(&mut credential_revocation_definition.tails).unwrap();

    // no delta because we assume issuance_by_default ==true
    let (cred, proof, _) = CryptoIssuer::sign_credential_with_revoc(
      &credential_request.subject,
      &credential_request.blinded_credential_secrets,
      &credential_request.blinded_credential_secrets_correctness_proof,
      &credential_request.credential_nonce,
      &credential_issuance_nonce,
      &credential_request.credential_values,
      credential_public_key,
      credential_private_key,
      credential_revocation_id,
      credential_revocation_definition.maximum_credential_count,
      true, // TODO: Make global var
      &mut credential_revocation_definition.registry,
      &revocation_private_key,
      &tails_accessor
    ).unwrap();

    return SignedCredential {
      signature: cred,
      correctness_proof: proof,
      issuance_nonce: credential_issuance_nonce
    };
  }

  /// Creates proof for VC document
  ///
  /// # Arguments
  ///
  /// * `vc` - vc to create proof for
  /// * `verification_method` - issuer of VC
  /// * `private_key` - private key to create proof as 32B hex string
  /// * `now` - timestamp of issuing, may have also been used to determine `validFrom` in VC
  fn create_proof(
    document_to_sign: &Value,
    verification_method: &str,
    issuer: &str,
    private_key: &str
  ) -> Result<Value, Box<dyn std::error::Error>> {
    // create to-be-signed jwt
    let header_str = r#"{"typ":"JWT","alg":"ES256K-R"}"#;
    let padded = BASE64URL.encode(header_str.as_bytes());
    let header_encoded = padded.trim_end_matches('=');
    debug!("header base64 url encdoded: {:?}", &header_encoded);

    // build data object and hash
    let mut data_json: Value = serde_json::from_str("{}").unwrap();
    let doc_clone: Value = serde_json::from_str(&format!("{}", &document_to_sign)).unwrap();
    data_json["iat"] = Value::from(Issuer::get_timestamp_now());
    data_json["doc"] = doc_clone;
    data_json["iss"] = Value::from(issuer);
    let padded = BASE64URL.encode(format!("{}", &data_json).as_bytes());
    let data_encoded = padded.trim_end_matches('=');
    debug!("data base64 url encdoded: {:?}", &data_encoded);

    // create hash of data (including header)
    let header_and_data = format!("{}.{}", header_encoded, data_encoded);
    let mut hasher = Sha256::new();
    hasher.input(&header_and_data);
    let hash = hasher.result();
    debug!("header_and_data hash {:?}", hash);

    // sign this hash
    let hash_arr: [u8; 32] = hash.try_into().expect("slice with incorrect length");
    let message = Message::parse(&hash_arr);
    let mut private_key_arr = [0u8; 32];
    hex::decode_to_slice(&private_key, &mut private_key_arr).expect("private key invalid");
    let secret_key = SecretKey::parse(&private_key_arr)?;
    let (sig, rec): (Signature, _) = sign(&message, &secret_key);
    // sig to bytes (len 64), append recoveryid
    let signature_arr = &sig.serialize();
    let mut sig_and_rec: [u8; 65] = [0; 65];
    for i in 0..64 {
        sig_and_rec[i] = signature_arr[i];
    }
    sig_and_rec[64] = rec.serialize();
    let padded = BASE64URL.encode(&sig_and_rec);
    let sig_base64url = padded.trim_end_matches('=');
    debug!("signature base64 url encdoded: {:?}", &sig_base64url);

    // build proof property as serde object
    let jws = format!("{}.{}", &header_and_data, sig_base64url);
    let utc_now = format!("{}", Issuer::get_timestamp_now());
    let proof_json_str = format!(r###"{{
        "type": "EcdsaPublicKeySecp256k1",
        "created": "{}",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "{}",
        "jws": "{}"
    }}"###, &utc_now, &verification_method, &jws);
    let proof: Value = serde_json::from_str(&proof_json_str).unwrap();

    Ok(proof)
  }

  fn get_timestamp_now() -> String {
    let now: DateTime<Utc> = Utc::now();
    return now.format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
  }

}
