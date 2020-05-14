use serde_json::Value;
use data_encoding::BASE64URL;
use sha2::{Digest, Sha256};
use secp256k1::{Message, Signature, SecretKey, sign};
use std::convert::TryInto;
use chrono::Utc;
use crate::crypto::crypto_datatypes::AssertionProof;
/// Creates proof for VC document
///
/// # Arguments
///
/// * `vc` - vc to create proof for
/// * `verification_method` - issuer of VC
/// * `private_key` - private key to create proof as 32B hex string
/// * `now` - timestamp of issuing, may have also been used to determine `validFrom` in VC
pub fn create_assertion_proof(
  document_to_sign: &Value,
  verification_method: &str,
  issuer: &str,
  private_key: &str
) -> Result<AssertionProof, Box<dyn std::error::Error>> {
  // create to-be-signed jwt
  let header_str = r#"{"typ":"JWT","alg":"ES256K-R"}"#;
  let padded = BASE64URL.encode(header_str.as_bytes());
  let header_encoded = padded.trim_end_matches('=');
  debug!("header base64 url encdoded: {:?}", &header_encoded);

  let now = Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
  // build data object and hash
  let mut data_json: Value = serde_json::from_str("{}").unwrap();
  let doc_clone: Value = serde_json::from_str(&format!("{}", &document_to_sign)).unwrap();
  data_json["iat"] = Value::from(now.clone());
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
  let jws: String = format!("{}.{}", &header_and_data, sig_base64url);
  let utc_now: String = format!("{}", &now);

  let proof = AssertionProof {
    r#type: "EcdsaPublicKeySecp256k1".to_string(),
    created: utc_now.to_string(),
    proof_purpose: "assertionMethod".to_string(),
    verification_method: verification_method.to_string(),
    jws: jws.to_string()
  };

  Ok(proof)
}
