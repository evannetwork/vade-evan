use serde::{Serialize, Deserialize};
use serde_json::{ Value, value::RawValue };
use data_encoding::BASE64URL;
use sha2::{Digest, Sha256};
use secp256k1::{Message, Signature, recover, RecoveryId, SecretKey, sign};
use std::convert::TryInto;
use chrono::Utc;
use sha3::Keccak256;
use crate::crypto::crypto_datatypes::AssertionProof;

#[derive(Serialize, Deserialize, Debug)]
pub struct JwsData<'a> {
  #[serde(borrow)]
  pub doc: &'a RawValue,
}

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
  let doc_clone: Value = document_to_sign.clone();
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

/// Checks given Vc document.
/// A Vc document is considered as valid if returning ().
/// Resolver may throw to indicate
/// - that it is not responsible for this Vc
/// - that it considers this Vc as invalid
///
/// Currently the test `vc_id` `"test"` is accepted as valid.
///
/// # Arguments
///
/// * `vc_id` - vc_id to check document for
/// * `value` - value to check
pub fn check_assertion_proof(
  vc_document: &str,
  signer_address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
  let mut vc: Value = serde_json::from_str(vc_document)?;
  if vc["proof"].is_null() {
      debug!("vcs without a proof are considered as valid");
      Ok(())
  } else {
      debug!("checking vc document");

      // separate proof and vc document (vc document will be a Map after this)
      let vc_without_proof = vc.as_object_mut().unwrap();
      let vc_proof =  vc_without_proof.remove("proof").unwrap();

      // recover address and payload text (pure jwt format)
      let (address, decoded_payload_text) = recover_address_and_data(vc_proof["jws"].as_str().unwrap())?;

      debug!("checking if document given and document from jws are equal");
      let jws: JwsData = serde_json::from_str(&decoded_payload_text)?;
      let doc = jws.doc.get();
      // parse recovered vc document into serde Map
      let parsed_caps1: Value = serde_json::from_str(&doc)?;
      let parsed_caps1_map = parsed_caps1.as_object().unwrap();
      // compare documents
      if vc_without_proof != parsed_caps1_map {
          return Err(Box::from("recovered VC document and given VC document do not match"));
      }

      debug!("checking proof of vc document");
      let address = format!("0x{}", address);
      let key_to_use = vc_proof["verificationMethod"].as_str().unwrap();
      debug!("recovered address: {}", &address);
      debug!("key to use for verification: {}", &key_to_use);
      if address != signer_address {
          return Err(Box::from("recovered and signing given address do not match"));
      }

      debug!("vc document is valid");
      Ok(())
  }
}

/// Recovers Ethereum address of signer and data part of a jwt.
///
/// # Arguments
///
/// * `jwt` - jwt as str&
pub fn recover_address_and_data(jwt: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
  // jwt text parsing
  let split: Vec<&str> = jwt.split('.').collect();
  let (header, data, signature) = (split[0], split[1], split[2]);
  let header_and_data = format!("{}.{}", header, data);

  // recover data for later checks
  let data_decoded = match BASE64URL.decode(data.as_bytes()) {
      Ok(decoded) => decoded,
      Err(_) => match BASE64URL.decode(format!("{}=", data).as_bytes()) {
          Ok(decoded) => decoded,
          Err(_) => match BASE64URL.decode(format!("{}==", data).as_bytes()) {
              Ok(decoded) => decoded,
              Err(_) => BASE64URL.decode(format!("{}===", data).as_bytes()).unwrap(),
          },
      },
  };
  let data_string = String::from_utf8(data_decoded)?;

  // decode signature for validation
  let signature_decoded = match BASE64URL.decode(signature.as_bytes()) {
      Ok(decoded) => decoded,
      Err(_) => match BASE64URL.decode(format!("{}=", signature).as_bytes()) {
          Ok(decoded) => decoded,
          Err(_) => BASE64URL.decode(format!("{}==", signature).as_bytes()).unwrap(),
      },
  };
  debug!("signature_decoded {:?}", &signature_decoded);
  debug!("signature_decoded.len {:?}", signature_decoded.len());

  // create hash of data (including header)
  let mut hasher = Sha256::new();
  hasher.input(&header_and_data);
  let hash = hasher.result();
  debug!("header_and_data hash {:?}", hash);

  // prepare arguments for public key recovery
  let hash_arr: [u8; 32] = hash.try_into().expect("header_and_data hash invalid");
  let ctx_msg = Message::parse(&hash_arr);
  let mut signature_array = [0u8; 64];
  for i in 0..64 {
      signature_array[i] = signature_decoded[i];
  }
  // slice signature and recovery for recovery
  debug!("recovery id: {}", signature_decoded[64]);
  let ctx_sig = Signature::parse(&signature_array);
  let recovery_id = RecoveryId::parse(signature_decoded[64]).unwrap();

  // recover public key, build ethereum address from it
  let recovered_key = recover(&ctx_msg, &ctx_sig, &recovery_id).unwrap();
  let mut hasher = Keccak256::new();
  hasher.input(&recovered_key.serialize()[1..65]);
  let hash = hasher.result();
  debug!("recovered_key hash {:?}", hash);
  let address = hex::encode(&hash[12..32]);
  debug!("address 0x{}", &address);

  Ok((address, data_string))
}
