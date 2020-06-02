extern crate vade_tnt;

use vade_tnt::crypto::crypto_issuer::Issuer as CryptoIssuer;
use vade_tnt::application::datatypes::{
  CredentialSchema
};
use vade_tnt::crypto::crypto_datatypes::CryptoCredentialDefinition;
use std::collections::HashMap;

const EXAMPLE_CREDENTIAL_SCHEMA: &str = r###"
{
  "id": "did:evan:zkp:0x123451234512345123451234512345",
  "type": "EvanVCSchema",
  "name": "test_schema",
  "author": "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD1",
  "createdAt": "2020-05-19T12:54:55.000Z",
  "description": "Test description",
  "properties": {
    "test_property_string3": {
      "type": "string"
    },
    "test_property_string": {
      "type": "string"
    },
    "test_property_string2": {
      "type": "string"
    }
  },
  "required": [
    "test_property_string"
  ],
  "additionalProperties": false,
  "proof": {
    "type": "EcdsaPublicKeySecp256k1",
    "created": "2020-05-19T12:54:55.000Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "null",
    "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIwLTA1LTE5VDEyOjU0OjU1LjAwMFoiLCJkb2MiOnsiaWQiOiJkaWQ6ZXZhbjp6a3A6MHgxMjM0NTEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUiLCJ0eXBlIjoiRXZhblZDU2NoZW1hIiwibmFtZSI6InRlc3Rfc2NoZW1hIiwiYXV0aG9yIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwRjczN0QxNDc4ZUEyOWRmMDg1NjE2OUYyNWNBOTEyOTAzNWQ2RkQxIiwiY3JlYXRlZEF0IjoiMjAyMC0wNS0xOVQxMjo1NDo1NS4wMDBaIiwiZGVzY3JpcHRpb24iOiJUZXN0IGRlc2NyaXB0aW9uIiwicHJvcGVydGllcyI6eyJ0ZXN0X3Byb3BlcnR5X3N0cmluZyI6eyJ0eXBlIjoic3RyaW5nIn19LCJyZXF1aXJlZCI6WyJ0ZXN0X3Byb3BlcnR5X3N0cmluZyJdLCJhZGRpdGlvbmFsUHJvcGVydGllcyI6ZmFsc2V9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBGNzM3RDE0NzhlQTI5ZGYwODU2MTY5RjI1Y0E5MTI5MDM1ZDZGRDEifQ.byfS5tIbnCN1M4PtfQQ9mq9mR2pIzgmBFoFNrGkINJBDVxPmKC2S337a2ulytG0G9upyAuOWVMBXESxQdF_MjwA"
  }
}
"###;

const EXAMPLE_CREDENTIAL_REQUEST: &str = r###"
{
  "subject": "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD2",
  "schema": "did:evan:zkp:0x123451234512345123451234512345",
  "credentialDefinition": "did:evan:zkp:0x123451234512345123451234512345",
  "type": "EvanZKPCredentialRequest",
  "blindedCredentialSecrets": {
      "u": "6527159286600476559402178891655562018360618432629077684841720887750736928668",
      "ur": null,
      "hidden_attributes": [
          "master_secret"
      ],
      "committed_attributes": {}
  },
  "blindedCredentialSecretsCorrectnessProof": {
      "c": "20367386172788628583581069979288777258265803702946855889190379363849341845166",
      "v_dash_cap": "491177763583491559808486489703842856342767973286443989062768943330151352838050114414255462283695004743450877509654921378756796669125909766564305702585600162853199189289552638456020713036307862969161096208829846573757972073791042145848708928121936753318602031396813436958294823382209950146543029344969929905748687702691359547489610201790287205471032807678974485854264374426982368821115702113686665285760835685172498644244381190256480344348645302061302006125108454133743291872472504260422933970828133271841396383988509371788718400831004534763069155659262079567468481268325756790827527338608794428865699403357206966982248717794002993196670828203994490406725253253779933320146273553341258416422363677758621398519638420838",
      "m_caps": {
          "master_secret": "5955930818414064981207717169543227399772053787483739176659140671900500137916435258512100166903365525939593833313139138384037878047223105397196528505914648748132898389178680597321"
      },
      "r_caps": {}
  },
  "credentialNonce": "372984590589467876940550",
  "credentialValues": {
      "key1": {
          "raw": "value1",
          "encoded": "27404702143883897701950953229849815393032792099783647152371385368148256400014"
      }
  }
}
"###;

const EXAMPLE_PRIVATE_KEY: &str = "d02f8a67f22ae7d1ffc5507ca9a4e6548024562a7b36881b7a29f66dd26c532e";

#[test]
fn can_create_credential_definition() {
  let credential_schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
  let def: CryptoCredentialDefinition = CryptoIssuer::create_credential_definition(&credential_schema).1;

  // Cannot access p_key.r because it is private, therefore serialize it
  let r_component_str = serde_json::to_string(&serde_json::to_value(&def.public_key).unwrap()["p_key"]["r"]).unwrap(); // :(
  let r_component: HashMap<String, String> = serde_json::from_str(&r_component_str).unwrap();

  for key in credential_schema.properties.keys() {
    assert_eq!(r_component.contains_key(key), true);
  }
}
