pub const ISSUER_DID: &'static str = "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD1";
pub const SUBJECT_DID: &'static str = "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD2";
pub const SCHEMA_DID: &'static str = "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD3";
pub const CREDENTIAL_DEFINITION_DID: &'static str = "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD4";
pub const ISSUER_DID_DOCUMENT_STR: &str = r###"
{
  "did": {
    "@context": "https://w3id.org/did/v1",
    "id": "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1",
    "publicKey": [
      {
        "id": "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1",
        "type": "Secp256k1VerificationKey2018",
        "controller": "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1",
        "ethereumAddress": "0x775018c020ae1b3fd4e8a707f8ecfeafc9055e9d"
      }
    ],
    "authentication": [
      "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1"
    ],
    "created": "2020-05-18T11:42:06.766Z",
    "updated": "2020-05-18T11:42:06.766Z",
    "proof": {
      "type": "EcdsaPublicKeySecp256k1",
      "created": "2020-05-18T11:42:06.778Z",
      "proofPurpose": "assertionMethod",
      "verificationMethod": "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1",
      "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1ODk4MDIxMjYsImRpZERvY3VtZW50Ijp7IkBjb250ZXh0IjoiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjEiLCJpZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4MGY3MzdkMTQ3OGVhMjlkZjA4NTYxNjlmMjVjYTkxMjkwMzVkNmZkMSIsInB1YmxpY0tleSI6W3siaWQiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBmNzM3ZDE0NzhlYTI5ZGYwODU2MTY5ZjI1Y2E5MTI5MDM1ZDZmZDEja2V5LTEiLCJ0eXBlIjoiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsImNvbnRyb2xsZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBmNzM3ZDE0NzhlYTI5ZGYwODU2MTY5ZjI1Y2E5MTI5MDM1ZDZmZDEiLCJldGhlcmV1bUFkZHJlc3MiOiIweDc3NTAxOGMwMjBhZTFiM2ZkNGU4YTcwN2Y4ZWNmZWFmYzkwNTVlOWQifV0sImF1dGhlbnRpY2F0aW9uIjpbImRpZDpldmFuOnRlc3Rjb3JlOjB4MGY3MzdkMTQ3OGVhMjlkZjA4NTYxNjlmMjVjYTkxMjkwMzVkNmZkMSNrZXktMSJdLCJjcmVhdGVkIjoiMjAyMC0wNS0xOFQxMTo0MjowNi43NjZaIiwidXBkYXRlZCI6IjIwMjAtMDUtMThUMTE6NDI6MDYuNzY2WiJ9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBmNzM3ZDE0NzhlYTI5ZGYwODU2MTY5ZjI1Y2E5MTI5MDM1ZDZmZDEifQ.MBBWlq_zH5cRzlpYcc4eoX_qbg2ICG3V-MZj-5TVPzhhIAE7dJdxREQPNtBya9Rk5sWc4bItJDvOyq4hwKX66wA"
    }
  },
  "status": "success"
}
"###;
pub const EXAMPLE_CREDENTIAL_SCHEMA: &str = r###"
{
    "id": "did:evan:zkp:0x123451234512345123451234512345",
    "type": "EvanVCSchema",
    "name": "test_schema",
    "author": "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD1",
    "createdAt": "2020-05-19T12:54:55.000Z",
    "description": "Test description",
    "properties": {
        "test_property_string": {
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
pub const ISSUER_PUBLIC_KEY_DID: &str = "did:evan:testcore:0x0f737d1478ea29df0856169f25ca9129035d6fd1#key-1";
pub const ISSUER_PRIVATE_KEY: &str = "d02f8a67f22ae7d1ffc5507ca9a4e6548024562a7b36881b7a29f66dd26c532e";