/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#[allow(dead_code)]
pub mod accounts {
    pub mod local {
        #[allow(dead_code)]
        pub const ISSUER_ADDRESS: &str = "0xd2787429c2a5d88662a8c4af690a4479e0199c5e";

        #[allow(dead_code)]
        pub const ISSUER_DID: &str = "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6";

        #[allow(dead_code)]
        pub const ISSUER_PRIVATE_KEY: &str =
            "30d446cc76b19c6eacad89237d021eb2c85144b61d63cb852aee09179f460920";

        #[allow(dead_code)]
        pub const ISSUER_PUBLIC_KEY_DID: &str =
            "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1";

        #[allow(dead_code)]
        pub const SIGNER_1_ADDRESS: &str = "0xcd5e1dbb5552c2baa1943e6b5f66d22107e9c05c";

        #[allow(dead_code)]
        pub const SIGNER_1_DID: &str =
            "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906";

        #[allow(dead_code)]
        pub const SIGNER_1_DID_DOCUMENT_JWS: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1OTM0OTg0MjYsImRpZERvY3VtZW50Ijp7IkBjb250ZXh0IjoiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjEiLCJpZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4MGQ4NzIwNGMzOTU3ZDczYjY4YWUyOGQwYWY5NjFkM2M3MjQwMzkwNiIsInB1YmxpY0tleSI6W3siaWQiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYja2V5LTEiLCJ0eXBlIjoiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsImNvbnRyb2xsZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYiLCJldGhlcmV1bUFkZHJlc3MiOiIweGNkNWUxZGJiNTU1MmMyYmFhMTk0M2U2YjVmNjZkMjIxMDdlOWMwNWMifV0sImF1dGhlbnRpY2F0aW9uIjpbImRpZDpldmFuOnRlc3Rjb3JlOjB4MGQ4NzIwNGMzOTU3ZDczYjY4YWUyOGQwYWY5NjFkM2M3MjQwMzkwNiNrZXktMSJdLCJjcmVhdGVkIjoiMjAyMC0wMy0yNFQwODozMToxMi4zODBaIiwidXBkYXRlZCI6IjIwMjAtMDYtMzBUMDY6Mjc6MDYuNzAxWiJ9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYifQ._fBhoqongCEZBizR508XHUtBWtbHs0y440-BihDNp7qfWizGFINXgALPRoaSe5-rwsTSpD3L23H-VUSOQyibqAA";

        #[allow(dead_code)]
        pub const SIGNER_1_PRIVATE_KEY: &str =
            "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106";

        #[allow(dead_code)]
        pub const SIGNER_2_DID: &str =
            "did:evan:testcore:0xc88d707c2436fa3ce4a1e52d751469acae689fdb";

        #[allow(dead_code)]
        pub const SIGNER_2_PRIVATE_KEY: &str =
            "16bd56948ba09a626551b3f39093da305b347ef4ef2182b2e667dfa5aaa0d4cd";
    }

    pub mod remote {
        #[allow(dead_code)]
        pub const SIGNER_1_PRIVATE_KEY: &str = "a1c48241-5978-4348-991e-255e92d81f1e";

        #[allow(dead_code)]
        pub const SIGNER_1_SIGNED_MESSAGE_HASH: &str =
            "0x52091d1299031b18c1099620a1786363855d9fcd91a7686c866ad64f83de13ff";
    }
}

#[allow(dead_code)]
pub mod did {
    #[allow(dead_code)]
    pub const EXAMPLE_DID_1: &str = "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901";

    #[allow(dead_code)]
    pub const EXAMPLE_DID_DOCUMENT_1: &str = r###"{
        "@context": "https://w3id.org/did/v1",
        "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901",
        "publicKey": [
            {
                "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1",
                "type": "Secp256k1VerificationKey2018",
                "controller": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906",
                "ethereumAddress": "0xcd5e1dbb5552c2baa1943e6b5f66d22107e9c05c"
            }
        ],
        "authentication": [
            "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1"
        ],
        "created": "2011-11-11T11:11:11.111Z",
        "updated": "2011-11-11T11:11:11.111Z"
    }"###;

    #[allow(dead_code)]
    pub const EXAMPLE_DID_DOCUMENT_2: &str = r###"{
        "@context": "https://w3id.org/did/v1",
        "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403902",
        "publicKey": [
            {
                "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1",
                "type": "Secp256k1VerificationKey2018",
                "controller": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906",
                "ethereumAddress": "0xcd5e1dbb5552c2baa1943e6b5f66d22107e9c05c"
            }
        ],
        "authentication": [
            "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1"
        ],
        "created": "2022-22-22T22:22:22.222Z",
        "updated": "2022-22-22T22:22:22.222Z"
    }"###;
}

#[allow(dead_code)]
pub mod environment {
    #[allow(dead_code)]
    pub const DEFAULT_VADE_EVAN_SIGNING_URL: &str =
        "https://tntkeyservices-c43a.azurewebsites.net/key/sign";

    #[allow(dead_code)]
    pub const DEFAULT_VADE_EVAN_SUBSTRATE_IP: &str = "13.69.59.185";
}

#[allow(dead_code)]
pub mod vc_zkp {
    #[allow(dead_code)]
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
    }"###;

    #[allow(dead_code)]
    pub const EXAMPLE_REVOCATION_REGISTRY_DEFINITION_DID: &str =
        "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD2";

    #[allow(dead_code)]
    pub const SCHEMA_DESCRIPTION: &str = "Test description";

    #[allow(dead_code)]
    pub const SCHEMA_NAME: &str = "test_schema";

    #[allow(dead_code)]
    pub const SCHEMA_PROPERTIES: &str = r###"{
        "test_property_string": {
            "type": "string"
        }
    }"###;

    #[allow(dead_code)]
    pub const SCHEMA_PROPERTIES_EXTENDED: &str = r###"{
        "test_property_string": {
            "type": "string"
        },
        "test_property_string2": {
            "type": "string"
        }
    }"###;

    #[allow(dead_code)]
    pub const SCHEMA_PROPERTIES_MORE_EXTENDED: &str = r###"{
        "test_property_string": {
            "type": "string"
        },
        "test_property_string2": {
            "type": "string"
        },
        "test_property_string3": {
            "type": "string"
        }
    }"###;

    #[allow(dead_code)]
    pub const SCHEMA_REQUIRED_PROPERTIES: &str = r###"[
        "test_property_string"
    ]"###;

    #[allow(dead_code)]
    pub const SUBJECT_DID: &str = "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD2";
}
