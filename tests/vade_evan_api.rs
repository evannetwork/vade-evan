use anyhow::Result;
use vade_evan::{VadeEvan, VadeEvanConfig};

#[test]
fn can_get_version_info() -> Result<()> {
    let vade_evan = VadeEvan::new(VadeEvanConfig {
        target: "test",
        signer: "remote|http://127.0.0.1:7070/key/sign",
    })?;
    let version_info = vade_evan.get_version_info();

    assert!(version_info.contains("vade-evan"));

    Ok(())
}

#[tokio::test]
async fn can_create_credential_request() -> Result<()> {
    let mut vade_evan = VadeEvan::new(VadeEvanConfig {
        target: "test",
        signer: "remote|http://127.0.0.1:7070/key/sign",
    })?;
    let credential_offer = r#"{
        "issuer": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906",
        "subject": "did:any:abc",
        "nonce": "QqJR4o6joiApYVXX7JLbRIZBQ9QprlFpewo8GbojIKY=",
        "credentialMessageCount": 2
    }"#;
    let bbs_secret = r#""OASkVMA8q6b3qJuabvgaN9K1mKoqptCv4SCNvRmnWuI=""#;
    let credential_values = r#"{
        "test_property_string": "value"
    }"#;
    let issuer_pub_key = r#""jCv7l26izalfcsFe6j/IqtVlDolo2Y3lNld7xOG63GjSNHBVWrvZQe2O859q9JeVEV4yXtfYofGQSWrMVfgH5ySbuHpQj4fSgLu4xXyFgMidUO1sIe0NHRcXpOorP01o""#;
    let credential_schema = r#"{
        "id": "did:evan:zkp:0x03d57c17c1202a0c859bc45afb0b102bcfe73ba51be137095fd3d70c91b68e03",
        "type": "EvanVCSchema",
        "name": "test_schema",
        "author": "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "createdAt": "2021-11-05T08:01:00.000Z",
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
            "created": "2021-11-05T08:01:00.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
            "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIxLTExLTA1VDA4OjAxOjAwLjAwMFoiLCJkb2MiOnsiaWQiOiJkaWQ6ZXZhbjp6a3A6MHgwM2Q1N2MxN2MxMjAyYTBjODU5YmM0NWFmYjBiMTAyYmNmZTczYmE1MWJlMTM3MDk1ZmQzZDcwYzkxYjY4ZTAzIiwidHlwZSI6IkV2YW5WQ1NjaGVtYSIsIm5hbWUiOiJ0ZXN0X3NjaGVtYSIsImF1dGhvciI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4NjI0MGNlZGZjODQwNTc5YjdmZGNkNjg2YmRjNjVhOWE4YzQyZGVhNiIsImNyZWF0ZWRBdCI6IjIwMjEtMTEtMDVUMDg6MDE6MDAuMDAwWiIsImRlc2NyaXB0aW9uIjoiVGVzdCBkZXNjcmlwdGlvbiIsInByb3BlcnRpZXMiOnsidGVzdF9wcm9wZXJ0eV9zdHJpbmciOnsidHlwZSI6InN0cmluZyJ9fSwicmVxdWlyZWQiOlsidGVzdF9wcm9wZXJ0eV9zdHJpbmciXSwiYWRkaXRpb25hbFByb3BlcnRpZXMiOmZhbHNlfSwiaXNzIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg2MjQwY2VkZmM4NDA1NzliN2ZkY2Q2ODZiZGM2NWE5YThjNDJkZWE2In0.y5t411efca94-QrSrduiO4fzrMFDvfCLx77etZGNak4rGXr_yoNhU2EwCDIiX0e_kryFxv6YrB85gGnTXa3R_gA"
        }
    }"#;
    let credential_request = vade_evan
        .create_credential_request(
            issuer_pub_key,
            bbs_secret,
            credential_values,
            credential_offer,
            credential_schema,
        )
        .await?;

    println!("{}", credential_request);
    assert!(credential_request.contains("blindSignatureContext"));

    Ok(())
}
