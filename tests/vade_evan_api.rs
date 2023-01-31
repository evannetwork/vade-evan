use anyhow::Result;
use vade_evan::{VadeEvan, VadeEvanConfig};

const SCHEMA_DID: &str = "did:evan:EiACv4q04NPkNRXQzQHOEMa3r1p_uINgX75VYP2gaK5ADw";

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
        "email": "value@x.com"
    }"#;
    let issuer_pub_key = r#""jCv7l26izalfcsFe6j/IqtVlDolo2Y3lNld7xOG63GjSNHBVWrvZQe2O859q9JeVEV4yXtfYofGQSWrMVfgH5ySbuHpQj4fSgLu4xXyFgMidUO1sIe0NHRcXpOorP01o""#;

    let credential_request = vade_evan
        .create_credential_request(
            issuer_pub_key,
            bbs_secret,
            credential_values,
            credential_offer,
            SCHEMA_DID,
        )
        .await?;

    println!("{}", credential_request);
    assert!(credential_request.contains("blindSignatureContext"));

    Ok(())
}
