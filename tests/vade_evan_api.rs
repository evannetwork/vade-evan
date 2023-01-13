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
