cfg_if::cfg_if! {
    if #[cfg(not(all(feature = "target-c-lib", feature = "target-c-sdk")))] {
        use anyhow::Result;
        use vade_evan::{VadeEvan, VadeEvanConfig};

        #[test]
        #[cfg(not(all(feature = "target-c-lib", feature = "target-c-sdk")))]
        fn can_get_version_info() -> Result<()> {
            let vade_evan = VadeEvan::new(VadeEvanConfig {
                target: "test",
                signer: "remote|http://127.0.0.1:7070/key/sign",
            })?;
            let version_info = vade_evan.get_version_info();

            assert!(version_info.contains("vade-evan"));

            Ok(())
        }
    } else {
        // currently no example for target-c-sdk and target-c-lib/target-java-lib
    }
}
