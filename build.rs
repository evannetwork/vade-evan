use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use serde_derive::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
struct Package {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct LockFile {
    package: Vec<Package>,
}

fn main() {
    let lock_path = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("Cargo.lock");
    let lock_content = std::fs::read_to_string(lock_path).unwrap();
    let lock_object: LockFile = toml::from_str(&lock_content).unwrap();
    let relevant_packages: Vec<Package> = lock_object
        .package
        .into_iter()
        .filter(|package| package.name.starts_with("vade-"))
        .collect();
    let filtered_lock_file = LockFile {
        package: relevant_packages,
    };
    println!("{}", &toml::to_string(&filtered_lock_file).unwrap());

    let dest_path = Path::new(&env::var("OUT_DIR").unwrap()).join("build_info.txt");
    let mut f = BufWriter::new(File::create(&dest_path).unwrap());

    // variable might be needlessly mutable due to the following feature listing not matching
    #[allow(unused_mut)]
    let mut output = toml::to_string(&filtered_lock_file).unwrap();

    #[cfg(feature = "default")]
    output.push_str(&format!("\n{}", "default"));
    #[cfg(feature = "bundle-default")]
    output.push_str(&format!("\n{}", "default"));
    #[cfg(feature = "bundle-sdk")]
    output.push_str(&format!("\n{}", "bundle-sdk"));
    #[cfg(feature = "plugin-vade-signer")]
    output.push_str(&format!("\n{}", "plugin-vade-signer"));
    #[cfg(feature = "plugin-did-sidetree")]
    output.push_str(&format!("\n{}", "plugin-did-sidetree"));
    #[cfg(feature = "plugin-did-substrate")]
    output.push_str(&format!("\n{}", "plugin-did-substrate"));
    #[cfg(feature = "plugin-didcomm")]
    output.push_str(&format!("\n{}", "plugin-didcomm"));
    #[cfg(feature = "plugin-jwt-vc")]
    output.push_str(&format!("\n{}", "plugin-jwt-vc"));
    #[cfg(feature = "plugin-vc-zkp-bbs")]
    output.push_str(&format!("\n{}", "plugin-vc-zkp-bbs"));
    #[cfg(feature = "capability-didcomm")]
    output.push_str(&format!("\n{}", "capability-didcomm"));
    #[cfg(feature = "capability-did-read")]
    output.push_str(&format!("\n{}", "capability-did-read"));
    #[cfg(feature = "capability-did-write")]
    output.push_str(&format!("\n{}", "capability-did-write"));
    #[cfg(feature = "capability-sdk")]
    output.push_str(&format!("\n{}", "capability-sdk"));
    #[cfg(feature = "capability-vc-zkp")]
    output.push_str(&format!("\n{}", "capability-vc-zkp"));
    #[cfg(feature = "capability-target-c-lib")]
    output.push_str(&format!("\n{}", "capability-target-c-lib"));
    #[cfg(feature = "capability-target-cli")]
    output.push_str(&format!("\n{}", "capability-target-cli"));
    #[cfg(feature = "capability-target-java-lib")]
    output.push_str(&format!("\n{}", "capability-target-java-lib"));
    #[cfg(feature = "capability-target-wasm")]
    output.push_str(&format!("\n{}", "capability-target-wasm"));

    write!(f, "{}", &output).unwrap();
}
