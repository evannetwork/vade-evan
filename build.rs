use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use serde_derive::{Deserialize, Serialize};

macro_rules! append_features {
    ( $output:ident, $( $feature:expr ),* ) => {
        {
            $output.push_str("\n[features]");
            $(
                #[cfg(feature = $feature)]
                $output.push_str(&format!("\n{}", $feature));
            )*
        }
    };
}

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

    append_features![
        output,
        "default",
        "bundle-default",
        "bundle-sdk",
        "plugin-did-sidetree",
        "plugin-did-substrate",
        "plugin-didcomm",
        "plugin-jwt-vc",
        "plugin-signer",
        "plugin-vc-zkp-bbs",
        "capability-didcomm",
        "capability-did-read",
        "capability-did-write",
        "capability-sdk",
        "capability-vc-zkp",
        "capability-target-c-lib",
        "capability-target-cli",
        "capability-target-java-lib",
        "capability-target-wasm"
    ];

    write!(f, "{}", &output).unwrap();
}
