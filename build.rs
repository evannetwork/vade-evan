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

    write!(f, "{}", toml::to_string(&filtered_lock_file).unwrap()).unwrap();
}
