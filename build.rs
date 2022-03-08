// Custom build script.
fn main() {
    // Tell Cargo to search particular directory for library dependency
    println!("cargo:rustc-link-search=builds/c");
    println!("cargo:rustc-link-lib=request_list");
}