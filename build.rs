//! Links the system C libraries that the optional features bind to
//! directly (the C++ build linked the same libraries).

fn main() {
    if std::env::var_os("CARGO_FEATURE_LIBXML2").is_some() {
        println!("cargo:rustc-link-lib=xml2");
    }
    if std::env::var_os("CARGO_FEATURE_SSDEEP").is_some() {
        println!("cargo:rustc-link-lib=fuzzy");
    }
}
