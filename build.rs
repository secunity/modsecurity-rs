//! Links the system C libraries that the optional features bind to
//! directly (the C++ build linked the same libraries).

fn main() {
    // Same SONAME as the C++ library (libtool -version-info 3:17:0), so the
    // cdylib is a drop-in replacement for libmodsecurity.so.3.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libmodsecurity.so.3");
    }
    if std::env::var_os("CARGO_FEATURE_LIBXML2").is_some() {
        println!("cargo:rustc-link-lib=xml2");
    }
    if std::env::var_os("CARGO_FEATURE_SSDEEP").is_some() {
        println!("cargo:rustc-link-lib=fuzzy");
    }
}
