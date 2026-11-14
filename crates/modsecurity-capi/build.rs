//! Gives the C library the SONAME of the C++ one.

fn main() {
    // Same SONAME as the C++ library (libtool -version-info 3:17:0), so the
    // cdylib is a drop-in replacement for libmodsecurity.so.3.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libmodsecurity.so.3");
    }
}
