//! `utils` (mirrors `src/utils/`).

pub mod acmp;
pub mod base64;
pub mod decode;
// MaxMind.
#[allow(unsafe_code)]
pub mod geo_lookup;
// curl.
#[allow(unsafe_code)]
pub mod https_client;
pub mod ip_tree;
pub mod json;
#[cfg(feature = "libxml2")]
// libxml2.
#[allow(unsafe_code)]
pub mod libxml2;
pub mod md5;
pub mod msc_tree;
pub mod random;
// PCRE2.
#[allow(unsafe_code)]
pub mod regex;
pub mod sha1;
pub mod shared_files;
pub mod string;
// libc.
#[allow(unsafe_code)]
pub mod system;
pub mod unordered_multimap;
