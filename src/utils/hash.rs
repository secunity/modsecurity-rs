//! MD5 and SHA-1 digests as hexadecimal text (the `md-5` and `sha1`
//! crates; C++ uses mbedtls).

use ::sha1::Digest;

use crate::utils::string::string_to_hex;

/// The MD5 digest of `input`, in lowercase hexadecimal.
pub fn md5_hex(input: &[u8]) -> String {
    string_to_hex(&::md5::Md5::digest(input))
}

/// The SHA-1 digest of `input`, in lowercase hexadecimal.
pub fn sha1_hex(input: &[u8]) -> String {
    string_to_hex(&::sha1::Sha1::digest(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }
}
