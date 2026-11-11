//! Port of `src/utils/md5.h`.

use crate::utils::sha1::DigestImpl;

/// `Utils::Md5` (`DigestImpl<MBEDTLS_MD_MD5, 16>`): provides `digest`,
/// `digest_replace` and `hexdigest`.
pub type Md5 = DigestImpl<::md5::Md5>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_digests() {
        assert_eq!(Md5::hexdigest(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(Md5::hexdigest(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        let mut v = b"abc".to_vec();
        assert!(Md5::digest_replace(&mut v));
        assert_eq!(v.len(), 16);
    }
}
