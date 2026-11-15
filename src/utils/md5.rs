//! MD5 digests.

use crate::utils::sha1::DigestImpl;

/// MD5 digests (`hexdigest`).
pub type Md5 = DigestImpl<::md5::Md5>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_digests() {
        assert_eq!(Md5::hexdigest(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(Md5::hexdigest(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }
}
