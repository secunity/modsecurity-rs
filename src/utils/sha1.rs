//! SHA-1 digests, and the digest helpers shared with MD5.
//!
//! The C++ code computes the digests with mbedtls; here they are generic
//! over a RustCrypto [`Digest`] (the `sha1` and `md-5` crates).

use std::marker::PhantomData;

use ::sha1::Digest;

use crate::utils::string::string_to_hex;

/// The digest helpers shared by [`Sha1`] and
/// [`crate::utils::md5::Md5`].
///
/// (The C++ helpers return `false` only for a null output pointer or an
/// unknown mbedtls digest type; neither can happen here, so they return the
/// result directly.)
#[derive(Debug, Clone, Copy, Default)]
pub struct DigestImpl<D: Digest>(PhantomData<D>);

impl<D: Digest> DigestImpl<D> {
    /// The raw digest bytes of `input`.
    pub fn digest(input: &[u8]) -> Vec<u8> {
        D::digest(input).to_vec()
    }

    /// Replaces `value` with its raw digest bytes.
    pub fn digest_replace(value: &mut Vec<u8>) -> bool {
        *value = Self::digest(value);
        true
    }

    /// The lowercase hexadecimal digest of `input`.
    pub fn hexdigest(input: &[u8]) -> String {
        string_to_hex(&D::digest(input))
    }
}

/// SHA-1 digests: provides `digest`, `digest_replace` and `hexdigest`.
pub type Sha1 = DigestImpl<::sha1::Sha1>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_digests() {
        assert_eq!(Sha1::hexdigest(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(Sha1::digest(b"").len(), 20);
        let mut v = b"abc".to_vec();
        assert!(Sha1::digest_replace(&mut v));
        assert_eq!(string_to_hex(&v), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }
}
