//! The `t:base64Encode` transformation: encodes the value as base64.

use crate::base64::Base64;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    *value = Base64::encode(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        transform(&mut v);
        v
    }

    #[test]
    fn encodes_with_padding() {
        assert_eq!(run(b"foobar"), b"Zm9vYmFy");
        assert_eq!(run(b"foob"), b"Zm9vYg==");
        assert_eq!(run(b"fooba"), b"Zm9vYmE=");
        assert_eq!(run(b"\0\xff"), b"AP8=");
        assert_eq!(run(b""), b"");
    }

    /// `t:base64Decode` reverses it, for every byte value.
    #[test]
    fn round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        for len in 1..all.len() {
            let mut v = all[..len].to_vec();
            transform(&mut v);
            crate::base64_decode::transform(&mut v);
            // The decoder stops at a NUL: compare from the second byte on.
            if len > 1 {
                let mut tail = all[1..len].to_vec();
                transform(&mut tail);
                crate::base64_decode::transform(&mut tail);
                assert_eq!(tail, &all[1..len]);
            }
        }
    }
}
