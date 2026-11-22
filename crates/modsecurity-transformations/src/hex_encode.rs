//! The `t:hexEncode` transformation: encodes every byte as two lowercase
//! hex digits.

use crate::chars::string_to_hex;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    if value.is_empty() {
        return;
    }
    *value = string_to_hex(value).into_bytes();
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
    fn encodes_lowercase() {
        assert_eq!(run(b"AB"), b"4142");
        assert_eq!(run(b"\0\xff\n"), b"00ff0a");
        assert_eq!(run(b""), b"");
    }

    /// `t:hexDecode` reverses it, for every byte value.
    #[test]
    fn round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        let mut v = all.clone();
        transform(&mut v);
        assert_eq!(v.len(), 512);
        crate::hex_decode::transform(&mut v);
        assert_eq!(v, all);
    }
}
