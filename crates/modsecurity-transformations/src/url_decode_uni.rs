//! The `t:urlDecodeUni` transformation: URL decoding that also decodes
//! IIS-style `%uHHHH` sequences, through the `SecUnicodeMapFile` map when
//! one is configured.

use crate::UnicodeMap;
use crate::chars::hex_pair;
use crate::js_decode::low_byte_of_code_point;

fn inplace(input: &mut Vec<u8>, map: Option<&UnicodeMap>) {
    let mut d = 0usize;
    let mut i = 0usize;
    // The byte of the two hex digits at `k`.
    let hex_at = |input: &[u8], k: usize| input.get(k..).and_then(hex_pair);

    while i < input.len() {
        let c = input[i];
        if c == b'%' && matches!(input.get(i + 1), Some(b'u' | b'U')) {
            // IIS-specific %uHHHH encoding.
            if let Some(high) = hex_at(input, i + 2)
                && let Some(low) = hex_at(input, i + 4)
            {
                // The byte the map gives for the code point, or its low
                // byte.
                input[d] = map
                    .and_then(|map| map.get(u16::from_be_bytes([high, low])))
                    .unwrap_or_else(|| low_byte_of_code_point(high, low));
                d += 1;
                i += 6;
            } else {
                // Not four hex digits: `%u` is kept as it is.
                input[d] = c;
                input[d + 1] = input[i + 1];
                d += 2;
                i += 2;
            }
        } else if c == b'%' {
            // Standard URL encoding, decoded only if it is valid.
            if let Some(byte) = hex_at(input, i + 1) {
                input[d] = byte;
                i += 3;
            } else {
                input[d] = c;
                i += 1;
            }
            d += 1;
        } else {
            input[d] = if c == b'+' { b' ' } else { c };
            d += 1;
            i += 1;
        }
    }

    input.truncate(d);
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>, map: Option<&UnicodeMap>) {
    inplace(value, map);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        inplace(&mut v, None);
        v
    }

    #[test]
    fn decodes_without_a_map() {
        assert_eq!(run(b"%41+%u0042%uff21"), b"A BA");
        assert_eq!(run(b"%u00"), b"%u00");
        assert_eq!(run(b"%uzzzz"), b"%uzzzz");
        assert_eq!(run(b"%4"), b"%4");
        assert_eq!(run(b"%zz"), b"%zz");
    }

    #[test]
    fn uses_the_unicode_map() {
        let mut table = UnicodeMap::default();
        table.set(0x0391, b'A');
        let mut v = b"%u0391%u00e9%uff21".to_vec();
        inplace(&mut v, Some(&table));
        // mapped, unmapped (lower byte), unmapped full width (+0x20)
        assert_eq!(v, b"A\xe9A");

        // Without a map.
        let mut v = b"%u0391".to_vec();
        inplace(&mut v, None);
        assert_eq!(v, b"\x91");
    }
}
