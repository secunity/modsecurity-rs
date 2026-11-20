//! The `t:urlDecodeUni` transformation: URL decoding that also decodes
//! IIS-style `%uHHHH` sequences, through the `SecUnicodeMapFile` map when
//! one is configured.

use crate::UnicodeMap;
use crate::chars::x2c;

fn inplace(input: &mut Vec<u8>, map: Option<&UnicodeMap>) {
    let input_len = input.len();
    let mut d = 0usize;
    let mut i = 0usize;

    while i < input_len {
        if input[i] == b'%' {
            if i + 1 < input_len && (input[i + 1] == b'u' || input[i + 1] == b'U') {
                // Character is a percent sign.
                // IIS-specific %u encoding.
                if i + 5 < input_len {
                    // We have at least 4 data bytes.
                    if input[i + 2].is_ascii_hexdigit()
                        && input[i + 3].is_ascii_hexdigit()
                        && input[i + 4].is_ascii_hexdigit()
                        && input[i + 5].is_ascii_hexdigit()
                    {
                        // The byte the map gives for the code point, if any.
                        let code = std::str::from_utf8(&input[i + 2..i + 6])
                            .ok()
                            .and_then(|h| u16::from_str_radix(h, 16).ok());
                        let hmap = map.zip(code).and_then(|(map, code)| map.get(code));

                        if let Some(byte) = hmap {
                            input[d] = byte;
                        } else {
                            // We first make use of the lower byte here,
                            // ignoring the higher byte.
                            let mut c = x2c(&input[i + 4..i + 6]);

                            // Full width ASCII (ff01 - ff5e)
                            // needs 0x20 added
                            if c > 0x00
                                && c < 0x5f
                                && (input[i + 2] == b'f' || input[i + 2] == b'F')
                                && (input[i + 3] == b'f' || input[i + 3] == b'F')
                            {
                                c += 0x20;
                            }
                            input[d] = c;
                        }
                        d += 1;
                        i += 6;
                    } else {
                        // Invalid data, skip %u.
                        input[d] = input[i];
                        input[d + 1] = input[i + 1];
                        d += 2;
                        i += 2;
                    }
                } else {
                    // Not enough bytes (4 data bytes), skip %u.
                    input[d] = input[i];
                    input[d + 1] = input[i + 1];
                    d += 2;
                    i += 2;
                }
            } else {
                // Standard URL encoding.

                // Are there enough bytes available?
                if i + 2 < input_len {
                    // Yes.

                    // Decode a %xx combo only if it is valid.
                    let c1 = input[i + 1];
                    let c2 = input[i + 2];

                    if c1.is_ascii_hexdigit() && c2.is_ascii_hexdigit() {
                        input[d] = x2c(&input[i + 1..i + 3]);
                        d += 1;
                        i += 3;
                    } else {
                        // Not a valid encoding, skip this %
                        input[d] = input[i];
                        d += 1;
                        i += 1;
                    }
                } else {
                    // Not enough bytes available, skip this %
                    input[d] = input[i];
                    d += 1;
                    i += 1;
                }
            }
        } else {
            // Character is not a percent sign.
            if input[i] == b'+' {
                input[d] = b' ';
            } else {
                input[d] = input[i];
            }
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
