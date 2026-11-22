//! The `t:utf8toUnicode` transformation: replaces each UTF-8 encoded
//! non-ASCII character with `%uHHHH`.

/// Appends `%u` followed by the code point in lowercase hex, zero padded to
/// (at least) four digits.
fn push_code_point(data: &mut Vec<u8>, d: u32) {
    data.extend_from_slice(format!("%u{d:04x}").as_bytes());
}

/// The code point of the `len` byte UTF-8 sequence (2 to 4 bytes, by its
/// lead byte) at the start of `bytes`; `None` when `bytes` is shorter or a
/// continuation byte does not start with binary 10. Overlong forms,
/// surrogates and values above U+10FFFF are decoded too.
fn decode_sequence(bytes: &[u8], len: usize) -> Option<u32> {
    let sequence = bytes.get(..len)?;
    let lead_bits = 0x7f >> len;
    sequence[1..].iter().try_fold(u32::from(sequence[0] & lead_bits), |d, &c| {
        (c & 0xC0 == 0x80).then_some(d << 6 | u32::from(c & 0x3F))
    })
}

fn encode(value: &mut Vec<u8>) {
    let input = std::mem::take(value);
    let mut data: Vec<u8> = Vec::with_capacity(input.len() * 4 + 1);

    let mut i = 0usize;
    while i < input.len() {
        let c = input[i];
        // The length of the sequence by its lead byte (RFC 3629).
        let len = match c {
            0x00..=0x7F => 1,
            0xC0..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF7 => 4,
            // A continuation byte or a byte UTF-8 never uses: copied.
            _ => 0,
        };
        if len <= 1 {
            // A byte that is not the lead byte of a sequence is copied.
            // Known quirk: a NUL that is not the last byte is dropped.
            if !(c == 0 && i + 1 < input.len()) {
                data.push(c);
            }
            i += 1;
            continue;
        }
        // A lead byte beyond U+10FFFF is copied (and the sequence decoded).
        if c >= 0xF5 {
            data.push(c);
        }
        let Some(d) = decode_sequence(&input[i..], len) else {
            // Missing or invalid continuation bytes: the lead byte is
            // dropped, and the bytes after it are read on their own.
            i += 1;
            continue;
        };
        push_code_point(&mut data, d);
        // A surrogate (not a character), or an overlong form (fewer bytes
        // would do): the lead byte is also copied after it.
        if (0xD800..=0xDFFF).contains(&d) {
            data.push(c);
        }
        let shortest = match len {
            2 => 0x80,
            3 => 0x800,
            _ => 0x10000,
        };
        if d < shortest {
            data.push(c);
        }
        i += len;
    }

    *value = data;
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    encode(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        encode(&mut v);
        v
    }

    #[test]
    fn encodes() {
        assert_eq!(run("aé€😀".as_bytes()), b"a%u00e9%u20ac%u1f600");
        assert_eq!(run(b"plain"), b"plain");
        // NUL inside the value is dropped, a final NUL is kept
        assert_eq!(run(b"a\0b\0"), b"ab\0");
        // truncated / invalid sequences produce nothing for the lead byte
        assert_eq!(run(b"ab\xc3"), b"ab");
        assert_eq!(run(b"\xc3("), b"(");
        // overlong encodings also copy the lead byte
        assert_eq!(run(b"\xc0\xaf"), b"%u002f\xc0");
        // invalid first byte copied as is
        assert_eq!(run(b"\xff"), b"\xff");
    }

    #[test]
    fn surrogates_also_copy_the_lead_byte() {
        assert_eq!(run(b"\xed\xa0\x80"), b"%ud800\xed");
    }

    #[test]
    fn lead_bytes_beyond_u10ffff_are_copied_and_decoded() {
        assert_eq!(run(b"\xf5\x80\x80\x80"), b"\xf5%u140000");
    }

    #[test]
    fn stray_continuation_bytes_are_copied() {
        assert_eq!(run(b"a\x80b"), b"a\x80b");
        assert_eq!(run(b""), b"");
    }
}
