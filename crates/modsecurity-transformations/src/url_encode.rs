//! The `t:urlEncode` transformation: URL-encodes the value (a space
//! becomes `+`).

use crate::chars::c2x;

fn url_enc(value: &mut Vec<u8>) {
    let mut ret = Vec::with_capacity(value.len() * 3 + 1);

    // ENH Only encode the characters that really need to be encoded.
    for &c in value.iter() {
        if c == b' ' {
            ret.push(b'+');
        } else if c == b'*' || c.is_ascii_digit() || c.is_ascii_uppercase() || c.is_ascii_lowercase() {
            ret.push(c);
        } else {
            ret.push(b'%');
            c2x(u32::from(c), &mut ret);
        }
    }

    *value = ret;
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    url_enc(value);
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
    fn keeps_letters_digits_and_star() {
        assert_eq!(run(b"azAZ09*"), b"azAZ09*");
        assert_eq!(run(b""), b"");
    }

    #[test]
    fn a_space_becomes_plus() {
        assert_eq!(run(b"a b"), b"a+b");
    }

    #[test]
    fn everything_else_is_percent_encoded_in_lowercase() {
        assert_eq!(run(b"a/b?c=d&e"), b"a%2fb%3fc%3dd%26e");
        assert_eq!(run(b"-_.~+%"), b"%2d%5f%2e%7e%2b%25");
        assert_eq!(run(b"\0\xff"), b"%00%ff");
    }

    /// `t:urlDecode` reverses it, for every byte value.
    #[test]
    fn round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        let mut v = all.clone();
        transform(&mut v);
        crate::url::urldecode_nonstrict_inplace(&mut v);
        assert_eq!(v, all);
    }
}
