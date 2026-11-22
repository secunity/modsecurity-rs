//! URL (percent) decoding.

use crate::chars::hex_pair;

/// Decodes `val` in place, turning `+` into a space; returns the number of
/// invalid `%` encodings.
pub fn urldecode_nonstrict_inplace(val: &mut Vec<u8>) -> usize {
    urldecode_nonstrict_inplace_ext(val, true)
}

/// Decodes the `%XX` escapes of `val` in place (and `+` into a space when
/// `plus_to_space` is set). Invalid escapes are kept as they are; returns
/// how many there are.
pub fn urldecode_nonstrict_inplace_ext(val: &mut Vec<u8>, plus_to_space: bool) -> usize {
    let mut s = 0usize;
    let mut d = 0usize;
    let mut invalid_count = 0;
    while s < val.len() {
        let c = val[s];
        if c == b'%' {
            if let Some(byte) = hex_pair(&val[s + 1..]) {
                val[d] = byte;
                s += 3;
            } else {
                val[d] = c;
                s += 1;
                invalid_count += 1;
            }
        } else {
            val[d] = if plus_to_space && c == b'+' { b' ' } else { c };
            s += 1;
        }
        d += 1;
    }
    val.truncate(d);
    invalid_count
}

/// Decodes the `%XX` escapes of `src`; invalid escapes are copied as they
/// are.
pub fn uri_decode(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len());
    let mut p = 0usize;
    while p < src.len() {
        if src[p] == b'%'
            && let Some(byte) = hex_pair(&src[p + 1..])
        {
            out.push(byte);
            p += 3;
        } else {
            out.push(src[p]);
            p += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonstrict() {
        let mut v = b"a%41+b%zz%4".to_vec();
        assert_eq!(urldecode_nonstrict_inplace(&mut v), 2);
        assert_eq!(v, b"aA b%zz%4".to_vec());
    }

    #[test]
    fn uri() {
        assert_eq!(uri_decode(b"/a%20b%2"), b"/a b%2".to_vec());
        assert_eq!(uri_decode(b"%"), b"%".to_vec());
    }

    #[test]
    fn plus_is_kept_when_asked() {
        let mut v = b"a+b%20".to_vec();
        assert_eq!(urldecode_nonstrict_inplace_ext(&mut v, false), 0);
        assert_eq!(v, b"a+b ");
    }

    #[test]
    fn hex_digits_of_either_case() {
        let mut v = b"%4a%4A%c3%A9".to_vec();
        assert_eq!(urldecode_nonstrict_inplace(&mut v), 0);
        assert_eq!(v, b"JJ\xc3\xa9");
    }

    #[test]
    fn invalid_escapes_are_counted_and_kept() {
        let mut v = b"%".to_vec();
        assert_eq!(urldecode_nonstrict_inplace(&mut v), 1);
        assert_eq!(v, b"%");
        let mut v = b"%%41".to_vec();
        assert_eq!(urldecode_nonstrict_inplace(&mut v), 1);
        assert_eq!(v, b"%A");
        let mut v = Vec::new();
        assert_eq!(urldecode_nonstrict_inplace(&mut v), 0);
    }

    #[test]
    fn uri_decode_keeps_plus() {
        assert_eq!(uri_decode(b"a+b%2B"), b"a+b+".to_vec());
        assert_eq!(uri_decode(b""), b"".to_vec());
    }
}
