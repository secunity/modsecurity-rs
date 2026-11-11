//! Port of `src/utils/decode.h` / `src/utils/decode.cc`.

use crate::utils::string::{hex2dec, valid_hex, x2c};

/// `urldecode_nonstrict_inplace`: returns whether the value changed and the
/// number of invalid `%` encodings.
pub fn urldecode_nonstrict_inplace(val: &mut Vec<u8>, invalid_count: &mut i32) -> bool {
    urldecode_nonstrict_inplace_ext(val, true, invalid_count)
}

/// `urldecode_nonstrict_inplace_ext`
pub fn urldecode_nonstrict_inplace_ext(val: &mut Vec<u8>, plus_to_space: bool, invalid_count: &mut i32) -> bool {
    let e = val.len();
    let mut s = 0usize;
    let mut d = 0usize;
    *invalid_count = 0;
    let mut changed = false;
    while s != e {
        if val[s] == b'%' {
            if s + 2 < e {
                let c1 = val[s + 1];
                let c2 = val[s + 2];
                if valid_hex(c1) && valid_hex(c2) {
                    let uni = x2c(&[c1, c2]);
                    val[d] = uni;
                    d += 1;
                    s += 3;
                    changed = true;
                } else {
                    val[d] = val[s];
                    d += 1;
                    s += 1;
                    *invalid_count += 1;
                }
            } else {
                val[d] = val[s];
                d += 1;
                s += 1;
                *invalid_count += 1;
            }
        } else {
            if plus_to_space && val[s] == b'+' {
                val[d] = b' ';
                changed = true;
            } else {
                val[d] = val[s];
            }
            d += 1;
            s += 1;
        }
    }
    if changed {
        val.truncate(d);
    }
    changed
}

/// `uri_decode`
pub fn uri_decode(src: &[u8]) -> Vec<u8> {
    let len = src.len();
    let mut out = Vec::with_capacity(len);
    let mut p = 0usize;
    let last_dec = len.saturating_sub(2);
    while len >= 2 && p < last_dec {
        if src[p] == b'%' {
            let d1 = hex2dec(src[p + 1]);
            let d2 = hex2dec(src[p + 2]);
            if d1 != -1 && d2 != -1 {
                out.push(((d1 as u8) << 4).wrapping_add(d2 as u8));
                p += 3;
                continue;
            }
        }
        out.push(src[p]);
        p += 1;
    }
    while p < len {
        out.push(src[p]);
        p += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonstrict() {
        let mut v = b"a%41+b%zz%4".to_vec();
        let mut inv = 0;
        assert!(urldecode_nonstrict_inplace(&mut v, &mut inv));
        assert_eq!(v, b"aA b%zz%4".to_vec());
        assert_eq!(inv, 2);
    }

    #[test]
    fn uri() {
        assert_eq!(uri_decode(b"/a%20b%2"), b"/a b%2".to_vec());
        assert_eq!(uri_decode(b"%"), b"%".to_vec());
    }
}
