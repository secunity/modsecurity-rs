//! The `t:compressWhitespace` transformation: replaces each run of
//! whitespace with a single space.

use crate::chars::is_space;

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    let old_len = value.len();
    let mut in_white_space = false;
    let mut d = 0usize;
    for s in 0..old_len {
        let c = value[s];
        if is_space(c) {
            if in_white_space {
                continue;
            }
            in_white_space = true;
            value[d] = b' ';
            d += 1;
        } else {
            in_white_space = false;
            value[d] = c;
            d += 1;
        }
    }
    value.truncate(d);
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
    fn compresses_runs_of_whitespace() {
        assert_eq!(run(b"a \t\n b"), b"a b");
        assert_eq!(run(b"  a  "), b" a ");
        assert_eq!(run(b"a\x0b\x0cb\rc"), b"a b c");
    }

    #[test]
    fn other_bytes_are_kept() {
        // A non-breaking space is not whitespace here.
        assert_eq!(run(b"a\xa0b"), b"a\xa0b");
        assert_eq!(run(b"ab"), b"ab");
        assert_eq!(run(b""), b"");
    }
}
