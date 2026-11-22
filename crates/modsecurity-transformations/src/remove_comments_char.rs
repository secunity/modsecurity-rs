//! The `t:removeCommentsChar` transformation: removes the comment
//! characters `/*`, `*/`, `<!--`, `-->`, `--` and `#`.

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    let e = value.len();
    let mut d = 0usize;
    let mut s = 0usize;

    while s < e {
        if (value[s] == b'/' && s + 1 < e && value[s + 1] == b'*')
            || (value[s] == b'*' && s + 1 < e && value[s + 1] == b'/')
        {
            // `/*` or `*/`
            s += 2;
        } else if value[s] == b'<'
            && s + 1 < e
            && value[s + 1] == b'!'
            && s + 2 < e
            && value[s + 2] == b'-'
            && s + 3 < e
            && value[s + 3] == b'-'
        {
            s += 4;
        } else if value[s] == b'-' && s + 1 < e && value[s + 1] == b'-' && s + 2 < e && value[s + 2] == b'>' {
            s += 3;
        } else if value[s] == b'-' && s + 1 < e && value[s + 1] == b'-' {
            s += 2;
        } else if value[s] == b'#' {
            s += 1;
        } else {
            value[d] = value[s];
            d += 1;
            s += 1;
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
    fn removes_the_comment_characters_only() {
        assert_eq!(run(b"/*a*/"), b"a");
        assert_eq!(run(b"<!--a-->"), b"a");
        assert_eq!(run(b"a--b#c"), b"abc");
        assert_eq!(run(b"un/**/ion"), b"union");
    }

    #[test]
    fn longest_sequence_first() {
        // `-->` is removed whole, then `--`, leaving `->` of `--->`.
        assert_eq!(run(b"--->"), b"->");
        assert_eq!(run(b"--->x"), b"->x");
    }

    #[test]
    fn lone_comment_characters_are_kept() {
        assert_eq!(run(b"a-b/c*d<!e"), b"a-b/c*d<!e");
        assert_eq!(run(b""), b"");
    }
}
