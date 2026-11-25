//! The `t:cmdLine` transformation: normalises a command line (drops
//! quotes, backslashes and carets, collapses separators into one space,
//! removes a space before `/` or `(`, and lowercases).

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    let old_len = value.len();
    let mut d = 0usize;
    let mut space = false;
    for s in 0..old_len {
        let a = value[s];
        match a {
            // Dropped.
            b'"' | b'\'' | b'\\' | b'^' => {}
            // Separators: a run of them becomes one space.
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !space {
                    value[d] = b' ';
                    d += 1;
                    space = true;
                }
            }
            // No space before `/` or `(`.
            b'/' | b'(' => {
                if space {
                    d -= 1;
                }
                space = false;
                value[d] = a;
                d += 1;
            }
            // Anything else is copied, lowercased.
            _ => {
                value[d] = a.to_ascii_lowercase();
                d += 1;
                space = false;
            }
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
    fn drops_quotes_backslashes_and_carets() {
        assert_eq!(run(b"w\\h\"o\'a^m\\i"), b"whoami");
    }

    #[test]
    fn collapses_separators_into_one_space() {
        assert_eq!(run(b"a ,;\t\r\nb"), b"a b");
        assert_eq!(run(b"  a"), b" a");
        assert_eq!(run(b"a "), b"a ");
    }

    #[test]
    fn removes_a_space_before_slash_or_parenthesis() {
        assert_eq!(run(b"cat /etc/passwd"), b"cat/etc/passwd");
        assert_eq!(run(b"echo (x)"), b"echo(x)");
        assert_eq!(run(b"\"Ca^t\" /etc/pass\'wd"), b"cat/etc/passwd");
    }

    #[test]
    fn lowercases() {
        assert_eq!(run(b"CMD.EXE /C DIR"), b"cmd.exe/c dir");
        assert_eq!(run(b""), b"");
    }
}
