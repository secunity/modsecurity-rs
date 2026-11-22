//! The `t:removeComments` transformation: removes `/* */` and `<!-- -->`
//! comments, and cuts the value at `--` or `#`.

fn inplace(input: &mut Vec<u8>) {
    let input_len = input.len();
    let mut incomment = false;
    let mut i = 0usize;
    let mut j = 0usize;

    while i < input_len {
        if !incomment {
            if input[i] == b'/' && i + 1 < input_len && input[i + 1] == b'*' {
                incomment = true;
                i += 2;
            } else if input[i] == b'<'
                && i + 1 < input_len
                && input[i + 1] == b'!'
                && i + 2 < input_len
                && input[i + 2] == b'-'
                && i + 3 < input_len
                && input[i + 3] == b'-'
            {
                incomment = true;
                i += 4;
            } else if input[i] == b'-' && i + 1 < input_len && input[i + 1] == b'-' {
                // The space is written at `i`, but the value is then cut at
                // `j` (<= i), so it is never kept.
                input[i] = b' ';
                break;
            } else if input[i] == b'#' {
                input[i] = b' ';
                break;
            } else {
                input[j] = input[i];
                i += 1;
                j += 1;
            }
        } else if input[i] == b'*' && i + 1 < input_len && input[i + 1] == b'/' {
            incomment = false;
            i += 2;
        } else if input[i] == b'-'
            && i + 1 < input_len
            && input[i + 1] == b'-'
            && i + 2 < input_len
            && input[i + 2] == b'>'
        {
            incomment = false;
            i += 3;
        } else {
            i += 1;
        }
    }

    if incomment {
        input[j] = b' ';
        j += 1;
    }

    input.truncate(j);
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    inplace(value);
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
    fn removes_c_and_html_comments() {
        assert_eq!(run(b"a/*x*/b"), b"ab");
        assert_eq!(run(b"a<!--x-->b"), b"ab");
        assert_eq!(run(b"un/**/ion"), b"union");
        // `--` inside a C comment does not end it.
        assert_eq!(run(b"/* -- */x"), b"x");
    }

    #[test]
    fn cuts_the_value_at_double_dash_or_hash() {
        assert_eq!(run(b"select 1 -- rest"), b"select 1 ");
        assert_eq!(run(b"a#b"), b"a");
        assert_eq!(run(b"--"), b"");
    }

    #[test]
    fn an_unterminated_comment_becomes_a_space() {
        assert_eq!(run(b"a/*xyz"), b"a ");
        assert_eq!(run(b"a<!--x"), b"a ");
    }

    #[test]
    fn lone_comment_characters_are_kept() {
        assert_eq!(run(b"a-b/c*d<!e"), b"a-b/c*d<!e");
        assert_eq!(run(b"a*/b"), b"a*/b");
        assert_eq!(run(b""), b"");
    }
}
