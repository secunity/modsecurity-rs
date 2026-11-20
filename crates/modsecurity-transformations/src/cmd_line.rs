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
            // remove some characters
            b'"' | b'\'' | b'\\' | b'^' => {}
            // replace some characters to space (only one)
            b' ' | b',' | b';' | b'\t' | b'\r' | b'\n' => {
                if !space {
                    value[d] = b' ';
                    d += 1;
                    space = true;
                }
            }
            // remove space before / or (
            b'/' | b'(' => {
                if space {
                    d -= 1;
                }
                space = false;
                value[d] = a;
                d += 1;
            }
            // copy normal characters
            _ => {
                value[d] = a.to_ascii_lowercase();
                d += 1;
                space = false;
            }
        }
    }
    value.truncate(d);
}
