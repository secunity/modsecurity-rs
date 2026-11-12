//! Port of `src/actions/transformations/remove_comments_char.cc`, `src/actions/transformations/remove_comments_char.h`.

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>) -> bool {
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

    let changed = d != s;
    value.truncate(d);
    changed
}
