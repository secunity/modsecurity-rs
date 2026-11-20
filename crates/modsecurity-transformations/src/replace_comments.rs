//! The `t:replaceComments` transformation: replaces each `/* */` comment
//! (also an unterminated one) with a single space.

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
            } else {
                input[j] = input[i];
                i += 1;
                j += 1;
            }
        } else if input[i] == b'*' && i + 1 < input_len && input[i + 1] == b'/' {
            incomment = false;
            i += 2;
            input[j] = b' ';
            j += 1;
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
