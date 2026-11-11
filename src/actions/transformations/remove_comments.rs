//! Port of `src/actions/transformations/remove_comments.cc`, `src/actions/transformations/remove_comments.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(RemoveComments);

fn inplace(input: &mut Vec<u8>) -> bool {
    let input_len = input.len();
    let mut changed = false;
    let mut incomment = false;
    let mut i = 0usize;
    let mut j = 0usize;

    while i < input_len {
        if !incomment {
            if input[i] == b'/' && i + 1 < input_len && input[i + 1] == b'*' {
                incomment = true;
                changed = true;
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
                changed = true;
                i += 4;
            } else if input[i] == b'-' && i + 1 < input_len && input[i + 1] == b'-' {
                // Quirk kept from C++: the space is written at `i`, but the
                // value is then cut at `j` (<= i), so it is never kept.
                input[i] = b' ';
                changed = true;
                break;
            } else if input[i] == b'#' {
                input[i] = b' ';
                changed = true;
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
    changed
}

impl Transformation for RemoveComments {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        inplace(value)
    }
}
