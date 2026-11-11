//! Port of `src/actions/transformations/replace_comments.cc`, `src/actions/transformations/replace_comments.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(ReplaceComments);

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
                i += 2;
                changed = true;
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
    changed
}

impl Transformation for ReplaceComments {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        inplace(value)
    }
}
