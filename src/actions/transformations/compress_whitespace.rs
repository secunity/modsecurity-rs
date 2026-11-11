//! Port of `src/actions/transformations/compress_whitespace.cc`, `src/actions/transformations/compress_whitespace.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::string::is_space;

crate::transformation_struct!(CompressWhitespace);

impl Transformation for CompressWhitespace {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
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
        d != old_len
    }
}
