//! Port of `src/actions/transformations/url_decode.cc`, `src/actions/transformations/url_decode.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::decode::urldecode_nonstrict_inplace;

crate::transformation_struct!(UrlDecode);

impl Transformation for UrlDecode {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        let mut invalid_count = 0;
        urldecode_nonstrict_inplace(value, &mut invalid_count)
    }
}
