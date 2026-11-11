//! Port of `src/actions/transformations/md5.cc`, `src/actions/transformations/md5.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::md5::Md5 as Md5Digest;

crate::transformation_struct!(Md5);

impl Transformation for Md5 {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        Md5Digest::digest_replace(value)
    }
}
