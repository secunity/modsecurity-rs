//! Port of `src/actions/transformations/sha1.cc`, `src/actions/transformations/sha1.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;
use crate::utils::sha1::Sha1 as Sha1Digest;

crate::transformation_struct!(Sha1);

impl Transformation for Sha1 {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        Sha1Digest::digest_replace(value)
    }
}
