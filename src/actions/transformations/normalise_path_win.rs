//! Port of `src/actions/transformations/normalise_path_win.cc`, `src/actions/transformations/normalise_path_win.h`.

use crate::actions::transformations::normalise_path::NormalisePath;
use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(NormalisePathWin);

impl Transformation for NormalisePathWin {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        NormalisePath::normalize_path_inplace(value, true)
    }
}
