//! Port of `src/actions/transformations/none.cc`, `src/actions/transformations/none.h`.
//!
//! `t:none` does not change the value; its effect is that the rule (and
//! `executeTransformations`) skip every transformation listed before it,
//! which is driven by `ActionBase::is_none` (C++ `m_isNone = true`).

use crate::actions::action::{Action, ActionBase};
use crate::actions::transformations::transformation::{Transformation, transformation_base};
use crate::transaction::Transaction;

#[derive(Debug, Clone)]
pub struct None {
    pub base: ActionBase,
}

impl None {
    pub fn new(action: &str) -> Self {
        let mut base = transformation_base(action);
        base.is_none = true;
        None { base }
    }
}

impl Action for None {
    crate::action_base_accessors!();
    fn as_transformation(&self) -> Option<&dyn Transformation> {
        Some(self)
    }
}

impl Transformation for None {
    fn transform(&self, _value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_is_marked() {
        assert!(None::new("t:none").base.is_none);
    }
}
