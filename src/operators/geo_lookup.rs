//! Port of `src/operators/geo_lookup.cc`, `src/operators/geo_lookup.h`.

use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::geo_lookup::GeoLookup as GeoDb;

/// `@geoLookup`: fills the `GEO` collection from the configured database.
#[derive(Debug)]
pub struct GeoLookup {
    pub base: OperatorBase,
}

impl Default for GeoLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoLookup {
    pub fn new() -> Self {
        GeoLookup { base: OperatorBase::new("GeoLookup") }
    }
}

impl Operator for GeoLookup {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        _rule: Option<&RuleWithActions>,
        input: &[u8],
        _rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        GeoDb::get_instance().lookup(input, t)
    }
}
