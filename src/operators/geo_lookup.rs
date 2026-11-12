//! Port of `src/operators/geo_lookup.cc`, `src/operators/geo_lookup.h`.

use crate::operators::operator::Operator;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::geo_lookup::GeoLookup as GeoDb;

/// `@geoLookup`: fills the `GEO` collection from the configured database.
#[derive(Debug)]
pub struct GeoLookup;

impl Default for GeoLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoLookup {
    pub fn new() -> Self {
        GeoLookup
    }
}

impl Operator for GeoLookup {
    fn name(&self) -> &'static str {
        "GeoLookup"
    }
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        GeoDb::get_instance().lookup(input, Some(t))
    }
}
