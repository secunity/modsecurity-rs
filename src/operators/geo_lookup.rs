//! `@geoLookup`.

use crate::operators::operator::Operator;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::utils::geo_lookup::GeoDb;

/// `@geoLookup`: fills the `GEO` collection from the database of the rule
/// set (`SecGeoLookupDb`).
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
        // The rules outlive the transaction's borrow.
        let rules = t.rules;
        match rules.properties.geo_db.as_deref() {
            Some(db) => db.lookup(input, Some(t)),
            None => GeoDb::not_loaded(t),
        }
    }
}

#[cfg(all(test, feature = "maxmind"))]
mod tests {
    use crate::modsecurity::ModSecurity;
    use crate::rules_set::RulesSet;
    use crate::transaction::Transaction;

    fn db() -> String {
        format!("{}/test/test-cases/data/GeoIP2-City-Test.mmdb", env!("CARGO_MANIFEST_DIR"))
    }

    /// `REMOTE_ADDR` 200.249.12.31 (Brazil in the test database) matched
    /// against `@geoLookup`.
    const RULE: &str = "SecRuleEngine On\nSecRule REMOTE_ADDR \"@geoLookup\" \"id:1,phase:1,deny,status:403\"\n";

    fn denied(rules: &RulesSet) -> bool {
        let ms = ModSecurity::new();
        let mut t = Transaction::new(&ms, rules, None);
        t.process_connection("200.249.12.31", 12345, "127.0.0.1", 80);
        t.process_uri(b"/", b"GET", b"1.1");
        t.process_request_headers();
        t.intervention().is_some_and(|it| it.status == 403)
    }

    #[test]
    fn each_rule_set_has_its_own_database() {
        let mut with_db = RulesSet::new();
        with_db.load(&format!("SecGeoLookupDb {}\n{}", db(), RULE)).unwrap();
        assert!(with_db.properties.geo_db.is_some());
        assert!(denied(&with_db));

        // C++ would use the database another rule set loaded.
        let mut without_db = RulesSet::new();
        without_db.load(RULE).unwrap();
        assert!(without_db.properties.geo_db.is_none());
        assert!(!denied(&without_db));

        // Merged rule sets inherit it (nginx locations from their parents).
        let mut parent = RulesSet::new();
        parent.load(&format!("SecGeoLookupDb {}\n", db())).unwrap();
        let mut child = RulesSet::new();
        child.load(RULE).unwrap();
        child.merge(&mut parent).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            child.properties.geo_db.as_ref().unwrap(),
            parent.properties.geo_db.as_ref().unwrap()
        ));
        assert!(denied(&child));
    }

    #[test]
    fn a_failed_database_after_one_that_opened() {
        // A file that is not a database.
        let bad = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
        // The database that opened stays in use, as in C++.
        let mut rules = RulesSet::new();
        let conf = format!("SecGeoLookupDb {}\nSecGeoLookupDb {}\n{}", db(), bad, RULE);
        rules.load(&conf).unwrap();
        assert!(denied(&rules));

        // Alone, it is an error.
        let mut rules = RulesSet::new();
        let err = rules.load(&format!("SecGeoLookupDb {}\n", bad)).unwrap_err();
        assert!(err.message().contains(&format!("Failed to load the GeoDB from: {}. Can't open: ", bad)), "{err}");
    }
}
