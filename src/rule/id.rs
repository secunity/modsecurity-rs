//! [`Id`]: the id of a rule.

/// The id of a rule (`id:942100`), 0 for a rule without one.
///
/// A rule keeps its id as a 64 bit integer, but the id is other numbers
/// elsewhere, as in C++: the `id` action reads a floating point number,
/// `SecRuleUpdateTargetById` and `SecRuleUpdateActionById` look rules up
/// by one, and `ctl:ruleRemoveById`, `ctl:ruleRemoveTargetById` and
/// `SecRuleRemoveById` hold `int`s. The comparisons between them are
/// here, each as C++ makes it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Id(i64);

impl Id {
    /// The id the `id` action read.
    pub fn from_number(id: f64) -> Self {
        Id(id as i64)
    }

    pub fn get(self) -> i64 {
        self.0
    }

    /// The id as the number the `SecRuleUpdate...ById` directives are
    /// looked up by.
    pub fn as_number(self) -> f64 {
        self.0 as f64
    }

    /// Whether this is `id`, the `int` of a `ctl:` action.
    pub fn is(self, id: i32) -> bool {
        self.0 == i64::from(id)
    }

    /// Whether this is in `first..=last`, a range of a `ctl:ruleRemoveById`.
    pub fn is_within(self, first: i32, last: i32) -> bool {
        i64::from(first) <= self.0 && i64::from(last) >= self.0
    }

    /// The id as `SecRuleRemoveById` compares it: narrowed to an `int`, as
    /// C++ does (`RulesExceptions::contains(int)` is given the 64 bit id),
    /// so that the rule 4294967297 is removed by `SecRuleRemoveById 1`.
    pub fn narrowed(self) -> i32 {
        self.0 as i32
    }
}

impl std::fmt::Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The number alone, as when the id was an integer.
impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::Id;

    #[test]
    fn comparisons() {
        let id = Id::from_number(942100.0);
        assert_eq!((id.get(), id.to_string(), format!("{id:?}")), (942100, "942100".to_string(), "942100".to_string()));
        assert!(id.is(942100) && !id.is(942101));
        assert!(id.is_within(942000, 942100) && id.is_within(942100, 942100) && !id.is_within(942101, 942200));
        assert_eq!(id.as_number(), 942100.0);

        // Beyond the `int` range: never the id of a `ctl:` action, but
        // another id for `SecRuleRemoveById`.
        let big = Id::from_number(4294967297.0);
        assert!(!big.is(1) && !big.is_within(0, i32::MAX));
        assert_eq!(big.narrowed(), 1);
    }

    /// Whether a request for `/x` is denied under `conf`.
    fn denied(conf: &str) -> bool {
        let ms = crate::ModSecurity::new();
        let mut rules = crate::RulesSet::new();
        rules.load(&format!("SecRuleEngine On\n{conf}")).unwrap();
        let mut t = crate::Transaction::new(&ms, &rules, None);
        t.process_uri(b"/x", b"GET", b"1.1");
        t.process_request_headers();
        t.intervention().is_some_and(|it| it.status == 403)
    }

    /// As in C++ (compared with the C++ library): `SecRuleRemoveById`
    /// sees the id narrowed to an `int`, `ctl:ruleRemoveById` does not.
    #[test]
    fn an_id_beyond_the_int_range() {
        let rule = "SecRule REQUEST_URI \"@contains x\" \"id:4294967297,phase:1,deny,status:403\"\n";
        assert!(denied(rule));
        assert!(!denied(&format!("{rule}SecRuleRemoveById 1\n")));
        assert!(denied(&format!("{rule}SecRuleRemoveById 2\n")));
        let ctl = "SecAction \"id:5,phase:1,pass,nolog,ctl:ruleRemoveById=1\"\n";
        assert!(denied(&format!("{ctl}{rule}")));
        let ctl_range = "SecAction \"id:5,phase:1,pass,nolog,ctl:ruleRemoveById=1-2147483647\"\n";
        assert!(denied(&format!("{ctl_range}{rule}")));
    }
}
