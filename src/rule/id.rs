//! [`Id`]: the id of a rule.

/// The id of a rule (`id:942100`), 0 for a rule without one.
///
/// A rule keeps its id as a 64 bit integer, and so do the directives that
/// name rules (`SecRuleRemoveById`, `SecRuleUpdateTargetById`,
/// `SecRuleUpdateActionById`). The actions `ctl:ruleRemoveById` and
/// `ctl:ruleRemoveTargetById` hold `int`s; the comparisons with those are
/// here.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Id(i64);

impl Id {
    pub fn new(id: i64) -> Self {
        Id(id)
    }

    /// The id written as `text`: a decimal number, up to the largest 64 bit
    /// integer.
    pub fn parse(text: &str) -> Option<Self> {
        let digits = !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit());
        text.parse().ok().filter(|_| digits).map(Id)
    }

    pub fn get(self) -> i64 {
        self.0
    }

    /// Whether this is `id`, the `int` of a `ctl:` action.
    pub fn is(self, id: i32) -> bool {
        self.0 == i64::from(id)
    }

    /// Whether this is in `first..=last`, a range of a `ctl:ruleRemoveById`.
    pub fn is_within(self, first: i32, last: i32) -> bool {
        i64::from(first) <= self.0 && i64::from(last) >= self.0
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
        let id = Id::new(942100);
        assert_eq!((id.get(), id.to_string(), format!("{id:?}")), (942100, "942100".to_string(), "942100".to_string()));
        assert!(id.is(942100) && !id.is(942101));
        assert!(id.is_within(942000, 942100) && id.is_within(942100, 942100) && !id.is_within(942101, 942200));
        assert_eq!(Id::parse("942100"), Some(id));
        assert_eq!(Id::parse("007"), Some(Id::new(7)));
        assert_eq!(Id::parse("9223372036854775807"), Some(Id::new(i64::MAX)));
        for text in ["", "+1", "-1", " 1", "1.0", "9.421e5", "0x10", "942100abc", "9223372036854775808"] {
            assert_eq!(Id::parse(text), None, "{text}");
        }

        // Beyond the `int` range: never the id of a `ctl:` action.
        let big = Id::new(4294967297);
        assert!(!big.is(1) && !big.is_within(0, i32::MAX));
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

    /// A rule with an id beyond the `int` range is removed by its own id
    /// only. (In C++ `SecRuleRemoveById` sees the id narrowed to an `int`:
    /// removing rule 1 removes rule 4294967297 too.)
    #[test]
    fn an_id_beyond_the_int_range() {
        let rule = "SecRule REQUEST_URI \"@contains x\" \"id:4294967297,phase:1,deny,status:403\"\n";
        assert!(denied(rule));
        assert!(denied(&format!("{rule}SecRuleRemoveById 1\n")));
        assert!(denied(&format!("{rule}SecRuleRemoveById 2-4294967296\n")));
        assert!(!denied(&format!("{rule}SecRuleRemoveById 4294967297\n")));
        assert!(!denied(&format!("{rule}SecRuleRemoveById 4294967290-4294967299\n")));
        let ctl = "SecAction \"id:5,phase:1,pass,nolog,ctl:ruleRemoveById=1\"\n";
        assert!(denied(&format!("{ctl}{rule}")));
        let ctl_range = "SecAction \"id:5,phase:1,pass,nolog,ctl:ruleRemoveById=1-2147483647\"\n";
        assert!(denied(&format!("{ctl_range}{rule}")));
    }

    /// `SecRuleUpdateTargetById` and `SecRuleUpdateActionById` take the id
    /// as the `id` action does (C++ reads the longest floating point
    /// prefix: `1e0`, `1.0`, `0x1` and `1abc` all name the rule 1 there).
    #[test]
    fn the_id_of_an_update_directive() {
        let rule = "SecRule REQUEST_URI \"@contains x\" \"id:1,phase:1,deny,status:403\"\n";
        assert!(!denied(&format!("{rule}SecRuleUpdateTargetById 1 !REQUEST_URI\n")));
        assert!(!denied(&format!("{rule}SecRuleUpdateActionById 1 \"pass\"\n")));
        for id in ["1e0", "1.0", "0x1", "1abc", "+1"] {
            for directive in
                [format!("SecRuleUpdateTargetById {id} !REQUEST_URI"), format!("SecRuleUpdateActionById {id} \"pass\"")]
            {
                let mut rules = crate::RulesSet::new();
                assert!(rules.load(&format!("{rule}{directive}\n")).is_err(), "{directive}");
            }
        }
    }
}
