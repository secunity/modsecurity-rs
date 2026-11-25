//! `multiMatch` — a marker: `Rule` records its presence, and the
//! evaluation then runs the operator on the original value and on every
//! value a transformation changed.

use crate::actions::action::Action;

#[derive(Debug)]
pub struct MultiMatch {
    name: String,
}

impl MultiMatch {
    pub fn new(name: &str) -> Self {
        MultiMatch { name: name.to_string() }
    }
}

impl Action for MultiMatch {
    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use crate::{ModSecurity, RulesSet, Transaction};

    fn denied(rule: &str, uri: &[u8]) -> bool {
        let ms = ModSecurity::new();
        let mut rules = RulesSet::new();
        rules.load(&format!("SecRuleEngine On\n{rule}")).unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_uri(uri, b"GET", b"1.1");
        t.process_request_headers();
        t.intervention().is_some()
    }

    /// Every value a transformation produces is inspected, whatever the
    /// transformation says about having changed it. (`t:normalisePath`
    /// turns `a/..` into nothing without reporting a change, so that value
    /// used to be skipped; C++ does the same.)
    #[test]
    fn every_value_that_differs_is_inspected() {
        let rule = |operator: &str| {
            format!("SecRule ARGS:p \"{operator}\" \"id:1,phase:1,deny,multiMatch,t:none,t:normalisePath,t:length\"")
        };
        // The original value, the normalised one (empty) and its length.
        assert!(denied(&rule("@streq a/.."), b"/?p=a/.."));
        assert!(denied(&rule("@rx ^$"), b"/?p=a/.."));
        assert!(denied(&rule("@streq 0"), b"/?p=a/.."));
        assert!(!denied(&rule("@streq 4"), b"/?p=a/.."));
        // A transformation that leaves the value alone adds nothing: "1"
        // is inspected once, and its length is "1" too.
        assert!(denied(&rule("@streq 1"), b"/?p=1"));
    }
}
