//! The id of a rule (`id:942100`), and how ids are written.

use std::ops::RangeInclusive;

/// The id of a rule; 0 for a rule without one.
pub type Id = u64;

/// The id written as `text`: decimal digits only.
pub fn parse(text: &str) -> Option<Id> {
    let digits = !text.is_empty() && text.bytes().all(|c| c.is_ascii_digit());
    text.parse().ok().filter(|_| digits)
}

/// The ids of a list as `SecRuleRemoveById` and `ctl:ruleRemoveById` take
/// it: ids and ranges (`first-last`) separated by spaces, each possibly in
/// quotes. A single id is a range of one.
pub fn parse_list(list: &str) -> Result<Vec<RangeInclusive<Id>>, String> {
    let mut ranges = Vec::new();
    let items = list.split(' ').map(|item| crate::utils::string::parser_sanitizer(item.to_string()));
    for item in items.filter(|item| !item.is_empty()) {
        let bound = |text: &str| parse(text).ok_or_else(|| format!("Not a number: {text}"));
        let range = match item.split_once('-') {
            None => parse(&item).map(|id| id..=id).ok_or_else(|| format!("Not a number or range: {item}"))?,
            Some((first, last)) => bound(first)?..=bound(last)?,
        };
        if range.is_empty() {
            return Err(format!("Invalid range: {item}"));
        }
        ranges.push(range);
    }
    if ranges.is_empty() {
        return Err(format!("Not a number or range: {list}"));
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_ids() {
        assert_eq!(parse("942100"), Some(942100));
        assert_eq!(parse("007"), Some(7));
        assert_eq!(parse("18446744073709551615"), Some(u64::MAX));
        for text in ["", "+1", "-1", " 1", "1.0", "9.421e5", "0x10", "942100abc", "18446744073709551616"] {
            assert_eq!(parse(text), None, "{text}");
        }
    }

    #[test]
    fn lists() {
        assert_eq!(parse_list("1  '2' 10-20 \"3\""), Ok(vec![1..=1, 2..=2, 10..=20, 3..=3]));
        for (list, error) in [
            ("10-5", "Invalid range: 10-5"),
            ("x", "Not a number or range: x"),
            ("12abc", "Not a number or range: 12abc"),
            ("1-x", "Not a number: x"),
            ("x-2", "Not a number: x"),
            ("-5", "Not a number: "),
            ("", "Not a number or range: "),
            ("  ", "Not a number or range:   "),
            ("30 x", "Not a number or range: x"),
        ] {
            assert_eq!(parse_list(list).unwrap_err(), error, "{list:?}");
        }
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
    /// only, by a directive or by a `ctl:` action. (In C++
    /// `SecRuleRemoveById` sees the id narrowed to an `int`, so removing
    /// rule 1 removes rule 4294967297 too, and `ctl:ruleRemoveById` cannot
    /// name such an id.)
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
        for removal in ["ruleRemoveById=4294967297", "ruleRemoveById=4294967290-4294967299"] {
            assert!(!denied(&format!("SecAction \"id:5,phase:1,pass,nolog,ctl:{removal}\"\n{rule}")), "{removal}");
        }
        let target = "SecAction \"id:5,phase:1,pass,nolog,ctl:ruleRemoveTargetById=4294967297;REQUEST_URI\"\n";
        assert!(!denied(&format!("{target}{rule}")));
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
