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
}
