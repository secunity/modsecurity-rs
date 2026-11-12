//! Port of `src/actions/rule_id.cc`, `src/actions/rule_id.h`.
//!
//! `id:N` — the rule id (configuration time).

use std::ffi::{CStr, c_char};

use crate::actions::action::{Action, ActionBase, Kind};
use crate::rule_with_actions::RuleWithActions;

#[derive(Debug)]
pub struct RuleId {
    pub base: ActionBase,
    rule_id: f64,
}

impl RuleId {
    pub fn new(action: &str) -> Self {
        RuleId { base: ActionBase::with_kind(action, Kind::ConfigurationKind), rule_id: 0.0 }
    }
}

/// `std::ostringstream << std::setprecision(40) << d`, i.e. `%.40g`.
fn format_g40(d: f64) -> String {
    let mut buf = [0 as c_char; 128];
    // SAFETY: the buffer is large enough for any `%.40g` output (at most
    // 40 significant digits, sign, point and exponent) and snprintf never
    // writes past `buf.len()` bytes; the format consumes exactly one double.
    unsafe {
        libc::snprintf(buf.as_mut_ptr(), buf.len(), c"%.40g".as_ptr(), d);
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}

impl Action for RuleId {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        let a = &self.base.parser_payload;
        // `std::stod`; whatever it accepts must also print back as the very
        // same text, so a stricter parser yields the same verdicts.
        let Ok(v) = a.parse::<f64>() else {
            self.rule_id = 0.0;
            return Err(format!("The input \"{}\" does not seems to be a valid rule id.", a));
        };
        self.rule_id = v;
        if *a != format_g40(v) || v < 0.0 {
            return Err(format!("The input \"{}\" does not seems to be a valid rule id.", a));
        }
        Ok(())
    }

    fn configure(&self, rule: &mut RuleWithActions) {
        rule.rule_id = self.rule_id as i64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::{RuleAction, rule};

    fn id(p: &str) -> Result<i64, String> {
        let mut a = RuleId::new(&format!("id:{}", p));
        a.init()?;
        Ok(rule(vec![RuleAction::Other(Box::new(a))]).rule_id)
    }

    #[test]
    fn init_and_configure() {
        assert_eq!(id("1234"), Ok(1234));
        assert_eq!(id("'900018'"), Ok(900018));
        // `%.40g` of 1.5 is "1.5": accepted, truncated by the rule.
        assert_eq!(id("1.5"), Ok(1));
        let err = |s: &str| Err(format!("The input \"{}\" does not seems to be a valid rule id.", s));
        assert_eq!(id("abc"), err("abc"));
        assert_eq!(id("01"), err("01"));
        assert_eq!(id("-1"), err("-1"));
        assert_eq!(id("1e3"), err("1e3"));
        assert_eq!(id("0.1"), err("0.1"));
        assert_eq!(id(""), err(""));
    }

    #[test]
    fn format() {
        assert_eq!(format_g40(1.0), "1");
        assert_eq!(format_g40(0.1), "0.1000000000000000055511151231257827021182");
        assert_eq!(format_g40(1e23), "99999999999999991611392");
    }
}
