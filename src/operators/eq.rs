//! Port of `src/operators/eq.cc`, `src/operators/eq.h`.
//!
//! Also hosts the C number parsing helpers shared by the numeric
//! comparison operators (`@eq`, `@ge`, `@gt`, `@le`, `@lt`).

use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

/// `::isspace` in the C locale.
fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// Parses like `strtoll(s, NULL, 10)`: leading white space, optional sign,
/// decimal digits. Returns the value (saturated on overflow, as `strtoll`
/// does), whether the value overflowed and whether any digit was read.
fn parse_c_integer(s: &[u8]) -> (i64, bool, bool) {
    let mut i = 0;
    while i < s.len() && is_c_space(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let start = i;
    // Accumulate negatively so that i64::MIN is representable.
    let mut v: i64 = 0;
    let mut overflow = false;
    while i < s.len() && s[i].is_ascii_digit() {
        let d = i64::from(s[i] - b'0');
        match v.checked_mul(10).and_then(|x| x.checked_sub(d)) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    let digits = i > start;
    if overflow {
        return (if neg { i64::MIN } else { i64::MAX }, true, digits);
    }
    if neg {
        (v, false, digits)
    } else {
        match v.checked_neg() {
            Some(x) => (x, false, digits),
            None => (i64::MAX, true, digits),
        }
    }
}

/// `atoll` (glibc: `strtoll(s, NULL, 10)`).
pub(crate) fn atoll(s: &[u8]) -> i64 {
    parse_c_integer(s).0
}

/// `std::stoi`: `None` where the C++ function throws (no conversion, or a
/// value out of the `int` range).
pub(crate) fn stoi(s: &[u8]) -> Option<i32> {
    let (v, overflow, digits) = parse_c_integer(s);
    if !digits || overflow {
        return None;
    }
    i32::try_from(v).ok()
}

#[derive(Debug)]
pub struct Eq {
    pub base: OperatorBase,
}

impl Eq {
    pub fn new(param: RunTimeString) -> Self {
        Eq { base: OperatorBase::with_string("Eq", param) }
    }
}

impl Operator for Eq {
    crate::operator_base_accessors!();
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        let pt = self.base.param_value(t);
        // A failing std::stoi counts as 0.
        let p = stoi(&pt).unwrap_or(0);
        let i = stoi(input).unwrap_or(0);
        p == i
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_number_parsing() {
        assert_eq!(atoll(b"  -12abc"), -12);
        assert_eq!(atoll(b"+7"), 7);
        assert_eq!(atoll(b"abc"), 0);
        assert_eq!(atoll(b"99999999999999999999"), i64::MAX);
        assert_eq!(atoll(b"-99999999999999999999"), i64::MIN);
        assert_eq!(atoll(b"-9223372036854775808"), i64::MIN);
        assert_eq!(stoi(b"\t42 "), Some(42));
        assert_eq!(stoi(b"x"), None);
        assert_eq!(stoi(b"-"), None);
        assert_eq!(stoi(b"2147483648"), None);
        assert_eq!(stoi(b"-2147483648"), Some(i32::MIN));
    }
}
