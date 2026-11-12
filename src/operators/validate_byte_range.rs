//! Port of `src/operators/validate_byte_range.cc`,
//! `src/operators/validate_byte_range.h`.

use crate::operators::eq::stoi;
use crate::operators::operator::{Operator, Param, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct ValidateByteRange {
    param: Param,
    /// Bitmap of the accepted byte values.
    table: [u8; 32],
}

impl ValidateByteRange {
    pub fn new(param: RunTimeString) -> Self {
        ValidateByteRange { param: Param::new(param), table: [0; 32] }
    }

    fn set(&mut self, b: i32) {
        self.table[(b >> 3) as usize] |= 1 << (b & 0x7);
    }

    /// `getRange`: adds `N` or `N-M` to the table.
    pub fn add_range(&mut self, range_representation: &[u8]) -> Result<(), String> {
        let lossy = |s: &[u8]| String::from_utf8_lossy(s).into_owned();
        let Some(pos) = range_representation.iter().position(|&c| c == b'-') else {
            let Some(start) = stoi(range_representation) else {
                return Err(format!("Not able to convert '{}' into a number", lossy(range_representation)));
            };
            if !(0..=255).contains(&start) {
                return Err(format!("Invalid byte value: {}", start));
            }
            self.set(start);
            return Ok(());
        };

        let start_s = &range_representation[..pos];
        let Some(mut start) = stoi(start_s) else {
            return Err(format!("Not able to convert '{}' into a number", lossy(start_s)));
        };

        let end_s = &range_representation[pos + 1..];
        let Some(end) = stoi(end_s) else {
            return Err(format!("Not able to convert '{}' into a number", lossy(end_s)));
        };

        if !(0..=255).contains(&start) {
            return Err(format!("Invalid range start value: {}", start));
        }
        if !(0..=255).contains(&end) {
            return Err(format!("Invalid range end value: {}", end));
        }
        if start > end {
            return Err(format!("Invalid range: {}-{}", start, end));
        }

        while start <= end {
            self.set(start);
            start += 1;
        }

        Ok(())
    }
}

impl Operator for ValidateByteRange {
    fn name(&self) -> &'static str {
        "ValidateByteRange"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    fn init(&mut self, _file: &str) -> Result<(), String> {
        let param = self.param.literal.clone();
        // Comma separated list of ranges (empty pieces fail to convert).
        for range in param.split(|&c| c == b',') {
            self.add_range(range)?;
        }
        Ok(())
    }

    fn evaluate(
        &self,
        _t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        let mut count = 0usize;
        for (i, &x) in input.iter().enumerate() {
            if self.table[usize::from(x >> 3)] & (1 << (x & 0x7)) == 0 {
                log_offset(rm, i, 1);
                count += 1;
            }
        }

        count != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::operator::test_support::eval;

    fn op(p: &str) -> Result<ValidateByteRange, String> {
        let mut o = ValidateByteRange::new(RunTimeString::from_text(p));
        o.init("").map(|_| o)
    }

    #[test]
    fn ranges() {
        let o = op("10,13,32-126").unwrap();
        assert!(!eval(&o, b"Hello World\r\n"));
        assert!(eval(&o, b"\x01"));
        assert_eq!(op("1-300").unwrap_err(), "Invalid range end value: 300");
        assert_eq!(op("20-10").unwrap_err(), "Invalid range: 20-10");
        assert_eq!(op("x").unwrap_err(), "Not able to convert 'x' into a number");
        assert_eq!(op("256").unwrap_err(), "Invalid byte value: 256");
        assert_eq!(op("1,").unwrap_err(), "Not able to convert '' into a number");
    }
}
