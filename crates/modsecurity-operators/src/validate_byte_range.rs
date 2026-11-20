//! The `@validateByteRange` operator: matches when the input holds a byte
//! outside the allowed values and ranges.

use crate::{Context, Operator, Param, Resources};

#[derive(Debug)]
pub struct ValidateByteRange {
    param: Param,
    /// Bitmap of the accepted byte values.
    table: [u8; 32],
}

impl ValidateByteRange {
    pub fn new(param: Param) -> Self {
        ValidateByteRange { param, table: [0; 32] }
    }

    fn set(&mut self, b: u8) {
        self.table[usize::from(b >> 3)] |= 1 << (b & 0x7);
    }

    /// Adds `N` or `N-M` to the table.
    pub fn add_range(&mut self, range_representation: &[u8]) -> Result<(), String> {
        // A number in decimal digits, with white space around it allowed
        // (`37-102, 127-255`); what it is too large for is said by the
        // caller.
        let number = |text: &[u8]| {
            let trimmed = std::str::from_utf8(text.trim_ascii()).ok();
            let digits = trimmed.filter(|t| !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit()));
            digits
                .map(|t| t.parse::<u64>().unwrap_or(u64::MAX))
                .ok_or_else(|| format!("Not able to convert '{}' into a number", String::from_utf8_lossy(text)))
        };
        let byte = |n: u64, what: &str| u8::try_from(n).map_err(|_| format!("Invalid {what} value: {n}"));

        let Some(pos) = range_representation.iter().position(|&c| c == b'-') else {
            let value = byte(number(range_representation)?, "byte")?;
            self.set(value);
            return Ok(());
        };
        let (start, end) = (number(&range_representation[..pos])?, number(&range_representation[pos + 1..])?);
        let (start, end) = (byte(start, "range start")?, byte(end, "range end")?);
        if start > end {
            return Err(format!("Invalid range: {}-{}", start, end));
        }
        for b in start..=end {
            self.set(b);
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

    fn init(&mut self, _file: &str, _resources: &dyn Resources) -> Result<(), String> {
        let param = self.param.literal.clone();
        // Comma separated list of ranges (empty pieces fail to convert).
        for range in param.split(|&c| c == b',') {
            self.add_range(range)?;
        }
        Ok(())
    }

    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let mut count = 0usize;
        for (i, &x) in input.iter().enumerate() {
            if self.table[usize::from(x >> 3)] & (1 << (x & 0x7)) == 0 {
                cx.offset(i, 1);
                count += 1;
            }
        }

        count != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::eval;

    fn op(p: &str) -> Result<ValidateByteRange, String> {
        let mut o = ValidateByteRange::new(Param::from_text(p));
        o.init("", &crate::test_support::LocalFiles).map(|_| o)
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
