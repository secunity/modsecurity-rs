//! Port of `src/actions/rule_id.cc`, `src/actions/rule_id.h`.
//!
//! `id:N` — the rule id (configuration time).

use crate::actions::action::{Action, Kind, name_and_payload};
use crate::rule_with_actions::RuleWithActions;

#[derive(Debug)]
pub struct RuleId {
    name: String,
    rule_id: f64,
}

impl RuleId {
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, a) = name_and_payload(action);
        // `std::stod`; whatever it accepts must also print back as the very
        // same text, so a stricter parser yields the same verdicts.
        match a.parse::<f64>() {
            Ok(rule_id) if a == format_g40(rule_id) && rule_id >= 0.0 => Ok(RuleId { name: name.to_string(), rule_id }),
            _ => Err(format!("The input \"{}\" does not seems to be a valid rule id.", a)),
        }
    }
}

/// `std::ostringstream << std::setprecision(40) << d`, i.e. `%.40g`.
fn format_g40(d: f64) -> String {
    format_g(d, 40)
}

/// C's `%.<precision>g`: the shortest of fixed and scientific notation for
/// `precision` significant digits, without trailing zeros. (Rust's `{:e}`
/// and `{:.N}` round exactly, as glibc does.)
fn format_g(d: f64, precision: usize) -> String {
    if !d.is_finite() {
        let s = if d.is_nan() { "nan" } else { "inf" };
        return if d.is_sign_negative() { format!("-{s}") } else { s.to_string() };
    }
    let p = precision.max(1);
    // The exponent of `d` rounded to `p` significant digits.
    let scientific = format!("{:.*e}", p - 1, d);
    let (mantissa, exponent) = scientific.split_once('e').expect("{:e} has an exponent");
    let exponent: i32 = exponent.parse().expect("{:e} exponent");
    let trim = |s: &str| -> String {
        if s.contains('.') { s.trim_end_matches('0').trim_end_matches('.').to_string() } else { s.to_string() }
    };
    if exponent < -4 || exponent >= p as i32 {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{}e{}{:02}", trim(mantissa), sign, exponent.unsigned_abs())
    } else {
        trim(&format!("{:.*}", (p as i32 - 1 - exponent) as usize, d))
    }
}

impl Action for RuleId {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::Configuration
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
        let a = RuleId::new(&format!("id:{}", p))?;
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
        assert_eq!(format_g(1e-5, 6), "1e-05");
        assert_eq!(format_g(123456789.0, 6), "1.23457e+08");
        assert_eq!(format_g(-0.0, 40), "-0");
    }

    /// `format_g` is `snprintf("%.Ng")` (compared on random doubles).
    #[test]
    #[allow(unsafe_code)]
    fn format_matches_snprintf() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let mut values: Vec<f64> = vec![
            0.0,
            -0.0,
            1.0,
            0.5,
            9.5,
            99.5,
            1e15,
            1e16,
            1e17,
            1e22,
            1e23,
            1e-4,
            1e-5,
            f64::MAX,
            f64::MIN_POSITIVE,
            5e-324,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];
        for _ in 0..20000 {
            values.push(f64::from_bits(rng.random::<u64>()));
            values.push(rng.random_range(0..10_000_000u64) as f64);
            values.push(rng.random::<f64>() * 10f64.powi(rng.random_range(-12..24)));
        }
        for d in values.into_iter().filter(|d| !d.is_nan()) {
            for p in [1usize, 2, 6, 17, 40] {
                let mut buf = [0 as std::ffi::c_char; 512];
                let fmt = std::ffi::CString::new(format!("%.{p}g")).unwrap();
                // SAFETY: the buffer bounds the output; the format takes one double.
                let c = unsafe {
                    libc::snprintf(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), d);
                    std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
                };
                assert_eq!(format_g(d, p), c, "{d:e} at precision {p}");
            }
        }
    }
}
