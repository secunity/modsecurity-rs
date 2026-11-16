//! The number conversions of C and C++ that the C++ library relies on
//! (`strtoll`, `atoi`, `std::stoi`, `std::stod`, `std::to_string`, `%g`),
//! with their corner cases: what counts as white space, where parsing
//! stops, and what overflow gives.

use crate::chars::is_space;

/// What `strtoll` makes of a text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Integer {
    /// The value, saturated at the `i64` bounds on overflow (as
    /// `strtoll` saturates at `LLONG_MIN`/`LLONG_MAX`); 0 without digits.
    pub value: i64,
    /// Whether the number was out of range (`ERANGE`).
    pub overflow: bool,
    /// Whether any digit was read.
    pub digits: bool,
}

/// Parses like `strtoll(s, NULL, base)`: leading white space, an optional
/// sign, for base 16 an optional `0x` or `0X` (when a hexadecimal digit
/// follows it), then digits of `base`.
pub fn strtoll(s: &[u8], base: u32) -> Integer {
    let mut i = 0;
    while i < s.len() && is_space(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    if base == 16
        && s.get(i) == Some(&b'0')
        && matches!(s.get(i + 1), Some(b'x' | b'X'))
        && s.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
    {
        i += 2;
    }
    let start = i;
    // Accumulate negatively so that i64::MIN is representable.
    let mut v: i64 = 0;
    let mut overflow = false;
    while i < s.len() {
        let Some(d) = (s[i] as char).to_digit(base) else {
            break;
        };
        match v.checked_mul(i64::from(base)).and_then(|x| x.checked_sub(i64::from(d))) {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    let digits = i > start;
    if overflow {
        return Integer { value: if neg { i64::MIN } else { i64::MAX }, overflow: true, digits };
    }
    if neg {
        Integer { value: v, overflow: false, digits }
    } else {
        match v.checked_neg() {
            Some(x) => Integer { value: x, overflow: false, digits },
            None => Integer { value: i64::MAX, overflow: true, digits },
        }
    }
}

/// Parses like `atoll` (glibc: `strtoll(s, NULL, 10)`).
pub fn atoll(s: &[u8]) -> i64 {
    strtoll(s, 10).value
}

/// Parses like glibc's `atoi`: `(int) strtol(s, NULL, 10)`.
pub fn atoi(s: &[u8]) -> i32 {
    strtoll(s, 10).value as i32
}

/// Parses like `std::stoi`: `None` where the C++ function throws (no
/// conversion, or a value out of the `int` range).
pub fn stoi(s: &[u8]) -> Option<i32> {
    let n = strtoll(s, 10);
    if !n.digits || n.overflow {
        return None;
    }
    i32::try_from(n.value).ok()
}

/// Parses an integer in `base` as `strtol(s, NULL, base)` does, truncated
/// to `int` (as the C++ code passes the result to `int` parameters).
pub fn strtol_int(s: &str, base: u32) -> i32 {
    strtoll(s.as_bytes(), base).value as i32
}

/// Formats `d` in fixed notation with six decimals, as
/// `std::to_string(double)` does.
pub fn double_to_string(d: f64) -> String {
    format!("{:.6}", d)
}

/// Parses the longest floating point prefix (after leading white space) as
/// `std::stod` does; fails when nothing can be converted or on overflow.
pub fn stod(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && is_space(b[i]) {
        i += 1;
    }
    let start = i;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let rest = &s[i..];
    let lower = rest.to_ascii_lowercase();
    if lower.starts_with("inf") || lower.starts_with("nan") {
        let n = if lower.starts_with("infinity") { 8 } else { 3 };
        return s[start..i + n].parse::<f64>().ok();
    }
    if lower.starts_with("0x") {
        // Hexadecimal floating point numbers: only the integer part is
        // supported here.
        let digits: String = rest[2..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if digits.is_empty() {
            return Some(0.0);
        }
        let v = u128::from_str_radix(&digits, 16).map(|v| v as f64).unwrap_or(f64::INFINITY);
        let neg = b.get(start) == Some(&b'-');
        return if v.is_infinite() { None } else { Some(if neg { -v } else { v }) };
    }
    let mut digits = 0;
    let mut nonzero = false;
    while i < b.len() && b[i].is_ascii_digit() {
        nonzero |= b[i] != b'0';
        digits += 1;
        i += 1;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            nonzero |= b[i] != b'0';
            digits += 1;
            i += 1;
        }
    }
    if digits == 0 {
        return None;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            i = j;
        }
    }
    let v: f64 = s[start..i].parse().ok()?;
    if v.is_infinite() || (v == 0.0 && nonzero) {
        // ERANGE: std::out_of_range
        return None;
    }
    Some(v)
}

/// C's `%.<precision>g`: the shortest of fixed and scientific notation for
/// `precision` significant digits, without trailing zeros. (Rust's `{:e}`
/// and `{:.N}` round exactly, as glibc does.)
pub fn format_g(d: f64, precision: usize) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        assert_eq!(atoll(b"  -12abc"), -12);
        assert_eq!(atoll(b"+7"), 7);
        assert_eq!(atoll(b"abc"), 0);
        assert_eq!(atoll(b"99999999999999999999"), i64::MAX);
        assert_eq!(atoll(b"-99999999999999999999"), i64::MIN);
        assert_eq!(atoll(b"-9223372036854775808"), i64::MIN);
        assert_eq!(strtoll(b"9223372036854775808", 10), Integer { value: i64::MAX, overflow: true, digits: true });
        assert_eq!(strtoll(b" -", 10), Integer { value: 0, overflow: false, digits: false });
        assert_eq!(stoi(b"\t42 "), Some(42));
        assert_eq!(stoi(b"x"), None);
        assert_eq!(stoi(b"-"), None);
        assert_eq!(stoi(b"2147483648"), None);
        assert_eq!(stoi(b"-2147483648"), Some(i32::MIN));
        // (int) of the saturated long, as glibc's atoi.
        assert_eq!(atoi(b"12x"), 12);
        assert_eq!(atoi(b"99999999999999999999"), -1);
        assert_eq!(atoi(b"-99999999999999999999"), 0);
        assert_eq!(atoi(b"4294967297"), 1);
        assert_eq!(strtol_int(" 0750", 8), 0o750);
        assert_eq!(strtol_int("\"0750\"", 8), 0);
        assert_eq!(strtol_int("-ff", 16), -255);
        // The optional prefix of base 16, only before a digit.
        assert_eq!(strtol_int("0x1f", 16), 31);
        assert_eq!(strtol_int(" -0X1f", 16), -31);
        assert_eq!(strtol_int("0xg", 16), 0);
        assert_eq!(strtol_int("0x1f", 8), 0);
    }

    /// `strtoll` is glibc's `strtol` (compared on generated texts).
    #[test]
    fn strtoll_matches_libc() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let alphabet = b"0123456789abcdefABCDEFxX+- \tgz:";
        for _ in 0..300_000 {
            let len = rng.random_range(0..24);
            let text: Vec<u8> = (0..len).map(|_| alphabet[rng.random_range(0..alphabet.len())]).collect();
            for base in [8u32, 10, 16] {
                let (value, erange) = modsecurity_native::testing::c_strtol(&text, base as i32).unwrap();
                let n = strtoll(&text, base);
                assert_eq!((n.value, n.overflow), (value, erange), "{:?} base {base}", String::from_utf8_lossy(&text));
            }
        }
    }

    #[test]
    fn floating_point() {
        assert_eq!(stod("12"), Some(12.0));
        assert_eq!(stod(" 1.5e3x"), Some(1500.0));
        assert_eq!(stod("abc"), None);
        assert_eq!(stod("1e999"), None);
        assert_eq!(double_to_string(1.5), "1.500000");
        assert_eq!(format_g(1e-5, 6), "1e-05");
        assert_eq!(format_g(123456789.0, 6), "1.23457e+08");
        assert_eq!(format_g(-0.0, 40), "-0");
    }

    /// `format_g` is `snprintf("%.Ng")` (compared on random doubles).
    #[test]
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
                let c = modsecurity_native::testing::snprintf_g(d, p);
                assert_eq!(format_g(d, p), c, "{d:e} at precision {p}");
            }
        }
    }
}
