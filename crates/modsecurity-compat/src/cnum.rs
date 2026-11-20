//! The number conversions of C (`strtoll`, `atoll`),
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
        // (int) of the saturated long, as glibc's atoi.
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
}
