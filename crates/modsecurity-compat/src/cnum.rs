//! The integer a text starts with, read as C's `strtoll` and `atoll` read
//! it: leading white space, an optional sign, then the digits there are; 0
//! without digits, and the `i64` bounds when the number is beyond them.
//!
//! This is how ModSecurity reads the numbers it compares and adds (`@gt`,
//! `setvar:tx.score=+5`, `&#65;`). A request value `500abc` is 500, as for
//! PHP's `intval` or JavaScript's `parseInt`: reading it as 0 would let text
//! after a number get it past a limit rule.

use crate::chars::is_space;

/// `strtoll(s, NULL, base)`: for base 16 a `0x` or `0X` before a
/// hexadecimal digit is skipped.
pub fn strtoll(s: &[u8], base: u32) -> i64 {
    let s = &s[s.iter().take_while(|&&c| is_space(c)).count()..];
    let (negative, mut digits) = match s {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, s),
    };
    if base == 16 && digits.len() > 2 && digits[0] == b'0' && digits[1] | 0x20 == b'x' && digits[2].is_ascii_hexdigit()
    {
        digits = &digits[2..];
    }
    // The magnitude of the digits there are (`None` beyond `u64`), then the
    // sign.
    let magnitude = digits
        .iter()
        .map_while(|&c| char::from(c).to_digit(base))
        .try_fold(0u64, |m, d| m.checked_mul(u64::from(base))?.checked_add(u64::from(d)));
    match magnitude {
        Some(m) if negative => 0i64.checked_sub_unsigned(m).unwrap_or(i64::MIN),
        Some(m) => i64::try_from(m).unwrap_or(i64::MAX),
        None if negative => i64::MIN,
        None => i64::MAX,
    }
}

/// `atoll(s)`: [`strtoll`] in base 10.
pub fn atoll(s: &[u8]) -> i64 {
    strtoll(s, 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers() {
        assert_eq!(atoll(b"  -12abc"), -12);
        assert_eq!(atoll(b"\x0b\x0c+7"), 7);
        assert_eq!(atoll(b"abc"), 0);
        assert_eq!(atoll(b" -"), 0);
        assert_eq!(atoll(b"+-1"), 0);
        assert_eq!(atoll(b"99999999999999999999"), i64::MAX);
        assert_eq!(atoll(b"-99999999999999999999"), i64::MIN);
        assert_eq!(atoll(b"9223372036854775808"), i64::MAX);
        assert_eq!(atoll(b"-9223372036854775808"), i64::MIN);
        assert_eq!(atoll(b"-9223372036854775809"), i64::MIN);
        assert_eq!(strtoll(b"0x1fz", 16), 0x1f);
        assert_eq!(strtoll(b"0xz", 16), 0);
        assert_eq!(strtoll(b"0x1f", 10), 0);
        assert_eq!(strtoll(b"777", 8), 0o777);
    }

    /// `strtoll` is glibc's `strtol` (compared on generated texts).
    #[test]
    fn strtoll_matches_libc() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let alphabet = b"0123456789abcdefABCDEFxX+- \t\x0bgz:";
        for _ in 0..300_000 {
            let len = rng.random_range(0..24);
            let text: Vec<u8> = (0..len).map(|_| alphabet[rng.random_range(0..alphabet.len())]).collect();
            for base in [8u32, 10, 16] {
                let (value, _) = modsecurity_native::testing::c_strtol(&text, base as i32).unwrap();
                assert_eq!(strtoll(&text, base), value, "{:?} base {base}", String::from_utf8_lossy(&text));
            }
        }
    }
}
