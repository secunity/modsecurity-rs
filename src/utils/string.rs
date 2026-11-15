//! String helpers: hex conversions, splitting, trimming and number parsing.
//!
//! C++ `std::string` is a byte string; the helpers here therefore operate on
//! `&[u8]`/`Vec<u8>`. Helpers that only ever see configuration text also
//! have `&str` conveniences.

pub use modsecurity_transformations::chars::{is_space, string_to_hex, valid_hex};

/// The local time `t` formatted by `strftime("%c")`.
pub fn asc_time(t: i64) -> String {
    crate::utils::system::strftime_local(t, "%c")
}

/// The bytes of `s`, or `-` when it is missing or empty.
pub fn dash_if_empty(s: Option<&[u8]>) -> Vec<u8> {
    match s {
        Some(s) if !s.is_empty() => s.to_vec(),
        _ => b"-".to_vec(),
    }
}

/// `s` cut to `amount` bytes, followed by ` (N characters omitted)` when
/// it was longer.
pub fn limit_to(amount: usize, s: &[u8]) -> Vec<u8> {
    if s.len() > amount {
        let mut ret = s[..amount].to_vec();
        ret.extend_from_slice(format!(" ({} characters omitted)", s.len() - amount).as_bytes());
        return ret;
    }
    s.to_vec()
}

/// Escapes non printable bytes as `\xHH` (and, with
/// `escape_spec`, also `"` and `\`). The result is always ASCII.
pub fn to_hex_if_needed(s: &[u8], escape_spec: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut res = String::with_capacity(s.len());
    for &c in s {
        if !(32..=126).contains(&c) || (escape_spec && (c == 34 || c == 92)) {
            res.push_str("\\x");
            res.push(HEX[usize::from(c >> 4)] as char);
            res.push(HEX[usize::from(c & 15)] as char);
        } else {
            res.push(c as char);
        }
    }
    res
}

/// Splits `s` at every `delimiter` as `std::getline` does: a trailing
/// delimiter does not produce an empty trailing element, and an empty input
/// produces nothing.
pub fn ssplit(s: &[u8], delimiter: u8) -> Vec<Vec<u8>> {
    let mut internal = Vec::new();
    if s.is_empty() {
        return internal;
    }
    let mut parts: Vec<&[u8]> = s.split(|&c| c == delimiter).collect();
    if s.last() == Some(&delimiter) {
        parts.pop();
    }
    for p in parts {
        internal.push(p.to_vec());
    }
    internal
}

/// Splits `s` at its first `delimiter`; the second half is empty when
/// there is none.
pub fn ssplit_pair(s: &[u8], delimiter: u8) -> (Vec<u8>, Vec<u8>) {
    match s.iter().position(|&c| c == delimiter) {
        Some(p) => (s[..p].to_vec(), s[p + 1..].to_vec()),
        None => (s.to_vec(), Vec::new()),
    }
}

/// Like [`ssplit`], but an input that produces nothing gives one element:
/// the input itself.
pub fn split(s: &[u8], delimiter: u8) -> Vec<Vec<u8>> {
    let mut internal = ssplit(s, delimiter);
    if internal.is_empty() {
        internal.push(s.to_vec());
    }
    internal
}

/// [`split`] for configuration strings.
pub fn split_str(s: &str, delimiter: char) -> Vec<String> {
    split(s.as_bytes(), delimiter as u8).into_iter().map(|v| String::from_utf8_lossy(&v).into_owned()).collect()
}

/// Removes the trailing `\n` and `\r` characters of `s` (an input made of
/// only those is left unchanged).
pub fn chomp(s: &mut Vec<u8>) {
    if let Some(pos) = s.iter().rposition(|&c| c != b'\n' && c != b'\r') {
        s.truncate(pos + 1);
    }
}

/// The position of the first `needle` in `haystack` at or after `pos`
/// (as `std::string::find`).
pub fn find_from(haystack: &[u8], needle: &[u8], pos: usize) -> Option<usize> {
    if pos > haystack.len() {
        return None;
    }
    if needle.is_empty() {
        return Some(pos);
    }
    haystack[pos..].windows(needle.len()).position(|w| w == needle).map(|p| p + pos)
}

/// The position of the first `needle` in `haystack`.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_from(haystack, needle, 0)
}

/// Removes leading and trailing spaces, leaving at least one character.
pub fn remove_white_spaces_if_needed(mut a: String) -> String {
    while a.len() > 1 && a.starts_with(' ') {
        a.remove(0);
    }
    while a.len() > 1 && a.ends_with(' ') {
        a.pop();
    }
    a
}

/// Removes one pair of surrounding double quotes, then one pair of single
/// quotes.
pub fn remove_brackets_if_needed(mut a: String) -> String {
    if a.len() > 1 && a.starts_with('"') && a.ends_with('"') {
        a.pop();
        a.remove(0);
    }
    if a.len() > 1 && a.starts_with('\'') && a.ends_with('\'') {
        a.pop();
        a.remove(0);
    }
    a
}

/// Trims the spaces around a configuration value, then its quotes.
pub fn parser_sanitizer(a: String) -> String {
    remove_brackets_if_needed(remove_white_spaces_if_needed(a))
}

/// Lowercases every byte (C locale `::tolower`).
pub fn tolower(s: &[u8]) -> Vec<u8> {
    s.to_ascii_lowercase()
}

/// Upper-cases the ASCII letters of a configuration string.
pub fn toupper_str(s: &str) -> String {
    s.to_ascii_uppercase()
}

/// Lossy view of bytes for log messages.
#[inline]
pub fn lossy(s: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(s)
}

/// Formats `d` in fixed notation with six decimals, as
/// `std::to_string(double)` does.
pub fn double_to_string(d: f64) -> String {
    format!("{:.6}", d)
}

/// Parses an integer as `atoi` does: leading whitespace, optional sign,
/// decimal digits; 0 on failure.
pub fn atoi(s: &[u8]) -> i64 {
    let mut i = 0;
    while i < s.len() && is_space(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((s[i] - b'0') as i64);
        i += 1;
    }
    if neg { -v } else { v }
}

/// Like [`atoi`] (and `std::stoi`), but reports whether any digit was
/// consumed (C++ throws `std::invalid_argument` otherwise).
pub fn stoi(s: &[u8]) -> Option<i64> {
    let mut i = 0;
    while i < s.len() && is_space(s[i]) {
        i += 1;
    }
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        i += 1;
    }
    if i < s.len() && s[i].is_ascii_digit() { Some(atoi(s)) } else { None }
}

fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Parses an integer in `base` as `strtol(s, NULL, base)` does, truncated
/// to `int` (as the C++ code passes the result to `int` parameters).
pub fn strtol_int(s: &str, base: u32) -> i32 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && is_c_space(b[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    let mut overflow = false;
    while i < b.len() {
        let Some(d) = (b[i] as char).to_digit(base) else {
            break;
        };
        match v.checked_mul(i64::from(base)).and_then(|x| x.checked_add(i64::from(d))) {
            Some(n) => v = n,
            None => overflow = true,
        }
        i += 1;
    }
    let v = if overflow {
        if neg { i64::MIN } else { i64::MAX }
    } else if neg {
        -v
    } else {
        v
    };
    v as i32
}

/// Parses the longest floating point prefix (after leading white space) as
/// `std::stod` does; fails when nothing can be converted or on overflow.
pub fn stod(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && is_c_space(b[i]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_hex_if_needed_matches_format() {
        let all: Vec<u8> = (0..=255).collect();
        for spec in [false, true] {
            let expected: String = all
                .iter()
                .map(|&c| {
                    if !(32..=126).contains(&c) || (spec && (c == 34 || c == 92)) {
                        format!("\\x{:02x}", c)
                    } else {
                        (c as char).to_string()
                    }
                })
                .collect();
            assert_eq!(to_hex_if_needed(&all, spec), expected);
        }
    }

    #[test]
    fn ssplit_matches_getline() {
        assert_eq!(ssplit(b"a&b&", b'&'), vec![b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(ssplit(b"&a", b'&'), vec![b"".to_vec(), b"a".to_vec()]);
        assert!(ssplit(b"", b'&').is_empty());
        assert_eq!(ssplit(b"&&", b'&'), vec![b"".to_vec(), b"".to_vec()]);
    }

    #[test]
    fn limit_and_hex() {
        assert_eq!(limit_to(3, b"abcdef"), b"abc (3 characters omitted)".to_vec());
        assert_eq!(to_hex_if_needed(b"a\x01\"", true), "a\\x01\\x22");
        assert_eq!(to_hex_if_needed(b"a\x01\"", false), "a\\x01\"");
    }
}
