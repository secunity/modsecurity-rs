//! String helpers: hex conversions, splitting, trimming and number parsing.
//!
//! C++ `std::string` is a byte string; the helpers here therefore operate on
//! `&[u8]`/`Vec<u8>`. Helpers that only ever see configuration text also
//! have `&str` conveniences.

pub use modsecurity_compat::chars::{
    find_from, is_space, limit_to, split, ssplit, ssplit_pair, string_to_hex, to_hex_if_needed,
};
pub use modsecurity_compat::cnum::{double_to_string, stod, strtol_int};

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
