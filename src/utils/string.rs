//! String helpers: hex conversions, splitting, trimming and number parsing.
//!
//! C++ `std::string` is a byte string; the helpers here therefore operate on
//! `&[u8]`/`Vec<u8>`. Helpers that only ever see configuration text also
//! have `&str` conveniences.

pub use modsecurity_compat::chars::{
    find_from, is_space, limit_to, split, ssplit, ssplit_pair, string_to_hex, to_hex_if_needed,
};
pub use modsecurity_compat::cnum::{atoi, stod, stoi, strtol_int};

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

// The helpers that clean a configuration value are part of the syntax.
pub use modsecurity_seclang::value::sanitize as parser_sanitizer;

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
