//! Port of `src/utils/string.h`.
//!
//! C++ `std::string` is a byte string; the helpers here therefore operate on
//! `&[u8]`/`Vec<u8>`. Helpers that only ever see configuration text also
//! have `&str` conveniences.

/// `VALID_HEX`
#[inline]
pub fn valid_hex(x: u8) -> bool {
    x.is_ascii_hexdigit()
}

/// `ISODIGIT`
#[inline]
pub fn isodigit(x: u8) -> bool {
    (b'0'..=b'7').contains(&x)
}

pub const NBSP: u8 = 160;

/// `HEX2DEC`: value of a hex digit, or -1.
#[inline]
pub fn hex2dec(c: u8) -> i8 {
    match c {
        b'0'..=b'9' => (c - b'0') as i8,
        b'a'..=b'f' => (c - b'a' + 10) as i8,
        b'A'..=b'F' => (c - b'A' + 10) as i8,
        _ => -1,
    }
}

/// `ascTime`: `strftime("%c")` of the local time.
pub fn asc_time(t: i64) -> String {
    crate::utils::system::strftime_local(t, "%c")
}

/// `dash_if_empty`
pub fn dash_if_empty(s: Option<&[u8]>) -> Vec<u8> {
    match s {
        Some(s) if !s.is_empty() => s.to_vec(),
        _ => b"-".to_vec(),
    }
}

/// `limitTo`
pub fn limit_to(amount: usize, s: &[u8]) -> Vec<u8> {
    if s.len() > amount {
        let mut ret = s[..amount].to_vec();
        ret.extend_from_slice(format!(" ({} characters omitted)", s.len() - amount).as_bytes());
        return ret;
    }
    s.to_vec()
}

/// `toHexIfNeeded`: escapes non printable bytes as `\xHH` (and, with
/// `escape_spec`, also `"` and `\`). The result is always ASCII.
pub fn to_hex_if_needed(s: &[u8], escape_spec: bool) -> String {
    let mut res = String::with_capacity(s.len());
    for &c in s {
        if !(32..=126).contains(&c) || (escape_spec && (c == 34 || c == 92)) {
            res.push_str(&format!("\\x{:02x}", c));
        } else {
            res.push(c as char);
        }
    }
    res
}

/// `ssplit`: `std::getline` based split (a trailing delimiter does not
/// produce an empty trailing element; an empty input produces nothing).
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

/// `ssplit_pair`
pub fn ssplit_pair(s: &[u8], delimiter: u8) -> (Vec<u8>, Vec<u8>) {
    match s.iter().position(|&c| c == delimiter) {
        Some(p) => (s[..p].to_vec(), s[p + 1..].to_vec()),
        None => (s.to_vec(), Vec::new()),
    }
}

/// `split`
pub fn split(s: &[u8], delimiter: u8) -> Vec<Vec<u8>> {
    let mut internal = ssplit(s, delimiter);
    if internal.is_empty() {
        internal.push(s.to_vec());
    }
    internal
}

/// `split` for configuration strings.
pub fn split_str(s: &str, delimiter: char) -> Vec<String> {
    split(s.as_bytes(), delimiter as u8).into_iter().map(|v| String::from_utf8_lossy(&v).into_owned()).collect()
}

/// `chomp`
pub fn chomp(s: &mut Vec<u8>) {
    if let Some(pos) = s.iter().rposition(|&c| c != b'\n' && c != b'\r') {
        s.truncate(pos + 1);
    }
}

/// `replaceAll`
pub fn replace_all(s: &mut Vec<u8>, from: &[u8], to: &[u8]) {
    if from.is_empty() {
        return;
    }
    let mut start = 0;
    while let Some(p) = find_from(s, from, start) {
        s.splice(p..p + from.len(), to.iter().copied());
        start = p + to.len();
    }
}

/// `replaceAll` for configuration strings.
pub fn replace_all_str(s: &mut String, from: &str, to: &str) {
    let mut v = std::mem::take(s).into_bytes();
    replace_all(&mut v, from.as_bytes(), to.as_bytes());
    *s = String::from_utf8(v).unwrap_or_default();
}

/// `std::string::find(needle, pos)`.
pub fn find_from(haystack: &[u8], needle: &[u8], pos: usize) -> Option<usize> {
    if pos > haystack.len() {
        return None;
    }
    if needle.is_empty() {
        return Some(pos);
    }
    haystack[pos..].windows(needle.len()).position(|w| w == needle).map(|p| p + pos)
}

/// `std::string::find(needle)`.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_from(haystack, needle, 0)
}

/// `removeWhiteSpacesIfNeeded`
pub fn remove_white_spaces_if_needed(mut a: String) -> String {
    while a.len() > 1 && a.starts_with(' ') {
        a.remove(0);
    }
    while a.len() > 1 && a.ends_with(' ') {
        a.pop();
    }
    a
}

/// `removeBracketsIfNeeded`
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

/// `parserSanitizer`
pub fn parser_sanitizer(a: String) -> String {
    remove_brackets_if_needed(remove_white_spaces_if_needed(a))
}

/// `xsingle2c`: converts a single hexadecimal digit into a decimal value.
#[inline]
pub fn xsingle2c(what: u8) -> u8 {
    if what >= b'A' { ((what & 0xdf).wrapping_sub(b'A')).wrapping_add(10) } else { what.wrapping_sub(b'0') }
}

/// `x2c`: converts two hexadecimal digits into a byte.
#[inline]
pub fn x2c(what: &[u8]) -> u8 {
    xsingle2c(what[0]).wrapping_mul(16).wrapping_add(xsingle2c(what[1]))
}

/// `c2x`: appends the two lowercase hex digits of `what`.
#[inline]
pub fn c2x(what: u32, out: &mut Vec<u8>) {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let what = what & 0xff;
    out.push(TABLE[(what >> 4) as usize]);
    out.push(TABLE[(what & 0x0f) as usize]);
}

/// `string_to_hex`
pub fn string_to_hex(input: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut a = String::with_capacity(input.len() * 2);
    for &c in input {
        a.push(LUT[(c >> 4) as usize] as char);
        a.push(LUT[(c & 15) as usize] as char);
    }
    a
}

/// `tolower` (C locale `::tolower` on every byte).
pub fn tolower(s: &[u8]) -> Vec<u8> {
    s.to_ascii_lowercase()
}

/// `toupper` (C locale `::toupper` on every byte).
pub fn toupper(s: &[u8]) -> Vec<u8> {
    s.to_ascii_uppercase()
}

/// `tolower` for configuration strings.
pub fn tolower_str(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// `toupper` for configuration strings.
pub fn toupper_str(s: &str) -> String {
    s.to_ascii_uppercase()
}

/// `::isspace` in the C locale.
#[inline]
pub fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

/// Case insensitive (ASCII) equality, as used by the many `std::equal(...,
/// tolower(a) == tolower(b))` comparisons of the C++ code.
#[inline]
pub fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Lossy view of bytes for log messages.
#[inline]
pub fn lossy(s: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(s)
}

/// `std::to_string(double)`: fixed notation with six decimals.
pub fn double_to_string(d: f64) -> String {
    format!("{:.6}", d)
}

/// `atoi`: leading whitespace, optional sign, decimal digits; 0 on failure.
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

/// `std::stoi`-like parse: like [`atoi`] but reports whether any digit was
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

    #[test]
    fn replace() {
        let mut s = b"%d and %d".to_vec();
        replace_all(&mut s, b"%d", b"403");
        assert_eq!(s, b"403 and 403".to_vec());
    }
}
