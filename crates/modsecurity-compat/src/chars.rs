//! Byte classes, hexadecimal conversions and small string helpers: searching
//! and splitting with the corner cases of `std::string::find` and
//! `std::getline`, the log escaping and truncation, C string views.

/// Whether `x` is an octal digit.
#[inline]
pub fn isodigit(x: u8) -> bool {
    (b'0'..=b'7').contains(&x)
}

/// The non-breaking space of ISO 8859-1.
pub const NBSP: u8 = 160;

/// The value of a hexadecimal digit (either case).
#[inline]
pub fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The byte written by the two hexadecimal digits that `s` starts with;
/// `None` when it does not start with two.
#[inline]
pub fn hex_pair(s: &[u8]) -> Option<u8> {
    match s {
        [high, low, ..] => Some(hex_digit(*high)? << 4 | hex_digit(*low)?),
        _ => None,
    }
}

/// Appends the two lowercase hex digits of `what`.
#[inline]
pub fn c2x(what: u32, out: &mut Vec<u8>) {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let what = what & 0xff;
    out.push(TABLE[(what >> 4) as usize]);
    out.push(TABLE[(what & 0x0f) as usize]);
}

/// The lowercase hexadecimal form of `input`, two digits per byte.
pub fn string_to_hex(input: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut a = String::with_capacity(input.len() * 2);
    for &c in input {
        a.push(LUT[(c >> 4) as usize] as char);
        a.push(LUT[(c & 15) as usize] as char);
    }
    a
}

/// Whether `c` is white space (`::isspace` in the C locale).
#[inline]
pub fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
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

/// The position of the first `needle` in `haystack` at or after `pos`
/// (as `std::string::find`).
pub fn find_from(haystack: &[u8], needle: &[u8], pos: usize) -> Option<usize> {
    memchr::memmem::find(haystack.get(pos..)?, needle).map(|p| p + pos)
}

/// The position of the first `needle` in `haystack`.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_from(haystack, needle, 0)
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

/// Removes the trailing `\n` and `\r` characters of `s` (an input made of
/// only those is left unchanged).
pub fn chomp(s: &mut Vec<u8>) {
    if let Some(pos) = s.iter().rposition(|&c| c != b'\n' && c != b'\r') {
        s.truncate(pos + 1);
    }
}

/// `s` as C code sees it through a `const char *`: up to its first NUL
/// byte. Used where a value goes to a C function, and where a result the
/// tests expect was defined by one: what follows a NUL byte is ignored.
#[inline]
pub fn c_str(s: &[u8]) -> &[u8] {
    match s.iter().position(|&c| c == 0) {
        Some(end) => &s[..end],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_digits() {
        assert_eq!(hex_digit(b'7'), Some(7));
        assert_eq!(hex_digit(b'b'), Some(11));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'g'), None);
        assert_eq!(hex_pair(b"4a"), Some(0x4a));
        assert_eq!(hex_pair(b"ffzz"), Some(0xff));
        assert_eq!(hex_pair(b"f"), None);
        assert_eq!(hex_pair(b"fz"), None);
        assert_eq!(hex_pair(b""), None);
    }

    /// The corner cases of `std::string::find`.
    #[test]
    fn find_from_corner_cases() {
        assert_eq!(find(b"abcabc", b"ca"), Some(2));
        assert_eq!(find_from(b"abcabc", b"abc", 1), Some(3));
        assert_eq!(find_from(b"abc", b"", 3), Some(3));
        assert_eq!(find_from(b"abc", b"", 4), None);
        assert_eq!(find_from(b"abc", b"c", 3), None);
        assert_eq!(find(b"", b""), Some(0));
        assert_eq!(find(b"ab", b"abc"), None);
    }
}
