//! Byte classes and hexadecimal conversions shared by the decoders.

/// Whether `x` is a hexadecimal digit.
#[inline]
pub fn valid_hex(x: u8) -> bool {
    x.is_ascii_hexdigit()
}

/// Whether `x` is an octal digit.
#[inline]
pub fn isodigit(x: u8) -> bool {
    (b'0'..=b'7').contains(&x)
}

/// The non-breaking space of ISO 8859-1.
pub const NBSP: u8 = 160;

/// The value of a hex digit, or -1.
#[inline]
pub fn hex2dec(c: u8) -> i8 {
    match c {
        b'0'..=b'9' => (c - b'0') as i8,
        b'a'..=b'f' => (c - b'a' + 10) as i8,
        b'A'..=b'F' => (c - b'A' + 10) as i8,
        _ => -1,
    }
}

/// Converts a single hexadecimal digit into a decimal value.
#[inline]
pub fn xsingle2c(what: u8) -> u8 {
    if what >= b'A' { ((what & 0xdf).wrapping_sub(b'A')).wrapping_add(10) } else { what.wrapping_sub(b'0') }
}

/// Converts two hexadecimal digits into a byte.
#[inline]
pub fn x2c(what: &[u8]) -> u8 {
    xsingle2c(what[0]).wrapping_mul(16).wrapping_add(xsingle2c(what[1]))
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
