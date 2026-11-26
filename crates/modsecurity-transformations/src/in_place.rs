//! The loop of the decoders whose escapes each decode to one byte.

/// Decodes `value` in place. At each position, `escape` reads the input
/// from there: `Some((byte, len))` when an escape of `len` bytes starts
/// there and decodes to `byte`, `None` to keep the byte as it is.
///
/// An escape is never shorter than what it decodes to, so the output
/// (`value[..write]`) never catches up with the input (`value[read..]`).
#[inline]
pub(crate) fn decode(value: &mut Vec<u8>, escape: impl Fn(&[u8]) -> Option<(u8, usize)>) {
    let mut read = 0;
    let mut write = 0;
    while read < value.len() {
        let (byte, len) = escape(&value[read..]).unwrap_or((value[read], 1));
        value[write] = byte;
        write += 1;
        read += len;
    }
    value.truncate(write);
}
