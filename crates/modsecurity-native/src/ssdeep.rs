//! libfuzzy (ssdeep): fuzzy hashes and their comparison.

use std::ffi::{CStr, CString, c_char};

/// The length of an ssdeep signature (`SPAMSUM_LENGTH` in fuzzy.h).
const SPAMSUM_LENGTH: usize = 64;
/// The size of a `fuzzy_hash_buf` result buffer (`FUZZY_MAX_RESULT`).
const FUZZY_MAX_RESULT: usize = 2 * SPAMSUM_LENGTH + 20;

// libfuzzy (fuzzy.h)
unsafe extern "C" {
    fn fuzzy_hash_buf(buf: *const u8, buf_len: u32, result: *mut c_char) -> i32;
    fn fuzzy_compare(sig1: *const c_char, sig2: *const c_char) -> i32;
}

/// The signature of `buf` (`fuzzy_hash_buf`), or `None` when libfuzzy
/// fails. The length is passed as 32 bits, as the C++ call does.
pub fn hash(buf: &[u8]) -> Option<CString> {
    let mut result = [0 as c_char; FUZZY_MAX_RESULT];
    // SAFETY: `buf` is readable for its length (truncated to 32 bits, never
    // more than it has) and `result` has room for FUZZY_MAX_RESULT bytes, as
    // fuzzy_hash_buf requires.
    let rc = unsafe { fuzzy_hash_buf(buf.as_ptr(), buf.len() as u32, result.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: fuzzy_hash_buf NUL terminates its result within the buffer.
    Some(unsafe { CStr::from_ptr(result.as_ptr()) }.to_owned())
}

/// The similarity (0 to 100) of two signatures (`fuzzy_compare`); -1 on
/// error.
pub fn compare(sig1: &CStr, sig2: &CStr) -> i32 {
    // SAFETY: both arguments are NUL terminated strings.
    unsafe { fuzzy_compare(sig1.as_ptr(), sig2.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_compare() {
        let text: Vec<u8> = (0..4096u32).map(|i| (i * 7 % 251) as u8).collect();
        let a = hash(&text).unwrap();
        assert!(a.to_bytes().contains(&b':'));
        assert_eq!(compare(&a, &a), 100);
        assert_eq!(compare(&a, c"3:x:y"), 0);
    }
}
