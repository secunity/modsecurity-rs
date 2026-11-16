//! The text of error numbers, as the C library gives it.

/// `strerror(errno)`: the text of an error number (through std, which
/// uses the thread safe `strerror_r`).
pub fn strerror(errnum: i32) -> String {
    let text = std::io::Error::from_raw_os_error(errnum).to_string();
    let suffix = format!(" (os error {})", errnum);
    text.strip_suffix(&suffix).map(str::to_owned).unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strerror_matches_libc() {
        for errnum in 0..200 {
            let c = modsecurity_native::testing::strerror(errnum);
            assert_eq!(strerror(errnum), c, "errno {errnum}");
        }
    }
}
