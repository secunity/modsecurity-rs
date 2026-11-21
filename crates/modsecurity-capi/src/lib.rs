//! The libmodsecurity C API: the `msc_*` functions, with the C structures and
//! memory conventions of `modsecurity/modsecurity.h`, `rules_set.h` and
//! `transaction.h`.
//!
//! This is where Rust meets C callers: raw pointers are checked and turned
//! into references here, and the engine (the `modsecurity` crate) is used
//! through its Rust API.

pub mod intervention;
pub mod modsecurity;
pub mod rules_set;
pub mod transaction;

/// Runs `f`, the body of an `msc_*` function. A panic in `f` does not
/// unwind into the C caller (that aborts the process): the function returns
/// `on_panic`, its error value, instead. The panic hook has already printed
/// the message (to stderr by default).
pub(crate) fn catch_panic<T>(on_panic: T, f: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(on_panic)
}

#[cfg(test)]
mod tests {
    use super::catch_panic;
    use std::ffi::c_int;

    extern "C" fn panics() -> c_int {
        catch_panic(-1, || panic!("a bug"))
    }

    #[test]
    fn a_panic_gives_the_error_value() {
        assert_eq!(panics(), -1);
        assert_eq!(catch_panic(-1, || 3), 3);
    }
}
