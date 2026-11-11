//! Port of `src/utils/random.h` / `src/utils/random.cc`.

/// `random_number`: uniformly distributed in `[from, to)`, seeded from the
/// operating system (the C++ code seeds a fresh engine from
/// `std::random_device` on every call).
pub fn random_number(from: f64, to: f64) -> f64 {
    let mut buf = [0u8; 8];
    // SAFETY: getrandom writes at most buf.len() bytes into buf.
    let n = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    let r = if n == buf.len() as isize {
        u64::from_ne_bytes(buf)
    } else {
        // Fallback: time based.
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
    };
    // 53 random bits -> [0, 1)
    let unit = (r >> 11) as f64 / (1u64 << 53) as f64;
    from + unit * (to - from)
}

/// `generate_transaction_unique_id`
pub fn generate_transaction_unique_id() -> f64 {
    random_number(0.0, 100.0)
}
