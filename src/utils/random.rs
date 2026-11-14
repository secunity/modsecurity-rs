//! Random numbers for transaction unique ids.

use rand::Rng;

/// A random number uniformly distributed in `[from, to)`. The C++ code
/// draws from a `std::uniform_real_distribution` with an engine seeded from
/// `std::random_device`; here the thread local generator of the `rand`
/// crate (seeded from the operating system) is used.
pub fn random_number(from: f64, to: f64) -> f64 {
    rand::rng().random_range(from..to)
}

/// The random part of a transaction unique id, in `[0, 100)`.
pub fn generate_transaction_unique_id() -> f64 {
    random_number(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_range() {
        for _ in 0..1000 {
            let r = generate_transaction_unique_id();
            assert!((0.0..100.0).contains(&r));
        }
    }
}
