//! The bound on the total size of the argument names a body processor
//! gives (JSON and XML).
//!
//! Every argument of a JSON or XML body is named after its whole path, so
//! one long key or element name high in the document is repeated in the
//! name of every value below it: a 1 MB body of one 500 KB key over an
//! array of 250 000 numbers names its arguments with 137 GB. A limit on
//! the length of one name does not prevent this (64 KiB names times the
//! number of values a body can hold is still tens of gigabytes), so the
//! total is bounded instead, in proportion to the body.
//!
//! The allowance is [`NAMES_BASE`] plus [`NAMES_PER_BODY_BYTE`] times the
//! size of the body. In an ordinary document the names are a few times the
//! size of the body: an array of one-digit numbers four arrays deep (2
//! bytes a value, `json.array_0.array_12.array_3.array_4` for a name) is
//! about 20 times. 64 times leaves room for documents several times deeper
//! than that, and keeps the names of a 1 MB body under 65 MB.

/// The allowance of every body, however small.
pub(crate) const NAMES_BASE: usize = 1 << 20;

/// The allowance for every byte of the body.
pub(crate) const NAMES_PER_BODY_BYTE: usize = 64;

/// What is left of the allowance of argument names for a body.
#[derive(Debug)]
pub(crate) struct NameBudget {
    left: usize,
}

impl NameBudget {
    /// The allowance of an empty body.
    pub(crate) fn new() -> Self {
        NameBudget { left: NAMES_BASE }
    }

    /// The allowance of a body of `len` bytes.
    pub(crate) fn for_body(len: usize) -> Self {
        let mut budget = Self::new();
        budget.add_body(len);
        budget
    }

    /// Adds the allowance of `len` more bytes of body.
    pub(crate) fn add_body(&mut self, len: usize) {
        self.left = self.left.saturating_add(len.saturating_mul(NAMES_PER_BODY_BYTE));
    }

    /// Takes a name of `len` bytes from the allowance; `false` (and nothing
    /// taken) when it does not fit.
    pub(crate) fn take(&mut self, len: usize) -> bool {
        match self.left.checked_sub(len) {
            Some(left) => {
                self.left = left;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowance_grows_with_the_body() {
        let mut budget = NameBudget::for_body(10);
        assert!(budget.take(NAMES_BASE + 10 * NAMES_PER_BODY_BYTE - 1));
        assert!(!budget.take(2));
        assert!(budget.take(1));
        assert!(!budget.take(1));
        budget.add_body(1);
        assert!(budget.take(NAMES_PER_BODY_BYTE));
        let mut huge = NameBudget::for_body(usize::MAX);
        assert!(huge.take(usize::MAX));
    }
}
