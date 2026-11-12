//! Port of `src/actions/transformations/lower_case.cc` and `upper_case.cc`
//! (with their headers).

/// `LowerCase::convert`: applies `op` to every byte; returns whether any
/// byte changed.
fn convert(val: &mut [u8], op: impl Fn(u8) -> u8) -> bool {
    let mut changed = false;
    for c in val.iter_mut() {
        let nc = op(*c);
        if nc != *c {
            changed = true;
        }
        *c = nc;
    }
    changed
}

/// `t:lowercase` (`std::tolower` in the C locale).
pub fn lower(value: &mut [u8]) -> bool {
    convert(value, |c| c.to_ascii_lowercase())
}

/// `t:uppercase` (`std::toupper` in the C locale).
pub fn upper(value: &mut [u8]) -> bool {
    convert(value, |c| c.to_ascii_uppercase())
}
