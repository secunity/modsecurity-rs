//! The candidates of the operators that verify a number (`@verifyCC`,
//! `@verifySSN`, `@verifyCPF`, `@verifySVNR`): the parts of a value that
//! their regular expression matches, each of which may or may not be a
//! valid number.

use crate::Param;
use modsecurity_native::regex::{Regex, Subject};

/// The regular expression of the parameter (case sensitive, multi-line);
/// a pattern that does not compile fails with the message of `@rx`.
pub(crate) fn compile(param: &Param) -> Result<Regex, String> {
    Regex::compile(&param.literal, false, true)
        .map_err(|_| format!("Invalid regular expression: {}", String::from_utf8_lossy(&param.literal)))
}

/// The first match of `re` in `input` that `verify` accepts, with where it
/// starts. Matches may overlap: after a match that is not accepted, the
/// search goes on one byte after its start.
pub(crate) fn first_verified<'a>(
    re: &Regex,
    input: &'a [u8],
    verify: impl Fn(&[u8]) -> bool,
) -> Option<(usize, &'a [u8])> {
    let subject = Subject::new(input);
    let mut from = 0;
    while from < input.len() {
        let (start, end) = re.find_at(&subject, from)?;
        let candidate = input.get(start..end)?;
        if verify(candidate) {
            return Some((start, candidate));
        }
        from = start + 1;
    }
    None
}

/// The first candidate that `verify` accepts when every suffix of `input`
/// is searched as a value of its own, with where it starts in `input`.
/// The candidates of a suffix are the groups of its successive matches,
/// last first.
///
/// This is how `@verifySSN`, `@verifyCPF` and `@verifySVNR` read their
/// expression: an anchor such as `^` holds at the start of every suffix,
/// so a number in the middle of a value is found by an expression written
/// `^...$`. The price is one search per byte of the value.
pub(crate) fn first_verified_in_a_suffix(
    re: &Regex,
    input: &[u8],
    verify: impl Fn(&[u8]) -> bool,
) -> Option<(usize, Vec<u8>)> {
    (0..input.len().saturating_sub(1)).find_map(|from| {
        let found = re.search_all(&input[from..]).into_iter().find(|m| verify(m.str()))?;
        Some((from + found.offset(), found.str().to_vec()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    /// What `@verifyCC` did: the first match from every offset.
    fn any_from_any_offset(re: &Regex, input: &[u8], verify: impl Fn(&[u8]) -> bool) -> bool {
        let subject = Subject::new(input);
        (0..input.len())
            .map_while(|offset| re.find_at(&subject, offset))
            .any(|(start, end)| input.get(start..end).is_some_and(&verify))
    }

    /// The scanner finds a valid number exactly when the scan of
    /// `@verifyCC` it replaces did, on generated values.
    #[test]
    fn same_answers_as_the_scans_it_replaces() {
        let digits_sum_to_multiple_of_five =
            |m: &[u8]| m.iter().filter(|c| c.is_ascii_digit()).map(|c| usize::from(c - b'0')).sum::<usize>() % 5 == 0;
        let mut rng = rand::rngs::StdRng::seed_from_u64(5);
        const PIECES: &[&[u8]] = &[b"0", b"1", b"2", b"3", b"7", b"9", b"-", b".", b" ", b"x", b"12", b"345", b"\n"];
        let mut found = 0;
        for pattern in
            [r"\d{3}-?\d{2}-?\d{4}", r"[0-9]{3}\.?[0-9]{3}", r"\d{4,6}", r"^\d{3}", r"\d\d$", r"(\d{2})\.(\d{2})"]
        {
            let re = Regex::new(pattern);
            for _ in 0..20_000 {
                let input: Vec<u8> = (0..rng.random_range(0..14))
                    .flat_map(|_| PIECES[rng.random_range(0..PIECES.len())].to_vec())
                    .collect();
                let new = first_verified(&re, &input, digits_sum_to_multiple_of_five).is_some();
                found += usize::from(new);
                assert_eq!(
                    new,
                    any_from_any_offset(&re, &input, digits_sum_to_multiple_of_five),
                    "{pattern} {input:?}"
                );
            }
        }
        assert!(found > 5_000, "{found}");
    }

    #[test]
    fn where_the_candidate_is() {
        let re = Regex::new(r"\d{3}");
        let ends_in_nine = |m: &[u8]| m.ends_with(b"9");
        // 123 and 234 are not accepted; 349 overlaps both.
        assert_eq!(first_verified(&re, b"a12349", ends_in_nine), Some((3, &b"349"[..])));
        assert_eq!(first_verified(&re, b"a1234", ends_in_nine), None);
        assert_eq!(first_verified(&re, b"", ends_in_nine), None);
    }

    /// In a suffix of its own, an anchored expression finds a number in
    /// the middle of a value, and the position is the one in the value.
    #[test]
    fn suffixes() {
        let re = Regex::new(r"^\d{3}$");
        let any = |_: &[u8]| true;
        assert_eq!(first_verified(&re, b"ab123", any), None);
        assert_eq!(first_verified_in_a_suffix(&re, b"ab123", any), Some((2, b"123".to_vec())));
        assert_eq!(first_verified_in_a_suffix(&re, b"ab12", any), None);
        // The last byte alone is not searched.
        assert_eq!(first_verified_in_a_suffix(&Regex::new(r"^\d$"), b"ab1", any), None);
    }

    /// A group that ends before the match (in a lookbehind) does not keep
    /// the search of a suffix at the same place.
    #[test]
    fn a_group_in_a_lookbehind() {
        let re = Regex::new(r"(?<=(a))b");
        assert_eq!(first_verified_in_a_suffix(&re, b"xab", |_| false), None);
        assert_eq!(first_verified_in_a_suffix(&re, b"xab", |m| m == b"b"), Some((2, b"b".to_vec())));
    }
}
