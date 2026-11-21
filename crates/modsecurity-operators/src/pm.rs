//! The `@pm` operator: matches when the input contains one of a set of
//! phrases (case insensitive).

use crate::{Context, Operator, Param};

/// Strips optional surrounding quotes and decodes the `|hex|` blocks and
/// the `\:`, `\;`, `\\` and `\"` escapes. On any invalid sequence the
/// parameter is returned unchanged.
pub fn parse_pm_content(op_parm: &[u8]) -> Vec<u8> {
    let Some(mut offset) = op_parm.iter().position(|&c| c != b' ' && c != b'\t') else {
        return op_parm.to_vec();
    };

    let mut size = op_parm.len() - offset;
    if size >= 2 && op_parm[offset] == b'"' && op_parm.last() == Some(&b'"') {
        offset += 1;
        size -= 2;
    }

    if size == 0 {
        return op_parm.to_vec();
    }

    let source = &op_parm[offset..offset + size];
    let mut parsed: Vec<u8> = Vec::with_capacity(size);

    let mut bin_offset = 0usize;
    let mut bin_parm = [0u8; 2];
    let mut bin = false;
    let mut esc = false;

    for &s in source {
        if s == b'|' {
            bin = !bin;
        } else if !esc && s == b'\\' {
            esc = true;
        } else if bin {
            if s.is_ascii_hexdigit() {
                bin_parm[bin_offset] = s;
                bin_offset += 1;
                if bin_offset == 2 {
                    let hex = std::str::from_utf8(&bin_parm).unwrap_or("0");
                    let c = u8::from_str_radix(hex, 16).unwrap_or(0);
                    bin_offset = 0;
                    parsed.push(c);
                }
            } else {
                // Invalid hex character
                return op_parm.to_vec();
            }
        } else if esc {
            if matches!(s, b':' | b';' | b'\\' | b'"') {
                parsed.push(s);
            } else {
                // Unsupported escape sequence
                return op_parm.to_vec();
            }
            esc = false;
        } else {
            parsed.push(s);
        }
    }

    parsed
}

/// The phrase matcher behind `@pm`: an Aho-Corasick automaton (the
/// `aho-corasick` crate). The first match is the one that ends first,
/// matching is ASCII case insensitive, and empty phrases are ignored.
///
/// This deviates from C++ on purpose (see "Intentional deviations from
/// C++" in `MIGRATION.md`). Its matcher, ACMP, misses some matches (its
/// fail links only look one level up), can report a phrase that is not
/// one of the phrases (the text of the trie node it stopped on), cuts the
/// reported phrase at a NUL byte, and never matches phrase bytes >= 0x80
/// where C `char` is signed. Here every occurrence is found and the
/// reported phrase is always the phrase that matched.
#[derive(Debug)]
pub(crate) struct Matcher {
    patterns: Vec<Vec<u8>>,
    ac: aho_corasick::AhoCorasick,
}

impl Matcher {
    /// The matcher of `phrases`.
    pub(crate) fn new<'a>(phrases: impl IntoIterator<Item = &'a [u8]>) -> Self {
        // Empty phrases are ignored.
        let patterns: Vec<Vec<u8>> = phrases.into_iter().filter(|p| !p.is_empty()).map(<[u8]>::to_vec).collect();
        let ac = aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(&patterns)
            .expect("aho-corasick automaton within default size limits");
        Matcher { patterns, ac }
    }

    fn find(&self, input: &[u8]) -> Option<(usize, &[u8])> {
        let m = self.ac.find(input)?;
        Some((m.end() - 1, &self.patterns[m.pattern().as_usize()]))
    }
}

#[derive(Debug)]
pub struct Pm {
    name: &'static str,
    param: Param,
    p: Matcher,
}

impl Pm {
    pub fn new(param: Param) -> Result<Self, String> {
        let op_parm = parse_pm_content(&param.literal);
        // The phrases are the white space separated words of the parameter.
        let p = Matcher::new(op_parm.split(|c| modsecurity_compat::chars::is_space(*c)));
        Ok(Self::with_matcher("Pm", param, p))
    }

    /// An operator named `name` in messages that searches the phrases of
    /// `p`: used by `@pmFromFile` / `@pmf`.
    pub(crate) fn with_matcher(name: &'static str, param: Param, p: Matcher) -> Self {
        Pm { name, param, p }
    }

    /// Searches `input` for the first phrase; a match is logged with its
    /// offset, added to the matched values and, with `capture`, stored in
    /// `TX.0`. Shared by the `@pm` family.
    pub(crate) fn evaluate_pm(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let rc = self.p.find(input);

        if let Some((offset, m)) = rc {
            cx.offset((offset + 1).saturating_sub(m.len()), m.len());
            cx.matched(m.to_vec());

            if cx.captures() {
                cx.set_capture(b"0", m.to_vec());
                crate::ms_dbg!(cx, 7, "Added pm match TX.0: {}", String::from_utf8_lossy(m));
            }
        }

        rc.is_some()
    }
}

impl Operator for Pm {
    fn name(&self) -> &'static str {
        self.name
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        self.evaluate_pm(cx, input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::eval;

    #[test]
    fn pm_content() {
        assert_eq!(parse_pm_content(b"abc def"), b"abc def".to_vec());
        assert_eq!(parse_pm_content(b"  \"abc\""), b"abc".to_vec());
        assert_eq!(parse_pm_content(b"a|4142|c"), b"aABc".to_vec());
        assert_eq!(parse_pm_content(b"a\\:b\\\\"), b"a:b\\".to_vec());
        assert_eq!(parse_pm_content(b"a\\nb"), b"a\\nb".to_vec());
        assert_eq!(parse_pm_content(b"|zz|"), b"|zz|".to_vec());
        assert_eq!(parse_pm_content(b"a|41 42|c"), b"a|41 42|c".to_vec());
        assert_eq!(parse_pm_content(b"\"\""), b"\"\"".to_vec());
        assert_eq!(parse_pm_content(b"   "), b"   ".to_vec());
    }

    fn matcher_of(patterns: &[&[u8]]) -> Matcher {
        Matcher::new(patterns.iter().copied())
    }

    /// Case insensitive, the first match is the one that ends first, and
    /// empty phrases never match.
    #[test]
    fn matcher() {
        let m = matcher_of(&[b"foo", b"Bar", b""]);
        assert_eq!(m.find(b"xxbARfoo"), Some((4, &b"Bar"[..])));
        assert_eq!(m.find(b"nothing"), None);
        assert_eq!(matcher_of(&[b""]).find(b"abc"), None);
        // "she" and "he" both end at offset 2: the longer one is reported.
        assert_eq!(matcher_of(&[b"he", b"she"]).find(b"she"), Some((2, &b"she"[..])));
    }

    /// Where the C++ matcher (ACMP) is wrong: see "Intentional deviations
    /// from C++" in MIGRATION.md. (Its results are in the comments.)
    #[test]
    fn where_acmp_differs() {
        // ACMP misses it: "B" occurs in the input.
        assert_eq!(matcher_of(&[b"aaBa", b"B", b"bcbA", b"ccc"]).find(b"AAAb"), Some((3, &b"B"[..])));
        // ACMP reports "abc", which is not a phrase.
        assert_eq!(matcher_of(&[b"abcd", b"bc"]).find(b"abcx"), Some((2, &b"bc"[..])));
        // ACMP reports "a": the phrase up to its NUL byte.
        assert_eq!(matcher_of(&[b"a\0b"]).find(b"xa\0b"), Some((3, &b"a\0b"[..])));
        // Bytes that are not ASCII are compared as they are (ACMP never
        // matches them where C `char` is signed).
        assert_eq!(matcher_of(&[b"\xe9t\xe9"]).find(b"x\xc9t\xe9"), None);
        assert_eq!(matcher_of(&[b"\xe9t\xe9"]).find(b"x\xe9t\xe9"), Some((3, &b"\xe9t\xe9"[..])));
    }

    #[test]
    fn pm_matches() {
        let op = Pm::new(Param::from_text("foo bar")).unwrap();
        assert!(eval(&op, b"xxBARxx"));
        assert!(!eval(&op, b"baz"));
    }
}
