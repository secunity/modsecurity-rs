//! Port of `src/operators/pm.cc`, `src/operators/pm.h`.

use crate::collection::collection::Collection;
use crate::operators::operator::{Operator, Param, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
#[cfg(not(feature = "pm-aho-corasick"))]
use crate::utils::acmp::{Acmp, Acmpt};
use crate::utils::string::valid_hex;

/// `parse_pm_content`: strips optional surrounding quotes and decodes the
/// `|hex|` blocks and the `\:`, `\;`, `\\` and `\"` escapes. On any invalid
/// sequence the parameter is returned unchanged.
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
            if valid_hex(s) {
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

/// The phrase matcher behind `@pm`: the C++ ACMP parser (default).
///
/// Patterns are matched case insensitively (`acmp_create(0)`); `find`
/// returns the offset of the last byte of the first match and the matched
/// phrase.
#[cfg(not(feature = "pm-aho-corasick"))]
#[derive(Debug)]
pub(crate) struct Matcher(Acmp);

#[cfg(not(feature = "pm-aho-corasick"))]
impl Matcher {
    fn new() -> Self {
        Matcher(Acmp::create(0))
    }

    pub(crate) fn add_pattern(&mut self, pattern: &[u8]) {
        self.0.add_pattern(pattern);
    }

    /// Builds the fail tree once all patterns were added.
    fn prepare(&mut self) {
        while !self.0.is_failtree_done() {
            self.0.prepare();
        }
    }

    fn find(&self, input: &[u8]) -> Option<(usize, &[u8])> {
        Acmpt::new(&self.0).process_quick(input)
    }
}

/// The phrase matcher behind `@pm` with the `pm-aho-corasick` feature: the
/// `aho-corasick` crate instead of the C++ ACMP parser.
///
/// This deliberately deviates from C++: ACMP misses some matches (its fail
/// links only look one level up), can report a phrase that is not one of
/// the patterns (the text of the trie node it stopped on), truncates the
/// reported phrase at a NUL byte, and never matches pattern bytes >= 0x80
/// where C `char` is signed. Here every occurrence is found and the
/// reported phrase is always the pattern that matched. As with ACMP, the
/// first match is the one that ends first, matching is ASCII case
/// insensitive, and empty patterns are ignored.
#[cfg(feature = "pm-aho-corasick")]
#[derive(Debug)]
pub(crate) struct Matcher {
    patterns: Vec<Vec<u8>>,
    ac: Option<aho_corasick::AhoCorasick>,
}

#[cfg(feature = "pm-aho-corasick")]
impl Matcher {
    fn new() -> Self {
        Matcher { patterns: Vec::new(), ac: None }
    }

    pub(crate) fn add_pattern(&mut self, pattern: &[u8]) {
        // As acmp_add_pattern: no-op once prepared, empty patterns ignored.
        if self.ac.is_none() && !pattern.is_empty() {
            self.patterns.push(pattern.to_vec());
        }
    }

    fn prepare(&mut self) {
        if self.ac.is_some() {
            return;
        }
        let ac = aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(&self.patterns)
            .expect("aho-corasick automaton within default size limits");
        self.ac = Some(ac);
    }

    fn find(&self, input: &[u8]) -> Option<(usize, &[u8])> {
        let m = self.ac.as_ref()?.find(input)?;
        Some((m.end() - 1, &self.patterns[m.pattern().as_usize()]))
    }
}

#[derive(Debug)]
pub struct Pm {
    name: &'static str,
    pub(crate) param: Param,
    pub(crate) p: Matcher,
}

impl Pm {
    pub fn new(param: RunTimeString) -> Self {
        Self::with_name("Pm", param)
    }

    /// `Pm(n, param)`: used by `@pmFromFile` / `@pmf`.
    pub fn with_name(name: &'static str, param: RunTimeString) -> Self {
        Pm { name, param: Param::new(param), p: Matcher::new() }
    }

    /// Makes the matcher ready for searching once all patterns were added.
    pub(crate) fn prepare(&mut self) {
        self.p.prepare();
    }

    /// `Pm::evaluate`, shared by the `@pm` family.
    pub(crate) fn evaluate_pm(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        let rc = self.p.find(input);

        if let Some((offset, m)) = rc {
            log_offset(rm, (offset + 1).saturating_sub(m.len()), m.len());
            t.matched.push(m.to_vec());

            if rule.has_capture_action() {
                t.collections.tx_collection.store_or_update_first(b"0", m);
                crate::ms_dbg_a!(t, 7, "Added pm match TX.0: {}", String::from_utf8_lossy(m));
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

    fn init(&mut self, _file: &str) -> Result<(), String> {
        let op_parm = parse_pm_content(&self.param.literal);

        // std::istream_iterator<std::string>: white space separated words.
        for a in op_parm.split(|c| crate::utils::string::is_space(*c)).filter(|a| !a.is_empty()) {
            self.p.add_pattern(a);
        }

        self.prepare();
        Ok(())
    }

    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        self.evaluate_pm(t, rule, input, rm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::operator::test_support::eval;

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

    fn matcher(patterns: &[&[u8]]) -> Matcher {
        let mut m = Matcher::new();
        for p in patterns {
            m.add_pattern(p);
        }
        m.prepare();
        m
    }

    /// Behaviour shared by both matchers: case insensitive, first match is
    /// the one that ends first, empty patterns never match.
    #[test]
    fn matcher_common() {
        let m = matcher(&[b"foo", b"Bar", b""]);
        assert_eq!(m.find(b"xxbARfoo"), Some((4, &b"Bar"[..])));
        assert_eq!(m.find(b"nothing"), None);
        assert_eq!(matcher(&[b""]).find(b"abc"), None);
        // "she" and "he" both end at offset 2: the longer one is reported.
        assert_eq!(matcher(&[b"he", b"she"]).find(b"she"), Some((2, &b"she"[..])));
    }

    /// The C++ ACMP quirks the default matcher keeps (checked against the
    /// C++ `acmp_process_quick`).
    #[cfg(not(feature = "pm-aho-corasick"))]
    #[test]
    fn matcher_acmp_quirks() {
        // A missed match: "B" occurs in the input.
        assert_eq!(matcher(&[b"aaBa", b"B", b"bcbA", b"ccc"]).find(b"AAAb"), None);
        // A reported phrase that is not a pattern.
        assert_eq!(matcher(&[b"abcd", b"bc"]).find(b"abcx"), Some((2, &b"abc"[..])));
        // Truncated at the NUL byte.
        assert_eq!(matcher(&[b"a\0b"]).find(b"xa\0b"), Some((3, &b"a"[..])));
    }

    /// The same inputs with the aho-corasick matcher.
    #[cfg(feature = "pm-aho-corasick")]
    #[test]
    fn matcher_aho_corasick() {
        assert_eq!(matcher(&[b"aaBa", b"B", b"bcbA", b"ccc"]).find(b"AAAb"), Some((3, &b"B"[..])));
        assert_eq!(matcher(&[b"abcd", b"bc"]).find(b"abcx"), Some((2, &b"bc"[..])));
        assert_eq!(matcher(&[b"a\0b"]).find(b"xa\0b"), Some((3, &b"a\0b"[..])));
        assert_eq!(matcher(&[b"\xe9t\xe9"]).find(b"x\xc9t\xe9"), None);
        assert_eq!(matcher(&[b"\xe9t\xe9"]).find(b"x\xe9t\xe9"), Some((3, &b"\xe9t\xe9"[..])));
    }

    #[test]
    fn pm_matches() {
        let mut op = Pm::new(RunTimeString::from_text("foo bar"));
        op.init("").unwrap();
        assert!(eval(&op, b"xxBARxx"));
        assert!(!eval(&op, b"baz"));
    }
}
