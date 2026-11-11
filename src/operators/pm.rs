//! Port of `src/operators/pm.cc`, `src/operators/pm.h`.

use crate::collection::collection::Collection;
use crate::operators::operator::{Operator, OperatorBase, log_offset};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
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

#[derive(Debug)]
pub struct Pm {
    pub base: OperatorBase,
    pub(crate) p: Acmp,
}

impl Pm {
    pub fn new(param: RunTimeString) -> Self {
        Self::with_name("Pm", param)
    }

    /// `Pm(n, param)`: used by `@pmFromFile` / `@pmf`.
    pub fn with_name(name: &str, param: RunTimeString) -> Self {
        Pm { base: OperatorBase::with_string(name, param), p: Acmp::create(0) }
    }

    /// Builds the fail tree once all patterns were added.
    pub(crate) fn prepare(&mut self) {
        while !self.p.is_failtree_done() {
            self.p.prepare();
        }
    }

    /// `Pm::evaluate`, shared by the `@pm` family.
    pub(crate) fn evaluate_pm(
        &self,
        t: Option<&mut Transaction<'_>>,
        rule: Option<&RuleWithActions>,
        input: &[u8],
        rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        let mut pt = Acmpt::new(&self.p);
        let rc = pt.process_quick(input);

        if let (Some((offset, m)), Some(t)) = (rc, t) {
            if let Some(rm) = rm {
                log_offset(rm, (offset + 1).saturating_sub(m.len()), m.len());
            }
            t.matched.push(m.to_vec());

            if rule.is_some_and(|r| r.has_capture_action()) {
                t.collections.tx_collection.store_or_update_first(b"0", m);
                crate::ms_dbg_a!(t, 7, "Added pm match TX.0: {}", String::from_utf8_lossy(m));
            }
        }

        rc.is_some()
    }
}

impl Operator for Pm {
    crate::operator_base_accessors!();

    fn init(&mut self, _file: &str) -> Result<(), String> {
        let op_parm = parse_pm_content(&self.base.param);

        // std::istream_iterator<std::string>: white space separated words.
        for a in op_parm.split(|c| crate::utils::string::is_space(*c)).filter(|a| !a.is_empty()) {
            self.p.add_pattern(a);
        }

        self.prepare();
        Ok(())
    }

    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        rule: Option<&RuleWithActions>,
        input: &[u8],
        rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        self.evaluate_pm(t, rule, input, rm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn pm_matches() {
        let mut op = Pm::new(RunTimeString::from_text("foo bar"));
        op.init("").unwrap();
        assert!(op.evaluate(None, None, b"xxBARxx", None));
        assert!(!op.evaluate(None, None, b"baz", None));
    }
}
