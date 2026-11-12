//! Port of `src/operators/verify_cc.cc`, `src/operators/verify_cc.h`.
//!
//! Like the C++ operator, the PCRE2 API is used directly: the pattern is
//! matched at every offset of the input (not through `utils::regex`).

use std::ptr;

use pcre2_sys::*;

use crate::collection::collection::Collection;
use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

/// A compiled pattern (`m_pc`) and its JIT compilation status (`m_pcje`).
#[derive(Debug)]
struct CompiledPattern {
    pc: *mut pcre2_code_8,
    pcje: i32,
}

// SAFETY: a compiled pcre2_code (and its JIT code) is immutable after
// compilation and may be used from several threads; the per-match state
// (match data) is allocated per evaluation.
unsafe impl Send for CompiledPattern {}
unsafe impl Sync for CompiledPattern {}

impl Drop for CompiledPattern {
    fn drop(&mut self) {
        // SAFETY: `pc` was returned by pcre2_compile_8 (non-null) and is
        // freed exactly once.
        unsafe { pcre2_code_free_8(self.pc) }
    }
}

/// RAII owner of a `pcre2_match_data`.
struct MatchData(*mut pcre2_match_data_8);

impl Drop for MatchData {
    fn drop(&mut self) {
        // SAFETY: allocated by pcre2_match_data_create_from_pattern_8 (a
        // null pointer is accepted by pcre2_match_data_free) and freed once.
        unsafe { pcre2_match_data_free_8(self.0) }
    }
}

#[derive(Debug)]
pub struct VerifyCC {
    pub base: OperatorBase,
    re: Option<CompiledPattern>,
}

impl VerifyCC {
    pub fn new(param: RunTimeString) -> Self {
        VerifyCC { base: OperatorBase::with_string("VerifyCC", param), re: None }
    }

    /// `luhnVerify`: Luhn Mod-10 Method (ISO 2894/ANSI 4.13). Only the
    /// digits of `ccnumber` are considered.
    pub fn luhn_verify(ccnumber: &[u8]) -> bool {
        let mut sum = [0i32; 2];
        let mut odd = 0usize;
        let mut digits = 0;

        // Weighted lookup table which is just a precalculated (i = index):
        //   i*2 + (( (i*2) > 9 ) ? -9 : 0)
        const WTABLE: [i32; 10] = [0, 2, 4, 6, 8, 1, 3, 5, 7, 9];

        // Add up only digits (weighted digits via lookup table) for both
        // odd and even CC numbers to avoid 2 passes.
        for &c in ccnumber {
            if c.is_ascii_digit() {
                let d = usize::from(c - b'0');
                sum[0] += if odd == 0 { WTABLE[d] } else { d as i32 };
                sum[1] += if odd != 0 { WTABLE[d] } else { d as i32 };
                odd = 1 - odd; // alternate weights
                digits += 1;
            }
        }

        // No digits extracted
        if digits == 0 {
            return false;
        }

        // Do a mod 10 on the sum; if the result is zero the card is valid.
        sum[odd] % 10 == 0
    }
}

impl Operator for VerifyCC {
    crate::operator_base_accessors!();

    fn init(&mut self, _file: &str) -> Result<(), String> {
        // PCRE2_ZERO_TERMINATED: the pattern ends at its first NUL byte.
        let param = &self.base.param;
        let len = param.iter().position(|&c| c == 0).unwrap_or(param.len());
        let mut errornumber: i32 = 0;
        let mut erroroffset: usize = 0;
        // SAFETY: `param` holds at least `len` readable bytes; the
        // out-parameters are valid; a null compile context selects the
        // defaults.
        let pc = unsafe {
            pcre2_compile_8(
                param.as_ptr(),
                len,
                PCRE2_DOTALL | PCRE2_MULTILINE,
                &mut errornumber,
                &mut erroroffset,
                ptr::null_mut(),
            )
        };
        if pc.is_null() {
            // The C++ (PCRE2) code fails without an error message.
            return Err(String::new());
        }
        // SAFETY: `pc` is a valid compiled pattern.
        let pcje = unsafe { pcre2_jit_compile_8(pc, PCRE2_JIT_COMPLETE) };
        self.re = Some(CompiledPattern { pc, pcje });
        Ok(())
    }

    fn evaluate(&self, t: &mut Transaction<'_>, rule: &RuleWithActions, i: &[u8], _rm: &mut RuleMessage<'_>) -> bool {
        // Without a successful init() the C++ code would dereference a null
        // pattern.
        let Some(re) = self.re.as_ref() else {
            return false;
        };
        let target_length = i.len();
        // SAFETY: `re.pc` is a valid compiled pattern; a null general
        // context selects malloc.
        let match_data = MatchData(unsafe { pcre2_match_data_create_from_pattern_8(re.pc, ptr::null_mut()) });
        if match_data.0.is_null() {
            return false;
        }

        for offset in 0..target_length {
            let mut ret = 0;
            if re.pcje == 0 {
                // SAFETY: valid pattern and match data; `i` is readable for
                // `target_length` bytes and `offset` is within it.
                ret = unsafe {
                    pcre2_jit_match_8(re.pc, i.as_ptr(), target_length, offset, 0, match_data.0, ptr::null_mut())
                };
            }

            if re.pcje != 0 || ret == PCRE2_ERROR_JIT_STACKLIMIT {
                // SAFETY: as above.
                ret = unsafe {
                    pcre2_match_8(re.pc, i.as_ptr(), target_length, offset, PCRE2_NO_JIT, match_data.0, ptr::null_mut())
                };
            }

            // If there was no match, then we are done.
            if ret < 0 {
                break;
            }

            if ret > 0 {
                // SAFETY: after a successful match the ovector holds at
                // least one (start, end) pair.
                let (start, end) = unsafe {
                    let ov = pcre2_get_ovector_pointer_8(match_data.0);
                    (*ov, *ov.add(1))
                };
                if start > end || end > target_length {
                    continue;
                }
                let m = &i[start..end];
                if Self::luhn_verify(m) {
                    if rule.has_capture_action() {
                        t.collections.tx_collection.store_or_update_first(b"0", m);
                        crate::ms_dbg_a!(t, 7, "Added VerifyCC match TX.0: {}", String::from_utf8_lossy(m));
                    }
                    crate::ms_dbg_a!(
                        t,
                        9,
                        "CC# match \"{}\" at {}. [offset {}]",
                        String::from_utf8_lossy(&self.base.param),
                        String::from_utf8_lossy(i),
                        offset
                    );

                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::operator::test_support::eval;

    #[test]
    fn luhn() {
        assert!(VerifyCC::luhn_verify(b"4111111111111111"));
        assert!(VerifyCC::luhn_verify(b"4111-1111-1111-1111"));
        assert!(!VerifyCC::luhn_verify(b"4111111111111112"));
        assert!(!VerifyCC::luhn_verify(b"abc"));
        assert!(VerifyCC::luhn_verify(b"0"));
    }

    #[test]
    fn verify_cc() {
        let mut op = VerifyCC::new(RunTimeString::from_text("\\d{13,16}"));
        op.init("").unwrap();
        assert!(eval(&op, b"cc: 4111111111111111 x"));
        assert!(!eval(&op, b"cc: 4111111111112 x"));
        let mut bad = VerifyCC::new(RunTimeString::from_text("(("));
        assert!(bad.init("").is_err());
    }
}
