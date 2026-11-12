//! Port of `src/operators/operator.h` / `src/operators/operator.cc`.

use std::borrow::Cow;

use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::regex::{Regex, RegexResult};
use crate::utils::string::{limit_to, to_hex_if_needed};

/// Data members of the C++ `Operator` base class.
#[derive(Debug, Default)]
pub struct OperatorBase {
    /// The fixed match message of operators that have one (C++
    /// `m_match_message`).
    pub match_message: Option<&'static str>,
    pub negation: bool,
    /// The operator name used in the match message (e.g. `Rx`).
    pub op: &'static str,
    pub param: Vec<u8>,
    pub string: Option<RunTimeString>,
    pub could_contain_macro: bool,
}

impl OperatorBase {
    /// `Operator(opName)`
    pub fn new(op_name: &'static str) -> Self {
        OperatorBase { op: op_name, ..Default::default() }
    }

    /// `Operator(opName, param)` with a literal parameter.
    pub fn with_param(op_name: &'static str, param: &[u8]) -> Self {
        OperatorBase { op: op_name, param: param.to_vec(), ..Default::default() }
    }

    /// `Operator(opName, std::unique_ptr<RunTimeString> param)`: the
    /// parameter is pre-expanded (without a transaction) into `param`.
    pub fn with_string(op_name: &'static str, param: RunTimeString) -> Self {
        let p = param.evaluate_static();
        OperatorBase { op: op_name, param: p, string: Some(param), ..Default::default() }
    }

    /// The parameter expanded for `t`, borrowed when it has no macro.
    pub fn param_value(&self, t: &Transaction<'_>) -> Cow<'_, [u8]> {
        self.string.as_ref().map_or(Cow::Borrowed(&[][..]), |s| s.evaluate_cow(Some(t)))
    }
}

/// A SecRule operator (`@rx`, `@pm`, ...).
pub trait Operator: Send + Sync + std::fmt::Debug {
    fn base(&self) -> &OperatorBase;
    fn base_mut(&mut self) -> &mut OperatorBase;

    /// `init(arg, error)`: `file` is the configuration file the rule came
    /// from (used to resolve relative resource paths).
    fn init(&mut self, _file: &str) -> Result<(), String> {
        Ok(())
    }

    /// `evaluate(transaction, rule, str, ruleMessage)`: whether `input`
    /// matches (before the negation of `!@op`).
    fn evaluate(&self, t: &mut Transaction<'_>, rule: &RuleWithActions, input: &[u8], rm: &mut RuleMessage<'_>)
    -> bool;

    /// `resolveMatchMessage`
    fn resolve_match_message(&self, t: &Transaction<'_>, key: &[u8], value: &[u8]) -> Vec<u8> {
        default_resolve_match_message(self.base(), t, key, value)
    }
}

/// The default `resolveMatchMessage` body.
pub fn default_resolve_match_message(b: &OperatorBase, t: &Transaction<'_>, key: &[u8], value: &[u8]) -> Vec<u8> {
    if let Some(m) = b.match_message {
        return m.as_bytes().to_vec();
    }
    let p: Cow<'_, [u8]> = if !b.could_contain_macro {
        Cow::Borrowed(&b.param)
    } else {
        Cow::Owned(b.string.as_ref().map(|s| s.evaluate(Some(t))).unwrap_or_default())
    };
    let mut ret = Vec::new();
    ret.extend_from_slice(b"Matched \"Operator `");
    ret.extend_from_slice(b.op.as_bytes());
    ret.extend_from_slice(b"' with parameter `");
    ret.extend_from_slice(&limit_to(200, &p));
    ret.extend_from_slice(b"' against variable `");
    ret.extend_from_slice(to_hex_if_needed(key, false).as_bytes());
    ret.extend_from_slice(b"' (Value: `");
    ret.extend_from_slice(&limit_to(100, to_hex_if_needed(value, false).as_bytes()));
    ret.extend_from_slice(b"' )");
    ret
}

impl dyn Operator {
    /// `evaluateInternal`: evaluates and applies the negation (`!@op`).
    pub fn evaluate_internal(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        let res = self.evaluate(t, rule, input, rm);
        if self.base().negation { !res } else { res }
    }
}

/// `Operator::logOffset`
pub fn log_offset(rm: &mut RuleMessage<'_>, offset: usize, len: usize) {
    rm.reference.extend_from_slice(format!("o{},{}", offset, len).as_bytes());
}

/// `Operator::reportRegexCompileError`: shared by `@rx` and `@rxGlobal`.
pub fn report_regex_compile_error(t: &mut Transaction<'_>, re: &Regex) {
    crate::ms_dbg_a!(t, 1, "Error with regular expression: \"{}\"", re.pattern);
    let off = t.vars.offset;
    t.vars.msc_pcre_error.set(b"1", off);
    {
        use crate::collection::collection::Collection;
        t.collections.tx_collection.store_or_update_first(b"MSC_PCRE_ERROR", b"1");
    }
    crate::ms_dbg_a!(t, 7, "Set TX.MSC_PCRE_ERROR to 1");
}

/// `Operator::reportRegexSearchError`
pub fn report_regex_search_error(t: &mut Transaction<'_>, re: &Regex, result: RegexResult, op_name: &str) {
    use crate::collection::collection::Collection;
    let off = t.vars.offset;
    t.vars.msc_pcre_error.set(b"1", off);
    t.collections.tx_collection.store_or_update_first(b"MSC_PCRE_ERROR", b"1");
    crate::ms_dbg_a!(t, 7, "Set TX.MSC_PCRE_ERROR to 1");
    let match_limit = result == RegexResult::ErrorMatchLimit;
    if match_limit {
        t.vars.msc_pcre_limits_exceeded.set(b"1", off);
        t.collections.tx_collection.store_or_update_first(b"MSC_PCRE_LIMITS_EXCEEDED", b"1");
        crate::ms_dbg_a!(t, 7, "Set TX.MSC_PCRE_LIMITS_EXCEEDED to 1");
    }
    crate::ms_dbg_a!(
        t,
        1,
        "{}: regex error '{}' for pattern '{}'",
        op_name,
        if match_limit { "MATCH_LIMIT" } else { "OTHER" },
        re.pattern
    );
}

/// Declares the `base`/`base_mut` accessors of [`Operator`] for a struct with
/// a `base: OperatorBase` field.
#[macro_export]
macro_rules! operator_base_accessors {
    () => {
        fn base(&self) -> &$crate::operators::operator::OperatorBase {
            &self.base
        }
        fn base_mut(&mut self) -> &mut $crate::operators::operator::OperatorBase {
            &mut self.base
        }
    };
}

/// `Operator::instantiate(op, param)`: the operator named `op` (case
/// insensitive, without the `@`) with a literal parameter.
pub fn instantiate(op: &str, param_str: &str) -> Option<Box<dyn Operator>> {
    let mut param = RunTimeString::new();
    param.append_text(param_str);
    instantiate_with_param(op, param)
}

/// Like [`instantiate`] but with an already parsed (possibly macro bearing)
/// parameter, as built by the configuration parser.
pub fn instantiate_with_param(op: &str, param: RunTimeString) -> Option<Box<dyn Operator>> {
    use crate::operators::*;
    let op_ = op.to_ascii_lowercase();
    let b: Box<dyn Operator> = match op_.as_str() {
        "beginswith" => Box::new(begins_with::BeginsWith::new(param)),
        "contains" => Box::new(contains::Contains::new(param)),
        "containsword" => Box::new(contains_word::ContainsWord::new(param)),
        "detectsqli" => Box::new(detect_sqli::DetectSQLi::new()),
        "detectxss" => Box::new(detect_xss::DetectXSS::new()),
        "endswith" => Box::new(ends_with::EndsWith::new(param)),
        "eq" => Box::new(eq::Eq::new(param)),
        "fuzzyhash" => Box::new(fuzzy_hash::FuzzyHash::new(param)),
        "geolookup" => Box::new(geo_lookup::GeoLookup::new()),
        "ge" => Box::new(ge::Ge::new(param)),
        "gsblookup" => Box::new(gsblookup::GsbLookup::new(param)),
        "gt" => Box::new(gt::Gt::new(param)),
        "inspectfile" => Box::new(inspect_file::InspectFile::new(param)),
        // `@ipMatchF` and `@pmf` are aliases (C++ `IpMatchF`, `PmF`).
        "ipmatchf" => Box::new(ip_match_from_file::IpMatchFromFile::new(param)),
        "ipmatchfromfile" => Box::new(ip_match_from_file::IpMatchFromFile::new(param)),
        "ipmatch" => Box::new(ip_match::IpMatch::new(param)),
        "le" => Box::new(le::Le::new(param)),
        "lt" => Box::new(lt::Lt::new(param)),
        "nomatch" => Box::new(no_match::NoMatch::new()),
        "pmfromfile" => Box::new(pm_from_file::PmFromFile::new(param)),
        "pmf" => Box::new(pm_from_file::PmFromFile::with_name("PmFromF", param)),
        "pm" => Box::new(pm::Pm::new(param)),
        "rbl" => Box::new(rbl::Rbl::new(param)),
        "rsub" => Box::new(rsub::Rsub::new(param)),
        "rx" => Box::new(rx::Rx::new(param)),
        "rxglobal" => Box::new(rx_global::RxGlobal::new(param)),
        "streq" => Box::new(str_eq::StrEq::new(param)),
        "strmatch" => Box::new(str_match::StrMatch::new(param)),
        "validatebyterange" => Box::new(validate_byte_range::ValidateByteRange::new(param)),
        "validatedtd" => Box::new(validate_dtd::ValidateDTD::new(param)),
        "validatehash" => Box::new(validate_hash::ValidateHash::new(param)),
        "validateschema" => Box::new(validate_schema::ValidateSchema::new(param)),
        "validateurlencoding" => Box::new(validate_url_encoding::ValidateUrlEncoding::new()),
        "validateutf8encoding" => Box::new(validate_utf8_encoding::ValidateUtf8Encoding::new()),
        "verifycc" => Box::new(verify_cc::VerifyCC::new(param)),
        "verifycpf" => Box::new(verify_cpf::VerifyCPF::new(param)),
        "verifyssn" => Box::new(verify_ssn::VerifySSN::new(param)),
        "verifysvnr" => Box::new(verify_svnr::VerifySVNR::new(param)),
        "within" => Box::new(within::Within::new(param)),
        "unconditionalmatch" => Box::new(unconditional_match::UnconditionalMatch::new()),
        _ => return None,
    };
    Some(b)
}

/// Evaluating operators in tests, with a fresh transaction and an empty rule.
#[cfg(test)]
pub(crate) mod test_support {
    use super::Operator;
    use crate::modsecurity::ModSecurity;
    use crate::rule_message::RuleMessage;
    use crate::rule_with_actions::{RuleWithActions, RuleWithActionsKind};
    use crate::rules_set::RulesSet;
    use crate::transaction::Transaction;

    /// `op` applied to `input` in a new transaction.
    pub fn eval(op: &dyn Operator, input: &[u8]) -> bool {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut t = Transaction::new(&ms, &rules, None);
        eval_in(op, &mut t, input)
    }

    /// `op` applied to `input` in `t`, for a rule without actions.
    pub fn eval_in(op: &dyn Operator, t: &mut Transaction<'_>, input: &[u8]) -> bool {
        let rule = RuleWithActions::new(None, None, "", 0, RuleWithActionsKind::Unconditional);
        let mut rm = RuleMessage::new(&rule);
        op.evaluate(t, &rule, input, &mut rm)
    }
}
