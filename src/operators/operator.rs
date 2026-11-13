//! Port of `src/operators/operator.h` / `src/operators/operator.cc`.

use std::borrow::Cow;

use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::regex::{Regex, RegexResult};
use crate::utils::string::{limit_to, to_hex_if_needed};

/// The parameter of an operator (`@op parameter`), which may hold macros
/// (`%{TX.x}`) expanded for each transaction.
#[derive(Debug, Default)]
pub struct Param {
    /// The parameter expanded without a transaction (macros left out):
    /// what operators compile or load when the rules are read.
    pub literal: Vec<u8>,
    pub string: RunTimeString,
    /// Whether the match message shows the parameter expanded for the
    /// transaction (C++ `m_couldContainsMacro`) or the literal.
    expanded_in_message: bool,
}

impl Param {
    pub fn new(string: RunTimeString) -> Self {
        Param { literal: string.evaluate_static(), string, expanded_in_message: false }
    }

    /// A parameter that the match message shows with its macros expanded.
    pub fn expanded_in_message(string: RunTimeString) -> Self {
        Param { expanded_in_message: true, ..Self::new(string) }
    }

    /// The parameter expanded for `t`, borrowed when it has no macro.
    pub fn value(&self, t: &Transaction<'_>) -> Cow<'_, [u8]> {
        self.string.evaluate_cow(Some(t))
    }

    pub fn contains_macro(&self) -> bool {
        self.string.contains_macro()
    }

    /// The literal as text, for operators whose parameter is a file name
    /// or similar.
    pub fn literal_lossy(&self) -> String {
        String::from_utf8_lossy(&self.literal).into_owned()
    }
}

/// A SecRule operator (`@rx`, `@pm`, ...).
pub trait Operator: Send + Sync + std::fmt::Debug {
    /// The operator name shown in match messages and the debug log (e.g.
    /// `Rx`).
    fn name(&self) -> &'static str;

    /// The parameter, for operators that take one.
    fn param(&self) -> Option<&Param> {
        None
    }

    /// `init(file, &error)`: compiles/loads what the parameter names;
    /// `file` is the configuration file of the rule.
    fn init(&mut self, _file: &str) -> Result<(), String> {
        Ok(())
    }

    /// Whether `input` matches (before the negation of `!@op`).
    fn evaluate(&self, t: &mut Transaction<'_>, rule: &RuleWithActions, input: &[u8], rm: &mut RuleMessage<'_>)
    -> bool;

    /// The result of the rule's operator: [`Operator::evaluate`] with the
    /// negation of `!@op` applied. Operators whose failures must not match
    /// even when negated override this.
    fn evaluate_negatable(
        &self,
        negated: bool,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        self.evaluate(t, rule, input, rm) != negated
    }

    /// The parameter as the match message shows it: expanded for `t` or
    /// the literal, depending on the operator.
    fn message_param(&self, t: &Transaction<'_>) -> Cow<'_, [u8]> {
        match self.param() {
            Some(param) if param.expanded_in_message => param.value(t),
            Some(param) => Cow::Borrowed(&param.literal),
            None => Cow::Borrowed(b""),
        }
    }

    /// The text logged for a match of `value` in the variable `key`
    /// (`resolveMatchMessage`); `param` is [`Operator::message_param`] at
    /// the time of the match.
    fn resolve_match_message(&self, param: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut ret = Vec::new();
        ret.extend_from_slice(b"Matched \"Operator `");
        ret.extend_from_slice(self.name().as_bytes());
        ret.extend_from_slice(b"' with parameter `");
        ret.extend_from_slice(&limit_to(200, param));
        ret.extend_from_slice(b"' against variable `");
        ret.extend_from_slice(to_hex_if_needed(key, false).as_bytes());
        ret.extend_from_slice(b"' (Value: `");
        ret.extend_from_slice(&limit_to(100, to_hex_if_needed(value, false).as_bytes()));
        ret.extend_from_slice(b"' )");
        ret
    }
}

/// The operator of a rule: the operator and whether the rule negates it
/// (`!@op`).
#[derive(Debug)]
pub struct RuleOperator {
    pub op: Box<dyn Operator>,
    pub negated: bool,
}

impl RuleOperator {
    pub fn new(op: Box<dyn Operator>) -> Self {
        RuleOperator { op, negated: false }
    }

    pub fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        self.op.evaluate_negatable(self.negated, t, rule, input, rm)
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
    t.collections.tx.set(b"MSC_PCRE_ERROR", b"1".to_vec());
    crate::ms_dbg_a!(t, 7, "Set TX.MSC_PCRE_ERROR to 1");
}

/// `Operator::reportRegexSearchError`
pub fn report_regex_search_error(t: &mut Transaction<'_>, re: &Regex, result: RegexResult, op_name: &str) {
    let off = t.vars.offset;
    t.vars.msc_pcre_error.set(b"1", off);
    t.collections.tx.set(b"MSC_PCRE_ERROR", b"1".to_vec());
    crate::ms_dbg_a!(t, 7, "Set TX.MSC_PCRE_ERROR to 1");
    let match_limit = result == RegexResult::ErrorMatchLimit;
    if match_limit {
        t.vars.msc_pcre_limits_exceeded.set(b"1", off);
        t.collections.tx.set(b"MSC_PCRE_LIMITS_EXCEEDED", b"1".to_vec());
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
