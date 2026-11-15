//! The [`Operator`] trait, operator parameters, helpers shared by the
//! operators, and [`instantiate`], which builds an operator by name.

use std::borrow::Cow;

use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::{limit_to, to_hex_if_needed};

/// The parameter of an operator (`@op parameter`), as the operator keeps
/// it: the text without its macros, and whether it has any. When it does
/// (`%{TX.x}`), the operator gets the parameter expanded for each
/// transaction from its [`MatchContext`].
#[derive(Debug, Default)]
pub struct Param {
    /// The parameter expanded without a transaction (macros left out):
    /// what operators compile or load when the rules are read.
    pub literal: Vec<u8>,
    has_macros: bool,
    /// Whether the match message shows the parameter expanded for the
    /// transaction or the literal.
    expanded_in_message: bool,
}

impl Param {
    /// A parameter whose text without macros is `literal`.
    pub fn new(literal: Vec<u8>, has_macros: bool) -> Self {
        Param { literal, has_macros, expanded_in_message: false }
    }

    /// A parameter without macros.
    pub fn from_text(text: &str) -> Self {
        Param::new(text.as_bytes().to_vec(), false)
    }

    /// The same parameter, shown in match messages with its macros
    /// expanded.
    pub fn expanded_in_message(self) -> Self {
        Param { expanded_in_message: true, ..self }
    }

    pub fn contains_macro(&self) -> bool {
        self.has_macros
    }

    /// The literal as text, for operators whose parameter is a file name
    /// or similar.
    pub fn literal_lossy(&self) -> String {
        String::from_utf8_lossy(&self.literal).into_owned()
    }
}

/// What an operator may do while it evaluates a value: read its parameter
/// for this transaction, record what it matched, and write to the debug
/// log. Operators see the transaction only through this.
///
/// (The few operators that are part of the engine rather than matchers,
/// such as `@geoLookup` or `@inspectFile`, reach the transaction with
/// [`MatchContext::transaction`].)
pub struct MatchContext<'c, 't, 'm> {
    t: &'c mut Transaction<'t>,
    rule: &'c RuleWithActions,
    rm: &'c mut RuleMessage<'m>,
    /// The operator's parameter with its macros, when it has one.
    param: Option<&'c RunTimeString>,
}

impl<'c, 't, 'm> MatchContext<'c, 't, 'm> {
    pub fn new(t: &'c mut Transaction<'t>, rule: &'c RuleWithActions, rm: &'c mut RuleMessage<'m>) -> Self {
        MatchContext { t, rule, rm, param: None }
    }

    /// The context of an operator whose parameter is `param`.
    pub fn with_param(self, param: Option<&'c RunTimeString>) -> Self {
        MatchContext { param, ..self }
    }

    /// Whether the debug log takes messages of `level`.
    pub fn debug_enabled(&self, level: i32) -> bool {
        self.t.debug_enabled(level)
    }

    /// Writes `message` to the debug log (see [`op_dbg`](crate::op_dbg)).
    pub fn debug(&self, level: i32, message: &str) {
        self.t.debug(level, message);
    }

    /// `param` with its macros expanded for this transaction, borrowed
    /// when it has none.
    pub fn param<'p>(&self, param: &'p Param) -> Cow<'p, [u8]> {
        match self.param {
            Some(string) if param.has_macros => Cow::Owned(string.evaluate(Some(self.t))),
            _ => Cow::Borrowed(&param.literal),
        }
    }

    /// Whether the rule has the `capture` action.
    pub fn captures(&self) -> bool {
        self.rule.has_capture_action()
    }

    /// Stores a captured value as `TX:<group>` (`TX:0` ... `TX:9`); for
    /// rules that capture ([`Self::captures`]).
    pub fn set_capture(&mut self, group: &[u8], value: Vec<u8>) {
        self.t.collections.tx.set(group, value);
    }

    /// Records text the operator matched (what `capture` and the logs
    /// refer to).
    pub fn matched(&mut self, value: Vec<u8>) {
        self.t.matched.push(value);
    }

    /// Records the position of a match in the input (`o<offset>,<length>`
    /// in the reference of the rule message).
    pub fn offset(&mut self, offset: usize, len: usize) {
        self.rm.reference.extend_from_slice(format!("o{},{}", offset, len).as_bytes());
    }

    /// `SecPcreMatchLimit` (0 when not set).
    pub fn pcre_match_limit(&self) -> u64 {
        self.t.rules.properties.pcre_match_limit.map_or(0, u64::from)
    }

    /// Reports a regular expression that failed to compile: logs it and
    /// sets `MSC_PCRE_ERROR` and `TX.MSC_PCRE_ERROR`.
    pub fn regex_compile_error(&mut self, pattern: &str) {
        let t = &mut *self.t;
        crate::ms_dbg_a!(t, 1, "Error with regular expression: \"{}\"", pattern);
        let off = t.vars.offset;
        t.vars.msc_pcre_error.set(b"1", off);
        t.collections.tx.set(b"MSC_PCRE_ERROR", b"1".to_vec());
        crate::ms_dbg_a!(t, 7, "Set TX.MSC_PCRE_ERROR to 1");
    }

    /// Reports a failed regular expression search by `op_name`: sets
    /// `MSC_PCRE_ERROR` (and `MSC_PCRE_LIMITS_EXCEEDED` when the match
    /// limit was hit), in TX too, and logs the error.
    pub fn regex_search_error(&mut self, pattern: &str, match_limit: bool, op_name: &str) {
        let t = &mut *self.t;
        let off = t.vars.offset;
        t.vars.msc_pcre_error.set(b"1", off);
        t.collections.tx.set(b"MSC_PCRE_ERROR", b"1".to_vec());
        crate::ms_dbg_a!(t, 7, "Set TX.MSC_PCRE_ERROR to 1");
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
            pattern
        );
    }

    /// The transaction, for the operators that are part of the engine.
    pub fn transaction(&mut self) -> &mut Transaction<'t> {
        self.t
    }

    /// [`Self::transaction`], to read from.
    pub fn transaction_ref(&self) -> &Transaction<'t> {
        self.t
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

    /// Compiles or loads what the parameter names, when the rule is read;
    /// `file` is the configuration file of the rule.
    fn init(&mut self, _file: &str) -> Result<(), String> {
        Ok(())
    }

    /// Whether `input` matches (before the negation of `!@op`).
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool;

    /// The result of the rule's operator: [`Operator::evaluate`] with the
    /// negation of `!@op` applied. Operators whose failures must not match
    /// even when negated override this.
    fn evaluate_negatable(&self, negated: bool, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        self.evaluate(cx, input) != negated
    }

    /// The text logged for a match of `value` in the variable `key`;
    /// `param` is [`RuleOperator::message_param`] at the time of the match.
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

/// The operator of a rule: the operator, its parameter with its macros,
/// and whether the rule negates it (`!@op`).
#[derive(Debug)]
pub struct RuleOperator {
    pub op: Box<dyn Operator>,
    /// The parameter as written, for operators that take one.
    pub param: Option<RunTimeString>,
    pub negated: bool,
}

impl RuleOperator {
    pub fn new(op: Box<dyn Operator>, param: RunTimeString) -> Self {
        let param = op.param().is_some().then_some(param);
        RuleOperator { op, param, negated: false }
    }

    pub fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        rule: &RuleWithActions,
        input: &[u8],
        rm: &mut RuleMessage<'_>,
    ) -> bool {
        let mut cx = MatchContext::new(t, rule, rm).with_param(self.param.as_ref());
        self.op.evaluate_negatable(self.negated, &mut cx, input)
    }

    /// The parameter as the match message shows it: expanded for `t` or
    /// the literal, depending on the operator.
    pub fn message_param(&self, t: &Transaction<'_>) -> Cow<'_, [u8]> {
        match (self.op.param(), &self.param) {
            (Some(param), Some(string)) if param.expanded_in_message => string.evaluate_cow(Some(t)),
            (Some(param), _) => Cow::Borrowed(&param.literal),
            (None, _) => Cow::Borrowed(b""),
        }
    }
}

/// The operator named `op` (case
/// insensitive, without the `@`) with a literal parameter.
pub fn instantiate(op: &str, param_str: &str) -> Option<Box<dyn Operator>> {
    instantiate_with_param(op, &RunTimeString::from_text(param_str))
}

/// Like [`instantiate`] but with an already parsed (possibly macro bearing)
/// parameter, as built by the configuration parser.
pub fn instantiate_with_param(op: &str, param: &RunTimeString) -> Option<Box<dyn Operator>> {
    let param = Param::new(param.evaluate_static(), param.contains_macro());
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
        op.evaluate(&mut super::MatchContext::new(t, &rule, &mut rm), input)
    }
}
