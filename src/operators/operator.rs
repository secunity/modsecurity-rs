//! The [`Operator`] trait, operator parameters, helpers shared by the
//! operators, and [`instantiate`], which builds an operator by name.

use std::borrow::Cow;

pub use modsecurity_operators::Param;
use modsecurity_operators::{Context, ResourceLookup, Resources};

use crate::rule::message::RuleMessage;
use crate::rule::with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

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

    /// Writes `message` to the debug log.
    pub fn debug(&self, level: i32, message: &str) {
        self.t.debug(level, message);
    }

    /// `param` with its macros expanded for this transaction, borrowed
    /// when it has none.
    pub fn param<'p>(&self, param: &'p Param) -> Cow<'p, [u8]> {
        match self.param {
            Some(string) if param.contains_macro() => Cow::Owned(string.evaluate(Some(self.t))),
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
        self.t.eval.matched.push(value);
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

    /// `SecHttpBlKey` (empty when not set), for `@rbl`.
    pub fn httpbl_key(&self) -> &[u8] {
        self.t.rules.properties.httpbl_key.as_deref().unwrap_or_default().as_bytes()
    }

    /// The document the XML request body processor parsed and its
    /// well-formedness flag (1 when well formed), for `@validateDTD` and
    /// `@validateSchema`; `None` without a document.
    #[cfg(feature = "libxml2")]
    pub fn xml_document(&self) -> Option<(&crate::utils::libxml2::Document, u32)> {
        self.t.body.xml.as_ref().and_then(|x| Some((x.document()?, x.well_formed())))
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
        modsecurity_operators::match_message(self.name(), param, key, value)
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
            (Some(param), Some(string)) if param.is_expanded_in_message() => string.evaluate_cow(Some(t)),
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
    use crate::operators::*;
    let param = Param::new(param.evaluate_static(), param.contains_macro());
    let b: Box<dyn Operator> = match op.to_ascii_lowercase().as_str() {
        // The operators that are part of the engine.
        "geolookup" => Box::new(geo_lookup::GeoLookup::new()),
        "inspectfile" => Box::new(inspect_file::InspectFile::new(param)),
        // The matchers.
        name => Box::new(Matcher(modsecurity_operators::instantiate(name, param)?)),
    };
    Some(b)
}

/// An operator of the `modsecurity-operators` crate, as an operator of the
/// engine: it sees the [`MatchContext`] through that crate's `Context`.
#[derive(Debug)]
struct Matcher(Box<dyn modsecurity_operators::Operator>);

impl Operator for Matcher {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn param(&self) -> Option<&Param> {
        self.0.param()
    }

    fn init(&mut self, file: &str) -> Result<(), String> {
        self.0.init(file, &EngineResources)
    }

    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        self.0.evaluate(cx, input)
    }

    fn evaluate_negatable(&self, negated: bool, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        self.0.evaluate_negatable(negated, cx, input)
    }

    fn resolve_match_message(&self, param: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
        self.0.resolve_match_message(param, key, value)
    }
}

/// How the matchers get files and URLs: the engine's resource lookup and
/// its HTTPS client.
struct EngineResources;

impl Resources for EngineResources {
    fn find(&self, resource: &str, config: &str) -> ResourceLookup {
        let lookup = crate::utils::system::find_resource(resource, config);
        ResourceLookup { path: lookup.path, looked_at: lookup.looked_at }
    }

    fn download(&self, url: &str) -> Result<Vec<u8>, String> {
        let mut client = crate::utils::https_client::HttpsClient::new();
        if client.download(url) { Ok(std::mem::take(&mut client.content)) } else { Err(client.error) }
    }
}

impl Context for MatchContext<'_, '_, '_> {
    fn debug_enabled(&self, level: i32) -> bool {
        MatchContext::debug_enabled(self, level)
    }
    fn debug(&self, level: i32, message: &str) {
        MatchContext::debug(self, level, message)
    }
    fn param<'p>(&self, param: &'p Param) -> Cow<'p, [u8]> {
        MatchContext::param(self, param)
    }
    fn captures(&self) -> bool {
        MatchContext::captures(self)
    }
    fn set_capture(&mut self, group: &[u8], value: Vec<u8>) {
        MatchContext::set_capture(self, group, value)
    }
    fn matched(&mut self, value: Vec<u8>) {
        MatchContext::matched(self, value)
    }
    fn offset(&mut self, offset: usize, len: usize) {
        MatchContext::offset(self, offset, len)
    }
    fn pcre_match_limit(&self) -> u64 {
        MatchContext::pcre_match_limit(self)
    }
    fn regex_compile_error(&mut self, pattern: &str) {
        MatchContext::regex_compile_error(self, pattern)
    }
    fn regex_search_error(&mut self, pattern: &str, match_limit: bool, op_name: &str) {
        MatchContext::regex_search_error(self, pattern, match_limit, op_name)
    }
    fn httpbl_key(&self) -> &[u8] {
        MatchContext::httpbl_key(self)
    }
    #[cfg(feature = "libxml2")]
    fn xml_document(&self) -> Option<(&crate::utils::libxml2::Document, u32)> {
        MatchContext::xml_document(self)
    }
}

/// Evaluating operators in tests, with a fresh transaction and an empty rule.
#[cfg(test)]
pub(crate) mod test_support {
    use super::Operator;
    use crate::instance::ModSecurity;
    use crate::rule::message::RuleMessage;
    use crate::rule::with_actions::{RuleWithActions, RuleWithActionsKind};
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
