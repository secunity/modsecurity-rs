//! [`Operator`], the operator of a rule ([`RuleOperator`]), what a
//! matcher sees of the transaction ([`MatchContext`]), and [`instantiate`],
//! which builds an operator by name.

use std::borrow::Cow;

pub use modsecurity_operators::Param;
use modsecurity_operators::{Context, ResourceLookup, Resources};

use crate::operators::inspect_file::InspectFile;
use crate::rule::Rule;
use crate::rule::message::RuleMessage;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

/// What a matcher may do while it evaluates a value: read its parameter
/// for this transaction, record what it matched, and write to the debug
/// log. Matchers see the transaction only through this. (`@inspectFile`
/// is given the transaction.)
pub struct MatchContext<'c, 't, 'm> {
    t: &'c mut Transaction<'t>,
    rule: &'c Rule,
    rm: &'c mut RuleMessage<'m>,
    /// The operator's parameter with its macros, when it has one.
    param: Option<&'c RunTimeString>,
}

impl<'c, 't, 'm> MatchContext<'c, 't, 'm> {
    pub fn new(t: &'c mut Transaction<'t>, rule: &'c Rule, rm: &'c mut RuleMessage<'m>) -> Self {
        MatchContext { t, rule, rm, param: None }
    }

    /// The context of an operator whose parameter is `param`.
    pub fn with_param(self, param: Option<&'c RunTimeString>) -> Self {
        MatchContext { param, ..self }
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
        self.t.rules.properties.settings.pcre_match_limit.map_or(0, u64::from)
    }

    /// Reports a regular expression that failed to compile: logs it and
    /// sets `MSC_PCRE_ERROR` and `TX.MSC_PCRE_ERROR`.
    pub fn regex_compile_error(&mut self, pattern: &str) {
        let t = &mut *self.t;
        crate::ms_dbg!(t, 1, "Error with regular expression: \"{}\"", pattern);
        let off = t.vars.offset;
        t.vars.msc_pcre_error.set(b"1", off);
        t.collections.tx.set(b"MSC_PCRE_ERROR", b"1".to_vec());
        crate::ms_dbg!(t, 7, "Set TX.MSC_PCRE_ERROR to 1");
    }

    /// Reports a failed regular expression search by `op_name`: sets
    /// `MSC_PCRE_ERROR` (and `MSC_PCRE_LIMITS_EXCEEDED` when the match
    /// limit was hit), in TX too, and logs the error.
    pub fn regex_search_error(&mut self, pattern: &str, match_limit: bool, op_name: &str) {
        let t = &mut *self.t;
        let off = t.vars.offset;
        t.vars.msc_pcre_error.set(b"1", off);
        t.collections.tx.set(b"MSC_PCRE_ERROR", b"1".to_vec());
        crate::ms_dbg!(t, 7, "Set TX.MSC_PCRE_ERROR to 1");
        if match_limit {
            t.vars.msc_pcre_limits_exceeded.set(b"1", off);
            t.collections.tx.set(b"MSC_PCRE_LIMITS_EXCEEDED", b"1".to_vec());
            crate::ms_dbg!(t, 7, "Set TX.MSC_PCRE_LIMITS_EXCEEDED to 1");
        }
        crate::ms_dbg!(
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
        self.t.rules.properties.settings.httpbl_key.as_deref().unwrap_or_default().as_bytes()
    }

    /// The document the XML request body processor parsed and its
    /// well-formedness flag (1 when well formed), for `@validateDTD` and
    /// `@validateSchema`; `None` without a document.
    #[cfg(feature = "libxml2")]
    pub fn xml_document(&self) -> Option<(&modsecurity_native::libxml2::Document, u32)> {
        self.t.body.xml.as_ref().and_then(|x| Some((x.document()?, x.well_formed())))
    }
}

/// A SecRule operator (`@rx`, `@pm`, ...): one of the matchers of the
/// `modsecurity-operators` crate, which see the [`MatchContext`] through
/// that crate's `Context`, or `@inspectFile`, which needs the transaction
/// itself.
#[derive(Debug)]
pub enum Operator {
    Matcher(Box<dyn modsecurity_operators::Operator>),
    InspectFile(InspectFile),
}

impl Operator {
    /// The operator name shown in match messages and the debug log (e.g.
    /// `Rx`).
    pub fn name(&self) -> &'static str {
        match self {
            Operator::Matcher(op) => op.name(),
            Operator::InspectFile(_) => "InspectFile",
        }
    }

    /// The parameter, for operators that take one.
    pub fn param(&self) -> Option<&Param> {
        match self {
            Operator::Matcher(op) => op.param(),
            Operator::InspectFile(op) => Some(op.param()),
        }
    }

    /// Compiles or loads what the parameter names, when the rule is read;
    /// `file` is the configuration file of the rule.
    pub fn init(&mut self, file: &str) -> Result<(), String> {
        match self {
            Operator::Matcher(op) => op.init(file, &EngineResources),
            Operator::InspectFile(op) => op.init(file),
        }
    }

    /// Whether `input` matches (before the negation of `!@op`).
    pub fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        match self {
            Operator::Matcher(op) => op.evaluate(cx, input),
            Operator::InspectFile(op) => op.evaluate(cx.t, input),
        }
    }

    /// The result of the rule's operator: [`Operator::evaluate`] with the
    /// negation of `!@op` applied (some matchers do not match on a failure
    /// even when negated).
    pub fn evaluate_negatable(&self, negated: bool, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        match self {
            Operator::Matcher(op) => op.evaluate_negatable(negated, cx, input),
            _ => self.evaluate(cx, input) != negated,
        }
    }

    /// The text logged for a match of `value` in the variable `key`;
    /// `param` is `RuleOperator::message_param` at the time of the match.
    pub fn resolve_match_message(&self, param: &[u8], key: &[u8], value: &[u8]) -> Vec<u8> {
        match self {
            Operator::Matcher(op) => op.resolve_match_message(param, key, value),
            _ => modsecurity_operators::match_message(self.name(), param, key, value),
        }
    }
}

/// The operator of a rule: the operator, its parameter with its macros,
/// and whether the rule negates it (`!@op`).
#[derive(Debug)]
pub struct RuleOperator {
    pub op: Operator,
    /// The parameter as written, for operators that take one.
    pub param: Option<RunTimeString>,
    pub negated: bool,
}

impl RuleOperator {
    pub fn new(op: Operator, param: RunTimeString) -> Self {
        let param = op.param().is_some().then_some(param);
        RuleOperator { op, param, negated: false }
    }

    pub fn evaluate(&self, t: &mut Transaction<'_>, rule: &Rule, input: &[u8], rm: &mut RuleMessage<'_>) -> bool {
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
pub fn instantiate(op: &str, param_str: &str) -> Option<Operator> {
    instantiate_with_param(op, &RunTimeString::from_text(param_str))
}

/// Like [`instantiate`] but with an already parsed (possibly macro bearing)
/// parameter, as built by the configuration parser.
pub fn instantiate_with_param(op: &str, param: &RunTimeString) -> Option<Operator> {
    let param = Param::new(param.evaluate_static(), param.contains_macro());
    Some(match op.to_ascii_lowercase().as_str() {
        "inspectfile" => Operator::InspectFile(InspectFile::new(param)),
        name => Operator::Matcher(modsecurity_operators::instantiate(name, param)?),
    })
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

impl crate::DebugSink for MatchContext<'_, '_, '_> {
    fn debug_enabled(&self, level: u8) -> bool {
        self.t.debug_enabled(level)
    }

    fn debug(&self, level: u8, message: &str) {
        self.t.debug(level, message);
    }
}

impl Context for MatchContext<'_, '_, '_> {
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
    fn geo_db(&self) -> Option<std::sync::Arc<modsecurity_operators::geo_lookup::GeoDb>> {
        self.t.rules.properties.settings.geo_db.clone()
    }
    fn set_geo(&mut self, name: &[u8], value: &[u8]) {
        self.t.vars.geo.set(name, value, 0);
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
    fn xml_document(&self) -> Option<(&modsecurity_native::libxml2::Document, u32)> {
        MatchContext::xml_document(self)
    }
}

/// Evaluating operators in tests, with a fresh transaction and an empty rule.
#[cfg(test)]
pub(crate) mod test_support {
    use super::Operator;
    use crate::instance::ModSecurity;
    use crate::rule::message::RuleMessage;
    use crate::rule::{Rule, RuleKind};
    use crate::rules_set::RulesSet;
    use crate::transaction::Transaction;

    /// `op` applied to `input` in a new transaction.
    pub fn eval(op: &Operator, input: &[u8]) -> bool {
        let ms = ModSecurity::new();
        let rules = RulesSet::new();
        let mut t = Transaction::new(&ms, &rules, None);
        eval_in(op, &mut t, input)
    }

    /// `op` applied to `input` in `t`, for a rule without actions.
    pub fn eval_in(op: &Operator, t: &mut Transaction<'_>, input: &[u8]) -> bool {
        let rule = Rule::new(None, None, "", 0, RuleKind::SecAction);
        let mut rm = RuleMessage::new(&rule);
        op.evaluate(&mut super::MatchContext::new(t, &rule, &mut rm), input)
    }
}
