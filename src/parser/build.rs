//! Applying a SecLang configuration: what the directives of the syntax tree
//! (`syntax.rs`) mean.
//!
//! Each statement is applied as soon as it is read, so that an `Include`d
//! file is loaded in place and the first error stops the load, with the
//! directives before it applied (as the C++ parser does).
//!
//! The grammar only describes the shape of a directive. The names it reads
//! (directives, variables, operators, actions, transformations) and the
//! values they accept are checked here, against the same rules as the
//! C++ scanner: a directive keyword and its value, an action name and its
//! payload. Values are read as the C++ scanner reads them (the first space
//! after the keyword separates it from the value, quotes are removed by the
//! same helpers), so that the properties and rules built are the same.

use crate::actions::action::{InertAction, Kind};
use crate::actions::rule_action::RuleAction;
use crate::actions::transformation::{Transformation, TransformationKind as TK};
use crate::actions::{self, ctl, data, disruptive};
use crate::audit_log::{AuditLogFormat, AuditLogStatus, AuditLogType};
use crate::operators::operator::{RuleOperator, instantiate_with_param};
use crate::parser::driver::Driver;
use crate::parser::driver::Position;
use crate::parser::syntax::{
    self, ActionKind, Directive, Modifier, Piece, Selector, SetVarOp, Target, UpdateBy, VarRef,
};
use crate::phases::Phases;
use crate::rule::script::RuleScript;
use crate::rule::with_actions::{RuleWithActions, RuleWithActionsKind};
use crate::rule::with_operator::RuleWithOperator;
use crate::rules_set::properties::{
    BodyLimitAction, ConfigUnicodeMap, OnFailedRemoteRulesAction, ParseXmlIntoArgs, RuleEngine, parse_config_number,
    parse_octal_mode,
};
use crate::run_time_string::RunTimeString;
use crate::utils::https_client::HttpsClient;
use crate::utils::string::{atoi, parser_sanitizer, remove_brackets_if_needed, ssplit, stod, strtol_int};
use crate::utils::system::{expand_env, find_resource};
use crate::variables::variable::Variable;
use crate::variables::{VariableSelector, new_variable};
use modsecurity_operators::seclang_operator;

/// The load stopped: the error is in `driver.properties.parser_error`.
#[derive(Debug)]
pub(crate) struct Failed;

type Res<T> = Result<T, Failed>;

/// Loads the configuration `data`, read from the file `file` (an index in
/// the driver's file names).
pub(crate) fn load(driver: &mut Driver, data: &[u8], file: usize) -> Res<()> {
    load_with(driver, data, file, true)
}

/// `load`; `whole_file: false` reads the statements one by one, as after a
/// syntax error (the tests compare both ways).
pub(crate) fn load_with(driver: &mut Driver, data: &[u8], file: usize, whole_file: bool) -> Res<()> {
    let source = syntax::Source::new(data);
    let text = source.text();
    let mut lines = Lines { text, offset: 0, line: 1 };
    // The usual case: the whole file is read at once.
    if let Some(Ok(statements)) = whole_file.then(|| syntax::parse_file(text)) {
        for (statement, _) in statements {
            let Some(statement) = statement else { break };
            apply(driver, file, &mut lines, statement)?;
        }
        return Ok(());
    }
    // A syntax error: the statements before it are applied first (they may
    // fail before it, or load files), one by one.
    let mut from = 0;
    loop {
        let (statement, end) = match syntax::parse_statement(text, from) {
            Ok(r) => r,
            Err(e) => {
                let at = lines.location(file, e.offset);
                driver.error(at, &e.message, "");
                return Err(Failed);
            }
        };
        let Some(statement) = statement else {
            return Ok(());
        };
        apply(driver, file, &mut lines, statement)?;
        from = end;
    }
}

fn apply(driver: &mut Driver, file: usize, lines: &mut Lines<'_>, statement: syntax::Statement<'_>) -> Res<()> {
    // The line of the keyword.
    let line = lines.line_of(statement.offset);
    let mut b = Builder { driver, file, lines, line, at: statement.offset };
    b.directive(statement.directive)
}

/// Line numbers of offsets of a text, read forward.
struct Lines<'a> {
    text: &'a str,
    offset: usize,
    line: usize,
}

impl Lines<'_> {
    /// The line of `offset`, at or after the last offset asked for.
    fn line_of(&mut self, offset: usize) -> usize {
        if offset < self.offset {
            return self.text[..offset].bytes().filter(|&b| b == b'\n').count() + 1;
        }
        self.line += self.text[self.offset..offset].bytes().filter(|&b| b == b'\n').count();
        self.offset = offset;
        self.line
    }

    fn location(&mut self, file: usize, offset: usize) -> Position {
        let line = self.line_of(offset);
        let column = offset - self.text[..offset].rfind('\n').map_or(0, |i| i + 1) + 1;
        Position { file, line, column }
    }
}

/// The text of a piece of the configuration, as the C++ code reads it
/// (`std::string`, shown as UTF-8).
fn string(s: &str) -> String {
    if s.is_ascii() {
        return s.to_string();
    }
    String::from_utf8_lossy(&syntax::bytes(s)).into_owned()
}

struct Builder<'d, 't> {
    driver: &'d mut Driver,
    file: usize,
    lines: &'d mut Lines<'t>,
    /// The line of the directive keyword.
    line: usize,
    /// Where errors are reported: the directive, or the action being built.
    at: usize,
}

impl Builder<'_, '_> {
    fn fail<T>(&mut self, msg: &str) -> Res<T> {
        let at = self.lines.location(self.file, self.at);
        self.driver.error(at, msg, "");
        Err(Failed)
    }

    /// Fails with an error already recorded (by `Driver::add_sec_rule`).
    fn failed<T>(&self) -> Res<T> {
        Err(Failed)
    }

    fn file_name(&self) -> String {
        self.driver.filename(self.file).to_string()
    }

    fn directive(&mut self, directive: Directive<'_>) -> Res<()> {
        let line = self.line as i32;
        match directive {
            Directive::Rule { variables, operator, actions } => {
                let vars = self.targets(&variables)?;
                let vars = exclusions(vars);
                let op = self.operator(&operator)?;
                let (a, t) = match actions {
                    Some(list) => {
                        let (a, t) = split_actions(self.actions(&list)?);
                        (Some(a), Some(t))
                    }
                    None => (None, None),
                };
                let file = self.file_name();
                let kind = RuleWithActionsKind::Operator(RuleWithOperator::new(op, vars));
                let rule = RuleWithActions::new(a, t, &file, line, kind);
                if !self.driver.add_sec_rule(rule) {
                    return self.failed();
                }
            }
            Directive::Action(list) => {
                let (a, t) = split_actions(self.actions(&list)?);
                let file = self.file_name();
                let rule = RuleWithActions::new(Some(a), Some(t), &file, line, RuleWithActionsKind::Unconditional);
                self.driver.add_sec_action(rule);
            }
            Directive::RuleScript { path, actions } => {
                if !path.quoted && !syntax::bytes(path.text).iter().all(|&c| is_path(c)) {
                    return self.fail(&format!("Invalid input: {}", string(path.text)));
                }
                let Some(list) = actions else {
                    return self.fail("SecRuleScript needs actions.");
                };
                let script = parser_sanitizer(if path.quoted {
                    format!("\"{}\"", string(path.text))
                } else {
                    string(path.text)
                });
                let (a, t) = split_actions(self.actions(&list)?);
                let file = self.file_name();
                let kind = RuleWithActionsKind::Script(RuleScript::new(&script));
                let mut r = RuleWithActions::new(Some(a), Some(t), &file, line, kind);
                if let Some(s) = r.as_rule_script_mut()
                    && let Err(err) = s.init()
                {
                    return self.fail(&format!("Failed to load script: {}", err));
                }
                if !self.driver.add_sec_rule_script(r) {
                    return self.failed();
                }
            }
            Directive::DefaultAction(list) => {
                let list = self.actions(&list)?;
                self.sec_default_action(list)?;
            }
            Directive::UpdateTarget { by, selector, variables } => {
                let v = update_value(selector);
                let vars = self.targets(&variables)?;
                let ex = &mut self.driver.properties.exceptions;
                match by {
                    UpdateBy::Tag => ex.load_update_target_by_tag(&v, vars),
                    UpdateBy::Msg => ex.load_update_target_by_msg(&v, vars),
                    UpdateBy::Id => {
                        let Some(rule_id) = stod(&v) else {
                            return self.fail(&format!(
                                "SecRuleUpdateTargetById: failed to load:The input \"{}\" does not seems to be a valid rule id.. ",
                                v
                            ));
                        };
                        ex.load_update_target_by_id(rule_id, vars);
                    }
                }
            }
            Directive::UpdateAction { id, actions } => {
                let v = update_value(id);
                let Some(rule_id) = stod(&v) else {
                    return self.fail(&format!(
                        "SecRuleUpdateActionById: failed to load:The input \"{}\" does not seems to be a valid rule id.. ",
                        v
                    ));
                };
                let acts = self.actions(&actions)?.into_iter().map(ParsedAction::into_action).collect();
                self.driver.properties.exceptions.load_update_action_by_id(rule_id, acts);
            }
            Directive::Setting { keyword, rest } => self.setting(keyword, rest)?,
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Variables
    // -----------------------------------------------------------------------

    fn targets(&mut self, targets: &[Target<'_>]) -> Res<Vec<Variable>> {
        let mut list = Vec::with_capacity(targets.len());
        for t in targets {
            let var = self.var(&t.var)?;
            list.push(match t.modifier {
                Some(Modifier::Exclusion) => Variable::exclusion(var),
                Some(Modifier::Count) => Variable::count(var),
                None => var,
            });
        }
        Ok(list)
    }

    /// A rule target or a macro variable.
    fn var(&mut self, v: &VarRef<'_>) -> Res<Variable> {
        let selector = match v.selector {
            Selector::None => VariableSelector::None,
            Selector::Key(k) => VariableSelector::DictElement(string(k)),
            Selector::Regex(r) => VariableSelector::Regexp(string(r)),
        };
        self.new_var(v.name, selector)
    }

    fn new_var(&mut self, name: &str, selector: VariableSelector) -> Res<Variable> {
        if name.eq_ignore_ascii_case("WEBSERVER_ERROR_LOG") {
            return self.fail("Variable VARIABLE_WEBSERVER_ERROR_LOG is not supported by libModSecurity");
        }
        match new_variable(name, selector) {
            Some(v) => Ok(v),
            None => self.fail(&format!("Expecting a variable, got: {}", name)),
        }
    }

    /// The parameter of an operator other than a regular expression.
    /// Between double quotes, `\"` is a quote (the C++ scanner kept the
    /// backslash, upstream issue 3750).
    fn param(&mut self, o: &syntax::Operator<'_>, pieces: &[Piece<'_>]) -> Res<RunTimeString> {
        if !o.quoted {
            return self.run_time_string(pieces);
        }
        let mut r = RunTimeString::new();
        for p in pieces {
            match p {
                Piece::Text(t) => r.append_bytes(&unescape_quotes(&syntax::bytes(t))),
                Piece::Macro(v) => {
                    let var = self.var(v)?;
                    r.append_var(var);
                }
            }
        }
        Ok(r)
    }

    fn run_time_string(&mut self, pieces: &[Piece<'_>]) -> Res<RunTimeString> {
        let mut r = RunTimeString::new();
        for p in pieces {
            match p {
                Piece::Text(t) => r.append_bytes(&syntax::bytes(t)),
                Piece::Macro(v) => {
                    let var = self.var(v)?;
                    r.append_var(var);
                }
            }
        }
        Ok(r)
    }

    // -----------------------------------------------------------------------
    // Operators
    // -----------------------------------------------------------------------

    fn operator(&mut self, o: &syntax::Operator<'_>) -> Res<RuleOperator> {
        let (name, param) = match o.name.map(seclang_operator) {
            // A bare parameter is a regular expression.
            None => {
                if o.param.is_empty() {
                    return self.fail("Expecting an operator or a regular expression.");
                }
                // `"@lt' 3"`: an operator name followed by something else
                // than a space.
                if o.raw.strip_prefix('@').is_some_and(|w| w.starts_with(|c: char| c.is_ascii_alphabetic())) {
                    return self.fail(&format!("Unknown operator: {}", string(o.raw)));
                }
                ("rx", self.run_time_string(&o.param)?)
            }
            Some(None) => {
                return self.fail(&format!("Unknown operator: @{}", string(o.name.unwrap_or(""))));
            }
            Some(Some(op)) if !op.takes_param && !blank_param(o) => {
                return self.fail(&format!("The operator @{} takes no parameter.", op.name));
            }
            Some(Some(op)) => {
                if let Some(not_supported) = op.not_supported {
                    return self.fail(&format!("Operator: {} is not yet supported.", not_supported));
                }
                if op.name == "geoLookup" && !cfg!(feature = "maxmind") {
                    return self.fail("This version of ModSecurity was not compiled with GeoIP or MaxMind support.");
                }
                if op.takes_param && o.param.is_empty() {
                    return self.fail(&format!("The operator {} needs a parameter.", op.name));
                }
                let param = if op.name.starts_with("rx") {
                    // PCRE already reads `\"` as `"`; the parameter is
                    // kept as written (it is shown in the logs).
                    self.run_time_string(&o.param)?
                } else {
                    self.param(o, &o.param)?
                };
                (op.name, param)
            }
        };
        let Some(o2) = instantiate_with_param(name, &param) else {
            return self.fail(&format!("Unknown operator: {}", name));
        };
        let mut op = RuleOperator::new(o2, param);
        op.negated = o.negated;
        let file = self.file_name();
        if let Err(error) = op.op.init(&file) {
            return self.fail(&error);
        }
        Ok(op)
    }

    // -----------------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------------

    fn actions(&mut self, list: &[syntax::Action<'_>]) -> Res<Vec<ParsedAction>> {
        let mut out = Vec::with_capacity(list.len());
        for a in list {
            self.at = a.offset;
            let built = match &a.kind {
                ActionKind::Plain { name, text } => self.plain_action(name, &string(text))?,
                ActionKind::Macro { name, value } => {
                    let z = self.run_time_string(value)?;
                    Ok(macro_action(name, z))
                }
                ActionKind::InitCol { text, value } => {
                    let z = self.run_time_string(value)?;
                    actions::init_col::InitCol::with_rts(&string(text), z).map(other)
                }
                ActionKind::SetVar { unset, collection, key, op } => self.setvar(*unset, collection, key, op)?,
            };
            match built {
                Ok(a) => out.push(a),
                Err(error) => return self.fail(&error),
            }
        }
        Ok(out)
    }

    fn setvar(
        &mut self,
        unset: bool,
        collection: &str,
        key: &[Piece<'_>],
        op: &Option<(SetVarOp, Vec<Piece<'_>>)>,
    ) -> Res<Result<ParsedAction, String>> {
        use crate::actions::set_var::{SetVar, SetVarOperation};
        if !is_collection(collection) {
            return self.fail(&format!("Expecting a variable, got: {}", collection));
        }
        let key = self.run_time_string(key)?;
        let var = self.new_var(collection, VariableSelector::Dynamic(key))?;
        let operation = match op {
            _ if unset => SetVarOperation::Unset,
            None => SetVarOperation::SetToOne,
            Some((o, value)) => {
                let value = self.run_time_string(value)?;
                match o {
                    SetVarOp::Add => SetVarOperation::Add(value),
                    SetVarOp::Subtract => SetVarOperation::Subtract(value),
                    SetVarOp::Set => SetVarOperation::Set(value),
                }
            }
        };
        Ok(Ok(ParsedAction::Action(RuleAction::SetVar(SetVar::new(var, operation)))))
    }

    /// An action other than `setvar`, `initcol` and the actions with macros:
    /// `text` is the whole action as written (`name` or `name:value`).
    fn plain_action(&mut self, name: &str, text: &str) -> Res<Result<ParsedAction, String>> {
        use ParsedAction::Transformation as T;
        let value = text.split_once(':').map(|(_, v)| v);
        let lname = name.to_ascii_lowercase();
        let s = text;
        let invalid = |b: &mut Self| b.fail(&format!("Expecting an action, got: {}", text));
        // Actions without a value.
        let bare = |b: &mut Self| if value.is_some() { invalid(b).map(|_| ()) } else { Ok(()) };
        let a = match lname.as_str() {
            "append"
            | "deprecatevar"
            | "pause"
            | "prepend"
            | "proxy"
            | "sanitisearg"
            | "sanitisematched"
            | "sanitisematchedbytes"
            | "sanitiserequestheader"
            | "sanitiseresponseheader" => {
                bare(self)?;
                let n = match lname.as_str() {
                    "append" => "Append",
                    "deprecatevar" => "DeprecateVar",
                    "pause" => "Pause",
                    "prepend" => "Prepend",
                    "proxy" => "Proxy",
                    "sanitisearg" => "SanitiseArg",
                    "sanitisematched" => "SanitiseMatched",
                    "sanitisematchedbytes" => "SanitiseMatchedBytes",
                    "sanitiserequestheader" => "SanitiseRequestHeader",
                    _ => "SanitiseResponseHeader",
                };
                return self.fail(&format!("Action: {} is not yet supported.", n));
            }
            "auditlog" => {
                bare(self)?;
                other(actions::audit_log::AuditLog::new(s))
            }
            "block" => {
                bare(self)?;
                ParsedAction::Action(RuleAction::Block(actions::block::Block::new(s)))
            }
            "capture" => {
                bare(self)?;
                ParsedAction::Action(RuleAction::Capture(actions::capture::Capture::new(s)))
            }
            "chain" => {
                bare(self)?;
                other(actions::chain::Chain::new(s))
            }
            "deny" => {
                bare(self)?;
                other(disruptive::deny::Deny::new(s))
            }
            "drop" => {
                bare(self)?;
                other(disruptive::drop::Drop::new(s))
            }
            "log" => {
                bare(self)?;
                other(actions::log::Log::new(s))
            }
            "multimatch" => {
                bare(self)?;
                ParsedAction::Action(RuleAction::MultiMatch(actions::multi_match::MultiMatch::new(s)))
            }
            "noauditlog" => {
                bare(self)?;
                other(actions::no_audit_log::NoAuditLog::new(s))
            }
            "nolog" => {
                bare(self)?;
                other(actions::no_log::NoLog::new(s))
            }
            "pass" => {
                bare(self)?;
                other(disruptive::pass::Pass::new(s))
            }
            "allow" => {
                if let Some(v) = value
                    && !(v.eq_ignore_ascii_case("request") || v.eq_ignore_ascii_case("phase"))
                {
                    return invalid(self);
                }
                return Ok(disruptive::allow::Allow::new(s).map(other));
            }
            "accuracy" | "maturity" => {
                if value.is_none_or(|v| unquote(v).unwrap_or(v).is_empty()) {
                    return invalid(self);
                }
                if lname == "accuracy" {
                    return Ok(actions::accuracy::Accuracy::new(s).map(other));
                }
                return Ok(actions::maturity::Maturity::new(s).map(other));
            }
            "exec" => {
                match value {
                    Some(v) if unquote(v).is_some_and(|q| !q.is_empty()) => {}
                    Some(v) if !v.is_empty() && !v.starts_with('\'') => {}
                    _ => return invalid(self),
                }
                return Ok(actions::exec::Exec::new(s).map(other));
            }
            "id" => {
                if !value.is_some_and(|v| is_number(unquote(v).unwrap_or(v))) {
                    return invalid(self);
                }
                return Ok(actions::rule_id::RuleId::new(s).map(other));
            }
            "phase" => {
                let v = value.unwrap_or("");
                let p = unquote(v).unwrap_or(v);
                let known = ["request", "response", "logging"].iter().any(|n| p.eq_ignore_ascii_case(n));
                if value.is_none() || !(known || is_number(p)) {
                    return invalid(self);
                }
                return Ok(actions::phase::Phase::new(s).map(|a| ParsedAction::Action(RuleAction::Phase(a))));
            }
            "rev" => {
                let v = value.unwrap_or("");
                let v = unquote(v).unwrap_or(v);
                if value.is_none() || v.is_empty() || v.contains([',', '\'']) {
                    return invalid(self);
                }
                other(actions::rev::Rev::new(s))
            }
            "severity" => {
                let v = value.unwrap_or("");
                let v = unquote(v).unwrap_or(v);
                let names = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"];
                if value.is_none() || !(is_number(v) || names.iter().any(|n| v.eq_ignore_ascii_case(n))) {
                    return invalid(self);
                }
                return Ok(actions::severity::Severity::new(s).map(|a| ParsedAction::Action(RuleAction::Severity(a))));
            }
            "skipafter" => {
                if !value.is_some_and(|v| !v.is_empty() && !v.starts_with('\'')) {
                    return invalid(self);
                }
                other(actions::skip_after::SkipAfter::new(s))
            }
            "skip" => {
                if !value.is_some_and(is_number) {
                    return invalid(self);
                }
                return Ok(actions::skip::Skip::new(s).map(other));
            }
            "status" => {
                if !value.is_some_and(is_number) {
                    return invalid(self);
                }
                return Ok(data::status::Status::new(s).map(other));
            }
            "ver" => {
                if value.and_then(unquote).is_none_or(|q| q.is_empty()) {
                    return invalid(self);
                }
                other(actions::ver::Ver::new(s))
            }
            "xmlns" => {
                if !value.is_some_and(|v| !v.is_empty() && !v.starts_with('\'')) {
                    return invalid(self);
                }
                return Ok(actions::xmlns::XmlNS::new(s).map(other));
            }
            "t" => match value.and_then(TK::from_name) {
                Some(kind) => T(Transformation::new(kind, s)),
                None => return invalid(self),
            },
            "ctl" => return self.ctl(text, value.unwrap_or("")),
            _ => return invalid(self),
        };
        Ok(Ok(a))
    }

    /// `ctl:<option>=<value>`
    fn ctl(&mut self, text: &str, option: &str) -> Res<Result<ParsedAction, String>> {
        use crate::audit_log::AuditLogStatus;
        use crate::rules_set::properties::{ParseXmlIntoArgs, RuleEngine};
        let invalid = |b: &mut Self| b.fail(&format!("Expecting an action, got: {}", text));
        let Some((name, value)) = option.split_once('=') else {
            return invalid(self);
        };
        // `ctl:<name>=`, what the actions with a value token are built from.
        let head = &text[..text.len() - value.len()];
        let is = |v: &str| value.eq_ignore_ascii_case(v);
        let s = text;
        let a = match name.to_ascii_lowercase().as_str() {
            "auditengine" if is("on") => {
                self.driver.properties.audit_log.set_ctl_audit_engine_active();
                other(ctl::audit_engine::AuditEngine::new(AuditLogStatus::On))
            }
            "auditengine" if is("off") => other(ctl::audit_engine::AuditEngine::new(AuditLogStatus::Off)),
            "auditengine" if is("relevantonly") => {
                self.driver.properties.audit_log.set_ctl_audit_engine_active();
                other(ctl::audit_engine::AuditEngine::new(AuditLogStatus::RelevantOnly))
            }
            "auditlogparts"
                if value.len() >= 2
                    && matches!(value.as_bytes()[0], b'+' | b'|' | b'-')
                    && value[1..].bytes().all(is_audit_part) =>
            {
                other(ctl::audit_log_parts::AuditLogParts::new(s))
            }
            "requestbodyprocessor" if is("json") => {
                other(ctl::request_body_processor_json::RequestBodyProcessorJSON::new(s))
            }
            "requestbodyprocessor" if is("xml") => {
                other(ctl::request_body_processor_xml::RequestBodyProcessorXML::new(s))
            }
            "requestbodyprocessor" if is("urlencoded") => {
                other(ctl::request_body_processor_urlencoded::RequestBodyProcessorURLENCODED::new(s))
            }
            "forcerequestbodyvariable" if is("on") || is("off") => other(InertAction::new(head)),
            "parsexmlintoargs" if is("on") => {
                other(ctl::parse_xml_into_args::ParseXmlIntoArgs::new(ParseXmlIntoArgs::On))
            }
            "parsexmlintoargs" if is("off") => {
                other(ctl::parse_xml_into_args::ParseXmlIntoArgs::new(ParseXmlIntoArgs::Off))
            }
            "parsexmlintoargs" if is("onlyargs") => {
                other(ctl::parse_xml_into_args::ParseXmlIntoArgs::new(ParseXmlIntoArgs::OnlyArgs))
            }
            "requestbodyaccess" if is("on") || is("off") => {
                other(ctl::request_body_access::RequestBodyAccess::new(head, is("on")))
            }
            "ruleengine" if is("on") => other(ctl::rule_engine::RuleEngine::new(RuleEngine::Enabled)),
            "ruleengine" if is("off") => other(ctl::rule_engine::RuleEngine::new(RuleEngine::Disabled)),
            "ruleengine" if is("detectiononly") => other(ctl::rule_engine::RuleEngine::new(RuleEngine::DetectionOnly)),
            "ruleremovebyid" | "ruleremovebytag" | "ruleremovetargetbyid" | "ruleremovetargetbytag"
                if !value.is_empty() && value.bytes().all(is_remove_rule_by) =>
            {
                return Ok(match name.to_ascii_lowercase().as_str() {
                    "ruleremovebyid" => ctl::rule_remove_by_id::RuleRemoveById::new(s).map(other),
                    "ruleremovebytag" => ctl::rule_remove_by_tag::RuleRemoveByTag::new(s).map(other),
                    "ruleremovetargetbyid" => ctl::rule_remove_target_by_id::RuleRemoveTargetById::new(s).map(other),
                    _ => ctl::rule_remove_target_by_tag::RuleRemoveTargetByTag::new(s).map(other),
                });
            }
            _ => return invalid(self),
        };
        Ok(Ok(a))
    }

    /// `SecDefaultAction`
    fn sec_default_action(&mut self, list: Vec<ParsedAction>) -> Res<()> {
        let mut has_disruptive = false;
        let mut checked_actions: Vec<RuleAction> = Vec::new();
        let mut defined_phase: Option<Phases> = None;
        let mut sec_rule_defined_phase: i32 = -1;
        for pa in list {
            let a = pa.into_action();
            if a.is_disruptive() && !matches!(a, RuleAction::Block(_)) {
                has_disruptive = true;
            }
            if let RuleAction::Phase(phase) = &a {
                defined_phase = phase.phase;
                sec_rule_defined_phase = match phase.phase {
                    None => -1,
                    Some(Phases::Connection) => 0,
                    Some(p) => p as i32 - 1,
                };
            } else if matches!(a.kind(), Kind::RunTimeOnlyIfMatch | Kind::RunTimeBeforeMatchAttempt) {
                if a.is_transformation_none() {
                    return self.fail("The transformation none is not suitable to be part of the SecDefaultActions");
                }
                checked_actions.push(a);
            } else {
                let msg = format!("The action '{}' is not suitable to be part of the SecDefaultActions", a.name());
                return self.fail(&msg);
            }
        }
        if !has_disruptive {
            return self.fail("SecDefaultAction must specify a disruptive action.");
        }
        let index = defined_phase.unwrap_or(Phases::RequestHeaders).index();
        if !self.driver.properties.default_actions[index].is_empty() {
            let msg = format!(
                "SecDefaultActions can only be placed once per phase and configuration context. Phase {} was informed already.",
                sec_rule_defined_phase
            );
            return self.fail(&msg);
        }
        self.driver.properties.default_actions[index].extend(checked_actions.into_iter().map(std::sync::Arc::new));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------------

    fn setting(&mut self, keyword: &str, rest: &str) -> Res<()> {
        let rest = syntax::bytes(rest);
        let Some(d) = setting_kind(keyword) else {
            return self.fail(&format!("Invalid input: {}{}", keyword, String::from_utf8_lossy(&rest)));
        };
        match d.form {
            Form::Value(patterns) => {
                let Some((end, extract, which)) = longest(&rest, patterns) else {
                    return self.fail(&format!(
                        "Invalid value for {}: {}",
                        keyword,
                        String::from_utf8_lossy(rest.trim_ascii_start())
                    ));
                };
                if !ignorable(&rest[end..]) {
                    return self.fail(&format!("Invalid input: {}", String::from_utf8_lossy(&rest[end..])));
                }
                let mut yytext = keyword.as_bytes().to_vec();
                yytext.extend_from_slice(&rest[..end]);
                let v = extract.apply(&yytext);
                // `SecArgumentSeparator` with more than a word is another
                // (ignored) directive of the C++ scanner.
                let dir = if d.dir == Effect::ArgumentSeparator && which == 2 { Effect::Ignored } else { d.dir };
                self.apply_value(dir, v, &rest[..end])
            }
            Form::Choice(choices) => {
                let r = rest.trim_ascii_start();
                if choices.is_empty() {
                    if !ignorable(&rest) {
                        return self.fail(&format!("Invalid input: {}", String::from_utf8_lossy(&rest)));
                    }
                    return self.apply_choice(d.dir, "");
                }
                let word_end = r.iter().position(|&c| matches!(c, b' ' | b'\t' | b'\r' | b'#')).unwrap_or(r.len());
                let word = String::from_utf8_lossy(&r[..word_end]);
                let separated = rest.first().is_some_and(|&c| c == b' ' || c == b'\t');
                let choice = choices.iter().find(|c| c.eq_ignore_ascii_case(&word));
                match choice {
                    Some(c) if separated && ignorable(&r[word_end..]) => self.apply_choice(d.dir, c),
                    _ => self.fail(&format!("Invalid value for {}: {}", keyword, String::from_utf8_lossy(r))),
                }
            }
        }
    }

    /// The directives with a choice of values (`SecRuleEngine On`).
    fn apply_choice(&mut self, dir: Effect, choice: &str) -> Res<()> {
        let is = |v: &str| choice.eq_ignore_ascii_case(v);
        let p = &mut self.driver.properties;
        match dir {
            Effect::RuleEngine => {
                p.settings.sec_rule_engine = Some(if is("off") {
                    RuleEngine::Disabled
                } else if is("on") {
                    RuleEngine::Enabled
                } else {
                    RuleEngine::DetectionOnly
                })
            }
            Effect::RequestBodyAccess => p.settings.sec_request_body_access = Some(is("on")),
            Effect::ResponseBodyAccess => p.settings.sec_response_body_access = Some(is("on")),
            Effect::AuditEngine => p.audit_log.set_status(if is("relevantonly") {
                AuditLogStatus::RelevantOnly
            } else if is("off") {
                AuditLogStatus::Off
            } else {
                AuditLogStatus::On
            }),
            Effect::AuditLogFormat => {
                p.audit_log.set_format(if is("json") { AuditLogFormat::Json } else { AuditLogFormat::Native })
            }
            Effect::AuditLogType => p.audit_log.set_type(if is("serial") {
                AuditLogType::Serial
            } else if is("https") {
                AuditLogType::Https
            } else {
                AuditLogType::Parallel
            }),
            Effect::UploadKeepFiles => {
                if is("relevantonly") {
                    return self.fail(
                        "SecUploadKeepFiles RelevantOnly is not currently supported. Accepted values are On or Off",
                    );
                }
                p.settings.upload_keep_files = Some(is("on"));
            }
            Effect::TmpSaveUploadedFiles => p.settings.tmp_save_uploaded_files = Some(is("on")),
            Effect::RequestBodyLimitAction => {
                p.settings.request_body_limit_action =
                    Some(if is("processpartial") { BodyLimitAction::ProcessPartial } else { BodyLimitAction::Reject })
            }
            Effect::ResponseBodyLimitAction => {
                p.settings.response_body_limit_action =
                    Some(if is("processpartial") { BodyLimitAction::ProcessPartial } else { BodyLimitAction::Reject })
            }
            Effect::RemoteRulesFailAction => {
                p.remote_rules_action_on_failed =
                    Some(if is("abort") { OnFailedRemoteRulesAction::Abort } else { OnFailedRemoteRulesAction::Warn })
            }
            Effect::XmlExternalEntity => p.settings.sec_xml_external_entity = Some(is("on")),
            Effect::ParseXmlIntoArgs => {
                p.settings.sec_xml_parse_xml_into_args = Some(if is("onlyargs") {
                    ParseXmlIntoArgs::OnlyArgs
                } else if is("off") {
                    ParseXmlIntoArgs::Off
                } else {
                    ParseXmlIntoArgs::On
                })
            }
            Effect::ResponseBodyMimeTypesClear => {
                let t = &mut p.response_body_type_to_be_inspected;
                t.set = true;
                t.clear = true;
                t.value.clear();
            }
            Effect::ConnEngine if is("on") => return self.fail("SecConnEngine is not yet supported."),
            Effect::DisableBackendCompression if is("on") => {
                return self.fail("SecDisableBackendCompression is not supported.");
            }
            Effect::ContentInjection if is("on") => return self.fail("SecContentInjection is not yet supported."),
            Effect::HashEngine if is("on") => return self.fail("SecHashEngine is not yet supported."),
            Effect::InterceptOnError if is("on") => return self.fail("SecInterceptOnError is not yet supported."),
            Effect::RuleInheritance if is("on") => return self.fail("SecRuleInheritance is not yet supported."),
            Effect::ConnEngine
            | Effect::DisableBackendCompression
            | Effect::ContentInjection
            | Effect::HashEngine
            | Effect::InterceptOnError
            | Effect::RuleInheritance => {}
            Effect::Unsupported(msg) => return self.fail(msg),
            _ => unreachable!("not a directive with a choice of values"),
        }
        Ok(())
    }

    /// The directives with a value. `v` is the value as the C++ scanner
    /// returns it; `token` is the text after the keyword it was read from.
    fn apply_value(&mut self, dir: Effect, v: Vec<u8>, token: &[u8]) -> Res<()> {
        let s = String::from_utf8_lossy(&v).into_owned();
        let p = &mut self.driver.properties;
        match dir {
            Effect::AuditLogDirMode => p.audit_log.set_storage_dir_mode(strtol_int(&s, 8)),
            Effect::AuditLogStorageDir => p.audit_log.set_storage_dir(&s),
            Effect::AuditLogFileMode => p.audit_log.set_file_mode(strtol_int(&s, 8)),
            Effect::AuditLog2 => p.audit_log.set_file_path2(&s),
            Effect::AuditLogParts => p.audit_log.set_parts(&s),
            Effect::AuditLog => p.audit_log.set_file_path1(&s),
            Effect::AuditLogRelevantStatus => p.audit_log.set_relevant_status(&s),
            Effect::AuditLogPrefix => p.audit_log.set_prefix(&s),
            Effect::UploadFileLimit => match parse_config_number(&s) {
                Ok(n) => p.settings.upload_file_limit = Some(n),
                Err(e) => return self.fail(&format!("Failed to parse SecUploadFileLimit: {}", e)),
            },
            Effect::UploadFileMode => match parse_octal_mode(&s) {
                Ok(n) => p.settings.upload_file_mode = Some(n),
                Err(e) => return self.fail(&format!("Failed to parse SecUploadFileMode: {}", e)),
            },
            Effect::UploadDir => p.settings.upload_directory = Some(s),
            Effect::Marker => {
                let marker = remove_brackets_if_needed(s);
                let file = self.file_name();
                self.driver.add_sec_marker(&marker, &file, self.line as i32);
            }
            Effect::ArgumentSeparator => {
                if v.len() != 1 {
                    return self.fail("Argument separator should be set to a single character.");
                }
                p.settings.sec_argument_separator = Some(s);
            }
            Effect::ComponentSignature => p.components.push(s),
            Effect::WebAppId => p.settings.sec_web_app_id = Some(s),
            Effect::RuleRemoveById => {
                if let Err(error) = p.exceptions.load(&s) {
                    return self.fail(&format!("SecRuleRemoveById: failed to load:{}. {}", s, error));
                }
            }
            Effect::RuleRemoveByTag => p.exceptions.load_remove_rule_by_tag(&s),
            Effect::RuleRemoveByMsg => p.exceptions.load_remove_rule_by_msg(&s),
            Effect::DebugLogLevel => p.debug_log.set_level(atoi(&v) as i32),
            Effect::DebugLog => {
                if let Err(error) = p.debug_log.set_file(&s) {
                    return self.fail(&format!("Failed to start DebugLog: {}", error));
                }
            }
            Effect::GeoLookupDb => {
                if !cfg!(feature = "maxmind") {
                    return self.fail("This version of ModSecurity was not compiled with GeoIP or MaxMind support.");
                }
                let lookup = find_resource(&s, &self.file_name());
                let Some(file) = lookup.path else {
                    return self
                        .fail(&format!("Failed to load locate the GeoDB file from: {} {}", s, lookup.looked_at));
                };
                match crate::utils::geo_lookup::GeoDb::open(&file) {
                    Ok(db) => self.driver.properties.settings.geo_db = Some(std::sync::Arc::new(db)),
                    // A database opened before stays in use, as in C++.
                    Err(_) if self.driver.properties.settings.geo_db.is_some() => {}
                    Err(err) => return self.fail(&format!("Failed to load the GeoDB from: {}. {}", file, err)),
                }
            }
            Effect::ArgumentsLimit => p.settings.arguments_limit = Some(atoi(&v) as i32 as u32),
            Effect::RequestBodyJsonDepthLimit => {
                p.settings.request_body_json_depth_limit = Some(atoi(&v) as i32 as u32)
            }
            Effect::RequestBodyLimit => match parse_config_number(&s) {
                Ok(n) => p.settings.request_body_limit = Some(n),
                Err(e) => return self.fail(&format!("Failed to parse SecRequestBodyLimit: {}", e)),
            },
            Effect::RequestBodyNoFilesLimit => match parse_config_number(&s) {
                Ok(n) => p.settings.request_body_no_files_limit = Some(n),
                Err(e) => return self.fail(&format!("Failed to parse SecRequestsBodyNoFilesLimit: {}", e)),
            },
            Effect::ResponseBodyLimit => match parse_config_number(&s) {
                Ok(n) => p.settings.response_body_limit = Some(n),
                Err(e) => return self.fail(&format!("Failed to parse SecResponseBodyLimit: {}", e)),
            },
            Effect::PcreMatchLimit => match parse_config_number(&s) {
                Ok(n) => p.settings.pcre_match_limit = Some(n),
                Err(e) => return self.fail(&format!("Failed to parse SecPcreMatchLimit: {}", e)),
            },
            Effect::ResponseBodyMimeType => {
                let tokens: std::collections::BTreeSet<&str> = s.split_ascii_whitespace().collect();
                let t = &mut p.response_body_type_to_be_inspected;
                t.set = true;
                for it in tokens {
                    t.value.insert(it.to_ascii_lowercase());
                }
            }
            Effect::CookieFormat => {
                if atoi(&v) as i32 == 1 {
                    return self.fail("SecCookieFormat 1 is not yet supported.");
                }
            }
            Effect::HttpBlKey => p.settings.httpbl_key = Some(s),
            Effect::UnicodeMapFile => return self.unicode_map_file(&s),
            Effect::Include => return self.include(token),
            Effect::RemoteRules => return self.remote_rules(&s),
            // Accepted and ignored.
            Effect::Ignored => {}
            Effect::Unsupported(msg) => return self.fail(msg),
            _ => unreachable!("not a directive with a value"),
        }
        Ok(())
    }

    /// `SecUnicodeMapFile <file> <code page>`
    fn unicode_map_file(&mut self, v: &str) -> Res<()> {
        let mut param: Vec<String> =
            ssplit(v.as_bytes(), b' ').into_iter().map(|p| String::from_utf8_lossy(&p).into_owned()).collect();
        if param.len() <= 1 {
            return self.fail(&format!("Failed to process unicode map, missing parameter: {} ", v));
        }
        let last = param.pop().unwrap_or_default();
        let Some(num) = stod(&last) else {
            return self
                .fail(&format!("Failed to process unicode map, last parameter is expected to be a number: {} ", last));
        };
        let f = param.join(" ");
        let lookup = find_resource(&f, &self.file_name());
        let Some(file) = lookup.path else {
            return self.fail(&format!("Failed to locate the unicode map file from: {} {}", f, lookup.looked_at));
        };
        if let Err(error) = ConfigUnicodeMap::load_config(&file, num, &mut self.driver.properties)
            && !error.is_empty()
        {
            return self.fail(&error);
        }
        Ok(())
    }

    /// `Include <path>`: loads each file the (glob) path names, in place.
    fn include(&mut self, token: &[u8]) -> Res<()> {
        let token = String::from_utf8_lossy(token);
        let after_whitespace = token.trim_start_matches([' ', '\t']);
        let quoted = after_whitespace.starts_with('"');
        let file = if quoted {
            after_whitespace.get(1..after_whitespace.len().saturating_sub(1)).unwrap_or("")
        } else {
            after_whitespace
        };
        let current = self.file_name();
        let lookup = find_resource(file, &current);
        let Some(fi) = lookup.path else {
            let at = self.lines.location(self.file, self.at);
            self.driver.error(at, "", &format!("{}: Not able to open file. {}", file, lookup.looked_at));
            return Err(Failed);
        };
        for s in expand_env(&fi, 0) {
            let lookup = find_resource(&s, &current);
            let f = lookup.path.unwrap_or_default();
            let Ok(data) = std::fs::read(&f) else {
                let at = self.lines.location(self.file, self.at);
                self.driver.error(at, "", &format!("{}: Not able to open file. {}", s, lookup.looked_at));
                return Err(Failed);
            };
            let idx = self.driver.add_filename(f);
            load(self.driver, &data, idx)?;
        }
        Ok(())
    }

    /// `SecRemoteRules <key> <url>`: downloads the rules and loads them.
    fn remote_rules(&mut self, v: &str) -> Res<()> {
        let Some((key, url)) = v.split_once(' ') else {
            return self.fail("SecRemoteRules demands a key and a URI");
        };
        let mut c = HttpsClient::new();
        c.set_key(key);
        if !c.download(url) {
            match self.driver.properties.remote_rules_action_on_failed {
                Some(OnFailedRemoteRulesAction::Abort) => {
                    return self.fail(&format!("{} - Failed to download: {}", url, c.error));
                }
                // TODO (C++): Implement the server logging mechanism.
                _ => return Ok(()),
            }
        }
        let content = match c.content.iter().position(|&b| b == 0) {
            Some(n) => &c.content[..n],
            None => &c.content[..],
        };
        let idx = self.driver.add_filename(url.to_string());
        load(self.driver, content, idx)
    }
}

// ---------------------------------------------------------------------------
// Actions as built
// ---------------------------------------------------------------------------

/// An action of a rule as built by the grammar: the C++ code keeps both
/// kinds in a `std::vector<std::unique_ptr<actions::Action>>` and sorts the
/// transformations out with `dynamic_cast` when the rule is built.
#[derive(Debug)]
pub(crate) enum ParsedAction {
    Action(RuleAction),
    Transformation(Transformation),
}

impl ParsedAction {
    pub(crate) fn into_action(self) -> RuleAction {
        match self {
            ParsedAction::Action(a) => a,
            ParsedAction::Transformation(t) => RuleAction::Transformation(t),
        }
    }
}

/// An action (not a transformation) as built by the grammar.
pub(crate) fn other(a: impl Into<RuleAction>) -> ParsedAction {
    ParsedAction::Action(a.into())
}

/// The actions and the transformations of a rule.
pub(crate) type RuleActions = (Vec<RuleAction>, Vec<Transformation>);

/// Splits the actions of a rule into actions and transformations.
pub(crate) fn split_actions(list: Vec<ParsedAction>) -> RuleActions {
    let mut a = Vec::new();
    let mut t = Vec::new();
    for i in list {
        match i {
            ParsedAction::Action(x) => a.push(x),
            ParsedAction::Transformation(x) => t.push(x),
        }
    }
    (a, t)
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// The actions whose value is a string with macros.
fn macro_action(name: &str, z: RunTimeString) -> ParsedAction {
    let a = match name.to_ascii_lowercase().as_str() {
        "expirevar" => actions::expire_var::ExpireVar::with_rts(z).into(),
        "logdata" => RuleAction::LogData(actions::log_data::LogData::with_rts(z)),
        "msg" => RuleAction::Msg(actions::msg::Msg::with_rts(z)),
        "redirect" => disruptive::redirect::Redirect::with_rts(z).into(),
        "setenv" => actions::set_env::SetENV::with_rts(z).into(),
        "setrsc" => actions::set_rsc::SetRSC::with_rts(z).into(),
        "setsid" => actions::set_sid::SetSID::with_rts(z).into(),
        "setuid" => actions::set_uid::SetUID::with_rts(z).into(),
        _ => RuleAction::Tag(actions::tag::Tag::with_rts(z)),
    };
    ParsedAction::Action(a)
}

/// `\"` -> `"`, reading the backslashes as the grammar does: `\\` is two
/// characters of text (so `\\"` ends a quoted text, and `\\\"` is `\\"`).
fn unescape_quotes(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        match (text[i], text.get(i + 1)) {
            (b'\\', Some(b'\\')) => {
                out.extend_from_slice(b"\\\\");
                i += 2;
            }
            (b'\\', Some(b'"')) => {
                out.push(b'"');
                i += 2;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Whether the parameter of an operator is empty: nothing, or (between
/// quotes) only spaces, which an operator without a parameter allows before
/// the closing quote.
fn blank_param(o: &syntax::Operator<'_>) -> bool {
    o.param.iter().all(|p| matches!(p, Piece::Text(t) if o.quoted && t.bytes().all(|c| c == b' ')))
}

/// The collections `setvar` can write to.
fn is_collection(name: &str) -> bool {
    ["TX", "IP", "SESSION", "USER", "GLOBAL", "RESOURCE"].iter().any(|c| name.eq_ignore_ascii_case(c))
}

/// Removes the excluded variables (`!ARGS:foo`) from the list, recording their
/// keys as exclusions of the variables of the same collection.
fn exclusions(mut original_list: Vec<Variable>) -> Vec<Variable> {
    let mut new_list: Vec<Variable> = Vec::new();
    let mut new_new_list: Vec<Variable> = Vec::new();
    let mut exclusion_vars: Vec<Variable> = Vec::new();
    while let Some(var) = original_list.pop() {
        if var.exclusion_base().is_some() {
            exclusion_vars.push(var);
        } else {
            new_list.push(var);
        }
    }
    while let Some(mut var) = new_list.pop() {
        let mut do_not_add = false;
        for i in &exclusion_vars {
            if var.same_as(i) {
                do_not_add = true;
            }
            if i.belongs_to_collection(&var) {
                var.adds_key_exclusion(i);
            }
        }
        if !do_not_add {
            new_new_list.push(var);
        }
    }
    new_new_list
}

/// The value of `SecRuleUpdate...By...`, as the scanner reads it.
fn update_value(v: syntax::Value<'_>) -> String {
    let s = string(v.text);
    let lead = string(v.lead);
    parser_sanitizer(if v.quoted { format!("{}\"{}\"", lead, s) } else { lead + &s })
}

/// The text of a quoted action value (`'...'`).
fn unquote(v: &str) -> Option<&str> {
    v.strip_prefix('\'')?.strip_suffix('\'')
}

fn is_number(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit())
}

fn is_audit_part(c: u8) -> bool {
    b"ABCDEFGHJKIZ".contains(&c)
}

/// Whether `c` may appear in the value of a `ctl:ruleRemoveById`,
/// `ctl:ruleRemoveByTag`, `ctl:ruleRemoveTargetById` or
/// `ctl:ruleRemoveTargetByTag` action.
fn is_remove_rule_by(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"_-.*/:;$@=()[]'".contains(&c)
}

/// Whether `c` may appear in an unquoted path (`SecRuleScript`, and the
/// directives with a path value).
fn is_path(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"_/.*: \\()-".contains(&c)
}

// ---------------------------------------------------------------------------
// Directive values
// ---------------------------------------------------------------------------

/// What a setting directive does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    AuditLogDirMode,
    AuditLogStorageDir,
    AuditEngine,
    AuditLogFileMode,
    AuditLog2,
    AuditLogParts,
    AuditLog,
    AuditLogFormat,
    AuditLogRelevantStatus,
    AuditLogPrefix,
    AuditLogType,
    UploadKeepFiles,
    UploadFileLimit,
    UploadFileMode,
    UploadDir,
    TmpSaveUploadedFiles,
    Marker,
    RuleEngine,
    RequestBodyAccess,
    ResponseBodyAccess,
    ArgumentSeparator,
    ComponentSignature,
    ConnEngine,
    WebAppId,
    DisableBackendCompression,
    ContentInjection,
    HashEngine,
    InterceptOnError,
    RuleInheritance,
    RuleRemoveById,
    RuleRemoveByTag,
    RuleRemoveByMsg,
    DebugLogLevel,
    DebugLog,
    GeoLookupDb,
    ArgumentsLimit,
    RequestBodyJsonDepthLimit,
    RequestBodyLimit,
    RequestBodyNoFilesLimit,
    ResponseBodyLimit,
    RequestBodyLimitAction,
    ResponseBodyLimitAction,
    RemoteRulesFailAction,
    PcreMatchLimit,
    ResponseBodyMimeType,
    ResponseBodyMimeTypesClear,
    XmlExternalEntity,
    ParseXmlIntoArgs,
    CookieFormat,
    UnicodeMapFile,
    HttpBlKey,
    Include,
    RemoteRules,
    /// Accepted and ignored (`SecTmpDir`, `SecDataDir`, ...).
    Ignored,
    /// Rejected with this message.
    Unsupported(&'static str),
}

/// A character class of the C++ scanner.
#[derive(Debug, Clone, Copy)]
enum Class {
    /// A number: `[0-9]+`.
    Number,
    /// A path: the bytes [`is_path`] accepts.
    Path,
    /// Text up to a quote, `|` or line feed: `[^"|\n]+`.
    FreeTextNewLine,
    /// A word: `[^, \t"\n\r]+`.
    Word,
    /// Audit log part letters (`ABCDEFGHJKIZ`).
    AuditParts,
    /// Any byte but a quote (the C++ scanner's `FREE_TEXT` was
    /// `([^"]|([^\\]\\"))+`).
    FreeText,
}

impl Class {
    fn contains(self, c: u8) -> bool {
        match self {
            Class::Number => c.is_ascii_digit(),
            Class::Path => is_path(c),
            Class::FreeTextNewLine => !matches!(c, b'"' | b'|' | b'\n'),
            Class::Word => !matches!(c, b',' | b' ' | b'\t' | b'"' | b'\n' | b'\r'),
            Class::AuditParts => is_audit_part(c),
            Class::FreeText => c != b'"',
        }
    }

    /// The length of the longest prefix of `s` made of this class.
    fn run(self, s: &[u8]) -> usize {
        s.iter().position(|&c| !self.contains(c)).unwrap_or(s.len())
    }
}

/// How the value of a directive is written after its keyword.
#[derive(Debug, Clone, Copy)]
enum Pattern {
    /// `[ \t]+CLASS`
    Sep(Class),
    /// `[ \t]+"CLASS"`
    SepQuoted(Class),
    /// `CLASS`, right after the keyword.
    Direct(Class),
    /// `[ \t]+[^"|\n]+[ ]+[0-9]+`: a file and a code page
    /// (`SecUnicodeMapFile`).
    UnicodeMap,
    /// `[ ][^ ]+[ ][^\n\r ]+`: a key and a URL (`SecRemoteRules`).
    Remote,
}

/// How the value is taken from the text the scanner matched (the keyword
/// and the value).
#[derive(Debug, Clone, Copy)]
enum Extract {
    /// After the first space or tab.
    FindSep,
    /// After the first space or tab, without the spaces and quotes around
    /// it.
    SanFindSep,
    /// Two bytes after the first space (`strchr(text, ' ') + 2`).
    Strchr2,
    /// Two bytes after the first space, without the spaces and quotes
    /// around it.
    SanStrchr2,
}

impl Extract {
    fn apply(self, yytext: &[u8]) -> Vec<u8> {
        let find_sep = || match yytext.iter().position(|&c| c == b' ' || c == b'\t') {
            Some(p) => &yytext[p + 1..],
            None => &yytext[yytext.len()..],
        };
        let strchr2 = || match yytext.iter().position(|&c| c == b' ') {
            Some(p) => &yytext[(p + 2).min(yytext.len())..],
            None => &yytext[yytext.len()..],
        };
        let sanitize = |s: &[u8]| parser_sanitizer(String::from_utf8_lossy(s).into_owned()).into_bytes();
        match self {
            Extract::FindSep => find_sep().to_vec(),
            Extract::SanFindSep => sanitize(find_sep()),
            Extract::Strchr2 => strchr2().to_vec(),
            Extract::SanStrchr2 => sanitize(strchr2()),
        }
    }
}

/// How a setting directive is written.
enum Form {
    /// A value, written in one of these ways (in the order of the C++
    /// scanner rules, which breaks ties).
    Value(&'static [(Pattern, Extract)]),
    /// One of these words (case-insensitive); none for a directive without
    /// a value.
    Choice(&'static [&'static str]),
}

struct Setting {
    dir: Effect,
    form: Form,
}

fn setting_kind(keyword: &str) -> Option<Setting> {
    use Class::*;
    use Extract::*;
    use Pattern::*;
    const ON_OFF: &[&str] = &["On", "Off"];
    let value = |dir, p: &'static [(Pattern, Extract)]| Some(Setting { dir, form: Form::Value(p) });
    let choice = |dir, c: &'static [&'static str]| Some(Setting { dir, form: Form::Choice(c) });
    const PATH: &[(Pattern, Extract)] = &[(Sep(Path), SanFindSep), (SepQuoted(Path), SanFindSep)];
    const NUMBER: &[(Pattern, Extract)] = &[(Sep(Number), FindSep)];
    const FREE_TEXT_LINE: &[(Pattern, Extract)] = &[(Sep(FreeTextNewLine), FindSep)];
    const FREE_TEXT_LINE_SAN: &[(Pattern, Extract)] =
        &[(Sep(FreeTextNewLine), SanFindSep), (SepQuoted(FreeTextNewLine), SanFindSep)];
    match keyword.to_ascii_lowercase().as_str() {
        "secauditlogdirmode" => {
            value(Effect::AuditLogDirMode, &[(Sep(Number), SanFindSep), (SepQuoted(Number), SanFindSep)])
        }
        "secauditlogstoragedir" => value(Effect::AuditLogStorageDir, PATH),
        "secauditengine" => choice(Effect::AuditEngine, &["RelevantOnly", "Off", "On"]),
        "secauditlogfilemode" => value(Effect::AuditLogFileMode, NUMBER),
        "secauditlog2" => value(Effect::AuditLog2, &[(Sep(Path), FindSep)]),
        "secauditlogparts" => {
            value(Effect::AuditLogParts, &[(Sep(AuditParts), SanFindSep), (SepQuoted(AuditParts), SanFindSep)])
        }
        "secauditlog" => value(Effect::AuditLog, &[(Sep(Path), FindSep), (SepQuoted(Path), SanFindSep)]),
        "secauditlogformat" => choice(Effect::AuditLogFormat, &["JSON", "Native"]),
        "secauditlogrelevantstatus" => {
            value(Effect::AuditLogRelevantStatus, &[(Sep(FreeTextNewLine), SanFindSep), (SepQuoted(Word), SanFindSep)])
        }
        "secauditlogprefix" => value(Effect::AuditLogPrefix, FREE_TEXT_LINE_SAN),
        "secauditlogtype" => choice(Effect::AuditLogType, &["Serial", "Parallel", "Concurrent", "https"]),
        "secuploadkeepfiles" => choice(Effect::UploadKeepFiles, &["On", "Off", "RelevantOnly"]),
        "secuploadfilelimit" => value(Effect::UploadFileLimit, NUMBER),
        "secuploadfilemode" => value(Effect::UploadFileMode, NUMBER),
        "secuploaddir" => value(Effect::UploadDir, PATH),
        "sectmpsaveuploadedfiles" => choice(Effect::TmpSaveUploadedFiles, ON_OFF),
        "secmarker" => value(Effect::Marker, &[(SepQuoted(Word), FindSep), (Sep(Word), FindSep)]),
        "secruleengine" => choice(Effect::RuleEngine, &["Off", "On", "DetectionOnly"]),
        "secrequestbodyaccess" => choice(Effect::RequestBodyAccess, ON_OFF),
        "secresponsebodyaccess" => choice(Effect::ResponseBodyAccess, ON_OFF),
        // `[ \t]+FREE_TEXT_NEW_LINE` (`CONGIG_DIR_SEC_ARG_SEP`, ignored)
        // wins when it is longer: with a space after the separator.
        "secargumentseparator" => value(
            Effect::ArgumentSeparator,
            &[(SepQuoted(Word), SanFindSep), (Sep(Word), SanFindSep), (Sep(FreeTextNewLine), FindSep)],
        ),
        "seccomponentsignature" => value(Effect::ComponentSignature, &[(SepQuoted(FreeText), Strchr2)]),
        "secconnengine" => choice(Effect::ConnEngine, ON_OFF),
        "secwebappid" => {
            value(Effect::WebAppId, &[(SepQuoted(FreeText), SanStrchr2), (Sep(FreeTextNewLine), SanFindSep)])
        }
        "secserversignature" => {
            value(Effect::Unsupported("SecServerSignature is not supported."), &[(SepQuoted(FreeText), Strchr2)])
        }
        "seccachetransformations" => value(
            Effect::Unsupported("SecCacheTransformations is not supported."),
            &[(Direct(FreeTextNewLine), FindSep)],
        ),
        "secdisablebackendcompression" => choice(Effect::DisableBackendCompression, ON_OFF),
        "seccontentinjection" => choice(Effect::ContentInjection, ON_OFF),
        "secchrootdir" => value(Effect::Unsupported("SecChrootDir is not supported."), PATH),
        "sechashengine" => choice(Effect::HashEngine, ON_OFF),
        "sechashkey" => choice(Effect::Unsupported("SecHashKey is not yet supported."), &[]),
        "sechashparam" => choice(Effect::Unsupported("SecHashParam is not yet supported."), &[]),
        "sechashmethodrx" => choice(Effect::Unsupported("SecHashMethodRx is not yet supported."), &[]),
        "sechashmethodpm" => choice(Effect::Unsupported("SecHashMethodPm is not yet supported."), &[]),
        "secgsblookupdb" => value(Effect::Unsupported("SecGsbLookupDb is not supported."), PATH),
        "secguardianlog" => choice(Effect::Unsupported("SecGuardianLog is not supported."), &[]),
        "secinterceptonerror" => choice(Effect::InterceptOnError, ON_OFF),
        "secconnreadstatelimit" => value(
            Effect::Unsupported("SecConnReadStateLimit is not yet supported."),
            &[(Direct(FreeTextNewLine), FindSep)],
        ),
        "secconnwritestatelimit" => value(
            Effect::Unsupported("SecConnWriteStateLimit is not yet supported."),
            &[(Direct(FreeTextNewLine), FindSep)],
        ),
        "secsensorid" => {
            value(Effect::Unsupported("SecSensorId is not yet supported."), &[(Direct(FreeTextNewLine), FindSep)])
        }
        "secruleinheritance" => choice(Effect::RuleInheritance, ON_OFF),
        "secruleperftime" => value(Effect::Unsupported("SecRulePerfTime is not yet supported."), NUMBER),
        "secstreaminbodyinspection" => choice(Effect::Unsupported("SecStreamInBodyInspection is not supported."), &[]),
        "secstreamoutbodyinspection" => {
            choice(Effect::Unsupported("SecStreamOutBodyInspection is not supported."), &[])
        }
        "secruleremovebyid" => value(Effect::RuleRemoveById, &[(Sep(FreeTextNewLine), SanFindSep)]),
        "secruleremovebymsg" => value(Effect::RuleRemoveByMsg, FREE_TEXT_LINE_SAN),
        "secruleremovebytag" => value(Effect::RuleRemoveByTag, FREE_TEXT_LINE_SAN),
        "secdebuglog" => value(Effect::DebugLog, &[(Sep(Path), FindSep), (SepQuoted(Path), SanFindSep)]),
        "secdebugloglevel" => value(Effect::DebugLogLevel, NUMBER),
        "secgeolookupdb" => value(Effect::GeoLookupDb, FREE_TEXT_LINE),
        "secargumentslimit" => value(Effect::ArgumentsLimit, NUMBER),
        "secrequestbodyjsondepthlimit" => value(Effect::RequestBodyJsonDepthLimit, NUMBER),
        "secrequestbodylimit" => value(Effect::RequestBodyLimit, NUMBER),
        "secrequestbodynofileslimit" => value(Effect::RequestBodyNoFilesLimit, NUMBER),
        "secrequestbodyinmemorylimit" => value(
            Effect::Unsupported(
                "As of ModSecurity version 3.0, SecRequestBodyInMemoryLimit is no longer supported. Instead, you can use your web server configurations to control those values. ModSecurity will follow the web server decision.",
            ),
            NUMBER,
        ),
        "secresponsebodylimit" => value(Effect::ResponseBodyLimit, NUMBER),
        "secrequestbodylimitaction" => choice(Effect::RequestBodyLimitAction, &["ProcessPartial", "Reject"]),
        "secresponsebodylimitaction" => choice(Effect::ResponseBodyLimitAction, &["ProcessPartial", "Reject"]),
        "secremoterulesfailaction" => choice(Effect::RemoteRulesFailAction, &["Abort", "Warn"]),
        // Accepted (without effect) so that modsecurity.conf-recommended
        // loads.
        "secpcrematchlimitrecursion" => value(Effect::Ignored, NUMBER),
        "secpcrematchlimit" => value(Effect::PcreMatchLimit, NUMBER),
        "secresponsebodymimetype" => value(Effect::ResponseBodyMimeType, FREE_TEXT_LINE),
        "secresponsebodymimetypesclear" => choice(Effect::ResponseBodyMimeTypesClear, &[]),
        "secxmlexternalentity" => choice(Effect::XmlExternalEntity, ON_OFF),
        "secparsexmlintoargs" => choice(Effect::ParseXmlIntoArgs, &["OnlyArgs", "Off", "On"]),
        "sectmpdir" | "secdatadir" => value(Effect::Ignored, PATH),
        "secstatusengine" => value(Effect::Ignored, &[(Sep(FreeTextNewLine), FindSep)]),
        "seccookieformat" => value(Effect::CookieFormat, NUMBER),
        "seccookiev0separator" => value(
            Effect::Unsupported("SecCookieV0Separator is not yet supported."),
            &[(SepQuoted(Word), SanFindSep), (Sep(Word), SanFindSep)],
        ),
        "secunicodemapfile" => value(Effect::UnicodeMapFile, &[(UnicodeMap, FindSep)]),
        "seccollectiontimeout" => value(Effect::Ignored, NUMBER),
        "sechttpblkey" => value(Effect::HttpBlKey, FREE_TEXT_LINE),
        "include" => value(Effect::Include, &[(Sep(Path), FindSep), (SepQuoted(Path), FindSep)]),
        "secremoterules" => value(Effect::RemoteRules, &[(Remote, FindSep)]),
        _ => None,
    }
}

/// The longest match of `patterns` at the start of `rest` (the first
/// pattern among those of the same length): its length, how its value is
/// extracted and which pattern it is.
fn longest(rest: &[u8], patterns: &[(Pattern, Extract)]) -> Option<(usize, Extract, usize)> {
    let mut best: Option<(usize, Extract, usize)> = None;
    for (i, &(p, e)) in patterns.iter().enumerate() {
        if let Some(n) = match_pattern(rest, p)
            && best.is_none_or(|(b, _, _)| n > b)
        {
            best = Some((n, e, i));
        }
    }
    best
}

/// The length of the longest match of `p` at the start of `rest`.
fn match_pattern(rest: &[u8], p: Pattern) -> Option<usize> {
    let ws = rest.iter().take_while(|&&c| c == b' ' || c == b'\t').count();
    let mut best = None;
    match p {
        Pattern::Direct(class) => {
            let n = class.run(rest);
            return (n > 0).then_some(n);
        }
        Pattern::Sep(class) => {
            for k in 1..=ws {
                let n = class.run(&rest[k..]);
                if n > 0 {
                    best = best.max(Some(k + n));
                }
            }
        }
        Pattern::SepQuoted(class) => {
            for k in 1..=ws {
                if rest.get(k) != Some(&b'"') {
                    continue;
                }
                let content = &rest[k + 1..];
                if let Class::FreeText = class {
                    // `([^"]|([^\\]\\"))+` followed by `"`: the last quote
                    // that closes a valid text.
                    let mut valid = vec![false; content.len() + 1];
                    valid[0] = true;
                    for i in 1..=content.len() {
                        valid[i] = (valid[i - 1] && content[i - 1] != b'"')
                            || (i >= 3
                                && valid[i - 3]
                                && content[i - 3] != b'\\'
                                && content[i - 2] == b'\\'
                                && content[i - 1] == b'"');
                    }
                    for i in 1..content.len() {
                        if valid[i] && content[i] == b'"' {
                            best = best.max(Some(k + 1 + i + 1));
                        }
                    }
                } else {
                    let n = class.run(content);
                    if n > 0 && content.get(n) == Some(&b'"') {
                        best = best.max(Some(k + 1 + n + 1));
                    }
                }
            }
        }
        Pattern::UnicodeMap => {
            for k in 1..=ws {
                let s = &rest[k..];
                let l = Class::FreeTextNewLine.run(s);
                for e in (1..=l).rev() {
                    if !s[e - 1].is_ascii_digit() {
                        continue;
                    }
                    let digits_start = s[..e].iter().rposition(|c| !c.is_ascii_digit()).map_or(0, |i| i + 1);
                    if digits_start >= 2 && s[digits_start - 1] == b' ' {
                        best = best.max(Some(k + e));
                        break;
                    }
                }
            }
        }
        Pattern::Remote => {
            if rest.first() != Some(&b' ') {
                return None;
            }
            let key = rest[1..].iter().take_while(|&&c| c != b' ').count();
            if key == 0 || rest.get(1 + key) != Some(&b' ') {
                return None;
            }
            let url = rest[2 + key..].iter().take_while(|&&c| !matches!(c, b'\n' | b'\r' | b' ')).count();
            return (url > 0).then_some(2 + key + url);
        }
    }
    best
}

/// What may follow a directive on its line: spaces, carriage returns and a
/// comment.
fn ignorable(s: &[u8]) -> bool {
    let n = s.iter().take_while(|&&c| matches!(c, b' ' | b'\t' | b'\r')).count();
    n == s.len() || s[n] == b'#'
}
