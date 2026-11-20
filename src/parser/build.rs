//! Applying a SecLang configuration: what the directives of the syntax tree
//! (`syntax.rs`) mean.
//!
//! Each statement is applied as soon as it is read, so that an `Include`d
//! file is loaded in place and the first error stops the load, with the
//! directives before it applied (as the C++ parser does).
//!
//! The grammar only describes the shape of a directive. The names it reads
//! (variables, operators, actions, transformations) are looked up here, in
//! the table of each family; the directives that are a keyword and a value
//! are in `settings.rs`.

use crate::actions::action::Kind;
use crate::actions::rule_action::RuleAction;
use crate::actions::seclang::{ParsedAction, other, split_actions};
use crate::actions::{self};
use crate::audit_log::AuditLogStatus;
use crate::operators::operator::{RuleOperator, instantiate_with_param};
use crate::parser::driver::Driver;
use crate::parser::driver::Position;
use crate::parser::syntax::{
    self, ActionKind, Directive, Modifier, Piece, Selector, SetVarOp, Target, UpdateBy, VarRef,
};
use crate::phases::Phases;
use crate::rule::sec_rule::SecRule;
use crate::rule::sec_rule_script::Script;
use crate::rule::{Rule, RuleKind};
use crate::run_time_string::RunTimeString;
use crate::utils::string::parser_sanitizer;
use crate::variables::variable::Variable;
use crate::variables::{VariableSelector, new_variable};
use modsecurity_operators::seclang_operator;

/// The load stopped: the error is in `driver.properties.parser_error`.
#[derive(Debug)]
pub(crate) struct Failed;

pub(super) type Res<T> = Result<T, Failed>;

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
pub(super) struct Lines<'a> {
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

    pub(super) fn location(&mut self, file: usize, offset: usize) -> Position {
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

pub(super) struct Builder<'d, 't> {
    pub(super) driver: &'d mut Driver,
    pub(super) file: usize,
    pub(super) lines: &'d mut Lines<'t>,
    /// The line of the directive keyword.
    pub(super) line: usize,
    /// Where errors are reported: the directive, or the action being built.
    pub(super) at: usize,
}

impl Builder<'_, '_> {
    pub(super) fn fail<T>(&mut self, msg: &str) -> Res<T> {
        let at = self.lines.location(self.file, self.at);
        self.driver.error(at, msg, "");
        Err(Failed)
    }

    /// Fails with an error already recorded (by `Driver::add_sec_rule`).
    fn failed<T>(&self) -> Res<T> {
        Err(Failed)
    }

    pub(super) fn file_name(&self) -> String {
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
                let kind = RuleKind::SecRule(SecRule::new(op, vars));
                let rule = Rule::new(a, t, &file, line, kind);
                if !self.driver.add_sec_rule(rule) {
                    return self.failed();
                }
            }
            Directive::Action(list) => {
                let (a, t) = split_actions(self.actions(&list)?);
                let file = self.file_name();
                let rule = Rule::new(Some(a), Some(t), &file, line, RuleKind::SecAction);
                self.driver.add_sec_action(rule);
            }
            Directive::Script { path, actions } => {
                if !path.quoted && !syntax::bytes(path.text).iter().all(|&c| syntax::value::is_path(c)) {
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
                let kind = RuleKind::SecRuleScript(Script::new(&script));
                let mut r = Rule::new(Some(a), Some(t), &file, line, kind);
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
                        let Some(rule_id) = crate::rule::Id::parse(&v) else {
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
                let Some(rule_id) = crate::rule::Id::parse(&v) else {
                    return self.fail(&format!(
                        "SecRuleUpdateActionById: failed to load:The input \"{}\" does not seems to be a valid rule id.. ",
                        v
                    ));
                };
                let acts = self.actions(&actions)?.into_iter().map(ParsedAction::into_action).collect();
                if let Err(error) = self.driver.properties.exceptions.load_update_action_by_id(rule_id, acts) {
                    return self.fail(&format!("SecRuleUpdateActionById: {error}. "));
                }
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
                ActionKind::Plain { name, text } => {
                    let built = actions::seclang::plain(name, &string(text));
                    // The audit log must be set up even when `SecAuditEngine`
                    // is off.
                    if let Ok(ParsedAction::Action(RuleAction::CtlAuditEngine(a))) = &built
                        && a.status() != AuditLogStatus::Off
                    {
                        self.driver.properties.audit_log.set_ctl_audit_engine_active();
                    }
                    built
                }
                ActionKind::Macro { name, value } => {
                    let z = self.run_time_string(value)?;
                    Ok(actions::seclang::with_macros(name, z))
                }
                ActionKind::InitCol { text, value } => {
                    let z = self.run_time_string(value)?;
                    let text = string(text);
                    let (name, payload) = actions::action::name_and_payload(&text);
                    actions::init_col::InitCol::with_rts(name, payload, z).map(other)
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
}

// ---------------------------------------------------------------------------
// Actions as built
// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

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
