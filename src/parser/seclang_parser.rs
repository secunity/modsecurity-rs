//! Port of `src/parser/seclang-parser.yy` (the bison grammar of the SecLang
//! configuration language) and of the parts of the bison `lalr1.cc`
//! skeleton it relies on (`location.hh`, the LALR(1) driver loop and the
//! `parse.error verbose` messages).
//!
//! The grammar is LALR(1); to accept exactly the same inputs and to report
//! syntax errors exactly as bison does (same detection point, same
//! "syntax error, unexpected X, expecting Y or Z" texts, same locations),
//! the parser is table driven and uses the automaton bison computed for
//! `seclang-parser.yy` (the `yypact`, `yydefact`, `yytable`, ... arrays at
//! the end of this file, with the symbol numbers and names of the grammar).
//! The semantic actions of the grammar are in [`SeclangParser::reduce`] and
//! its helpers, grouped by nonterminal.

use crate::actions::action::{Action, InertAction, Kind};
use crate::actions::transformations::transformation::{Transformation, TransformationKind as TK};
use crate::actions::{self, ctl, data, disruptive};
use crate::audit_log::audit_log::{AuditLogFormat, AuditLogStatus, AuditLogType};
use crate::modsecurity::Phases;
use crate::operators::operator::{RuleOperator, instantiate_with_param};
use crate::parser::driver::Driver;
use crate::parser::seclang_scanner::{ScanError, Scanner, Token};
use crate::rule_script::RuleScript;
use crate::rule_with_actions::{RuleAction, RuleWithActions, RuleWithActionsKind};
use crate::rule_with_operator::RuleWithOperator;
use crate::rules_set_properties::{
    BodyLimitAction, ConfigUnicodeMap, OnFailedRemoteRulesAction, ParseXmlIntoArgs, RuleEngine, parse_config_number,
    parse_octal_mode,
};
use crate::run_time_string::RunTimeString;
use crate::utils::string::{atoi, remove_brackets_if_needed, ssplit};
use crate::utils::system::find_resource;
use crate::variables::variable::{Variable, VariableModificatorCount, VariableModificatorExclusion};
use crate::variables::{VariableSelector, new_variable, xml};

// ---------------------------------------------------------------------------
// location.hh
// ---------------------------------------------------------------------------

/// `yy::position`: a point in a source file. The file name is an index in
/// the driver's list of file names (`Driver::m_filenames`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub filename: usize,
    pub line: i32,
    pub column: i32,
}

impl Position {
    /// `lines(count)`: advances to the first column of a following line.
    fn lines(&mut self, count: i32) {
        if count != 0 {
            self.column = 1;
            self.line = add(self.line, count, 1);
        }
    }

    /// `columns(count)`
    fn columns(&mut self, count: i32) {
        self.column = add(self.column, count, 1);
    }
}

/// `position::add_`: computes `max(min, lhs + rhs)`.
fn add(lhs: i32, rhs: i32, min: i32) -> i32 {
    if lhs.saturating_add(rhs) < min { min } else { lhs.saturating_add(rhs) }
}

/// `yy::location`: a range of the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub begin: Position,
    pub end: Position,
}

impl Location {
    /// A location at line 1, column 1 of `filename`.
    pub fn new(filename: usize) -> Self {
        let p = Position { filename, line: 1, column: 1 };
        Location { begin: p, end: p }
    }

    /// `step()`: resets the beginning of the location to its end.
    pub fn step(&mut self) {
        self.begin = self.end;
    }

    /// `columns(count)`: extends the location by `count` columns.
    pub fn columns(&mut self, count: i32) {
        self.end.columns(count);
    }

    /// `lines(count)`: extends the location by `count` lines.
    pub fn lines(&mut self, count: i32) {
        self.end.lines(count);
    }
}

// ---------------------------------------------------------------------------
// Semantic values
// ---------------------------------------------------------------------------

/// An action of a rule as built by the grammar: the C++ code keeps both
/// kinds in a `std::vector<std::unique_ptr<actions::Action>>` and sorts the
/// transformations out with `dynamic_cast` when the rule is built.
#[derive(Debug)]
pub(crate) enum ParsedAction {
    Action(RuleAction),
    Transformation(Transformation),
}

/// What `act` yields: the action, or the error of an invalid payload. The
/// error is reported when the action joins its list (the C++ `ACTION_INIT`
/// of `actions_may_quoted`), with that reduction's location.
type ActResult = Result<ParsedAction, String>;

impl ParsedAction {
    fn into_action(self) -> Box<dyn Action> {
        match self {
            ParsedAction::Action(a) => a.into_action(),
            ParsedAction::Transformation(t) => Box::new(t),
        }
    }

    fn as_action(&self) -> &dyn Action {
        match self {
            ParsedAction::Action(a) => a.as_action(),
            ParsedAction::Transformation(t) => t,
        }
    }
}

/// An action without a slot of its own in the rule.
fn other(a: impl Action + 'static) -> ParsedAction {
    ParsedAction::Action(RuleAction::Other(Box::new(a)))
}

/// The actions and the transformations of a rule.
type RuleActions = (Vec<RuleAction>, Vec<Transformation>);

/// Splits the actions of a rule into actions and transformations.
fn split_actions(list: Vec<ParsedAction>) -> RuleActions {
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

/// The semantic value of a grammar symbol (bison `api.value.type variant`).
#[derive(Debug, Default)]
enum Value {
    #[default]
    None,
    Str(Vec<u8>),
    Operator(RuleOperator),
    RunTimeString(RunTimeString),
    Variable(Box<dyn Variable>),
    Action(ActResult),
    Variables(Vec<Box<dyn Variable>>),
    Actions(Vec<ParsedAction>),
}

/// An element of the parser stack (`stack_symbol_type`).
#[derive(Debug)]
struct StackEntry {
    state: usize,
    /// The grammar symbol (token kind or nonterminal number).
    kind: u16,
    value: Value,
    loc: Location,
}

impl StackEntry {
    fn take(&mut self) -> Value {
        std::mem::take(&mut self.value)
    }

    /// The `std::string` value of a token.
    fn bytes(&mut self) -> Vec<u8> {
        match self.take() {
            Value::Str(s) => s,
            _ => Vec::new(),
        }
    }

    fn string(&mut self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    fn operator(&mut self) -> Option<RuleOperator> {
        match self.take() {
            Value::Operator(o) => Some(o),
            _ => None,
        }
    }

    fn run_time_string(&mut self) -> RunTimeString {
        match self.take() {
            Value::RunTimeString(r) => r,
            _ => RunTimeString::new(),
        }
    }

    fn variable(&mut self) -> Option<Box<dyn Variable>> {
        match self.take() {
            Value::Variable(v) => Some(v),
            _ => None,
        }
    }

    fn action(&mut self) -> Option<ActResult> {
        match self.take() {
            Value::Action(a) => Some(a),
            _ => None,
        }
    }

    fn variables(&mut self) -> Vec<Box<dyn Variable>> {
        match self.take() {
            Value::Variables(v) => v,
            _ => Vec::new(),
        }
    }

    fn actions(&mut self) -> Vec<ParsedAction> {
        match self.take() {
            Value::Actions(a) => a,
            _ => Vec::new(),
        }
    }
}

/// How a semantic action leaves the reduction when it does not produce a
/// value.
enum Flow {
    /// `YYERROR`
    Error,
    /// `return 0` from `parse()` (the `input: END` rule).
    Accept,
}

/// Nonterminal symbols of the grammar.
mod nt {
    pub const INPUT: u16 = 356;
    pub const LINE: u16 = 357;
    pub const AUDIT_LOG: u16 = 358;
    pub const ACTIONS: u16 = 359;
    pub const ACTIONS_MAY_QUOTED: u16 = 360;
    pub const OP: u16 = 361;
    pub const OP_BEFORE_INIT: u16 = 362;
    pub const EXPRESSION: u16 = 363;
    pub const VARIABLES: u16 = 364;
    pub const VARIABLES_PRE_PROCESS: u16 = 365;
    pub const VARIABLES_MAY_BE_QUOTED: u16 = 366;
    pub const VAR: u16 = 367;
    pub const ACT: u16 = 368;
    pub const SETVAR_ACTION: u16 = 369;
    pub const RUN_TIME_STRING: u16 = 370;
}

// ---------------------------------------------------------------------------
// C library helpers used by the semantic actions
// ---------------------------------------------------------------------------

fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `strtol(s, NULL, base)` truncated to `int`, as the C++ code passes the
/// result to `int` parameters.
fn strtol_int(s: &str, base: u32) -> i32 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && is_c_space(b[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    let mut overflow = false;
    while i < b.len() {
        let Some(d) = (b[i] as char).to_digit(base) else {
            break;
        };
        match v.checked_mul(i64::from(base)).and_then(|x| x.checked_add(i64::from(d))) {
            Some(n) => v = n,
            None => overflow = true,
        }
        i += 1;
    }
    let v = if overflow {
        if neg { i64::MIN } else { i64::MAX }
    } else if neg {
        -v
    } else {
        v
    };
    v as i32
}

/// `std::stod`: parses the longest floating point prefix (after leading
/// white space); fails when nothing can be converted or on overflow.
fn stod(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && is_c_space(b[i]) {
        i += 1;
    }
    let start = i;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let rest = &s[i..];
    let lower = rest.to_ascii_lowercase();
    if lower.starts_with("inf") || lower.starts_with("nan") {
        let n = if lower.starts_with("infinity") { 8 } else { 3 };
        return s[start..i + n].parse::<f64>().ok();
    }
    if lower.starts_with("0x") {
        // Hexadecimal floating point numbers: only the integer part is
        // supported here.
        let digits: String = rest[2..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if digits.is_empty() {
            return Some(0.0);
        }
        let v = u128::from_str_radix(&digits, 16).map(|v| v as f64).unwrap_or(f64::INFINITY);
        let neg = b.get(start) == Some(&b'-');
        return if v.is_infinite() { None } else { Some(if neg { -v } else { v }) };
    }
    let mut digits = 0;
    let mut nonzero = false;
    while i < b.len() && b[i].is_ascii_digit() {
        nonzero |= b[i] != b'0';
        digits += 1;
        i += 1;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            nonzero |= b[i] != b'0';
            digits += 1;
            i += 1;
        }
    }
    if digits == 0 {
        return None;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            i = j;
        }
    }
    let v: f64 = s[start..i].parse().ok()?;
    if v.is_infinite() || (v == 0.0 && nonzero) {
        // ERANGE: std::out_of_range
        return None;
    }
    Some(v)
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

const YYNTOKENS: i32 = 355;
const YYLAST: i32 = 3452;
const YYFINAL: usize = 350;
const YYPACT_NINF: i16 = -424;
const YYTABLE_NINF: i16 = -1;
/// `symbol_kind::S_YYerror`
const S_YYERROR: i32 = 1;

/// `yy_lr_goto_state_`
fn goto_state(state: usize, sym: u16) -> usize {
    let idx = sym as usize - YYNTOKENS as usize;
    let r = i32::from(YYPGOTO[idx]) + state as i32;
    if (0..=YYLAST).contains(&r) && YYCHECK[r as usize] as i32 == state as i32 {
        YYTABLE[r as usize] as usize
    } else {
        YYDEFGOTO[idx] as usize
    }
}

/// `yytnamerr_`: strips the double quotes of a symbol name unless they are
/// needed.
fn tname(sym: usize) -> String {
    let s = YYTNAME[sym];
    let b = s.as_bytes();
    if b.first() == Some(&b'"') {
        let mut r = String::new();
        let mut i = 1;
        loop {
            match b.get(i) {
                Some(b'\'') | Some(b',') | None => break,
                Some(b'\\') => {
                    if b.get(i + 1) != Some(&b'\\') {
                        break;
                    }
                    r.push('\\');
                    i += 2;
                    continue;
                }
                Some(b'"') => return r,
                Some(&c) => r.push(c as char),
            }
            i += 1;
        }
    }
    s.to_string()
}

/// `context::expected_tokens`: the tokens that would be accepted in
/// `state`, or `None` when there are more than `max` of them.
fn expected_tokens(state: usize, max: usize) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    let yyn = i32::from(YYPACT[state]);
    if yyn != i32::from(YYPACT_NINF) {
        let xbegin = if yyn < 0 { -yyn } else { 0 };
        let checklim = YYLAST - yyn + 1;
        let xend = checklim.min(YYNTOKENS);
        for x in xbegin..xend {
            if i32::from(YYCHECK[(x + yyn) as usize]) == x
                && x != S_YYERROR
                && YYTABLE[(x + yyn) as usize] != YYTABLE_NINF
            {
                if out.len() == max {
                    return None;
                }
                out.push(x as usize);
            }
        }
    }
    Some(out)
}

/// `yysyntax_error_`
fn syntax_error_message(state: usize, lookahead: Option<u16>) -> String {
    let mut args: Vec<usize> = Vec::new();
    if let Some(la) = lookahead {
        args.push(la as usize);
        if let Some(expected) = expected_tokens(state, 4) {
            args.extend(expected);
        }
    }
    let mut res = String::from("syntax error");
    if let Some((first, rest)) = args.split_first() {
        res.push_str(", unexpected ");
        res.push_str(&tname(*first));
        for (i, a) in rest.iter().enumerate() {
            res.push_str(if i == 0 { ", expecting " } else { " or " });
            res.push_str(&tname(*a));
        }
    }
    res
}

/// `yy::seclang_parser`
pub(crate) struct SeclangParser;

impl SeclangParser {
    /// `seclang_parser::parse()`: 0 on success, 1 on failure.
    pub(crate) fn parse(driver: &mut Driver, scanner: &mut Scanner) -> i32 {
        // User initialization code (%initial-action).
        let file = driver.file.clone();
        let fidx = driver.add_filename(file);
        let mut la: Option<Token> = None;
        // Location of the last lookahead (bison keeps it in `yyla` after
        // the token itself is consumed).
        let mut la_loc = Location::new(fidx);
        let mut stack: Vec<StackEntry> = vec![StackEntry { state: 0, kind: 0, value: Value::None, loc: la_loc }];

        loop {
            // yynewstate
            let state = stack[stack.len() - 1].state;
            if state == YYFINAL {
                return 0;
            }
            // yybackup: try to take a decision without lookahead.
            let mut rule: usize = 0;
            let mut shift: Option<usize> = None;
            let mut error = false;
            let yyn = YYPACT[state];
            if yyn == YYPACT_NINF {
                rule = YYDEFACT[state] as usize;
                error = rule == 0;
            } else {
                if la.is_none() {
                    match scanner.lex(driver) {
                        Ok(t) => {
                            la_loc = t.loc;
                            la = Some(t);
                        }
                        Err(ScanError { loc }) => {
                            driver.error(&loc, "", "");
                            // yyerrlab1: no rule handles the error token.
                            return 1;
                        }
                    }
                }
                let kind = la.as_ref().map(|t| t.kind).unwrap_or(0);
                let idx = i32::from(yyn) + i32::from(kind);
                if !(0..=YYLAST).contains(&idx) || YYCHECK[idx as usize] != kind as i16 {
                    rule = YYDEFACT[state] as usize;
                    error = rule == 0;
                } else {
                    let act = YYTABLE[idx as usize];
                    if act <= 0 {
                        if act == YYTABLE_NINF {
                            error = true;
                        } else {
                            rule = (-act) as usize;
                        }
                    } else {
                        shift = Some(act as usize);
                    }
                }
            }

            if error {
                // yyerrlab
                let msg = syntax_error_message(state, la.as_ref().map(|t| t.kind));
                driver.error(&la_loc, &msg, "");
                // yyerrlab1: the grammar has no error recovery rule, every
                // state gets popped.
                return 1;
            }

            if let Some(new_state) = shift {
                if let Some(t) = la.take() {
                    stack.push(StackEntry { state: new_state, kind: t.kind, value: Value::Str(t.value), loc: t.loc });
                }
                continue;
            }

            // yyreduce
            let len = YYR2[rule] as usize;
            let lhs = YYR1[rule] as u16;
            let base = stack.len() - len;
            let lhs_state = goto_state(stack[base - 1].state, lhs);
            // YYLLOC_DEFAULT
            let loc = if len > 0 {
                Location { begin: stack[base].loc.begin, end: stack[stack.len() - 1].loc.end }
            } else {
                let e = stack[base - 1].loc.end;
                Location { begin: e, end: e }
            };
            let at0 = stack[base - 1].loc;
            let mut rhs = stack.split_off(base);
            match Self::reduce(driver, lhs, &mut rhs, &at0) {
                Ok(value) => stack.push(StackEntry { state: lhs_state, kind: lhs, value, loc }),
                // YYERROR -> yyerrorlab -> yyerrlab1: nothing can shift the
                // error token, the parse is aborted.
                Err(Flow::Error) => return 1,
                Err(Flow::Accept) => return 0,
            }
        }
    }

    /// The semantic actions (`switch (yyn)` of the generated parser).
    /// `rhs` holds `$1..$n`, `at0` is `@0` (the location of the symbol
    /// before the rule).
    fn reduce(driver: &mut Driver, lhs: u16, rhs: &mut [StackEntry], at0: &Location) -> Result<Value, Flow> {
        match lhs {
            // input:
            //     END { return 0; }
            //   | input line
            //   | line
            nt::INPUT => {
                if rhs.len() == 1 && rhs[0].kind == sym::END {
                    return Err(Flow::Accept);
                }
                Ok(Value::None)
            }
            // line: expression
            nt::LINE => Ok(Value::None),
            nt::AUDIT_LOG => Self::audit_log(driver, rhs, at0).map(|_| Value::None),
            // actions:
            //     QUOTATION_MARK actions_may_quoted QUOTATION_MARK
            //   | actions_may_quoted
            nt::ACTIONS => {
                let i = if rhs.len() == 3 { 1 } else { 0 };
                Ok(Value::Actions(rhs[i].actions()))
            }
            // actions_may_quoted:
            //     actions_may_quoted COMMA act
            //   | act
            nt::ACTIONS_MAY_QUOTED => {
                let (mut list, a) =
                    if rhs.len() == 3 { (rhs[0].actions(), rhs[2].action()) } else { (Vec::new(), rhs[0].action()) };
                match a {
                    Some(Ok(a)) => list.push(a),
                    // ACTION_INIT($n, @0)
                    Some(Err(error)) => {
                        driver.error(at0, &error, "");
                        return Err(Flow::Error);
                    }
                    None => {}
                }
                Ok(Value::Actions(list))
            }
            nt::OP => Self::op(driver, rhs, at0),
            nt::OP_BEFORE_INIT => Self::op_before_init(driver, rhs, at0),
            nt::EXPRESSION => Self::expression(driver, rhs, at0).map(|_| Value::None),
            nt::VARIABLES => Ok(Value::Variables(Self::variables(rhs[0].variables()))),
            // variables_pre_process:
            //     variables_may_be_quoted
            //   | QUOTATION_MARK variables_may_be_quoted QUOTATION_MARK
            nt::VARIABLES_PRE_PROCESS => {
                let i = if rhs.len() == 3 { 1 } else { 0 };
                Ok(Value::Variables(rhs[i].variables()))
            }
            nt::VARIABLES_MAY_BE_QUOTED => Ok(Value::Variables(Self::variables_may_be_quoted(rhs))),
            nt::VAR => Self::var(driver, rhs, at0).map(Value::Variable),
            nt::ACT => Self::act(driver, rhs, at0).map(Value::Action),
            nt::SETVAR_ACTION => Ok(Value::Action(Ok(Self::setvar_action(rhs)))),
            nt::RUN_TIME_STRING => Ok(Value::RunTimeString(Self::run_time_string(rhs))),
            // $accept: input $end -- never reduced (the parser accepts
            // when it reaches the final state).
            _ => Ok(Value::None),
        }
    }

    /// `audit_log:` (audit log and upload related directives).
    fn audit_log(driver: &mut Driver, rhs: &mut [StackEntry], at0: &Location) -> Result<(), Flow> {
        let second = rhs.get(1).map(|e| e.kind);
        let p = &mut driver.properties;
        match (rhs[0].kind, second) {
            // SecAuditLogDirMode
            (sym::CONFIG_DIR_AUDIT_DIR_MOD, _) => {
                let v = strtol_int(&rhs[0].string(), 8);
                p.audit_log.set_storage_dir_mode(v);
            }
            // SecAuditLogStorageDir
            (sym::CONFIG_DIR_AUDIT_DIR, _) => {
                p.audit_log.set_storage_dir(&rhs[0].string());
            }
            // SecAuditEngine
            (sym::CONFIG_DIR_AUDIT_ENG, Some(sym::CONFIG_VALUE_RELEVANT_ONLY)) => {
                p.audit_log.set_status(AuditLogStatus::RelevantOnly);
            }
            (sym::CONFIG_DIR_AUDIT_ENG, Some(sym::CONFIG_VALUE_OFF)) => {
                p.audit_log.set_status(AuditLogStatus::Off);
            }
            (sym::CONFIG_DIR_AUDIT_ENG, _) => {
                p.audit_log.set_status(AuditLogStatus::On);
            }
            // SecAuditLogFileMode
            (sym::CONFIG_DIR_AUDIT_FLE_MOD, _) => {
                let v = strtol_int(&rhs[0].string(), 8);
                p.audit_log.set_file_mode(v);
            }
            // SecAuditLog2
            (sym::CONFIG_DIR_AUDIT_LOG2, _) => {
                p.audit_log.set_file_path2(&rhs[0].string());
            }
            // SecAuditLogParts
            (sym::CONFIG_DIR_AUDIT_LOG_P, _) => {
                p.audit_log.set_parts(&rhs[0].string());
            }
            // SecAuditLog
            (sym::CONFIG_DIR_AUDIT_LOG, _) => {
                p.audit_log.set_file_path1(&rhs[0].string());
            }
            (sym::CONFIG_DIR_AUDIT_LOG_FMT, Some(sym::JSON)) => {
                p.audit_log.set_format(AuditLogFormat::Json);
            }
            (sym::CONFIG_DIR_AUDIT_LOG_FMT, _) => {
                p.audit_log.set_format(AuditLogFormat::Native);
            }
            // SecAuditLogRelevantStatus
            (sym::CONFIG_DIR_AUDIT_STS, _) => {
                let relevant_status = rhs[0].string();
                p.audit_log.set_relevant_status(&relevant_status);
            }
            // SecAuditLogPrefix
            (sym::CONFIG_DIR_AUDIT_PREFIX, _) => {
                let prefix = rhs[0].string();
                p.audit_log.set_prefix(&prefix);
            }
            // SecAuditLogType
            (sym::CONFIG_DIR_AUDIT_TPE, Some(sym::CONFIG_VALUE_SERIAL)) => {
                p.audit_log.set_type(AuditLogType::Serial);
            }
            (sym::CONFIG_DIR_AUDIT_TPE, Some(sym::CONFIG_VALUE_PARALLEL)) => {
                p.audit_log.set_type(AuditLogType::Parallel);
            }
            (sym::CONFIG_DIR_AUDIT_TPE, _) => {
                p.audit_log.set_type(AuditLogType::Https);
            }
            // Upload
            (sym::CONFIG_UPDLOAD_KEEP_FILES, Some(sym::CONFIG_VALUE_ON)) => {
                p.upload_keep_files = Some(true);
            }
            (sym::CONFIG_UPDLOAD_KEEP_FILES, Some(sym::CONFIG_VALUE_OFF)) => {
                p.upload_keep_files = Some(false);
            }
            (sym::CONFIG_UPDLOAD_KEEP_FILES, _) => {
                driver.error(
                    at0,
                    "SecUploadKeepFiles RelevantOnly is not currently supported. Accepted values are On or Off",
                    "",
                );
                return Err(Flow::Error);
            }
            (sym::CONFIG_UPLOAD_FILE_LIMIT, _) => match parse_config_number(&rhs[0].string()) {
                Ok(v) => p.upload_file_limit = Some(v),
                Err(errmsg) => {
                    driver.error(at0, &format!("Failed to parse SecUploadFileLimit: {}", errmsg), "");
                    return Err(Flow::Error);
                }
            },
            (sym::CONFIG_UPLOAD_FILE_MODE, _) => match parse_octal_mode(&rhs[0].string()) {
                Ok(v) => p.upload_file_mode = Some(v),
                Err(errmsg) => {
                    driver.error(at0, &format!("Failed to parse SecUploadFileMode: {}", errmsg), "");
                    return Err(Flow::Error);
                }
            },
            (sym::CONFIG_UPLOAD_DIR, _) => {
                p.upload_directory = Some(rhs[0].string());
            }
            (sym::CONFIG_UPDLOAD_SAVE_TMP_FILES, Some(sym::CONFIG_VALUE_ON)) => {
                p.tmp_save_uploaded_files = Some(true);
            }
            (sym::CONFIG_UPDLOAD_SAVE_TMP_FILES, _) => {
                p.tmp_save_uploaded_files = Some(false);
            }
            _ => {}
        }
        Ok(())
    }

    /// `op:` the operator of a `SecRule`, initialised.
    ///
    /// ```text
    /// op: op_before_init | NOT op_before_init | run_time_string | NOT run_time_string
    /// ```
    fn op(driver: &mut Driver, rhs: &mut [StackEntry], at0: &Location) -> Result<Value, Flow> {
        let negated = rhs[0].kind == sym::NOT;
        let last = rhs.len() - 1;
        let mut op = if rhs[last].kind == nt::RUN_TIME_STRING {
            // A bare parameter is a regular expression.
            let param = rhs[last].run_time_string();
            match instantiate_with_param("rx", param) {
                Some(o) => RuleOperator::new(o),
                None => return Err(Flow::Error),
            }
        } else {
            match rhs[last].operator() {
                Some(o) => o,
                None => return Err(Flow::Error),
            }
        };
        op.negated = negated;
        let file = driver.filename(rhs[0].loc.end.filename).to_string();
        if let Err(error) = op.op.init(&file) {
            driver.error(at0, &error, "");
            return Err(Flow::Error);
        }
        Ok(Value::Operator(op))
    }

    /// `op_before_init:` an operator token and its parameter.
    fn op_before_init(driver: &mut Driver, rhs: &mut [StackEntry], at0: &Location) -> Result<Value, Flow> {
        let name = match rhs[0].kind {
            sym::OPERATOR_UNCONDITIONAL_MATCH => "unconditionalMatch",
            sym::OPERATOR_DETECT_SQLI => "detectSQLi",
            sym::OPERATOR_DETECT_XSS => "detectXSS",
            sym::OPERATOR_VALIDATE_URL_ENCODING => "validateUrlEncoding",
            sym::OPERATOR_VALIDATE_UTF8_ENCODING => "validateUtf8Encoding",
            sym::OPERATOR_INSPECT_FILE => "inspectFile",
            sym::OPERATOR_FUZZY_HASH => "fuzzyHash",
            sym::OPERATOR_VALIDATE_BYTE_RANGE => "validateByteRange",
            sym::OPERATOR_VALIDATE_DTD => "validateDTD",
            sym::OPERATOR_VALIDATE_HASH => {
                // $$ = new operators::ValidateHash($1);
                return Self::operator_not_supported(driver, "ValidateHash", at0);
            }
            sym::OPERATOR_VALIDATE_SCHEMA => "validateSchema",
            sym::OPERATOR_VERIFY_CC => "verifyCC",
            sym::OPERATOR_VERIFY_CPF => "verifyCPF",
            sym::OPERATOR_VERIFY_SSN => "verifySSN",
            sym::OPERATOR_VERIFY_SVNR => "verifySVNR",
            sym::OPERATOR_GSB_LOOKUP => {
                // $$ = new operators::GsbLookup($1);
                return Self::operator_not_supported(driver, "GsbLookup", at0);
            }
            sym::OPERATOR_RSUB => {
                // $$ = new operators::Rsub($1);
                return Self::operator_not_supported(driver, "Rsub", at0);
            }
            sym::OPERATOR_WITHIN => "within",
            sym::OPERATOR_CONTAINS_WORD => "containsWord",
            sym::OPERATOR_CONTAINS => "contains",
            sym::OPERATOR_ENDS_WITH => "endsWith",
            sym::OPERATOR_EQ => "eq",
            sym::OPERATOR_GE => "ge",
            sym::OPERATOR_GT => "gt",
            // `@ipMatchF` is an alias of `@ipMatchFromFile`.
            sym::OPERATOR_IP_MATCH_FROM_FILE => "ipMatchF",
            sym::OPERATOR_IP_MATCH => "ipMatch",
            sym::OPERATOR_LE => "le",
            sym::OPERATOR_LT => "lt",
            // Both `@pmf` and `@pmFromFile` build a `PmFromFile`.
            sym::OPERATOR_PM_FROM_FILE => "pmFromFile",
            sym::OPERATOR_PM => "pm",
            sym::OPERATOR_RBL => "rbl",
            sym::OPERATOR_RX => "rx",
            sym::OPERATOR_RX_GLOBAL => "rxGlobal",
            sym::OPERATOR_STR_EQ => "streq",
            sym::OPERATOR_STR_MATCH => "strmatch",
            sym::OPERATOR_BEGINS_WITH => "beginsWith",
            sym::OPERATOR_GEOLOOKUP => {
                if cfg!(feature = "maxmind") {
                    "geoLookup"
                } else {
                    driver.error(
                        at0,
                        "This version of ModSecurity was not compiled with GeoIP or MaxMind support.",
                        "",
                    );
                    return Err(Flow::Error);
                }
            }
            _ => return Err(Flow::Error),
        };
        let param = if rhs.len() > 1 { rhs[1].run_time_string() } else { RunTimeString::new() };
        match instantiate_with_param(name, param) {
            Some(o) => Ok(Value::Operator(RuleOperator::new(o))),
            None => Err(Flow::Error),
        }
    }

    /// `OPERATOR_NOT_SUPPORTED(a, b)`
    fn operator_not_supported(driver: &mut Driver, name: &str, at0: &Location) -> Result<Value, Flow> {
        driver.error(at0, &format!("Operator: {} is not yet supported.", name), "");
        Err(Flow::Error)
    }

    /// `ACTION_NOT_SUPPORTED(a, b)`
    fn action_not_supported(driver: &mut Driver, name: &str, at0: &Location) -> Result<ActResult, Flow> {
        driver.error(at0, &format!("Action: {} is not yet supported.", name), "");
        Err(Flow::Error)
    }

    /// Reports `msg` at `@0` and fails the reduction (`driver.error(@0, msg);
    /// YYERROR;`).
    fn fail(driver: &mut Driver, at0: &Location, msg: &str) -> Result<(), Flow> {
        driver.error(at0, msg, "");
        Err(Flow::Error)
    }

    /// `expression:` the directives.
    fn expression(driver: &mut Driver, rhs: &mut [StackEntry], at0: &Location) -> Result<(), Flow> {
        let second = rhs.get(1).map(|e| e.kind);
        let file = driver.filename(rhs[0].loc.end.filename).to_string();
        let line = rhs[0].loc.end.line;
        match (rhs[0].kind, second) {
            (nt::AUDIT_LOG, _) => {}
            // DIRECTIVE variables op actions
            // DIRECTIVE variables op
            (sym::DIRECTIVE, _) => {
                let vars = rhs[1].variables();
                let Some(op) = rhs[2].operator() else {
                    return Err(Flow::Error);
                };
                let (a, t) = if rhs.len() == 4 {
                    let (a, t) = split_actions(rhs[3].actions());
                    (Some(a), Some(t))
                } else {
                    (None, None)
                };
                let rule = RuleWithActions::new(
                    a,
                    t,
                    &file,
                    line,
                    RuleWithActionsKind::Operator(RuleWithOperator::new(op, vars)),
                );
                if !driver.add_sec_rule(rule) {
                    return Err(Flow::Error);
                }
            }
            // CONFIG_DIR_SEC_ACTION actions
            (sym::CONFIG_DIR_SEC_ACTION, _) => {
                let (a, t) = split_actions(rhs[1].actions());
                let rule = RuleWithActions::new(Some(a), Some(t), &file, line, RuleWithActionsKind::Unconditional);
                driver.add_sec_action(rule);
            }
            // DIRECTIVE_SECRULESCRIPT actions
            (sym::DIRECTIVE_SECRULESCRIPT, _) => {
                let script = rhs[0].string();
                let (a, t) = split_actions(rhs[1].actions());
                let mut r = RuleWithActions::new(
                    Some(a),
                    Some(t),
                    &file,
                    line,
                    RuleWithActionsKind::Script(RuleScript::new(&script)),
                );
                if let Some(s) = r.as_rule_script_mut()
                    && let Err(err) = s.init()
                {
                    return Self::fail(driver, at0, &format!("Failed to load script: {}", err));
                }
                if !driver.add_sec_rule_script(r) {
                    return Err(Flow::Error);
                }
            }
            // CONFIG_DIR_SEC_DEFAULT_ACTION actions
            (sym::CONFIG_DIR_SEC_DEFAULT_ACTION, _) => {
                return Self::sec_default_action(driver, rhs[1].actions(), at0);
            }
            (sym::CONFIG_DIR_SEC_MARKER, _) => {
                let marker = remove_brackets_if_needed(rhs[0].string());
                driver.add_sec_marker(&marker, &file, line);
            }
            (sym::CONFIG_DIR_RULE_ENG, Some(sym::CONFIG_VALUE_OFF)) => {
                driver.properties.sec_rule_engine = Some(RuleEngine::Disabled);
            }
            (sym::CONFIG_DIR_RULE_ENG, Some(sym::CONFIG_VALUE_ON)) => {
                driver.properties.sec_rule_engine = Some(RuleEngine::Enabled);
            }
            (sym::CONFIG_DIR_RULE_ENG, _) => {
                driver.properties.sec_rule_engine = Some(RuleEngine::DetectionOnly);
            }
            (sym::CONFIG_DIR_REQ_BODY, Some(sym::CONFIG_VALUE_ON)) => {
                driver.properties.sec_request_body_access = Some(true);
            }
            (sym::CONFIG_DIR_REQ_BODY, _) => {
                driver.properties.sec_request_body_access = Some(false);
            }
            (sym::CONFIG_DIR_RES_BODY, Some(sym::CONFIG_VALUE_ON)) => {
                driver.properties.sec_response_body_access = Some(true);
            }
            (sym::CONFIG_DIR_RES_BODY, _) => {
                driver.properties.sec_response_body_access = Some(false);
            }
            (sym::CONFIG_SEC_ARGUMENT_SEPARATOR, _) => {
                let v = rhs[0].bytes();
                if v.len() != 1 {
                    return Self::fail(driver, at0, "Argument separator should be set to a single character.");
                }
                driver.properties.sec_argument_separator = Some(String::from_utf8_lossy(&v).into_owned());
            }
            (sym::CONFIG_COMPONENT_SIG, _) => {
                let v = rhs[0].string();
                driver.properties.components.push(v);
            }
            (sym::CONFIG_CONN_ENGINE, Some(sym::CONFIG_VALUE_ON)) => {
                return Self::fail(driver, at0, "SecConnEngine is not yet supported.");
            }
            (sym::CONFIG_CONN_ENGINE, _) => {}
            (sym::CONFIG_SEC_WEB_APP_ID, _) => {
                driver.properties.sec_web_app_id = Some(rhs[0].string());
            }
            (sym::CONFIG_SEC_SERVER_SIG, _) => {
                return Self::fail(driver, at0, "SecServerSignature is not supported.");
            }
            (sym::CONFIG_SEC_CACHE_TRANSFORMATIONS, _) => {
                return Self::fail(driver, at0, "SecCacheTransformations is not supported.");
            }
            (sym::CONFIG_SEC_DISABLE_BACKEND_COMPRESS, Some(sym::CONFIG_VALUE_ON)) => {
                return Self::fail(driver, at0, "SecDisableBackendCompression is not supported.");
            }
            (sym::CONFIG_SEC_DISABLE_BACKEND_COMPRESS, _) => {}
            (sym::CONFIG_CONTENT_INJECTION, Some(sym::CONFIG_VALUE_ON)) => {
                return Self::fail(driver, at0, "SecContentInjection is not yet supported.");
            }
            (sym::CONFIG_CONTENT_INJECTION, _) => {}
            (sym::CONFIG_SEC_CHROOT_DIR, _) => {
                return Self::fail(driver, at0, "SecChrootDir is not supported.");
            }
            (sym::CONFIG_SEC_HASH_ENGINE, Some(sym::CONFIG_VALUE_ON)) => {
                return Self::fail(driver, at0, "SecHashEngine is not yet supported.");
            }
            (sym::CONFIG_SEC_HASH_ENGINE, _) => {}
            (sym::CONFIG_SEC_HASH_KEY, _) => {
                return Self::fail(driver, at0, "SecHashKey is not yet supported.");
            }
            (sym::CONFIG_SEC_HASH_PARAM, _) => {
                return Self::fail(driver, at0, "SecHashParam is not yet supported.");
            }
            (sym::CONFIG_SEC_HASH_METHOD_RX, _) => {
                return Self::fail(driver, at0, "SecHashMethodRx is not yet supported.");
            }
            (sym::CONFIG_SEC_HASH_METHOD_PM, _) => {
                return Self::fail(driver, at0, "SecHashMethodPm is not yet supported.");
            }
            (sym::CONFIG_DIR_GSB_DB, _) => {
                return Self::fail(driver, at0, "SecGsbLookupDb is not supported.");
            }
            (sym::CONFIG_SEC_GUARDIAN_LOG, _) => {
                return Self::fail(driver, at0, "SecGuardianLog is not supported.");
            }
            (sym::CONFIG_SEC_INTERCEPT_ON_ERROR, Some(sym::CONFIG_VALUE_ON)) => {
                return Self::fail(driver, at0, "SecInterceptOnError is not yet supported.");
            }
            (sym::CONFIG_SEC_INTERCEPT_ON_ERROR, _) => {}
            (sym::CONFIG_SEC_CONN_R_STATE_LIMIT, _) => {
                return Self::fail(driver, at0, "SecConnReadStateLimit is not yet supported.");
            }
            (sym::CONFIG_SEC_CONN_W_STATE_LIMIT, _) => {
                return Self::fail(driver, at0, "SecConnWriteStateLimit is not yet supported.");
            }
            (sym::CONFIG_SEC_SENSOR_ID, _) => {
                return Self::fail(driver, at0, "SecSensorId is not yet supported.");
            }
            (sym::CONFIG_SEC_RULE_INHERITANCE, Some(sym::CONFIG_VALUE_ON)) => {
                return Self::fail(driver, at0, "SecRuleInheritance is not yet supported.");
            }
            (sym::CONFIG_SEC_RULE_INHERITANCE, _) => {}
            (sym::CONFIG_SEC_RULE_PERF_TIME, _) => {
                return Self::fail(driver, at0, "SecRulePerfTime is not yet supported.");
            }
            (sym::CONFIG_SEC_STREAM_IN_BODY_INSPECTION, _) => {
                return Self::fail(driver, at0, "SecStreamInBodyInspection is not supported.");
            }
            (sym::CONFIG_SEC_STREAM_OUT_BODY_INSPECTION, _) => {
                return Self::fail(driver, at0, "SecStreamOutBodyInspection is not supported.");
            }
            (sym::CONFIG_SEC_RULE_REMOVE_BY_ID, _) => {
                let v = rhs[0].string();
                if let Err(error) = driver.properties.exceptions.load(&v) {
                    return Self::fail(driver, at0, &format!("SecRuleRemoveById: failed to load:{}. {}", v, error));
                }
            }
            (sym::CONFIG_SEC_RULE_REMOVE_BY_TAG, _) => {
                let v = rhs[0].string();
                driver.properties.exceptions.load_remove_rule_by_tag(&v);
            }
            (sym::CONFIG_SEC_RULE_REMOVE_BY_MSG, _) => {
                let v = rhs[0].string();
                driver.properties.exceptions.load_remove_rule_by_msg(&v);
            }
            (sym::CONFIG_SEC_RULE_UPDATE_TARGET_BY_TAG, _) => {
                let v = rhs[0].string();
                let vars = rhs[1].variables();
                driver.properties.exceptions.load_update_target_by_tag(&v, vars);
            }
            (sym::CONFIG_SEC_RULE_UPDATE_TARGET_BY_MSG, _) => {
                let v = rhs[0].string();
                let vars = rhs[1].variables();
                driver.properties.exceptions.load_update_target_by_msg(&v, vars);
            }
            (sym::CONFIG_SEC_RULE_UPDATE_TARGET_BY_ID, _) => {
                let v = rhs[0].string();
                let Some(rule_id) = stod(&v) else {
                    return Self::fail(
                        driver,
                        at0,
                        &format!(
                            "SecRuleUpdateTargetById: failed to load:The input \"{}\" does not seems to be a valid rule id.. ",
                            v
                        ),
                    );
                };
                let vars = rhs[1].variables();
                driver.properties.exceptions.load_update_target_by_id(rule_id, vars);
            }
            (sym::CONFIG_SEC_RULE_UPDATE_ACTION_BY_ID, _) => {
                let v = rhs[0].string();
                let Some(rule_id) = stod(&v) else {
                    return Self::fail(
                        driver,
                        at0,
                        &format!(
                            "SecRuleUpdateActionById: failed to load:The input \"{}\" does not seems to be a valid rule id.. ",
                            v
                        ),
                    );
                };
                let acts: Vec<Box<dyn Action>> = rhs[1].actions().into_iter().map(ParsedAction::into_action).collect();
                driver.properties.exceptions.load_update_action_by_id(rule_id, acts);
            }
            // Debug log: start
            (sym::CONFIG_DIR_DEBUG_LVL, _) => {
                let level = atoi(&rhs[0].bytes()) as i32;
                driver.properties.debug_log.set_debug_log_level(level);
            }
            (sym::CONFIG_DIR_DEBUG_LOG, _) => {
                let v = rhs[0].string();
                if let Err(error) = driver.properties.debug_log.set_debug_log_file(&v) {
                    return Self::fail(driver, at0, &format!("Failed to start DebugLog: {}", error));
                }
            }
            // Debug log: end
            (sym::CONFIG_DIR_GEO_DB, _) => {
                let v = rhs[0].string();
                if cfg!(feature = "maxmind") {
                    let lookup = find_resource(&v, driver.filename(rhs[0].loc.end.filename));
                    let Some(file) = lookup.path else {
                        return Self::fail(
                            driver,
                            at0,
                            &format!("Failed to load locate the GeoDB file from: {} {}", v, lookup.looked_at),
                        );
                    };
                    if let Err(err) = crate::utils::geo_lookup::GeoLookup::get_instance().set_data_base(&file) {
                        return Self::fail(driver, at0, &format!("Failed to load the GeoDB from: {}. {}", file, err));
                    }
                } else {
                    return Self::fail(
                        driver,
                        at0,
                        "This version of ModSecurity was not compiled with GeoIP or MaxMind support.",
                    );
                }
            }
            (sym::CONFIG_DIR_ARGS_LIMIT, _) => {
                driver.properties.arguments_limit = Some(atoi(&rhs[0].bytes()) as i32 as u32);
            }
            (sym::CONFIG_DIR_REQ_BODY_JSON_DEPTH_LIMIT, _) => {
                driver.properties.request_body_json_depth_limit = Some(atoi(&rhs[0].bytes()) as i32 as u32);
            }
            // Body limits
            (sym::CONFIG_DIR_REQ_BODY_LIMIT, _) => match parse_config_number(&rhs[0].string()) {
                Ok(v) => driver.properties.request_body_limit = Some(v),
                Err(errmsg) => {
                    return Self::fail(driver, at0, &format!("Failed to parse SecRequestBodyLimit: {}", errmsg));
                }
            },
            (sym::CONFIG_DIR_REQ_BODY_NO_FILES_LIMIT, _) => match parse_config_number(&rhs[0].string()) {
                Ok(v) => driver.properties.request_body_no_files_limit = Some(v),
                Err(errmsg) => {
                    return Self::fail(
                        driver,
                        at0,
                        &format!("Failed to parse SecRequestsBodyNoFilesLimit: {}", errmsg),
                    );
                }
            },
            (sym::CONFIG_DIR_REQ_BODY_IN_MEMORY_LIMIT, _) => {
                return Self::fail(
                    driver,
                    at0,
                    "As of ModSecurity version 3.0, SecRequestBodyInMemoryLimit is no longer supported. Instead, you can use your web server configurations to control those values. ModSecurity will follow the web server decision.",
                );
            }
            (sym::CONFIG_DIR_RES_BODY_LIMIT, _) => match parse_config_number(&rhs[0].string()) {
                Ok(v) => driver.properties.response_body_limit = Some(v),
                Err(errmsg) => {
                    return Self::fail(driver, at0, &format!("Failed to parse SecResponseBodyLimit: {}", errmsg));
                }
            },
            (sym::CONFIG_DIR_REQ_BODY_LIMIT_ACTION, Some(sym::CONFIG_VALUE_PROCESS_PARTIAL)) => {
                driver.properties.request_body_limit_action = Some(BodyLimitAction::ProcessPartial);
            }
            (sym::CONFIG_DIR_REQ_BODY_LIMIT_ACTION, _) => {
                driver.properties.request_body_limit_action = Some(BodyLimitAction::Reject);
            }
            (sym::CONFIG_DIR_RES_BODY_LIMIT_ACTION, Some(sym::CONFIG_VALUE_PROCESS_PARTIAL)) => {
                driver.properties.response_body_limit_action = Some(BodyLimitAction::ProcessPartial);
            }
            (sym::CONFIG_DIR_RES_BODY_LIMIT_ACTION, _) => {
                driver.properties.response_body_limit_action = Some(BodyLimitAction::Reject);
            }
            (sym::CONFIG_SEC_REMOTE_RULES_FAIL_ACTION, Some(sym::CONFIG_VALUE_ABORT)) => {
                driver.properties.remote_rules_action_on_failed = Some(OnFailedRemoteRulesAction::Abort);
            }
            (sym::CONFIG_SEC_REMOTE_RULES_FAIL_ACTION, _) => {
                driver.properties.remote_rules_action_on_failed = Some(OnFailedRemoteRulesAction::Warn);
            }
            (sym::CONFIG_DIR_PCRE_MATCH_LIMIT_RECURSION, _) => {
                // Parser error disabled to avoid breaking default
                // installations with modsecurity.conf-recommended:
                // "SecPcreMatchLimitRecursion is not currently supported.
                // Default PCRE values are being used for now"
            }
            (sym::CONFIG_DIR_PCRE_MATCH_LIMIT, _) => match parse_config_number(&rhs[0].string()) {
                Ok(v) => driver.properties.pcre_match_limit = Some(v),
                Err(errmsg) => {
                    return Self::fail(driver, at0, &format!("Failed to parse SecPcreMatchLimit: {}", errmsg));
                }
            },
            (sym::CONGIG_DIR_RESPONSE_BODY_MP, _) => {
                let v = rhs[0].string();
                // std::istream_iterator<std::string> into a std::set.
                let tokens: std::collections::BTreeSet<&str> = v.split_ascii_whitespace().collect();
                let t = &mut driver.properties.response_body_type_to_be_inspected;
                t.set = true;
                for it in tokens {
                    t.value.insert(it.to_ascii_lowercase());
                }
            }
            (sym::CONGIG_DIR_RESPONSE_BODY_MP_CLEAR, _) => {
                let t = &mut driver.properties.response_body_type_to_be_inspected;
                t.set = true;
                t.clear = true;
                t.value.clear();
            }
            (sym::CONFIG_XML_EXTERNAL_ENTITY, Some(sym::CONFIG_VALUE_OFF)) => {
                driver.properties.sec_xml_external_entity = Some(false);
            }
            (sym::CONFIG_XML_EXTERNAL_ENTITY, _) => {
                driver.properties.sec_xml_external_entity = Some(true);
            }
            (sym::CONFIG_XML_PARSE_XML_INTO_ARGS, Some(sym::CONFIG_VALUE_ONLYARGS)) => {
                driver.properties.sec_xml_parse_xml_into_args = Some(ParseXmlIntoArgs::OnlyArgs);
            }
            (sym::CONFIG_XML_PARSE_XML_INTO_ARGS, Some(sym::CONFIG_VALUE_OFF)) => {
                driver.properties.sec_xml_parse_xml_into_args = Some(ParseXmlIntoArgs::Off);
            }
            (sym::CONFIG_XML_PARSE_XML_INTO_ARGS, _) => {
                driver.properties.sec_xml_parse_xml_into_args = Some(ParseXmlIntoArgs::On);
            }
            (sym::CONGIG_DIR_SEC_TMP_DIR, _) => {
                // Parser error disabled to avoid breaking default
                // installations with modsecurity.conf-recommended:
                // "As of ModSecurity version 3.0, SecTmpDir is no longer
                // supported. [...]"
            }
            (sym::CONGIG_DIR_SEC_DATA_DIR, _) => {
                // Parser error disabled to avoid breaking default
                // installations with modsecurity.conf-recommended:
                // "SecDataDir is not currently supported. [...]"
            }
            (sym::CONGIG_DIR_SEC_ARG_SEP, _) => {}
            (sym::CONGIG_DIR_SEC_COOKIE_FORMAT, _) => {
                if atoi(&rhs[0].bytes()) as i32 == 1 {
                    return Self::fail(driver, at0, "SecCookieFormat 1 is not yet supported.");
                }
            }
            (sym::CONFIG_SEC_COOKIEV0_SEPARATOR, _) => {
                return Self::fail(driver, at0, "SecCookieV0Separator is not yet supported.");
            }
            (sym::CONGIG_DIR_SEC_STATUS_ENGINE, _) => {
                // Parser error disabled to avoid breaking default
                // installations with modsecurity.conf-recommended:
                // "SecStatusEngine is not yet supported."
            }
            (sym::CONFIG_DIR_UNICODE_MAP_FILE, _) => {
                let v = rhs[0].string();
                return Self::unicode_map_file(driver, &v, rhs[0].loc.end.filename, at0);
            }
            (sym::CONFIG_SEC_COLLECTION_TIMEOUT, _) => {
                // Parser error disabled to avoid breaking default CRS
                // installations with crs-setup.conf-recommended:
                // "SecCollectionTimeout is not yet supported."
            }
            (sym::CONFIG_SEC_HTTP_BLKEY, _) => {
                driver.properties.httpbl_key = Some(rhs[0].string());
            }
            _ => {}
        }
        Ok(())
    }

    /// `CONFIG_DIR_SEC_DEFAULT_ACTION actions`
    fn sec_default_action(driver: &mut Driver, list: Vec<ParsedAction>, at0: &Location) -> Result<(), Flow> {
        let mut has_disruptive = false;
        let mut checked_actions: Vec<Box<dyn Action>> = Vec::new();
        let mut defined_phase: i32 = -1;
        let mut sec_rule_defined_phase: i32 = -1;
        for pa in list {
            let a = pa.as_action();
            if a.is_disruptive() && !a.is_block() {
                has_disruptive = true;
            }
            if matches!(pa, ParsedAction::Action(RuleAction::Phase(_))) {
                // `phase->m_phase`: applied the way the rule constructor
                // does it (`evaluate(rule, nullptr)`).
                let mut scratch = RuleWithActions::new(None, None, "", 0, RuleWithActionsKind::Unconditional);
                a.configure(&mut scratch);
                defined_phase = scratch.get_phase();
                // `phase->m_secRulesPhase`: the SecLang phase number, i.e.
                // the internal one minus the URI phase that SecLang cannot
                // name (phase:0 is the connection phase).
                sec_rule_defined_phase =
                    if defined_phase <= Phases::ConnectionPhase as i32 { defined_phase } else { defined_phase - 1 };
            } else if matches!(a.kind(), Kind::RunTimeOnlyIfMatch | Kind::RunTimeBeforeMatchAttempt) {
                if a.as_transformation().is_some_and(Transformation::is_none) {
                    return Self::fail(
                        driver,
                        at0,
                        "The transformation none is not suitable to be part of the SecDefaultActions",
                    );
                }
                checked_actions.push(pa.into_action());
            } else {
                let msg = format!("The action '{}' is not suitable to be part of the SecDefaultActions", a.name());
                return Self::fail(driver, at0, &msg);
            }
        }
        if defined_phase == -1 {
            defined_phase = Phases::RequestHeadersPhase as i32;
        }

        if !has_disruptive {
            return Self::fail(driver, at0, "SecDefaultAction must specify a disruptive action.");
        }

        let idx = defined_phase as usize;
        if idx >= driver.properties.default_actions.len() {
            // C++ indexes the array out of bounds here.
            return Err(Flow::Error);
        }
        if !driver.properties.default_actions[idx].is_empty() {
            let msg = format!(
                "SecDefaultActions can only be placed once per phase and configuration context. Phase {} was informed already.",
                sec_rule_defined_phase
            );
            return Self::fail(driver, at0, &msg);
        }

        for a in checked_actions {
            driver.properties.default_actions[idx].push(std::sync::Arc::from(a));
        }
        Ok(())
    }

    /// `CONFIG_DIR_UNICODE_MAP_FILE` (`SecUnicodeMapFile <file> <code page>`)
    fn unicode_map_file(driver: &mut Driver, v: &str, filename: usize, at0: &Location) -> Result<(), Flow> {
        let mut param: Vec<String> =
            ssplit(v.as_bytes(), b' ').into_iter().map(|p| String::from_utf8_lossy(&p).into_owned()).collect();
        if param.len() <= 1 {
            return Self::fail(driver, at0, &format!("Failed to process unicode map, missing parameter: {} ", v));
        }

        let last = param.last().cloned().unwrap_or_default();
        let Some(num) = stod(&last) else {
            return Self::fail(
                driver,
                at0,
                &format!("Failed to process unicode map, last parameter is expected to be a number: {} ", last),
            );
        };
        param.pop();

        let mut f = String::new();
        while let Some(p) = param.pop() {
            if f.is_empty() {
                f = p;
            } else {
                f = format!("{} {}", p, f);
            }
        }

        let config = driver.filename(filename).to_string();
        let lookup = find_resource(&f, &config);
        let Some(file) = lookup.path else {
            return Self::fail(
                driver,
                at0,
                &format!("Failed to locate the unicode map file from: {} {}", f, lookup.looked_at),
            );
        };

        if let Err(error) = ConfigUnicodeMap::load_config(&file, num, &mut driver.properties)
            && !error.is_empty()
        {
            return Self::fail(driver, at0, &error);
        }
        Ok(())
    }

    /// `variables: variables_pre_process`: removes the excluded variables
    /// (`!ARGS:foo`) from the list, recording their keys as exclusions of
    /// the variables of the same collection.
    fn variables(mut original_list: Vec<Box<dyn Variable>>) -> Vec<Box<dyn Variable>> {
        let mut new_list: Vec<Box<dyn Variable>> = Vec::new();
        let mut new_new_list: Vec<Box<dyn Variable>> = Vec::new();
        let mut exclusion_vars: Vec<Box<dyn Variable>> = Vec::new();
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
                if var.same_as(i.as_ref()) {
                    do_not_add = true;
                }
                if i.belongs_to_collection(var.as_ref()) {
                    var.adds_key_exclusion(i.as_ref());
                }
            }
            if !do_not_add {
                new_new_list.push(var);
            }
        }
        new_new_list
    }

    /// ```text
    /// variables_may_be_quoted:
    ///     variables_may_be_quoted PIPE var
    ///   | variables_may_be_quoted PIPE VAR_EXCLUSION var
    ///   | variables_may_be_quoted PIPE VAR_COUNT var
    ///   | var
    ///   | VAR_EXCLUSION var
    ///   | VAR_COUNT var
    /// ```
    fn variables_may_be_quoted(rhs: &mut [StackEntry]) -> Vec<Box<dyn Variable>> {
        let (mut list, rest) = if rhs[0].kind == nt::VARIABLES_MAY_BE_QUOTED {
            let l = rhs[0].variables();
            (l, &mut rhs[2..])
        } else {
            (Vec::new(), &mut rhs[..])
        };
        let modifier = if rest.len() == 2 { Some(rest[0].kind) } else { None };
        let Some(var) = rest[rest.len() - 1].variable() else {
            return list;
        };
        let var: Box<dyn Variable> = match modifier {
            Some(sym::VAR_EXCLUSION) => Box::new(VariableModificatorExclusion::new(var)),
            Some(sym::VAR_COUNT) => Box::new(VariableModificatorCount::new(var)),
            _ => var,
        };
        list.push(var);
        list
    }

    /// `var:` a variable (rule target or macro).
    fn var(driver: &mut Driver, rhs: &mut [StackEntry], at0: &Location) -> Result<Box<dyn Variable>, Flow> {
        let kind = rhs[0].kind;
        let selector = match rhs.get(1).map(|e| e.kind) {
            Some(sym::DICT_ELEMENT) => VariableSelector::DictElement(rhs[1].string()),
            Some(sym::DICT_ELEMENT_REGEXP) => VariableSelector::Regexp(rhs[1].string()),
            Some(nt::RUN_TIME_STRING) => VariableSelector::Dynamic(rhs[1].run_time_string()),
            _ => VariableSelector::None,
        };
        match kind {
            // Env("ENV:" + $2) for both the plain and the regexp element.
            sym::RUN_TIME_VAR_ENV => {
                let selector = match selector {
                    VariableSelector::Regexp(s) => VariableSelector::DictElement(s),
                    s => s,
                };
                Self::new_var(driver, "ENV", selector, at0)
            }
            // XML("XML:" + $2) / XML_NoDictElement()
            sym::RUN_TIME_VAR_XML => match selector {
                VariableSelector::DictElement(s) | VariableSelector::Regexp(s) => {
                    Ok(Box::new(xml::Xml::new(&format!("XML:{}", s))))
                }
                _ => Ok(Box::new(xml::XmlNoDictElement::new())),
            },
            // The variables built from the text as written (`new
            // Duration(name)`, `new TimeHour(name)`, ...).
            sym::RUN_TIME_VAR_DUR
            | sym::RUN_TIME_VAR_BLD
            | sym::RUN_TIME_VAR_HSV
            | sym::RUN_TIME_VAR_REMOTE_USER
            | sym::RUN_TIME_VAR_TIME
            | sym::RUN_TIME_VAR_TIME_DAY
            | sym::RUN_TIME_VAR_TIME_EPOCH
            | sym::RUN_TIME_VAR_TIME_HOUR
            | sym::RUN_TIME_VAR_TIME_MIN
            | sym::RUN_TIME_VAR_TIME_MON
            | sym::RUN_TIME_VAR_TIME_SEC
            | sym::RUN_TIME_VAR_TIME_WDAY
            | sym::RUN_TIME_VAR_TIME_YEAR => {
                let name = rhs[0].string();
                match new_variable(&name, VariableSelector::None) {
                    Some(v) => Ok(v),
                    None => Self::new_var(driver, &name.to_ascii_uppercase(), VariableSelector::None, at0),
                }
            }
            _ => match variable_name(kind) {
                Some(name) => Self::new_var(driver, name, selector, at0),
                None => Err(Flow::Error),
            },
        }
    }

    fn new_var(
        driver: &mut Driver,
        name: &str,
        selector: VariableSelector,
        at0: &Location,
    ) -> Result<Box<dyn Variable>, Flow> {
        match new_variable(name, selector) {
            Some(v) => Ok(v),
            None => {
                // Cannot happen with the C++ grammar (every variable
                // token has its class).
                driver.error(at0, &format!("Variable {} is not supported by libModSecurity", name), "");
                Err(Flow::Error)
            }
        }
    }

    /// `act:` an action of a rule.
    fn act(driver: &mut Driver, rhs: &mut [StackEntry], at0: &Location) -> Result<ActResult, Flow> {
        use ParsedAction::Transformation as T;
        let kind = rhs[0].kind;
        let second = rhs.get(1).map(|e| e.kind);
        if rhs.len() == 2 && second == Some(nt::RUN_TIME_STRING) {
            let z = rhs[1].run_time_string();
            let a: RuleAction = match kind {
                sym::ACTION_EXPIRE_VAR => RuleAction::Other(Box::new(actions::expire_var::ExpireVar::with_rts(z))),
                sym::ACTION_INITCOL => {
                    let a = rhs[0].string();
                    return Ok(actions::init_col::InitCol::with_rts(&a, z).map(other));
                }
                sym::ACTION_LOG_DATA => RuleAction::LogData(actions::log_data::LogData::with_rts(z)),
                sym::ACTION_MSG => RuleAction::Msg(actions::msg::Msg::with_rts(z)),
                sym::ACTION_REDIRECT => RuleAction::Other(Box::new(disruptive::redirect::Redirect::with_rts(z))),
                sym::ACTION_SETENV => RuleAction::Other(Box::new(actions::set_env::SetENV::with_rts(z))),
                sym::ACTION_SETRSC => RuleAction::Other(Box::new(actions::set_rsc::SetRSC::with_rts(z))),
                sym::ACTION_SETSID => RuleAction::Other(Box::new(actions::set_sid::SetSID::with_rts(z))),
                sym::ACTION_SETUID => RuleAction::Other(Box::new(actions::set_uid::SetUID::with_rts(z))),
                sym::ACTION_TAG => RuleAction::Tag(actions::tag::Tag::with_rts(z)),
                _ => return Err(Flow::Error),
            };
            return Ok(Ok(ParsedAction::Action(a)));
        }
        if kind == sym::ACTION_SETVAR {
            // ACTION_SETVAR setvar_action
            return rhs[1].action().ok_or(Flow::Error);
        }
        if let Some(value) = second {
            // ctl:<option>=<value>
            let t = rhs[0].string();
            use crate::audit_log::audit_log::AuditLogStatus;
            use crate::rules_set_properties::{ParseXmlIntoArgs, RuleEngine};
            let a = match (kind, value) {
                (sym::ACTION_CTL_AUDIT_ENGINE, sym::CONFIG_VALUE_ON) => {
                    driver.properties.audit_log.set_ctl_audit_engine_active();
                    other(ctl::audit_engine::AuditEngine::new(AuditLogStatus::On))
                }
                (sym::ACTION_CTL_AUDIT_ENGINE, sym::CONFIG_VALUE_OFF) => {
                    other(ctl::audit_engine::AuditEngine::new(AuditLogStatus::Off))
                }
                (sym::ACTION_CTL_AUDIT_ENGINE, _) => {
                    driver.properties.audit_log.set_ctl_audit_engine_active();
                    other(ctl::audit_engine::AuditEngine::new(AuditLogStatus::RelevantOnly))
                }
                // ACTION_NOT_SUPPORTED("CtlForceReequestBody", @0) is
                // commented out in C++: a plain action is built.
                (sym::ACTION_CTL_FORCE_REQ_BODY_VAR, _) => other(InertAction::new(&t)),
                (sym::ACTION_CTL_PARSE_XML_INTO_ARGS, sym::CONFIG_VALUE_ON) => {
                    other(ctl::parse_xml_into_args::ParseXmlIntoArgs::new(ParseXmlIntoArgs::On))
                }
                (sym::ACTION_CTL_PARSE_XML_INTO_ARGS, sym::CONFIG_VALUE_OFF) => {
                    other(ctl::parse_xml_into_args::ParseXmlIntoArgs::new(ParseXmlIntoArgs::Off))
                }
                (sym::ACTION_CTL_PARSE_XML_INTO_ARGS, _) => {
                    other(ctl::parse_xml_into_args::ParseXmlIntoArgs::new(ParseXmlIntoArgs::OnlyArgs))
                }
                (sym::ACTION_CTL_REQUEST_BODY_ACCESS, v) => {
                    other(ctl::request_body_access::RequestBodyAccess::new(&t, v == sym::CONFIG_VALUE_ON))
                }
                (sym::ACTION_CTL_RULE_ENGINE, sym::CONFIG_VALUE_ON) => {
                    other(ctl::rule_engine::RuleEngine::new(RuleEngine::Enabled))
                }
                (sym::ACTION_CTL_RULE_ENGINE, sym::CONFIG_VALUE_OFF) => {
                    other(ctl::rule_engine::RuleEngine::new(RuleEngine::Disabled))
                }
                (sym::ACTION_CTL_RULE_ENGINE, _) => other(ctl::rule_engine::RuleEngine::new(RuleEngine::DetectionOnly)),
                _ => return Err(Flow::Error),
            };
            return Ok(Ok(a));
        }
        let s = rhs[0].string();
        let s = s.as_str();
        Ok(Ok(match kind {
            sym::ACTION_ACCURACY => return Ok(actions::accuracy::Accuracy::new(s).map(other)),
            sym::ACTION_ALLOW => return Ok(disruptive::allow::Allow::new(s).map(other)),
            sym::ACTION_APPEND => return Self::action_not_supported(driver, "Append", at0),
            sym::ACTION_AUDIT_LOG => other(actions::audit_log::AuditLog::new(s)),
            sym::ACTION_BLOCK => ParsedAction::Action(RuleAction::Block(actions::block::Block::new(s))),
            sym::ACTION_CAPTURE => ParsedAction::Action(RuleAction::Capture(actions::capture::Capture::new(s))),
            sym::ACTION_CHAIN => other(actions::chain::Chain::new(s)),
            sym::ACTION_CTL_AUDIT_LOG_PARTS => other(ctl::audit_log_parts::AuditLogParts::new(s)),
            sym::ACTION_CTL_BDY_JSON => other(ctl::request_body_processor_json::RequestBodyProcessorJSON::new(s)),
            sym::ACTION_CTL_BDY_XML => other(ctl::request_body_processor_xml::RequestBodyProcessorXML::new(s)),
            sym::ACTION_CTL_BDY_URLENCODED => {
                other(ctl::request_body_processor_urlencoded::RequestBodyProcessorURLENCODED::new(s))
            }
            sym::ACTION_CTL_RULE_REMOVE_BY_ID => return Ok(ctl::rule_remove_by_id::RuleRemoveById::new(s).map(other)),
            sym::ACTION_CTL_RULE_REMOVE_BY_TAG => {
                return Ok(ctl::rule_remove_by_tag::RuleRemoveByTag::new(s).map(other));
            }
            sym::ACTION_CTL_RULE_REMOVE_TARGET_BY_ID => {
                return Ok(ctl::rule_remove_target_by_id::RuleRemoveTargetById::new(s).map(other));
            }
            sym::ACTION_CTL_RULE_REMOVE_TARGET_BY_TAG => {
                return Ok(ctl::rule_remove_target_by_tag::RuleRemoveTargetByTag::new(s).map(other));
            }
            sym::ACTION_DENY => other(disruptive::deny::Deny::new(s)),
            sym::ACTION_DEPRECATE_VAR => return Self::action_not_supported(driver, "DeprecateVar", at0),
            sym::ACTION_DROP => other(disruptive::drop::Drop::new(s)),
            sym::ACTION_EXEC => return Ok(actions::exec::Exec::new(s).map(other)),
            sym::ACTION_ID => return Ok(actions::rule_id::RuleId::new(s).map(other)),
            sym::ACTION_LOG => other(actions::log::Log::new(s)),
            sym::ACTION_MATURITY => return Ok(actions::maturity::Maturity::new(s).map(other)),
            sym::ACTION_MULTI_MATCH => {
                ParsedAction::Action(RuleAction::MultiMatch(actions::multi_match::MultiMatch::new(s)))
            }
            sym::ACTION_NO_AUDIT_LOG => other(actions::no_audit_log::NoAuditLog::new(s)),
            sym::ACTION_NO_LOG => other(actions::no_log::NoLog::new(s)),
            sym::ACTION_PASS => other(disruptive::pass::Pass::new(s)),
            sym::ACTION_PAUSE => return Self::action_not_supported(driver, "Pause", at0),
            sym::ACTION_PHASE => {
                return Ok(actions::phase::Phase::new(s).map(|a| ParsedAction::Action(RuleAction::Phase(a))));
            }
            sym::ACTION_PREPEND => return Self::action_not_supported(driver, "Prepend", at0),
            sym::ACTION_PROXY => return Self::action_not_supported(driver, "Proxy", at0),
            sym::ACTION_REV => other(actions::rev::Rev::new(s)),
            sym::ACTION_SANITISE_ARG => return Self::action_not_supported(driver, "SanitiseArg", at0),
            sym::ACTION_SANITISE_MATCHED => return Self::action_not_supported(driver, "SanitiseMatched", at0),
            sym::ACTION_SANITISE_MATCHED_BYTES => {
                return Self::action_not_supported(driver, "SanitiseMatchedBytes", at0);
            }
            sym::ACTION_SANITISE_REQUEST_HEADER => {
                return Self::action_not_supported(driver, "SanitiseRequestHeader", at0);
            }
            sym::ACTION_SANITISE_RESPONSE_HEADER => {
                return Self::action_not_supported(driver, "SanitiseResponseHeader", at0);
            }
            sym::ACTION_SEVERITY => {
                return Ok(actions::severity::Severity::new(s).map(|a| ParsedAction::Action(RuleAction::Severity(a))));
            }
            sym::ACTION_SKIP => return Ok(actions::skip::Skip::new(s).map(other)),
            sym::ACTION_SKIP_AFTER => other(actions::skip_after::SkipAfter::new(s)),
            sym::ACTION_STATUS => return Ok(data::status::Status::new(s).map(other)),
            sym::ACTION_VER => other(actions::ver::Ver::new(s)),
            sym::ACTION_XMLNS => return Ok(actions::xmlns::XmlNS::new(s).map(other)),
            sym::ACTION_TRANSFORMATION_PARITY_ZERO_7_BIT => T(Transformation::new(TK::ParityZero7bit, s)),
            sym::ACTION_TRANSFORMATION_PARITY_ODD_7_BIT => T(Transformation::new(TK::ParityOdd7bit, s)),
            sym::ACTION_TRANSFORMATION_PARITY_EVEN_7_BIT => T(Transformation::new(TK::ParityEven7bit, s)),
            sym::ACTION_TRANSFORMATION_SQL_HEX_DECODE => T(Transformation::new(TK::SqlHexDecode, s)),
            sym::ACTION_TRANSFORMATION_BASE_64_ENCODE => T(Transformation::new(TK::Base64Encode, s)),
            sym::ACTION_TRANSFORMATION_BASE_64_DECODE => T(Transformation::new(TK::Base64Decode, s)),
            sym::ACTION_TRANSFORMATION_BASE_64_DECODE_EXT => T(Transformation::new(TK::Base64DecodeExt, s)),
            sym::ACTION_TRANSFORMATION_CMD_LINE => T(Transformation::new(TK::CmdLine, s)),
            sym::ACTION_TRANSFORMATION_SHA1 => T(Transformation::new(TK::Sha1, s)),
            sym::ACTION_TRANSFORMATION_MD5 => T(Transformation::new(TK::Md5, s)),
            sym::ACTION_TRANSFORMATION_ESCAPE_SEQ_DECODE => T(Transformation::new(TK::EscapeSeqDecode, s)),
            sym::ACTION_TRANSFORMATION_HEX_ENCODE => T(Transformation::new(TK::HexEncode, s)),
            sym::ACTION_TRANSFORMATION_HEX_DECODE => T(Transformation::new(TK::HexDecode, s)),
            sym::ACTION_TRANSFORMATION_LOWERCASE => T(Transformation::new(TK::LowerCase, s)),
            sym::ACTION_TRANSFORMATION_UPPERCASE => T(Transformation::new(TK::UpperCase, s)),
            sym::ACTION_TRANSFORMATION_URL_DECODE_UNI => T(Transformation::new(TK::UrlDecodeUni, s)),
            sym::ACTION_TRANSFORMATION_URL_DECODE => T(Transformation::new(TK::UrlDecode, s)),
            sym::ACTION_TRANSFORMATION_URL_ENCODE => T(Transformation::new(TK::UrlEncode, s)),
            sym::ACTION_TRANSFORMATION_NONE => T(Transformation::new(TK::None, s)),
            sym::ACTION_TRANSFORMATION_COMPRESS_WHITESPACE => T(Transformation::new(TK::CompressWhitespace, s)),
            sym::ACTION_TRANSFORMATION_REMOVE_WHITESPACE => T(Transformation::new(TK::RemoveWhitespace, s)),
            sym::ACTION_TRANSFORMATION_REPLACE_NULLS => T(Transformation::new(TK::ReplaceNulls, s)),
            sym::ACTION_TRANSFORMATION_REMOVE_NULLS => T(Transformation::new(TK::RemoveNulls, s)),
            sym::ACTION_TRANSFORMATION_HTML_ENTITY_DECODE => T(Transformation::new(TK::HtmlEntityDecode, s)),
            sym::ACTION_TRANSFORMATION_JS_DECODE => T(Transformation::new(TK::JsDecode, s)),
            sym::ACTION_TRANSFORMATION_CSS_DECODE => T(Transformation::new(TK::CssDecode, s)),
            sym::ACTION_TRANSFORMATION_TRIM => T(Transformation::new(TK::Trim, s)),
            sym::ACTION_TRANSFORMATION_TRIM_LEFT => T(Transformation::new(TK::TrimLeft, s)),
            sym::ACTION_TRANSFORMATION_TRIM_RIGHT => T(Transformation::new(TK::TrimRight, s)),
            sym::ACTION_TRANSFORMATION_NORMALISE_PATH_WIN => T(Transformation::new(TK::NormalisePathWin, s)),
            sym::ACTION_TRANSFORMATION_NORMALISE_PATH => T(Transformation::new(TK::NormalisePath, s)),
            sym::ACTION_TRANSFORMATION_LENGTH => T(Transformation::new(TK::Length, s)),
            sym::ACTION_TRANSFORMATION_UTF8_TO_UNICODE => T(Transformation::new(TK::Utf8ToUnicode, s)),
            sym::ACTION_TRANSFORMATION_REMOVE_COMMENTS_CHAR => T(Transformation::new(TK::RemoveCommentsChar, s)),
            sym::ACTION_TRANSFORMATION_REMOVE_COMMENTS => T(Transformation::new(TK::RemoveComments, s)),
            sym::ACTION_TRANSFORMATION_REPLACE_COMMENTS => T(Transformation::new(TK::ReplaceComments, s)),
            _ => return Err(Flow::Error),
        }))
    }

    /// ```text
    /// setvar_action:
    ///     NOT var
    ///   | var
    ///   | var SETVAR_OPERATION_EQUALS run_time_string
    ///   | var SETVAR_OPERATION_EQUALS_PLUS run_time_string
    ///   | var SETVAR_OPERATION_EQUALS_MINUS run_time_string
    /// ```
    fn setvar_action(rhs: &mut [StackEntry]) -> ParsedAction {
        use crate::actions::set_var::{SetVar, SetVarOperation};
        let (op, var, value) = if rhs[0].kind == sym::NOT {
            (SetVarOperation::UnsetOperation, rhs[1].variable(), None)
        } else if rhs.len() == 1 {
            (SetVarOperation::SetToOneOperation, rhs[0].variable(), None)
        } else {
            let op = match rhs[1].kind {
                sym::SETVAR_OPERATION_EQUALS_PLUS => SetVarOperation::SumAndSetOperation,
                sym::SETVAR_OPERATION_EQUALS_MINUS => SetVarOperation::SubstractAndSetOperation,
                _ => SetVarOperation::SetOperation,
            };
            (op, rhs[0].variable(), Some(rhs[2].run_time_string()))
        };
        let var: Box<dyn Variable> = match var {
            Some(v) => v,
            None => Box::new(xml::XmlNoDictElement::new()),
        };
        ParsedAction::Action(RuleAction::SetVar(SetVar::new(op, var, value)))
    }

    /// ```text
    /// run_time_string:
    ///     run_time_string FREE_TEXT_QUOTE_MACRO_EXPANSION
    ///   | run_time_string var
    ///   | FREE_TEXT_QUOTE_MACRO_EXPANSION
    ///   | var
    /// ```
    fn run_time_string(rhs: &mut [StackEntry]) -> RunTimeString {
        let (mut r, e) = if rhs.len() == 2 {
            let r = rhs[0].run_time_string();
            (r, &mut rhs[1])
        } else {
            (RunTimeString::new(), &mut rhs[0])
        };
        if e.kind == nt::VAR {
            if let Some(v) = e.variable() {
                r.append_var(v);
            }
        } else {
            r.append_bytes(&e.bytes());
        }
        r
    }
}

/// The name of the variable built for a variable token (the C++ class the
/// grammar instantiates).
fn variable_name(kind: u16) -> Option<&'static str> {
    Some(match kind {
        sym::VARIABLE_ARGS => "ARGS",
        sym::VARIABLE_ARGS_POST => "ARGS_POST",
        sym::VARIABLE_ARGS_GET => "ARGS_GET",
        sym::VARIABLE_FILES_SIZES => "FILES_SIZES",
        sym::VARIABLE_FILES_NAMES => "FILES_NAMES",
        sym::VARIABLE_FILES_TMP_CONTENT => "FILES_TMP_CONTENT",
        sym::VARIABLE_MULTIPART_FILENAME => "MULTIPART_FILENAME",
        sym::VARIABLE_MULTIPART_FILENAME_CHARSET => "MULTIPART_FILENAME_CHARSET",
        sym::VARIABLE_MULTIPART_FILENAME_LANGUAGE => "MULTIPART_FILENAME_LANGUAGE",
        sym::VARIABLE_MULTIPART_NAME => "MULTIPART_NAME",
        sym::VARIABLE_MATCHED_VARS_NAMES => "MATCHED_VARS_NAMES",
        sym::VARIABLE_MATCHED_VARS => "MATCHED_VARS",
        sym::VARIABLE_FILES => "FILES",
        sym::VARIABLE_REQUEST_COOKIES => "REQUEST_COOKIES",
        sym::VARIABLE_REQUEST_HEADERS => "REQUEST_HEADERS",
        sym::VARIABLE_RESPONSE_HEADERS => "RESPONSE_HEADERS",
        sym::VARIABLE_GEO => "GEO",
        sym::VARIABLE_REQUEST_COOKIES_NAMES => "REQUEST_COOKIES_NAMES",
        sym::VARIABLE_MULTIPART_PART_HEADERS => "MULTIPART_PART_HEADERS",
        sym::VARIABLE_RULE => "RULE",
        sym::VARIABLE_FILES_TMP_NAMES => "FILES_TMPNAMES",
        sym::VARIABLE_RESOURCE => "RESOURCE",
        sym::VARIABLE_IP => "IP",
        sym::VARIABLE_GLOBAL => "GLOBAL",
        sym::VARIABLE_USER => "USER",
        sym::VARIABLE_TX => "TX",
        sym::VARIABLE_SESSION => "SESSION",
        sym::VARIABLE_ARGS_NAMES => "ARGS_NAMES",
        sym::VARIABLE_ARGS_GET_NAMES => "ARGS_GET_NAMES",
        sym::VARIABLE_ARGS_POST_NAMES => "ARGS_POST_NAMES",
        sym::VARIABLE_REQUEST_HEADERS_NAMES => "REQUEST_HEADERS_NAMES",
        sym::VARIABLE_RESPONSE_CONTENT_TYPE => "RESPONSE_CONTENT_TYPE",
        sym::VARIABLE_RESPONSE_HEADERS_NAMES => "RESPONSE_HEADERS_NAMES",
        sym::VARIABLE_ARGS_COMBINED_SIZE => "ARGS_COMBINED_SIZE",
        sym::VARIABLE_AUTH_TYPE => "AUTH_TYPE",
        sym::VARIABLE_FILES_COMBINED_SIZE => "FILES_COMBINED_SIZE",
        sym::VARIABLE_FULL_REQUEST => "FULL_REQUEST",
        sym::VARIABLE_FULL_REQUEST_LENGTH => "FULL_REQUEST_LENGTH",
        sym::VARIABLE_INBOUND_DATA_ERROR => "INBOUND_DATA_ERROR",
        sym::VARIABLE_MATCHED_VAR => "MATCHED_VAR",
        sym::VARIABLE_MATCHED_VAR_NAME => "MATCHED_VAR_NAME",
        sym::VARIABLE_MSC_PCRE_ERROR => "MSC_PCRE_ERROR",
        sym::VARIABLE_MSC_PCRE_LIMITS_EXCEEDED => "MSC_PCRE_LIMITS_EXCEEDED",
        sym::VARIABLE_MULTIPART_BOUNDARY_QUOTED => "MULTIPART_BOUNDARY_QUOTED",
        sym::VARIABLE_MULTIPART_BOUNDARY_WHITESPACE => "MULTIPART_BOUNDARY_WHITESPACE",
        sym::VARIABLE_MULTIPART_CRLF_LF_LINES => "MULTIPART_CRLF_LF_LINES",
        sym::VARIABLE_MULTIPART_DATA_AFTER => "MULTIPART_DATA_AFTER",
        sym::VARIABLE_MULTIPART_DATA_BEFORE => "MULTIPART_DATA_BEFORE",
        sym::VARIABLE_MULTIPART_DUPLICATE_PART_HEADER => "MULTIPART_DUPLICATE_PART_HEADER",
        sym::VARIABLE_MULTIPART_FILE_LIMIT_EXCEEDED => "MULTIPART_FILE_LIMIT_EXCEEDED",
        sym::VARIABLE_MULTIPART_HEADER_FOLDING => "MULTIPART_HEADER_FOLDING",
        sym::VARIABLE_MULTIPART_INVALID_HEADER_FOLDING => "MULTIPART_INVALID_HEADER_FOLDING",
        sym::VARIABLE_MULTIPART_INVALID_PART => "MULTIPART_INVALID_PART",
        sym::VARIABLE_MULTIPART_INVALID_QUOTING => "MULTIPART_INVALID_QUOTING",
        sym::VARIABLE_MULTIPART_LF_LINE => "MULTIPART_LF_LINE",
        // Both spellings build a `MultipartMissingSemicolon`.
        sym::VARIABLE_MULTIPART_MISSING_SEMICOLON | sym::VARIABLE_MULTIPART_SEMICOLON_MISSING => {
            "MULTIPART_MISSING_SEMICOLON"
        }
        sym::VARIABLE_MULTIPART_STRICT_ERROR => "MULTIPART_STRICT_ERROR",
        sym::VARIABLE_MULTIPART_UNMATCHED_BOUNDARY => "MULTIPART_UNMATCHED_BOUNDARY",
        sym::VARIABLE_OUTBOUND_DATA_ERROR => "OUTBOUND_DATA_ERROR",
        sym::VARIABLE_PATH_INFO => "PATH_INFO",
        sym::VARIABLE_QUERY_STRING => "QUERY_STRING",
        sym::VARIABLE_REMOTE_ADDR => "REMOTE_ADDR",
        sym::VARIABLE_REMOTE_HOST => "REMOTE_HOST",
        sym::VARIABLE_REMOTE_PORT => "REMOTE_PORT",
        sym::VARIABLE_REQBODY_ERROR => "REQBODY_ERROR",
        sym::VARIABLE_REQBODY_ERROR_MSG => "REQBODY_ERROR_MSG",
        sym::VARIABLE_REQBODY_PROCESSOR => "REQBODY_PROCESSOR",
        sym::VARIABLE_REQBODY_PROCESSOR_ERROR => "REQBODY_PROCESSOR_ERROR",
        sym::VARIABLE_REQBODY_PROCESSOR_ERROR_MSG => "REQBODY_PROCESSOR_ERROR_MSG",
        sym::VARIABLE_REQUEST_BASENAME => "REQUEST_BASENAME",
        sym::VARIABLE_REQUEST_BODY => "REQUEST_BODY",
        sym::VARIABLE_REQUEST_BODY_LENGTH => "REQUEST_BODY_LENGTH",
        sym::VARIABLE_REQUEST_FILE_NAME => "REQUEST_FILENAME",
        sym::VARIABLE_REQUEST_LINE => "REQUEST_LINE",
        sym::VARIABLE_REQUEST_METHOD => "REQUEST_METHOD",
        sym::VARIABLE_REQUEST_PROTOCOL => "REQUEST_PROTOCOL",
        sym::VARIABLE_REQUEST_URI => "REQUEST_URI",
        sym::VARIABLE_REQUEST_URI_RAW => "REQUEST_URI_RAW",
        sym::VARIABLE_RESPONSE_BODY => "RESPONSE_BODY",
        sym::VARIABLE_RESPONSE_CONTENT_LENGTH => "RESPONSE_CONTENT_LENGTH",
        sym::VARIABLE_RESPONSE_PROTOCOL => "RESPONSE_PROTOCOL",
        sym::VARIABLE_RESPONSE_STATUS => "RESPONSE_STATUS",
        sym::VARIABLE_SERVER_ADDR => "SERVER_ADDR",
        sym::VARIABLE_SERVER_NAME => "SERVER_NAME",
        sym::VARIABLE_SERVER_PORT => "SERVER_PORT",
        sym::VARIABLE_SESSION_ID => "SESSIONID",
        sym::VARIABLE_UNIQUE_ID => "UNIQUE_ID",
        sym::VARIABLE_URL_ENCODED_ERROR => "URLENCODED_ERROR",
        sym::VARIABLE_USER_ID => "USERID",
        // Both STATUS and STATUS_LINE build a `Status`.
        sym::VARIABLE_STATUS | sym::VARIABLE_STATUS_LINE => "STATUS",
        sym::VARIABLE_WEB_APP_ID => "WEBAPPID",
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Symbols and LALR(1) tables of seclang-parser.yy (computed by bison 3.8.2)
// ---------------------------------------------------------------------------

/// Symbol kinds (bison `symbol_kind::S_*`) of the terminals the scanner
/// returns. (`error`, `"invalid token"`, `NEW_LINE`, `OPERATOR_RX_CONTENT_ONLY`,
/// `CONFIG_DIR_UNICODE_CODE_PAGE`, `VARIABLE` and `DICT_ELEMENT_WITH_EQUALS`
/// are declared by the grammar but never produced.)
pub(crate) mod sym {
    pub const END: u16 = 0;
    pub const COMMA: u16 = 3;
    pub const CONFIG_CONTENT_INJECTION: u16 = 4;
    pub const CONGIG_DIR_RESPONSE_BODY_MP_CLEAR: u16 = 5;
    pub const PIPE: u16 = 6;
    pub const VAR_COUNT: u16 = 8;
    pub const VAR_EXCLUSION: u16 = 9;
    pub const VARIABLE_ARGS: u16 = 10;
    pub const VARIABLE_ARGS_POST: u16 = 11;
    pub const VARIABLE_ARGS_GET: u16 = 12;
    pub const VARIABLE_FILES_SIZES: u16 = 13;
    pub const VARIABLE_FILES_NAMES: u16 = 14;
    pub const VARIABLE_FILES_TMP_CONTENT: u16 = 15;
    pub const VARIABLE_MULTIPART_FILENAME: u16 = 16;
    pub const VARIABLE_MULTIPART_FILENAME_CHARSET: u16 = 17;
    pub const VARIABLE_MULTIPART_FILENAME_LANGUAGE: u16 = 18;
    pub const VARIABLE_MULTIPART_NAME: u16 = 19;
    pub const VARIABLE_MATCHED_VARS_NAMES: u16 = 20;
    pub const VARIABLE_MATCHED_VARS: u16 = 21;
    pub const VARIABLE_FILES: u16 = 22;
    pub const VARIABLE_REQUEST_COOKIES: u16 = 23;
    pub const VARIABLE_REQUEST_HEADERS: u16 = 24;
    pub const VARIABLE_RESPONSE_HEADERS: u16 = 25;
    pub const VARIABLE_GEO: u16 = 26;
    pub const VARIABLE_REQUEST_COOKIES_NAMES: u16 = 27;
    pub const VARIABLE_MULTIPART_PART_HEADERS: u16 = 28;
    pub const VARIABLE_ARGS_COMBINED_SIZE: u16 = 29;
    pub const VARIABLE_ARGS_GET_NAMES: u16 = 30;
    pub const VARIABLE_RULE: u16 = 31;
    pub const VARIABLE_ARGS_NAMES: u16 = 32;
    pub const VARIABLE_ARGS_POST_NAMES: u16 = 33;
    pub const VARIABLE_AUTH_TYPE: u16 = 34;
    pub const VARIABLE_FILES_COMBINED_SIZE: u16 = 35;
    pub const VARIABLE_FILES_TMP_NAMES: u16 = 36;
    pub const VARIABLE_FULL_REQUEST: u16 = 37;
    pub const VARIABLE_FULL_REQUEST_LENGTH: u16 = 38;
    pub const VARIABLE_INBOUND_DATA_ERROR: u16 = 39;
    pub const VARIABLE_MATCHED_VAR: u16 = 40;
    pub const VARIABLE_MATCHED_VAR_NAME: u16 = 41;
    pub const VARIABLE_MSC_PCRE_ERROR: u16 = 42;
    pub const VARIABLE_MSC_PCRE_LIMITS_EXCEEDED: u16 = 43;
    pub const VARIABLE_MULTIPART_BOUNDARY_QUOTED: u16 = 44;
    pub const VARIABLE_MULTIPART_BOUNDARY_WHITESPACE: u16 = 45;
    pub const VARIABLE_MULTIPART_CRLF_LF_LINES: u16 = 46;
    pub const VARIABLE_MULTIPART_DATA_AFTER: u16 = 47;
    pub const VARIABLE_MULTIPART_DATA_BEFORE: u16 = 48;
    pub const VARIABLE_MULTIPART_DUPLICATE_PART_HEADER: u16 = 49;
    pub const VARIABLE_MULTIPART_FILE_LIMIT_EXCEEDED: u16 = 50;
    pub const VARIABLE_MULTIPART_HEADER_FOLDING: u16 = 51;
    pub const VARIABLE_MULTIPART_INVALID_HEADER_FOLDING: u16 = 52;
    pub const VARIABLE_MULTIPART_INVALID_PART: u16 = 53;
    pub const VARIABLE_MULTIPART_INVALID_QUOTING: u16 = 54;
    pub const VARIABLE_MULTIPART_LF_LINE: u16 = 55;
    pub const VARIABLE_MULTIPART_MISSING_SEMICOLON: u16 = 56;
    pub const VARIABLE_MULTIPART_SEMICOLON_MISSING: u16 = 57;
    pub const VARIABLE_MULTIPART_STRICT_ERROR: u16 = 58;
    pub const VARIABLE_MULTIPART_UNMATCHED_BOUNDARY: u16 = 59;
    pub const VARIABLE_OUTBOUND_DATA_ERROR: u16 = 60;
    pub const VARIABLE_PATH_INFO: u16 = 61;
    pub const VARIABLE_QUERY_STRING: u16 = 62;
    pub const VARIABLE_REMOTE_ADDR: u16 = 63;
    pub const VARIABLE_REMOTE_HOST: u16 = 64;
    pub const VARIABLE_REMOTE_PORT: u16 = 65;
    pub const VARIABLE_REQBODY_ERROR_MSG: u16 = 66;
    pub const VARIABLE_REQBODY_ERROR: u16 = 67;
    pub const VARIABLE_REQBODY_PROCESSOR_ERROR_MSG: u16 = 68;
    pub const VARIABLE_REQBODY_PROCESSOR_ERROR: u16 = 69;
    pub const VARIABLE_REQBODY_PROCESSOR: u16 = 70;
    pub const VARIABLE_REQUEST_BASENAME: u16 = 71;
    pub const VARIABLE_REQUEST_BODY_LENGTH: u16 = 72;
    pub const VARIABLE_REQUEST_BODY: u16 = 73;
    pub const VARIABLE_REQUEST_FILE_NAME: u16 = 74;
    pub const VARIABLE_REQUEST_HEADERS_NAMES: u16 = 75;
    pub const VARIABLE_REQUEST_LINE: u16 = 76;
    pub const VARIABLE_REQUEST_METHOD: u16 = 77;
    pub const VARIABLE_REQUEST_PROTOCOL: u16 = 78;
    pub const VARIABLE_REQUEST_URI_RAW: u16 = 79;
    pub const VARIABLE_REQUEST_URI: u16 = 80;
    pub const VARIABLE_RESOURCE: u16 = 81;
    pub const VARIABLE_RESPONSE_BODY: u16 = 82;
    pub const VARIABLE_RESPONSE_CONTENT_LENGTH: u16 = 83;
    pub const VARIABLE_RESPONSE_CONTENT_TYPE: u16 = 84;
    pub const VARIABLE_RESPONSE_HEADERS_NAMES: u16 = 85;
    pub const VARIABLE_RESPONSE_PROTOCOL: u16 = 86;
    pub const VARIABLE_RESPONSE_STATUS: u16 = 87;
    pub const VARIABLE_SERVER_ADDR: u16 = 88;
    pub const VARIABLE_SERVER_NAME: u16 = 89;
    pub const VARIABLE_SERVER_PORT: u16 = 90;
    pub const VARIABLE_SESSION_ID: u16 = 91;
    pub const VARIABLE_UNIQUE_ID: u16 = 92;
    pub const VARIABLE_URL_ENCODED_ERROR: u16 = 93;
    pub const VARIABLE_USER_ID: u16 = 94;
    pub const VARIABLE_WEB_APP_ID: u16 = 95;
    pub const VARIABLE_STATUS: u16 = 96;
    pub const VARIABLE_STATUS_LINE: u16 = 97;
    pub const VARIABLE_IP: u16 = 98;
    pub const VARIABLE_GLOBAL: u16 = 99;
    pub const VARIABLE_TX: u16 = 100;
    pub const VARIABLE_SESSION: u16 = 101;
    pub const VARIABLE_USER: u16 = 102;
    pub const RUN_TIME_VAR_ENV: u16 = 103;
    pub const RUN_TIME_VAR_XML: u16 = 104;
    pub const ACTION_SETVAR: u16 = 105;
    pub const SETVAR_OPERATION_EQUALS: u16 = 106;
    pub const SETVAR_OPERATION_EQUALS_PLUS: u16 = 107;
    pub const SETVAR_OPERATION_EQUALS_MINUS: u16 = 108;
    pub const NOT: u16 = 109;
    pub const OPERATOR_BEGINS_WITH: u16 = 110;
    pub const OPERATOR_CONTAINS: u16 = 111;
    pub const OPERATOR_CONTAINS_WORD: u16 = 112;
    pub const OPERATOR_DETECT_SQLI: u16 = 113;
    pub const OPERATOR_DETECT_XSS: u16 = 114;
    pub const OPERATOR_ENDS_WITH: u16 = 115;
    pub const OPERATOR_EQ: u16 = 116;
    pub const OPERATOR_FUZZY_HASH: u16 = 117;
    pub const OPERATOR_GEOLOOKUP: u16 = 118;
    pub const OPERATOR_GE: u16 = 119;
    pub const OPERATOR_GSB_LOOKUP: u16 = 120;
    pub const OPERATOR_GT: u16 = 121;
    pub const OPERATOR_INSPECT_FILE: u16 = 122;
    pub const OPERATOR_IP_MATCH_FROM_FILE: u16 = 123;
    pub const OPERATOR_IP_MATCH: u16 = 124;
    pub const OPERATOR_LE: u16 = 125;
    pub const OPERATOR_LT: u16 = 126;
    pub const OPERATOR_PM_FROM_FILE: u16 = 127;
    pub const OPERATOR_PM: u16 = 128;
    pub const OPERATOR_RBL: u16 = 129;
    pub const OPERATOR_RSUB: u16 = 130;
    pub const OPERATOR_RX: u16 = 132;
    pub const OPERATOR_RX_GLOBAL: u16 = 133;
    pub const OPERATOR_STR_EQ: u16 = 134;
    pub const OPERATOR_STR_MATCH: u16 = 135;
    pub const OPERATOR_UNCONDITIONAL_MATCH: u16 = 136;
    pub const OPERATOR_VALIDATE_BYTE_RANGE: u16 = 137;
    pub const OPERATOR_VALIDATE_DTD: u16 = 138;
    pub const OPERATOR_VALIDATE_HASH: u16 = 139;
    pub const OPERATOR_VALIDATE_SCHEMA: u16 = 140;
    pub const OPERATOR_VALIDATE_URL_ENCODING: u16 = 141;
    pub const OPERATOR_VALIDATE_UTF8_ENCODING: u16 = 142;
    pub const OPERATOR_VERIFY_CC: u16 = 143;
    pub const OPERATOR_VERIFY_CPF: u16 = 144;
    pub const OPERATOR_VERIFY_SSN: u16 = 145;
    pub const OPERATOR_VERIFY_SVNR: u16 = 146;
    pub const OPERATOR_WITHIN: u16 = 147;
    pub const CONFIG_DIR_AUDIT_LOG_FMT: u16 = 148;
    pub const JSON: u16 = 149;
    pub const NATIVE: u16 = 150;
    pub const ACTION_CTL_RULE_ENGINE: u16 = 151;
    pub const ACTION_ACCURACY: u16 = 152;
    pub const ACTION_ALLOW: u16 = 153;
    pub const ACTION_APPEND: u16 = 154;
    pub const ACTION_AUDIT_LOG: u16 = 155;
    pub const ACTION_BLOCK: u16 = 156;
    pub const ACTION_CAPTURE: u16 = 157;
    pub const ACTION_CHAIN: u16 = 158;
    pub const ACTION_CTL_AUDIT_ENGINE: u16 = 159;
    pub const ACTION_CTL_AUDIT_LOG_PARTS: u16 = 160;
    pub const ACTION_CTL_BDY_JSON: u16 = 161;
    pub const ACTION_CTL_BDY_XML: u16 = 162;
    pub const ACTION_CTL_BDY_URLENCODED: u16 = 163;
    pub const ACTION_CTL_FORCE_REQ_BODY_VAR: u16 = 164;
    pub const ACTION_CTL_PARSE_XML_INTO_ARGS: u16 = 165;
    pub const ACTION_CTL_REQUEST_BODY_ACCESS: u16 = 166;
    pub const ACTION_CTL_RULE_REMOVE_BY_ID: u16 = 167;
    pub const ACTION_CTL_RULE_REMOVE_BY_TAG: u16 = 168;
    pub const ACTION_CTL_RULE_REMOVE_TARGET_BY_ID: u16 = 169;
    pub const ACTION_CTL_RULE_REMOVE_TARGET_BY_TAG: u16 = 170;
    pub const ACTION_DENY: u16 = 171;
    pub const ACTION_DEPRECATE_VAR: u16 = 172;
    pub const ACTION_DROP: u16 = 173;
    pub const ACTION_EXEC: u16 = 174;
    pub const ACTION_EXPIRE_VAR: u16 = 175;
    pub const ACTION_ID: u16 = 176;
    pub const ACTION_INITCOL: u16 = 177;
    pub const ACTION_LOG: u16 = 178;
    pub const ACTION_LOG_DATA: u16 = 179;
    pub const ACTION_MATURITY: u16 = 180;
    pub const ACTION_MSG: u16 = 181;
    pub const ACTION_MULTI_MATCH: u16 = 182;
    pub const ACTION_NO_AUDIT_LOG: u16 = 183;
    pub const ACTION_NO_LOG: u16 = 184;
    pub const ACTION_PASS: u16 = 185;
    pub const ACTION_PAUSE: u16 = 186;
    pub const ACTION_PHASE: u16 = 187;
    pub const ACTION_PREPEND: u16 = 188;
    pub const ACTION_PROXY: u16 = 189;
    pub const ACTION_REDIRECT: u16 = 190;
    pub const ACTION_REV: u16 = 191;
    pub const ACTION_SANITISE_ARG: u16 = 192;
    pub const ACTION_SANITISE_MATCHED: u16 = 193;
    pub const ACTION_SANITISE_MATCHED_BYTES: u16 = 194;
    pub const ACTION_SANITISE_REQUEST_HEADER: u16 = 195;
    pub const ACTION_SANITISE_RESPONSE_HEADER: u16 = 196;
    pub const ACTION_SETENV: u16 = 197;
    pub const ACTION_SETRSC: u16 = 198;
    pub const ACTION_SETSID: u16 = 199;
    pub const ACTION_SETUID: u16 = 200;
    pub const ACTION_SEVERITY: u16 = 201;
    pub const ACTION_SKIP: u16 = 202;
    pub const ACTION_SKIP_AFTER: u16 = 203;
    pub const ACTION_STATUS: u16 = 204;
    pub const ACTION_TAG: u16 = 205;
    pub const ACTION_TRANSFORMATION_BASE_64_ENCODE: u16 = 206;
    pub const ACTION_TRANSFORMATION_BASE_64_DECODE: u16 = 207;
    pub const ACTION_TRANSFORMATION_BASE_64_DECODE_EXT: u16 = 208;
    pub const ACTION_TRANSFORMATION_CMD_LINE: u16 = 209;
    pub const ACTION_TRANSFORMATION_COMPRESS_WHITESPACE: u16 = 210;
    pub const ACTION_TRANSFORMATION_CSS_DECODE: u16 = 211;
    pub const ACTION_TRANSFORMATION_ESCAPE_SEQ_DECODE: u16 = 212;
    pub const ACTION_TRANSFORMATION_HEX_ENCODE: u16 = 213;
    pub const ACTION_TRANSFORMATION_HEX_DECODE: u16 = 214;
    pub const ACTION_TRANSFORMATION_HTML_ENTITY_DECODE: u16 = 215;
    pub const ACTION_TRANSFORMATION_JS_DECODE: u16 = 216;
    pub const ACTION_TRANSFORMATION_LENGTH: u16 = 217;
    pub const ACTION_TRANSFORMATION_LOWERCASE: u16 = 218;
    pub const ACTION_TRANSFORMATION_MD5: u16 = 219;
    pub const ACTION_TRANSFORMATION_NONE: u16 = 220;
    pub const ACTION_TRANSFORMATION_NORMALISE_PATH: u16 = 221;
    pub const ACTION_TRANSFORMATION_NORMALISE_PATH_WIN: u16 = 222;
    pub const ACTION_TRANSFORMATION_PARITY_EVEN_7_BIT: u16 = 223;
    pub const ACTION_TRANSFORMATION_PARITY_ODD_7_BIT: u16 = 224;
    pub const ACTION_TRANSFORMATION_PARITY_ZERO_7_BIT: u16 = 225;
    pub const ACTION_TRANSFORMATION_REMOVE_COMMENTS: u16 = 226;
    pub const ACTION_TRANSFORMATION_REMOVE_COMMENTS_CHAR: u16 = 227;
    pub const ACTION_TRANSFORMATION_REMOVE_NULLS: u16 = 228;
    pub const ACTION_TRANSFORMATION_REMOVE_WHITESPACE: u16 = 229;
    pub const ACTION_TRANSFORMATION_REPLACE_COMMENTS: u16 = 230;
    pub const ACTION_TRANSFORMATION_REPLACE_NULLS: u16 = 231;
    pub const ACTION_TRANSFORMATION_SHA1: u16 = 232;
    pub const ACTION_TRANSFORMATION_SQL_HEX_DECODE: u16 = 233;
    pub const ACTION_TRANSFORMATION_TRIM: u16 = 234;
    pub const ACTION_TRANSFORMATION_TRIM_LEFT: u16 = 235;
    pub const ACTION_TRANSFORMATION_TRIM_RIGHT: u16 = 236;
    pub const ACTION_TRANSFORMATION_UPPERCASE: u16 = 237;
    pub const ACTION_TRANSFORMATION_URL_ENCODE: u16 = 238;
    pub const ACTION_TRANSFORMATION_URL_DECODE: u16 = 239;
    pub const ACTION_TRANSFORMATION_URL_DECODE_UNI: u16 = 240;
    pub const ACTION_TRANSFORMATION_UTF8_TO_UNICODE: u16 = 241;
    pub const ACTION_VER: u16 = 242;
    pub const ACTION_XMLNS: u16 = 243;
    pub const CONFIG_COMPONENT_SIG: u16 = 244;
    pub const CONFIG_CONN_ENGINE: u16 = 245;
    pub const CONFIG_SEC_ARGUMENT_SEPARATOR: u16 = 246;
    pub const CONFIG_SEC_WEB_APP_ID: u16 = 247;
    pub const CONFIG_SEC_SERVER_SIG: u16 = 248;
    pub const CONFIG_DIR_AUDIT_DIR: u16 = 249;
    pub const CONFIG_DIR_AUDIT_DIR_MOD: u16 = 250;
    pub const CONFIG_DIR_AUDIT_ENG: u16 = 251;
    pub const CONFIG_DIR_AUDIT_FLE_MOD: u16 = 252;
    pub const CONFIG_DIR_AUDIT_LOG: u16 = 253;
    pub const CONFIG_DIR_AUDIT_LOG2: u16 = 254;
    pub const CONFIG_DIR_AUDIT_LOG_P: u16 = 255;
    pub const CONFIG_DIR_AUDIT_STS: u16 = 256;
    pub const CONFIG_DIR_AUDIT_PREFIX: u16 = 257;
    pub const CONFIG_DIR_AUDIT_TPE: u16 = 258;
    pub const CONFIG_DIR_DEBUG_LOG: u16 = 259;
    pub const CONFIG_DIR_DEBUG_LVL: u16 = 260;
    pub const CONFIG_SEC_CACHE_TRANSFORMATIONS: u16 = 261;
    pub const CONFIG_SEC_DISABLE_BACKEND_COMPRESS: u16 = 262;
    pub const CONFIG_SEC_HASH_ENGINE: u16 = 263;
    pub const CONFIG_SEC_HASH_KEY: u16 = 264;
    pub const CONFIG_SEC_HASH_PARAM: u16 = 265;
    pub const CONFIG_SEC_HASH_METHOD_RX: u16 = 266;
    pub const CONFIG_SEC_HASH_METHOD_PM: u16 = 267;
    pub const CONFIG_SEC_CHROOT_DIR: u16 = 268;
    pub const CONFIG_DIR_GEO_DB: u16 = 269;
    pub const CONFIG_DIR_GSB_DB: u16 = 270;
    pub const CONFIG_SEC_GUARDIAN_LOG: u16 = 271;
    pub const CONFIG_DIR_PCRE_MATCH_LIMIT: u16 = 272;
    pub const CONFIG_DIR_PCRE_MATCH_LIMIT_RECURSION: u16 = 273;
    pub const CONFIG_SEC_CONN_R_STATE_LIMIT: u16 = 274;
    pub const CONFIG_SEC_CONN_W_STATE_LIMIT: u16 = 275;
    pub const CONFIG_SEC_SENSOR_ID: u16 = 276;
    pub const CONFIG_DIR_ARGS_LIMIT: u16 = 277;
    pub const CONFIG_DIR_REQ_BODY_JSON_DEPTH_LIMIT: u16 = 278;
    pub const CONFIG_DIR_REQ_BODY: u16 = 279;
    pub const CONFIG_DIR_REQ_BODY_IN_MEMORY_LIMIT: u16 = 280;
    pub const CONFIG_DIR_REQ_BODY_LIMIT: u16 = 281;
    pub const CONFIG_DIR_REQ_BODY_LIMIT_ACTION: u16 = 282;
    pub const CONFIG_DIR_REQ_BODY_NO_FILES_LIMIT: u16 = 283;
    pub const CONFIG_DIR_RES_BODY: u16 = 284;
    pub const CONFIG_DIR_RES_BODY_LIMIT: u16 = 285;
    pub const CONFIG_DIR_RES_BODY_LIMIT_ACTION: u16 = 286;
    pub const CONFIG_SEC_RULE_INHERITANCE: u16 = 287;
    pub const CONFIG_SEC_RULE_PERF_TIME: u16 = 288;
    pub const CONFIG_DIR_RULE_ENG: u16 = 289;
    pub const CONFIG_DIR_SEC_ACTION: u16 = 290;
    pub const CONFIG_DIR_SEC_DEFAULT_ACTION: u16 = 291;
    pub const CONFIG_DIR_SEC_MARKER: u16 = 292;
    pub const CONFIG_DIR_UNICODE_MAP_FILE: u16 = 293;
    pub const CONFIG_SEC_COLLECTION_TIMEOUT: u16 = 295;
    pub const CONFIG_SEC_HTTP_BLKEY: u16 = 296;
    pub const CONFIG_SEC_INTERCEPT_ON_ERROR: u16 = 297;
    pub const CONFIG_SEC_REMOTE_RULES_FAIL_ACTION: u16 = 298;
    pub const CONFIG_SEC_RULE_REMOVE_BY_ID: u16 = 299;
    pub const CONFIG_SEC_RULE_REMOVE_BY_MSG: u16 = 300;
    pub const CONFIG_SEC_RULE_REMOVE_BY_TAG: u16 = 301;
    pub const CONFIG_SEC_RULE_UPDATE_TARGET_BY_TAG: u16 = 302;
    pub const CONFIG_SEC_RULE_UPDATE_TARGET_BY_MSG: u16 = 303;
    pub const CONFIG_SEC_RULE_UPDATE_TARGET_BY_ID: u16 = 304;
    pub const CONFIG_SEC_RULE_UPDATE_ACTION_BY_ID: u16 = 305;
    pub const CONFIG_UPDLOAD_KEEP_FILES: u16 = 306;
    pub const CONFIG_UPDLOAD_SAVE_TMP_FILES: u16 = 307;
    pub const CONFIG_UPLOAD_DIR: u16 = 308;
    pub const CONFIG_UPLOAD_FILE_LIMIT: u16 = 309;
    pub const CONFIG_UPLOAD_FILE_MODE: u16 = 310;
    pub const CONFIG_VALUE_ABORT: u16 = 311;
    pub const CONFIG_VALUE_DETC: u16 = 312;
    pub const CONFIG_VALUE_HTTPS: u16 = 313;
    pub const CONFIG_VALUE_ONLYARGS: u16 = 314;
    pub const CONFIG_VALUE_OFF: u16 = 315;
    pub const CONFIG_VALUE_ON: u16 = 316;
    pub const CONFIG_VALUE_PARALLEL: u16 = 317;
    pub const CONFIG_VALUE_PROCESS_PARTIAL: u16 = 318;
    pub const CONFIG_VALUE_REJECT: u16 = 319;
    pub const CONFIG_VALUE_RELEVANT_ONLY: u16 = 320;
    pub const CONFIG_VALUE_SERIAL: u16 = 321;
    pub const CONFIG_VALUE_WARN: u16 = 322;
    pub const CONFIG_XML_EXTERNAL_ENTITY: u16 = 323;
    pub const CONFIG_XML_PARSE_XML_INTO_ARGS: u16 = 324;
    pub const CONGIG_DIR_RESPONSE_BODY_MP: u16 = 325;
    pub const CONGIG_DIR_SEC_ARG_SEP: u16 = 326;
    pub const CONGIG_DIR_SEC_COOKIE_FORMAT: u16 = 327;
    pub const CONFIG_SEC_COOKIEV0_SEPARATOR: u16 = 328;
    pub const CONGIG_DIR_SEC_DATA_DIR: u16 = 329;
    pub const CONGIG_DIR_SEC_STATUS_ENGINE: u16 = 330;
    pub const CONFIG_SEC_STREAM_IN_BODY_INSPECTION: u16 = 331;
    pub const CONFIG_SEC_STREAM_OUT_BODY_INSPECTION: u16 = 332;
    pub const CONGIG_DIR_SEC_TMP_DIR: u16 = 333;
    pub const DIRECTIVE: u16 = 334;
    pub const DIRECTIVE_SECRULESCRIPT: u16 = 335;
    pub const FREE_TEXT_QUOTE_MACRO_EXPANSION: u16 = 336;
    pub const QUOTATION_MARK: u16 = 337;
    pub const RUN_TIME_VAR_BLD: u16 = 338;
    pub const RUN_TIME_VAR_DUR: u16 = 339;
    pub const RUN_TIME_VAR_HSV: u16 = 340;
    pub const RUN_TIME_VAR_REMOTE_USER: u16 = 341;
    pub const RUN_TIME_VAR_TIME: u16 = 342;
    pub const RUN_TIME_VAR_TIME_DAY: u16 = 343;
    pub const RUN_TIME_VAR_TIME_EPOCH: u16 = 344;
    pub const RUN_TIME_VAR_TIME_HOUR: u16 = 345;
    pub const RUN_TIME_VAR_TIME_MIN: u16 = 346;
    pub const RUN_TIME_VAR_TIME_MON: u16 = 347;
    pub const RUN_TIME_VAR_TIME_SEC: u16 = 348;
    pub const RUN_TIME_VAR_TIME_WDAY: u16 = 349;
    pub const RUN_TIME_VAR_TIME_YEAR: u16 = 350;
    pub const DICT_ELEMENT: u16 = 352;
    pub const DICT_ELEMENT_REGEXP: u16 = 354;
}
#[rustfmt::skip]
const YYPACT: [i16; 552] = [
    2874, -424, -294, -424, 71, -424, -93, -424, -424, -424, -424, -424, -282, -424, -424, -424,
    -424, -424, -424, -285, -424, -424, -424, -91, -89, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -87, -424, -424, -88, -424, -83, -424, -84,
    -79, -424, -267, -95, -95, -424, -424, -424, -424, -77, -293, -424, -424, -424, 1550, 1550,
    1550, -95, -276, -75, -424, -424, -424, -72, -302, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, 1550, -95, 3020, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, -424, -424, 2426, -265, -424, -424, -424, -424, -424, -424, -424, -274, -424,
    -424, -424, -424, -70, -262, -68, -424, -424, -424, -424, -424, -424, -424, -424, 2564, -424,
    2564, -424, 2564, -424, 2564, -424, -424, -424, -424, -424, -424, -424, -424, 2564, -424, -424,
    -424, -424, -424, -424, 2564, 2564, 2564, 2564, -424, -424, -424, -424, 2564, -424, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, 3209, -424, 3, -424, -424, -424, -424, -424, -424, 2767, 2767, -199, -198,
    -192, -191, -188, -187, -178, -177, -174, -173, -170, -169, -166, -165, -162, -161, -158, -157,
    -154, -424, -153, -150, -149, -145, -424, -424, -144, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -140,
    -424, -424, -424, -424, -424, 478, -424, -424, -424, -139, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, -424, -424, -424, 573, 668, 1013, 1108, 1203, -136, -135, 1647, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, 9, -424, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, 2085, -424, -424, -424, -424,
    2767, 43, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 8, 3209, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424, -424,
    -424, -424, -424, -424, 2659, -424, -424, -424, -424, 2659, -424, -424, 2659, -424, -424, 2659,
    -424, -424, 2659, -424, -424, 2659, -424, -424, -424, -424, 13, 1744, 2223, 2564, 2564, 2564,
    -424, -424, 2564, 2564, 2564, -424, 2564, 2564, 2564, 2564, 2564, 2564, 2564, 2564, 2564, 2564,
    2564, 2564, 2564, 2564, 2564, 2564, -424, 2564, 2564, 2564, 2564, -424, -424, 2564, 2564, 2564,
    2564, 2564, -95, -424, 2659, -424, 2564, 2564, 2564, -424, -424, -424, -424, -424, 2767, 2767,
    -424, -424, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659,
    2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659, 2659,
    2659, 2659, -424, 2659, 2659, 2659, -424, -424,
];
#[rustfmt::skip]
const YYDEFACT: [i16; 552] = [
    0, 2, 0, 144, 0, 90, 0, 89, 93, 94, 7, 6, 0, 11, 14, 12,
    13, 17, 18, 0, 127, 126, 95, 0, 0, 103, 104, 105, 106, 100, 128, 107,
    108, 142, 141, 111, 112, 113, 129, 130, 0, 133, 131, 0, 132, 0, 134, 0,
    0, 116, 0, 0, 0, 81, 156, 157, 158, 0, 0, 119, 121, 120, 0, 0,
    0, 0, 0, 0, 27, 25, 26, 0, 0, 143, 152, 153, 154, 151, 155, 117,
    118, 150, 0, 0, 0, 4, 75, 5, 99, 98, 15, 16, 92, 91, 9, 10,
    8, 21, 20, 19, 97, 96, 102, 101, 86, 85, 135, 136, 88, 87, 137, 138,
    115, 114, 84, 82, 83, 0, 0, 350, 351, 352, 353, 354, 355, 356, 0, 360,
    361, 362, 363, 0, 0, 0, 374, 375, 376, 377, 378, 379, 380, 381, 0, 383,
    0, 386, 0, 387, 0, 389, 390, 391, 392, 393, 394, 395, 396, 0, 398, 399,
    400, 401, 402, 403, 0, 0, 0, 0, 409, 410, 411, 412, 0, 420, 421, 422,
    423, 435, 441, 426, 427, 428, 439, 440, 447, 429, 425, 434, 446, 445, 418, 417,
    416, 450, 449, 438, 436, 451, 437, 424, 419, 442, 443, 444, 430, 433, 432, 431,
    448, 414, 415, 0, 78, 31, 33, 80, 110, 109, 139, 140, 0, 0, 170, 173,
    176, 179, 182, 185, 188, 191, 194, 197, 200, 203, 206, 209, 212, 215, 218, 221,
    224, 277, 266, 227, 263, 269, 278, 279, 236, 280, 281, 282, 283, 284, 285, 286,
    287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302,
    303, 304, 305, 306, 307, 308, 310, 309, 313, 312, 311, 314, 316, 315, 317, 272,
    318, 319, 320, 322, 321, 240, 323, 324, 273, 276, 325, 326, 327, 328, 329, 330,
    331, 332, 333, 336, 334, 335, 244, 248, 256, 260, 252, 230, 233, 0, 338, 337,
    339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 122, 160, 165, 123, 124,
    125, 23, 22, 24, 29, 28, 145, 146, 147, 148, 149, 0, 159, 79, 1, 3,
    0, 453, 408, 373, 372, 371, 358, 357, 359, 365, 364, 368, 367, 366, 370, 369,
    459, 460, 382, 384, 385, 388, 397, 404, 405, 406, 407, 413, 0, 0, 167, 166,
    168, 169, 171, 172, 174, 175, 177, 178, 180, 181, 183, 184, 186, 187, 189, 190,
    192, 193, 195, 196, 198, 199, 201, 202, 204, 205, 207, 208, 210, 211, 213, 214,
    216, 217, 219, 220, 222, 223, 264, 265, 225, 226, 261, 262, 267, 268, 234, 235,
    270, 271, 238, 239, 237, 274, 275, 242, 243, 241, 246, 247, 245, 254, 255, 253,
    258, 259, 257, 250, 251, 249, 228, 229, 231, 232, 0, 0, 0, 0, 0, 0,
    39, 40, 0, 0, 0, 74, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 38, 0, 0, 0, 0, 41, 42, 0, 0, 0,
    0, 0, 77, 34, 36, 452, 0, 0, 0, 457, 458, 30, 32, 161, 0, 0,
    162, 35, 37, 73, 57, 56, 58, 59, 44, 60, 53, 61, 43, 62, 63, 64,
    65, 66, 67, 68, 54, 69, 70, 71, 72, 45, 46, 47, 48, 49, 50, 51,
    52, 55, 76, 454, 455, 456, 164, 163,
];
#[rustfmt::skip]
const YYPGOTO: [i16; 16] = [
    -424, -424, -54, -424, -48, -168, -424, -423, -424, -424, -55, -160, -62, -213, -424, -141,
];
#[rustfmt::skip]
const YYDEFGOTO: [i16; 16] = [
    0, 84, 85, 86, 212, 213, 498, 499, 87, 347, 331, 332, 369, 214, 354, 370,
];
#[rustfmt::skip]
const YYTABLE: [i16; 3453] = [
    333, 333, 333, 371, 215, 372, 381, 373, 334, 335, 117, 381, 344, 345, 346, 459,
    374, 336, 218, 459, 333, 88, 89, 375, 376, 377, 378, 348, 97, 219, 351, 379,
    98, 94, 95, 349, 99, 513, 96, 337, 338, 358, 359, 380, 339, 114, 360, 355,
    115, 116, 356, 357, 363, 364, 365, 353, 118, 119, 120, 121, 122, 123, 124, 125,
    126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141,
    142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157,
    158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173,
    174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189,
    190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205,
    206, 207, 208, 209, 210, 502, 503, 504, 436, 384, 386, 385, 387, 458, 382, 383,
    388, 390, 389, 391, 392, 394, 393, 395, 508, 441, 444, 447, 450, 453, 396, 398,
    397, 399, 400, 402, 401, 403, 404, 406, 405, 407, 408, 410, 409, 411, 412, 414,
    413, 415, 416, 418, 417, 419, 420, 422, 421, 423, 424, 426, 425, 427, 500, 428,
    430, 429, 431, 0, 432, 437, 433, 438, 454, 456, 455, 457, 90, 91, 92, 93,
    100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 216, 217,
    340, 341, 211, 342, 343, 361, 362, 366, 367, 0, 0, 0, 0, 0, 0, 333,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 501, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 506, 506, 506, 506, 506, 506, 506, 506, 506, 506, 0, 514,
    515, 516, 517, 0, 0, 518, 519, 520, 0, 521, 522, 523, 524, 525, 526, 527,
    528, 529, 530, 531, 532, 533, 534, 535, 536, 507, 537, 538, 539, 540, 509, 0,
    541, 542, 543, 544, 545, 0, 0, 0, 0, 547, 548, 549, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 506, 0, 0, 0, 0, 506, 0, 0, 506, 0,
    0, 506, 0, 0, 506, 0, 0, 506, 0, 0, 0, 0, 0, 512, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 506, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    550, 551, 546, 0, 506, 506, 506, 506, 506, 506, 506, 506, 506, 506, 506, 506,
    506, 506, 506, 506, 506, 506, 506, 506, 506, 506, 506, 506, 506, 506, 506, 506,
    506, 506, 506, 506, 0, 506, 506, 506, 222, 223, 224, 225, 226, 227, 228, 229,
    230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245,
    246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261,
    262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277,
    278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293,
    294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309,
    310, 311, 312, 313, 314, 315, 316, 222, 223, 224, 225, 226, 227, 228, 229, 230,
    231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246,
    247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262,
    263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278,
    279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294,
    295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310,
    311, 312, 313, 314, 315, 316, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231,
    232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247,
    248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263,
    264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279,
    280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295,
    296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311,
    312, 313, 314, 315, 316, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 368, 0,
    318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 0, 434, 0,
    435, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 368, 0, 318,
    319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 0, 439, 0, 440,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 368, 0, 318, 319,
    320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 0, 442, 0, 443, 222,
    223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
    239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
    255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270,
    271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286,
    287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302,
    303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 222, 223,
    224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
    256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271,
    272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287,
    288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303,
    304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
    241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256,
    257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272,
    273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288,
    289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304,
    305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 368, 0, 318, 319, 320, 321, 322, 323, 324, 325, 326,
    327, 328, 329, 330, 0, 445, 0, 446, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 368, 0, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327,
    328, 329, 330, 0, 448, 0, 449, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 368, 0, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328,
    329, 330, 0, 451, 0, 452, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229,
    230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245,
    246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261,
    262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277,
    278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293,
    294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309,
    310, 311, 312, 313, 314, 315, 316, 220, 221, 222, 223, 224, 225, 226, 227, 228,
    229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
    245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260,
    261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276,
    277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292,
    293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308,
    309, 310, 311, 312, 313, 314, 315, 316, 510, 511, 222, 223, 224, 225, 226, 227,
    228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243,
    244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259,
    260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275,
    276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291,
    292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307,
    308, 309, 310, 311, 312, 313, 314, 315, 316, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 317,
    318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 222,
    223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
    239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254,
    255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270,
    271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286,
    287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302,
    303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 0, 0,
    0, 0, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473,
    474, 475, 476, 477, 478, 479, 480, 481, 0, 482, 483, 484, 485, 486, 487, 488,
    489, 490, 491, 492, 493, 494, 495, 496, 497, 222, 223, 224, 225, 226, 227, 228,
    229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
    245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260,
    261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276,
    277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292,
    293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308,
    309, 310, 311, 312, 313, 314, 315, 316, 0, 0, 0, 0, 0, 461, 462, 463,
    464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479,
    480, 481, 0, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494,
    495, 496, 497, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 368, 0, 318, 319, 320, 321, 322, 323, 324, 325, 326,
    327, 328, 329, 330, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
    234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
    250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265,
    266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281,
    282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297,
    298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313,
    314, 315, 316, 0, 0, 0, 0, 352, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 368,
    0, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 222, 223,
    224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255,
    256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271,
    272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287,
    288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303,
    304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 222, 223, 224,
    225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
    241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256,
    257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272,
    273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288,
    289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304,
    305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 318, 319, 320, 321,
    322, 323, 324, 325, 326, 327, 328, 329, 330, 222, 223, 224, 225, 226, 227, 228,
    229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244,
    245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260,
    261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276,
    277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292,
    293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308,
    309, 310, 311, 312, 313, 314, 315, 316, 0, 0, 1, 0, 0, 0, 2, 3,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 368, 0, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327,
    328, 329, 330, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 505, 0, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328,
    329, 330, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 350, 0, 4, 0,
    2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 5, 6,
    7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
    4, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
    70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71, 72, 73,
    74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
    37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
    53, 54, 117, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
    68, 69, 70, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 71,
    72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 0, 0, 0, 0,
    118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133,
    134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
    150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165,
    166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181,
    182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197,
    198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
];
#[rustfmt::skip]
const YYCHECK: [i16; 3453] = [
    62, 63, 64, 144, 52, 146, 3, 148, 63, 64, 105, 3, 314, 315, 316, 6,
    157, 65, 311, 6, 82, 315, 316, 164, 165, 166, 167, 82, 313, 322, 84, 172,
    317, 315, 316, 83, 321, 460, 320, 315, 316, 315, 316, 211, 320, 312, 320, 312,
    315, 316, 315, 316, 314, 315, 316, 117, 151, 152, 153, 154, 155, 156, 157, 158,
    159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174,
    175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190,
    191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206,
    207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222,
    223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
    239, 240, 241, 242, 243, 106, 107, 108, 293, 352, 352, 354, 354, 317, 220, 221,
    352, 352, 354, 354, 352, 352, 354, 354, 381, 310, 311, 312, 313, 314, 352, 352,
    354, 354, 352, 352, 354, 354, 352, 352, 354, 354, 352, 352, 354, 354, 352, 352,
    354, 354, 352, 352, 354, 354, 352, 352, 354, 354, 352, 352, 354, 354, 347, 352,
    352, 354, 354, -1, 352, 352, 354, 354, 352, 352, 354, 354, 149, 150, 315, 316,
    315, 316, 315, 316, 315, 316, 318, 319, 315, 316, 318, 319, 315, 316, 315, 316,
    315, 316, 337, 315, 316, 315, 316, 315, 316, -1, -1, -1, -1, -1, -1, 317,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, 352, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, -1, 460,
    461, 462, 463, -1, -1, 466, 467, 468, -1, 470, 471, 472, 473, 474, 475, 476,
    477, 478, 479, 480, 481, 482, 483, 484, 485, 337, 487, 488, 489, 490, 337, -1,
    493, 494, 495, 496, 497, -1, -1, -1, -1, 502, 503, 504, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, 436, -1, -1, -1, -1, 441, -1, -1, 444, -1,
    -1, 447, -1, -1, 450, -1, -1, 453, -1, -1, -1, -1, -1, 459, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, 500, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    510, 511, 498, -1, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525,
    526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 541,
    542, 543, 544, 545, -1, 547, 548, 549, 10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
    34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
    66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
    82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97,
    98, 99, 100, 101, 102, 103, 104, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,
    67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82,
    83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98,
    99, 100, 101, 102, 103, 104, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67,
    68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83,
    84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
    100, 101, 102, 103, 104, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 336, -1,
    338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, -1, 352, -1,
    354, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 336, -1, 338,
    339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, -1, 352, -1, 354,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 336, -1, 338, 339,
    340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, -1, 352, -1, 354, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
    59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
    75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 10, 11,
    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
    44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
    60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75,
    76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91,
    92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 10, 11, 12,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
    77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92,
    93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, 336, -1, 338, 339, 340, 341, 342, 343, 344, 345, 346,
    347, 348, 349, 350, -1, 352, -1, 354, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, 336, -1, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347,
    348, 349, 350, -1, 352, -1, 354, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, 336, -1, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348,
    349, 350, -1, 352, -1, 354, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
    34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
    66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
    82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97,
    98, 99, 100, 101, 102, 103, 104, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
    81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
    97, 98, 99, 100, 101, 102, 103, 104, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
    96, 97, 98, 99, 100, 101, 102, 103, 104, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 337,
    338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 10,
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
    59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74,
    75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, -1, -1,
    -1, -1, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
    123, 124, 125, 126, 127, 128, 129, 130, -1, 132, 133, 134, 135, 136, 137, 138,
    139, 140, 141, 142, 143, 144, 145, 146, 147, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
    81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
    97, 98, 99, 100, 101, 102, 103, 104, -1, -1, -1, -1, -1, 110, 111, 112,
    113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128,
    129, 130, -1, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
    145, 146, 147, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, 336, -1, 338, 339, 340, 341, 342, 343, 344, 345, 346,
    347, 348, 349, 350, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
    38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
    54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
    70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
    86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101,
    102, 103, 104, -1, -1, -1, -1, 109, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 336,
    -1, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 10, 11,
    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
    44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
    60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75,
    76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91,
    92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 10, 11, 12,
    13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
    61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76,
    77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92,
    93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 338, 339, 340, 341,
    342, 343, 344, 345, 346, 347, 348, 349, 350, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
    81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96,
    97, 98, 99, 100, 101, 102, 103, 104, -1, -1, 0, -1, -1, -1, 4, 5,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, 336, -1, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347,
    348, 349, 350, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, 336, -1, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348,
    349, 350, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, -1, 148, -1,
    4, 5, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 244, 245,
    246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261,
    262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277,
    278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293,
    148, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309,
    310, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 323, 324, 325,
    326, 327, 328, 329, 330, 331, 332, 333, 334, 335, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259,
    260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275,
    276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291,
    292, 293, 105, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307,
    308, 309, 310, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 323,
    324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, -1, -1, -1, -1,
    151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166,
    167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182,
    183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198,
    199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214,
    215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230,
    231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243,
];
#[rustfmt::skip]
const YYR1: [i16; 461] = [
    0, 355, 356, 356, 356, 357, 358, 358, 358, 358, 358, 358, 358, 358, 358, 358,
    358, 358, 358, 358, 358, 358, 358, 358, 358, 358, 358, 358, 358, 358, 359, 359,
    360, 360, 361, 361, 361, 361, 362, 362, 362, 362, 362, 362, 362, 362, 362, 362,
    362, 362, 362, 362, 362, 362, 362, 362, 362, 362, 362, 362, 362, 362, 362, 362,
    362, 362, 362, 362, 362, 362, 362, 362, 362, 362, 362, 363, 363, 363, 363, 363,
    363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363,
    363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363,
    363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363,
    363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363,
    363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 363, 364,
    365, 365, 366, 366, 366, 366, 366, 366, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367,
    367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 367, 368, 368,
    368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368,
    368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368,
    368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368,
    368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368,
    368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368,
    368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368, 368,
    368, 368, 368, 368, 369, 369, 369, 369, 369, 370, 370, 370, 370,
];
#[rustfmt::skip]
const YYR2: [i8; 461] = [
    0, 2, 1, 2, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 2,
    2, 1, 1, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 3, 1,
    3, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 4, 3, 2, 2,
    2, 1, 2, 2, 2, 2, 2, 2, 2, 1, 1, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 1, 2, 2, 1, 1, 1, 1, 1, 1, 2, 2, 1,
    1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 1, 1, 1,
    1, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 3, 3, 4, 4, 1, 2, 2, 2, 2, 1, 2, 2, 1, 2, 2,
    1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1,
    2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2,
    2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2,
    1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 2,
    1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2,
    1, 2, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2, 1, 2, 2,
    1, 1, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1,
    2, 2, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1,
    1, 1, 1, 1, 2, 2, 2, 2, 2, 1, 1, 1, 1, 2, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 2, 1, 3, 3, 3, 2, 2, 1, 1,
];
#[rustfmt::skip]
const YYTNAME: [&str; 371] = [
    "\"end of file\"",
    "error",
    "\"invalid token\"",
    "\",\"",
    "\"CONFIG_CONTENT_INJECTION\"",
    "\"CONGIG_DIR_RESPONSE_BODY_MP_CLEAR\"",
    "PIPE",
    "NEW_LINE",
    "VAR_COUNT",
    "VAR_EXCLUSION",
    "VARIABLE_ARGS",
    "VARIABLE_ARGS_POST",
    "VARIABLE_ARGS_GET",
    "VARIABLE_FILES_SIZES",
    "VARIABLE_FILES_NAMES",
    "VARIABLE_FILES_TMP_CONTENT",
    "VARIABLE_MULTIPART_FILENAME",
    "VARIABLE_MULTIPART_FILENAME_CHARSET",
    "VARIABLE_MULTIPART_FILENAME_LANGUAGE",
    "VARIABLE_MULTIPART_NAME",
    "VARIABLE_MATCHED_VARS_NAMES",
    "VARIABLE_MATCHED_VARS",
    "VARIABLE_FILES",
    "VARIABLE_REQUEST_COOKIES",
    "VARIABLE_REQUEST_HEADERS",
    "VARIABLE_RESPONSE_HEADERS",
    "VARIABLE_GEO",
    "VARIABLE_REQUEST_COOKIES_NAMES",
    "VARIABLE_MULTIPART_PART_HEADERS",
    "VARIABLE_ARGS_COMBINED_SIZE",
    "VARIABLE_ARGS_GET_NAMES",
    "VARIABLE_RULE",
    "\"Variable ARGS_NAMES\"",
    "VARIABLE_ARGS_POST_NAMES",
    "\"AUTH_TYPE\"",
    "\"FILES_COMBINED_SIZE\"",
    "\"FILES_TMPNAMES\"",
    "\"FULL_REQUEST\"",
    "\"FULL_REQUEST_LENGTH\"",
    "\"INBOUND_DATA_ERROR\"",
    "\"MATCHED_VAR\"",
    "\"MATCHED_VAR_NAME\"",
    "\"MSC_PCRE_ERROR\"",
    "\"MSC_PCRE_LIMITS_EXCEEDED\"",
    "VARIABLE_MULTIPART_BOUNDARY_QUOTED",
    "VARIABLE_MULTIPART_BOUNDARY_WHITESPACE",
    "\"MULTIPART_CRLF_LF_LINES\"",
    "\"MULTIPART_DATA_AFTER\"",
    "VARIABLE_MULTIPART_DATA_BEFORE",
    "\"MULTIPART_DUPLICATE_PART_HEADER\"",
    "\"MULTIPART_FILE_LIMIT_EXCEEDED\"",
    "\"MULTIPART_HEADER_FOLDING\"",
    "\"MULTIPART_INVALID_HEADER_FOLDING\"",
    "VARIABLE_MULTIPART_INVALID_PART",
    "\"MULTIPART_INVALID_QUOTING\"",
    "VARIABLE_MULTIPART_LF_LINE",
    "VARIABLE_MULTIPART_MISSING_SEMICOLON",
    "VARIABLE_MULTIPART_SEMICOLON_MISSING",
    "\"MULTIPART_STRICT_ERROR\"",
    "\"MULTIPART_UNMATCHED_BOUNDARY\"",
    "\"OUTBOUND_DATA_ERROR\"",
    "\"PATH_INFO\"",
    "\"QUERY_STRING\"",
    "\"REMOTE_ADDR\"",
    "\"REMOTE_HOST\"",
    "\"REMOTE_PORT\"",
    "\"REQBODY_ERROR_MSG\"",
    "\"REQBODY_ERROR\"",
    "\"REQBODY_PROCESSOR_ERROR_MSG\"",
    "\"REQBODY_PROCESSOR_ERROR\"",
    "\"REQBODY_PROCESSOR\"",
    "\"REQUEST_BASENAME\"",
    "\"REQUEST_BODY_LENGTH\"",
    "\"REQUEST_BODY\"",
    "\"REQUEST_FILENAME\"",
    "VARIABLE_REQUEST_HEADERS_NAMES",
    "\"REQUEST_LINE\"",
    "\"REQUEST_METHOD\"",
    "\"REQUEST_PROTOCOL\"",
    "\"REQUEST_URI_RAW\"",
    "\"REQUEST_URI\"",
    "\"RESOURCE\"",
    "\"RESPONSE_BODY\"",
    "\"RESPONSE_CONTENT_LENGTH\"",
    "VARIABLE_RESPONSE_CONTENT_TYPE",
    "VARIABLE_RESPONSE_HEADERS_NAMES",
    "\"RESPONSE_PROTOCOL\"",
    "\"RESPONSE_STATUS\"",
    "\"SERVER_ADDR\"",
    "\"SERVER_NAME\"",
    "\"SERVER_PORT\"",
    "\"SESSIONID\"",
    "\"UNIQUE_ID\"",
    "\"URLENCODED_ERROR\"",
    "\"USERID\"",
    "\"WEBAPPID\"",
    "\"VARIABLE_STATUS\"",
    "\"VARIABLE_STATUS_LINE\"",
    "\"VARIABLE_IP\"",
    "\"VARIABLE_GLOBAL\"",
    "\"VARIABLE_TX\"",
    "\"VARIABLE_SESSION\"",
    "\"VARIABLE_USER\"",
    "\"RUN_TIME_VAR_ENV\"",
    "\"RUN_TIME_VAR_XML\"",
    "\"SetVar\"",
    "SETVAR_OPERATION_EQUALS",
    "SETVAR_OPERATION_EQUALS_PLUS",
    "SETVAR_OPERATION_EQUALS_MINUS",
    "\"NOT\"",
    "\"OPERATOR_BEGINS_WITH\"",
    "\"OPERATOR_CONTAINS\"",
    "\"OPERATOR_CONTAINS_WORD\"",
    "\"OPERATOR_DETECT_SQLI\"",
    "\"OPERATOR_DETECT_XSS\"",
    "\"OPERATOR_ENDS_WITH\"",
    "\"OPERATOR_EQ\"",
    "\"OPERATOR_FUZZY_HASH\"",
    "\"OPERATOR_GEOLOOKUP\"",
    "\"OPERATOR_GE\"",
    "\"OPERATOR_GSB_LOOKUP\"",
    "\"OPERATOR_GT\"",
    "\"OPERATOR_INSPECT_FILE\"",
    "\"OPERATOR_IP_MATCH_FROM_FILE\"",
    "\"OPERATOR_IP_MATCH\"",
    "\"OPERATOR_LE\"",
    "\"OPERATOR_LT\"",
    "\"OPERATOR_PM_FROM_FILE\"",
    "\"OPERATOR_PM\"",
    "\"OPERATOR_RBL\"",
    "\"OPERATOR_RSUB\"",
    "\"Operator RX (content only)\"",
    "\"OPERATOR_RX\"",
    "\"OPERATOR_RX_GLOBAL\"",
    "\"OPERATOR_STR_EQ\"",
    "\"OPERATOR_STR_MATCH\"",
    "\"OPERATOR_UNCONDITIONAL_MATCH\"",
    "\"OPERATOR_VALIDATE_BYTE_RANGE\"",
    "\"OPERATOR_VALIDATE_DTD\"",
    "\"OPERATOR_VALIDATE_HASH\"",
    "\"OPERATOR_VALIDATE_SCHEMA\"",
    "\"OPERATOR_VALIDATE_URL_ENCODING\"",
    "\"OPERATOR_VALIDATE_UTF8_ENCODING\"",
    "\"OPERATOR_VERIFY_CC\"",
    "\"OPERATOR_VERIFY_CPF\"",
    "\"OPERATOR_VERIFY_SSN\"",
    "\"OPERATOR_VERIFY_SVNR\"",
    "\"OPERATOR_WITHIN\"",
    "CONFIG_DIR_AUDIT_LOG_FMT",
    "JSON",
    "NATIVE",
    "\"ACTION_CTL_RULE_ENGINE\"",
    "\"Accuracy\"",
    "\"Allow\"",
    "\"Append\"",
    "\"AuditLog\"",
    "\"Block\"",
    "\"Capture\"",
    "\"Chain\"",
    "\"ACTION_CTL_AUDIT_ENGINE\"",
    "\"ACTION_CTL_AUDIT_LOG_PARTS\"",
    "\"ACTION_CTL_BDY_JSON\"",
    "\"ACTION_CTL_BDY_XML\"",
    "\"ACTION_CTL_BDY_URLENCODED\"",
    "\"ACTION_CTL_FORCE_REQ_BODY_VAR\"",
    "\"ACTION_CTL_PARSE_XML_INTO_ARGS\"",
    "\"ACTION_CTL_REQUEST_BODY_ACCESS\"",
    "\"ACTION_CTL_RULE_REMOVE_BY_ID\"",
    "\"ACTION_CTL_RULE_REMOVE_BY_TAG\"",
    "\"ACTION_CTL_RULE_REMOVE_TARGET_BY_ID\"",
    "\"ACTION_CTL_RULE_REMOVE_TARGET_BY_TAG\"",
    "\"Deny\"",
    "\"DeprecateVar\"",
    "\"Drop\"",
    "\"Exec\"",
    "\"ExpireVar\"",
    "\"Id\"",
    "\"InitCol\"",
    "\"Log\"",
    "\"LogData\"",
    "\"Maturity\"",
    "\"Msg\"",
    "\"MultiMatch\"",
    "\"NoAuditLog\"",
    "\"NoLog\"",
    "\"Pass\"",
    "\"Pause\"",
    "\"Phase\"",
    "\"Prepend\"",
    "\"Proxy\"",
    "\"Redirect\"",
    "\"Rev\"",
    "\"SanitiseArg\"",
    "\"SanitiseMatched\"",
    "\"SanitiseMatchedBytes\"",
    "\"SanitiseRequestHeader\"",
    "\"SanitiseResponseHeader\"",
    "\"SetEnv\"",
    "\"SetRsc\"",
    "\"SetSid\"",
    "\"SetUID\"",
    "\"Severity\"",
    "\"Skip\"",
    "\"SkipAfter\"",
    "\"Status\"",
    "\"Tag\"",
    "\"ACTION_TRANSFORMATION_BASE_64_ENCODE\"",
    "\"ACTION_TRANSFORMATION_BASE_64_DECODE\"",
    "\"ACTION_TRANSFORMATION_BASE_64_DECODE_EXT\"",
    "\"ACTION_TRANSFORMATION_CMD_LINE\"",
    "\"ACTION_TRANSFORMATION_COMPRESS_WHITESPACE\"",
    "\"ACTION_TRANSFORMATION_CSS_DECODE\"",
    "\"ACTION_TRANSFORMATION_ESCAPE_SEQ_DECODE\"",
    "\"ACTION_TRANSFORMATION_HEX_ENCODE\"",
    "\"ACTION_TRANSFORMATION_HEX_DECODE\"",
    "\"ACTION_TRANSFORMATION_HTML_ENTITY_DECODE\"",
    "\"ACTION_TRANSFORMATION_JS_DECODE\"",
    "\"ACTION_TRANSFORMATION_LENGTH\"",
    "\"ACTION_TRANSFORMATION_LOWERCASE\"",
    "\"ACTION_TRANSFORMATION_MD5\"",
    "\"ACTION_TRANSFORMATION_NONE\"",
    "\"ACTION_TRANSFORMATION_NORMALISE_PATH\"",
    "\"ACTION_TRANSFORMATION_NORMALISE_PATH_WIN\"",
    "\"ACTION_TRANSFORMATION_PARITY_EVEN_7_BIT\"",
    "\"ACTION_TRANSFORMATION_PARITY_ODD_7_BIT\"",
    "\"ACTION_TRANSFORMATION_PARITY_ZERO_7_BIT\"",
    "\"ACTION_TRANSFORMATION_REMOVE_COMMENTS\"",
    "\"ACTION_TRANSFORMATION_REMOVE_COMMENTS_CHAR\"",
    "\"ACTION_TRANSFORMATION_REMOVE_NULLS\"",
    "\"ACTION_TRANSFORMATION_REMOVE_WHITESPACE\"",
    "\"ACTION_TRANSFORMATION_REPLACE_COMMENTS\"",
    "\"ACTION_TRANSFORMATION_REPLACE_NULLS\"",
    "\"ACTION_TRANSFORMATION_SHA1\"",
    "\"ACTION_TRANSFORMATION_SQL_HEX_DECODE\"",
    "\"ACTION_TRANSFORMATION_TRIM\"",
    "\"ACTION_TRANSFORMATION_TRIM_LEFT\"",
    "\"ACTION_TRANSFORMATION_TRIM_RIGHT\"",
    "\"ACTION_TRANSFORMATION_UPPERCASE\"",
    "\"ACTION_TRANSFORMATION_URL_ENCODE\"",
    "\"ACTION_TRANSFORMATION_URL_DECODE\"",
    "\"ACTION_TRANSFORMATION_URL_DECODE_UNI\"",
    "\"ACTION_TRANSFORMATION_UTF8_TO_UNICODE\"",
    "\"Ver\"",
    "\"xmlns\"",
    "\"CONFIG_COMPONENT_SIG\"",
    "\"CONFIG_CONN_ENGINE\"",
    "\"CONFIG_SEC_ARGUMENT_SEPARATOR\"",
    "\"CONFIG_SEC_WEB_APP_ID\"",
    "\"CONFIG_SEC_SERVER_SIG\"",
    "\"CONFIG_DIR_AUDIT_DIR\"",
    "\"CONFIG_DIR_AUDIT_DIR_MOD\"",
    "\"CONFIG_DIR_AUDIT_ENG\"",
    "\"CONFIG_DIR_AUDIT_FLE_MOD\"",
    "\"CONFIG_DIR_AUDIT_LOG\"",
    "\"CONFIG_DIR_AUDIT_LOG2\"",
    "\"CONFIG_DIR_AUDIT_LOG_P\"",
    "\"CONFIG_DIR_AUDIT_STS\"",
    "\"CONFIG_DIR_AUDIT_PREFIX\"",
    "\"CONFIG_DIR_AUDIT_TPE\"",
    "\"CONFIG_DIR_DEBUG_LOG\"",
    "\"CONFIG_DIR_DEBUG_LVL\"",
    "\"CONFIG_SEC_CACHE_TRANSFORMATIONS\"",
    "\"CONFIG_SEC_DISABLE_BACKEND_COMPRESS\"",
    "\"CONFIG_SEC_HASH_ENGINE\"",
    "\"CONFIG_SEC_HASH_KEY\"",
    "\"CONFIG_SEC_HASH_PARAM\"",
    "\"CONFIG_SEC_HASH_METHOD_RX\"",
    "\"CONFIG_SEC_HASH_METHOD_PM\"",
    "\"CONFIG_SEC_CHROOT_DIR\"",
    "\"CONFIG_DIR_GEO_DB\"",
    "\"CONFIG_DIR_GSB_DB\"",
    "\"CONFIG_SEC_GUARDIAN_LOG\"",
    "\"CONFIG_DIR_PCRE_MATCH_LIMIT\"",
    "\"CONFIG_DIR_PCRE_MATCH_LIMIT_RECURSION\"",
    "\"CONFIG_SEC_CONN_R_STATE_LIMIT\"",
    "\"CONFIG_SEC_CONN_W_STATE_LIMIT\"",
    "\"CONFIG_SEC_SENSOR_ID\"",
    "\"CONFIG_DIR_ARGS_LIMIT\"",
    "\"CONFIG_DIR_REQ_BODY_JSON_DEPTH_LIMIT\"",
    "\"CONFIG_DIR_REQ_BODY\"",
    "\"CONFIG_DIR_REQ_BODY_IN_MEMORY_LIMIT\"",
    "\"CONFIG_DIR_REQ_BODY_LIMIT\"",
    "\"CONFIG_DIR_REQ_BODY_LIMIT_ACTION\"",
    "\"CONFIG_DIR_REQ_BODY_NO_FILES_LIMIT\"",
    "\"CONFIG_DIR_RES_BODY\"",
    "\"CONFIG_DIR_RES_BODY_LIMIT\"",
    "\"CONFIG_DIR_RES_BODY_LIMIT_ACTION\"",
    "\"CONFIG_SEC_RULE_INHERITANCE\"",
    "\"CONFIG_SEC_RULE_PERF_TIME\"",
    "\"CONFIG_DIR_RULE_ENG\"",
    "\"CONFIG_DIR_SEC_ACTION\"",
    "\"CONFIG_DIR_SEC_DEFAULT_ACTION\"",
    "\"CONFIG_DIR_SEC_MARKER\"",
    "\"CONFIG_DIR_UNICODE_MAP_FILE\"",
    "\"CONFIG_DIR_UNICODE_CODE_PAGE\"",
    "\"CONFIG_SEC_COLLECTION_TIMEOUT\"",
    "\"CONFIG_SEC_HTTP_BLKEY\"",
    "\"CONFIG_SEC_INTERCEPT_ON_ERROR\"",
    "\"CONFIG_SEC_REMOTE_RULES_FAIL_ACTION\"",
    "\"CONFIG_SEC_RULE_REMOVE_BY_ID\"",
    "\"CONFIG_SEC_RULE_REMOVE_BY_MSG\"",
    "\"CONFIG_SEC_RULE_REMOVE_BY_TAG\"",
    "\"CONFIG_SEC_RULE_UPDATE_TARGET_BY_TAG\"",
    "\"CONFIG_SEC_RULE_UPDATE_TARGET_BY_MSG\"",
    "\"CONFIG_SEC_RULE_UPDATE_TARGET_BY_ID\"",
    "\"CONFIG_SEC_RULE_UPDATE_ACTION_BY_ID\"",
    "\"CONFIG_UPDLOAD_KEEP_FILES\"",
    "\"CONFIG_UPDLOAD_SAVE_TMP_FILES\"",
    "\"CONFIG_UPLOAD_DIR\"",
    "\"CONFIG_UPLOAD_FILE_LIMIT\"",
    "\"CONFIG_UPLOAD_FILE_MODE\"",
    "\"CONFIG_VALUE_ABORT\"",
    "\"CONFIG_VALUE_DETC\"",
    "\"CONFIG_VALUE_HTTPS\"",
    "\"CONFIG_VALUE_ONLYARGS\"",
    "\"CONFIG_VALUE_OFF\"",
    "\"CONFIG_VALUE_ON\"",
    "\"CONFIG_VALUE_PARALLEL\"",
    "\"CONFIG_VALUE_PROCESS_PARTIAL\"",
    "\"CONFIG_VALUE_REJECT\"",
    "\"CONFIG_VALUE_RELEVANT_ONLY\"",
    "\"CONFIG_VALUE_SERIAL\"",
    "\"CONFIG_VALUE_WARN\"",
    "\"CONFIG_XML_EXTERNAL_ENTITY\"",
    "\"CONFIG_XML_PARSE_XML_INTO_ARGS\"",
    "\"CONGIG_DIR_RESPONSE_BODY_MP\"",
    "\"CONGIG_DIR_SEC_ARG_SEP\"",
    "\"CONGIG_DIR_SEC_COOKIE_FORMAT\"",
    "\"CONFIG_SEC_COOKIEV0_SEPARATOR\"",
    "\"CONGIG_DIR_SEC_DATA_DIR\"",
    "\"CONGIG_DIR_SEC_STATUS_ENGINE\"",
    "\"CONFIG_SEC_STREAM_IN_BODY_INSPECTION\"",
    "\"CONFIG_SEC_STREAM_OUT_BODY_INSPECTION\"",
    "\"CONGIG_DIR_SEC_TMP_DIR\"",
    "\"DIRECTIVE\"",
    "\"DIRECTIVE_SECRULESCRIPT\"",
    "\"FREE_TEXT_QUOTE_MACRO_EXPANSION\"",
    "\"QUOTATION_MARK\"",
    "\"RUN_TIME_VAR_BLD\"",
    "\"RUN_TIME_VAR_DUR\"",
    "\"RUN_TIME_VAR_HSV\"",
    "\"RUN_TIME_VAR_REMOTE_USER\"",
    "\"RUN_TIME_VAR_TIME\"",
    "\"RUN_TIME_VAR_TIME_DAY\"",
    "\"RUN_TIME_VAR_TIME_EPOCH\"",
    "\"RUN_TIME_VAR_TIME_HOUR\"",
    "\"RUN_TIME_VAR_TIME_MIN\"",
    "\"RUN_TIME_VAR_TIME_MON\"",
    "\"RUN_TIME_VAR_TIME_SEC\"",
    "\"RUN_TIME_VAR_TIME_WDAY\"",
    "\"RUN_TIME_VAR_TIME_YEAR\"",
    "\"VARIABLE\"",
    "\"Dictionary element\"",
    "\"Dictionary element, with equals\"",
    "\"Dictionary element, selected by regexp\"",
    "$accept",
    "input",
    "line",
    "audit_log",
    "actions",
    "actions_may_quoted",
    "op",
    "op_before_init",
    "expression",
    "variables",
    "variables_pre_process",
    "variables_may_be_quoted",
    "var",
    "act",
    "setvar_action",
    "run_time_string",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_set::RulesSet;

    /// The C API view of a load: the number of rules or -1, and the
    /// parser errors.
    fn load(rules: &str, reference: &str) -> (i32, String) {
        let mut r = RulesSet::new();
        let n = r.load_with_ref(rules, reference).map_or(-1, |n| n as i32);
        (n, r.get_parser_error())
    }

    #[test]
    fn locations() {
        let mut l = Location::new(0);
        l.columns(5);
        assert_eq!(l.end.column, 6);
        l.columns(-10);
        assert_eq!(l.end.column, 1);
        l.lines(2);
        assert_eq!((l.end.line, l.end.column), (3, 1));
        l.step();
        assert_eq!(l.begin, l.end);
    }

    #[test]
    fn symbol_names() {
        assert_eq!(tname(sym::END as usize), "end of file");
        assert_eq!(tname(sym::COMMA as usize), "\",\"");
        assert_eq!(tname(sym::PIPE as usize), "PIPE");
        assert_eq!(tname(sym::ACTION_ALLOW as usize), "Allow");
    }

    #[test]
    fn c_conversions() {
        assert_eq!(strtol_int(" 0750", 8), 0o750);
        assert_eq!(strtol_int("\"0750\"", 8), 0);
        assert_eq!(stod("12"), Some(12.0));
        assert_eq!(stod(" 1.5e3x"), Some(1500.0));
        assert_eq!(stod("abc"), None);
        assert_eq!(stod("1e999"), None);
    }

    #[test]
    fn empty_and_comments() {
        assert_eq!(load("", "x").0, 0);
        assert_eq!(load("# just a comment\n", "x").0, 0);
        assert_eq!(load("\n\n", "x").0, 0);
    }

    #[test]
    fn default_action_error_location() {
        let (n, err) =
            load("SecRuleEngine On\nSecDefaultAction \"phase:1,log,block,status:404\"\n", "action-block.json");
        assert_eq!(n, -1);
        assert_eq!(
            err,
            "Rules error. File: action-block.json. Line: 1. Column: 16. SecDefaultAction must specify a disruptive action. "
        );
    }

    #[test]
    fn scanner_errors() {
        let (n, err) = load("SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,t:trim,ctl:ruleRemoveById,123\"\n", "t");
        assert_eq!(n, -1);
        assert!(err.contains("Expecting an action, got:  ctl:ruleRemoveById,123"), "{}", err);
        let (n, err) = load("SecUnicodeMapFile does-not-exist-unicode.mapping eita\n", "t");
        assert_eq!(n, -1);
        assert!(err.contains("Invalid input:  SecUnicodeMapFile does-not-exist-unicode.mapping eita"), "{}", err);
        let (_, err) = load("SecRule WEBSERVER_ERROR_LOG \"@rx x\" \"id:1\"\n", "t");
        assert_eq!(
            err,
            "Rules error. File: t. Line: 1. Column: 27. Variable VARIABLE_WEBSERVER_ERROR_LOG is not supported by libModSecurity "
        );
    }

    #[test]
    fn syntax_errors() {
        let (n, err) = load("SecRuleEngine\n", "t");
        assert_eq!(n, -1);
        assert!(
            err.starts_with("Rules error. File: t. Line: 2. Column: 0. syntax error, unexpected end of file"),
            "{}",
            err
        );
    }

    #[test]
    fn chains_and_duplicates() {
        let rules = "SecRule ARGS \"@rx a\" \"id:1,phase:2,chain,deny\"\nSecRule ARGS \"@rx b\" \"chain\"\nSecRule ARGS \"@rx c\" \"t:none\"\nSecRule ARGS \"@rx d\" \"id:2,phase:2,pass\"\n";
        let mut d = Driver::new();
        assert!(d.parse(rules, "t"), "{}", d.properties.parser_error);
        let phase = &d.rules_set_phases.at(Phases::RequestBodyPhase as usize).rules;
        assert_eq!(phase.len(), 2);
        let r = phase[0].as_rule_with_actions().unwrap();
        let child = r.chained_rule_child.as_ref().unwrap();
        assert!(child.chained_rule_parent);
        assert!(child.chained_rule_child.is_some());
        assert_eq!(child.get_phase(), Phases::RequestBodyPhase as i32);

        let (n, err) = load("SecRule ARGS \"@rx a\" \"id:40\"\nSecRule ARGS \"@rx a\" \"id:40\"\n", "t");
        assert_eq!(n, -1);
        assert_eq!(err, "Rule id: 40 is duplicated\n");
    }

    /// A minimal JSON reader for the regression test files.
    mod json {
        #[derive(Debug, Clone)]
        pub enum J {
            Null,
            Bool,
            Num(f64),
            Str(String),
            Arr(Vec<J>),
            Obj(Vec<(String, J)>),
        }

        impl J {
            pub fn get(&self, k: &str) -> Option<&J> {
                match self {
                    J::Obj(v) => v.iter().find(|(n, _)| n == k).map(|(_, v)| v),
                    _ => None,
                }
            }
        }

        pub fn parse(s: &str) -> J {
            let mut p = P { b: s.as_bytes(), i: 0 };
            p.value()
        }

        struct P<'a> {
            b: &'a [u8],
            i: usize,
        }

        impl P<'_> {
            fn ws(&mut self) {
                while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
                    self.i += 1;
                }
            }

            fn value(&mut self) -> J {
                self.ws();
                match self.b[self.i] {
                    b'{' => {
                        self.i += 1;
                        let mut v = Vec::new();
                        loop {
                            self.ws();
                            if self.b[self.i] == b'}' {
                                self.i += 1;
                                return J::Obj(v);
                            }
                            let J::Str(k) = self.value() else { panic!("bad key") };
                            self.ws();
                            assert_eq!(self.b[self.i], b':');
                            self.i += 1;
                            let val = self.value();
                            v.push((k, val));
                            self.ws();
                            if self.b[self.i] == b',' {
                                self.i += 1;
                            }
                        }
                    }
                    b'[' => {
                        self.i += 1;
                        let mut v = Vec::new();
                        loop {
                            self.ws();
                            if self.b[self.i] == b']' {
                                self.i += 1;
                                return J::Arr(v);
                            }
                            v.push(self.value());
                            self.ws();
                            if self.b[self.i] == b',' {
                                self.i += 1;
                            }
                        }
                    }
                    b'"' => {
                        self.i += 1;
                        let mut out: Vec<u8> = Vec::new();
                        loop {
                            let c = self.b[self.i];
                            self.i += 1;
                            match c {
                                b'"' => break,
                                b'\\' => {
                                    let e = self.b[self.i];
                                    self.i += 1;
                                    match e {
                                        b'n' => out.push(b'\n'),
                                        b't' => out.push(b'\t'),
                                        b'r' => out.push(b'\r'),
                                        b'b' => out.push(8),
                                        b'f' => out.push(12),
                                        b'u' => {
                                            let h = |p: &mut Self| {
                                                let s = std::str::from_utf8(&p.b[p.i..p.i + 4]).unwrap_or("0");
                                                p.i += 4;
                                                u32::from_str_radix(s, 16).unwrap_or(0)
                                            };
                                            let mut cp = h(self);
                                            if (0xd800..0xdc00).contains(&cp) && self.b[self.i] == b'\\' {
                                                self.i += 2;
                                                let lo = h(self);
                                                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                                            }
                                            let ch = char::from_u32(cp).unwrap_or('\u{fffd}');
                                            let mut buf = [0u8; 4];
                                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                                        }
                                        o => out.push(o),
                                    }
                                }
                                o => out.push(o),
                            }
                        }
                        J::Str(String::from_utf8_lossy(&out).into_owned())
                    }
                    b't' => {
                        self.i += 4;
                        J::Bool
                    }
                    b'f' => {
                        self.i += 5;
                        J::Bool
                    }
                    b'n' => {
                        self.i += 4;
                        J::Null
                    }
                    _ => {
                        let st = self.i;
                        while self.i < self.b.len() && b"+-0123456789.eE".contains(&self.b[self.i]) {
                            self.i += 1;
                        }
                        J::Num(std::str::from_utf8(&self.b[st..self.i]).unwrap_or("0").parse().unwrap_or(0.0))
                    }
                }
            }
        }
    }

    /// Parses the rules of every test of `test/test-cases/regression` the
    /// way the regression harness does (after `SecDebugLogLevel 9`, with the
    /// test file name as reference) and checks the expected parser errors.
    ///
    /// Run from the crate root with
    /// `cargo test --lib regression_parser_errors -- --ignored`; it changes
    /// the working directory to `test/` (the tests use relative paths).
    #[test]
    #[ignore]
    fn regression_parser_errors() {
        use crate::utils::regex::{Regex, regex_search};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test");
        std::env::set_current_dir(&root).expect("test directory");
        let mut resources = Vec::new();
        if cfg!(feature = "maxmind") {
            resources.extend(["geoip-or-maxmind", "maxmind"]);
        }
        if cfg!(feature = "curl") {
            resources.push("curl");
        }
        if cfg!(feature = "ssdeep") {
            resources.push("ssdeep");
        }
        let mut files: Vec<_> = std::fs::read_dir("test-cases/regression")
            .expect("regression tests")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        files.sort();
        let (mut pass, mut fail, mut skipped) = (0, 0, 0);
        let mut failures = Vec::new();
        for f in files {
            let filename = f.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let content = std::fs::read_to_string(&f).expect("test file");
            let tests = match json::parse(&content) {
                json::J::Arr(v) => v,
                o => vec![o],
            };
            for t in tests {
                let enabled = matches!(t.get("enabled"), Some(json::J::Num(n)) if *n != 0.0);
                let resource = match t.get("resource") {
                    Some(json::J::Str(r)) => Some(r.clone()),
                    _ => None,
                };
                if !enabled || resource.is_some_and(|r| !resources.contains(&r.as_str())) {
                    skipped += 1;
                    continue;
                }
                let mut rules = String::new();
                if let Some(json::J::Arr(lines)) = t.get("rules") {
                    for l in lines {
                        if let json::J::Str(l) = l {
                            rules.push_str(l);
                            rules.push('\n');
                        }
                    }
                }
                let expected = match t.get("expected").and_then(|e| e.get("parser_error")) {
                    Some(json::J::Str(e)) => Some(e.clone()),
                    _ => None,
                };
                let mut r = RulesSet::new();
                r.load("SecDebugLogLevel 9").expect("valid directive");
                let failed = r.load_with_ref(&rules, &filename).is_err();
                let err = r.get_parser_error();
                let ok = match &expected {
                    Some(e) => failed && regex_search(err.as_bytes(), &Regex::new(e)) > 0,
                    None => !failed,
                };
                if ok {
                    pass += 1;
                } else {
                    fail += 1;
                    failures.push(format!("{}: got {:?}, expected {:?}", filename, err, expected));
                }
            }
        }
        for f in &failures {
            eprintln!("{}", f);
        }
        eprintln!("parser check: {} passed, {} failed, {} skipped", pass, fail, skipped);
        assert!(failures.is_empty());
    }
}
