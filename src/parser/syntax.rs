//! The SecLang syntax tree, read with the `pest` grammar in `seclang.pest`.
//!
//! [`parse_statement`] reads one directive (with the blank lines and
//! comments before it) from a configuration text and returns it as a
//! [`Directive`] that borrows the text. What the names in it mean is decided
//! by `build.rs`.
//!
//! Configuration files are bytes. They are given to the grammar as text with
//! one `char` per byte (Latin-1), so that any byte is accepted where the
//! grammar accepts "any character"; [`bytes`] turns a piece of that text back
//! into the original bytes.

use pest::Parser;
use pest::iterators::Pair;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "parser/seclang.pest"]
struct SecLang;

/// A configuration text, one `char` per byte.
pub struct Source<'a> {
    text: std::borrow::Cow<'a, str>,
}

impl<'a> Source<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        // ASCII is its own Latin-1 text (the usual case): no copy.
        let text = match std::str::from_utf8(bytes) {
            Ok(s) if s.is_ascii() => std::borrow::Cow::Borrowed(s),
            _ => std::borrow::Cow::Owned(bytes.iter().map(|&b| char::from(b)).collect()),
        };
        Source { text }
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

/// The original bytes of a piece of a [`Source`].
pub fn bytes(s: &str) -> std::borrow::Cow<'_, [u8]> {
    if s.is_ascii() {
        return std::borrow::Cow::Borrowed(s.as_bytes());
    }
    // Every char of a `Source` is below 256.
    std::borrow::Cow::Owned(s.chars().map(|c| c as u8).collect())
}

/// One directive of a configuration.
#[derive(Debug)]
pub enum Directive<'a> {
    /// `SecRule VARIABLES OPERATOR [ACTIONS]`
    Rule { variables: Vec<Target<'a>>, operator: Operator<'a>, actions: Option<Vec<Action<'a>>> },
    /// `SecRuleScript PATH [ACTIONS]`
    RuleScript { path: Value<'a>, actions: Option<Vec<Action<'a>>> },
    /// `SecAction ACTIONS`
    Action(Vec<Action<'a>>),
    /// `SecDefaultAction ACTIONS`
    DefaultAction(Vec<Action<'a>>),
    /// `SecRuleUpdateTargetBy{Id,Tag,Msg} SELECTOR VARIABLES`
    UpdateTarget { by: UpdateBy, selector: Value<'a>, variables: Vec<Target<'a>> },
    /// `SecRuleUpdateActionById ID ACTIONS`
    UpdateAction { id: Value<'a>, actions: Vec<Action<'a>> },
    /// Every other directive: a keyword and the rest of its line (after the
    /// keyword, up to the line feed), e.g. `SecRuleEngine` and ` On`.
    Setting { keyword: &'a str, rest: &'a str },
}

/// What `SecRuleUpdateTargetBy...` selects rules by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateBy {
    Id,
    Tag,
    Msg,
}

/// A directive value, as written (without its quotes when quoted).
#[derive(Debug, Clone, Copy)]
pub struct Value<'a> {
    pub text: &'a str,
    pub quoted: bool,
    /// The spaces and tabs before it, after the first one.
    pub lead: &'a str,
}

/// A rule target: a variable, possibly excluded (`!`) or counted (`&`).
#[derive(Debug)]
pub struct Target<'a> {
    pub modifier: Option<Modifier>,
    pub var: VarRef<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    /// `!VAR`
    Exclusion,
    /// `&VAR`
    Count,
}

/// A variable reference: `ARGS`, `ARGS:foo`, `ARGS:/regex/`.
#[derive(Debug)]
pub struct VarRef<'a> {
    pub name: &'a str,
    pub selector: Selector<'a>,
}

#[derive(Debug)]
pub enum Selector<'a> {
    None,
    Key(&'a str),
    Regex(&'a str),
}

/// A piece of a string that may contain `%{VAR}` macros.
#[derive(Debug)]
pub enum Piece<'a> {
    Text(&'a str),
    Macro(VarRef<'a>),
}

/// The operator of a `SecRule`.
#[derive(Debug)]
pub struct Operator<'a> {
    pub negated: bool,
    /// The operator name without `@`; `None` for a bare parameter (a regex).
    pub name: Option<&'a str>,
    pub param: Vec<Piece<'a>>,
    /// The operator as written (after `!`, without the quotes).
    pub raw: &'a str,
    pub quoted: bool,
}

/// An action, with the offset where it starts.
#[derive(Debug)]
pub struct Action<'a> {
    pub kind: ActionKind<'a>,
    pub offset: usize,
}

#[derive(Debug)]
pub enum ActionKind<'a> {
    /// `name` or `name:value`; `text` is the whole action as written.
    Plain { name: &'a str, text: &'a str },
    /// `msg:...`, `tag:...`, `logdata:...`, ...: a value with macros.
    Macro { name: &'a str, value: Vec<Piece<'a>> },
    /// `initcol:COLLECTION=VALUE`; `text` is `initcol:COLLECTION=`.
    InitCol { text: &'a str, value: Vec<Piece<'a>> },
    /// `setvar:[!]COLLECTION.KEY[=VALUE|=+VALUE|=-VALUE]`
    SetVar { unset: bool, collection: &'a str, key: Vec<Piece<'a>>, op: Option<(SetVarOp, Vec<Piece<'a>>)> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetVarOp {
    Set,
    Add,
    Subtract,
}

/// A directive read by [`parse_statement`]: the offset of its keyword and
/// what it is.
///
/// Line numbers are counted as the C++ scanner counts them (they are in
/// the error log): a line feed inside a quoted text (an operator parameter,
/// a `msg`) is not counted, nor the line continuation between the variables
/// and the operator of a `SecRule` or between `SecAction` and its actions,
/// and a commented out `SecRule` counts the blank lines that follow its
/// first line as one.
#[derive(Debug)]
pub struct Statement<'a> {
    pub offset: usize,
    pub directive: Directive<'a>,
    /// The lines the C++ scanner counts before the keyword (from where the
    /// statement was read).
    pub lines_before: usize,
    /// The lines it counts from the keyword to the end of the statement.
    pub lines_in: usize,
}

/// A syntax error: the offset where the grammar stopped, and what is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError {
    pub offset: usize,
    pub message: String,
}

/// Reads a whole configuration: its statements, in order (`None` for the
/// end), each with the offset after it. Fails at the first syntax error;
/// [`parse_statement`] then reads the statements before it one by one.
pub fn parse_file(text: &str) -> Result<impl Iterator<Item = (Option<Statement<'_>>, usize)>, SyntaxError> {
    let file = SecLang::parse(Rule::file, text).map_err(|e| syntax_error(text, 0, &e))?;
    let mut from = 0;
    let statements =
        file.into_iter().next().expect("a file").into_inner().filter(|p| p.as_rule() == Rule::directive_statement);
    Ok(statements.map(move |p| {
        let (statement, end) = statement_from_pair(text, 0, from, p);
        from = end;
        (statement, end)
    }))
}

/// Reads the next statement of `text` from byte offset `from`. Returns the
/// statement (`None` at the end of the text) and the offset after it.
pub fn parse_statement(text: &str, from: usize) -> Result<(Option<Statement<'_>>, usize), SyntaxError> {
    let mut pairs = SecLang::parse(Rule::statement, &text[from..]).map_err(|e| syntax_error(text, from, &e))?;
    Ok(statement_from_pair(text, from, from, pairs.next().expect("a statement")))
}

/// A statement from its pair, whose spans are relative to `base`. Lines are
/// counted from `from` (the end of the previous statement, which may be
/// past the start of this one's pair).
fn statement_from_pair<'a>(
    text: &'a str,
    base: usize,
    from: usize,
    statement: Pair<'a, Rule>,
) -> (Option<Statement<'a>>, usize) {
    let end = base + statement.as_span().end();
    let sub = &text[base..];
    // Line feeds of the comments that the C++ scanner does not count.
    let mut absorbed = 0;
    let mut inner = None;
    for p in statement.into_inner() {
        match p.as_rule() {
            Rule::comment_gap => absorbed += line_feeds(p.as_str()) - 1,
            Rule::sec_rule
            | Rule::sec_rule_script
            | Rule::sec_action
            | Rule::sec_default_action
            | Rule::update_target
            | Rule::update_action
            | Rule::setting => inner = Some(p),
            // `end`, `EOI`, comment text.
            _ => {}
        }
    }
    let Some(inner) = inner else {
        return (None, end.max(from));
    };
    let start = base + inner.as_span().start();
    let mut uncounted = 0;
    let mut tail = Tail::Initial;
    let directive = directive(inner, sub, base, &mut uncounted, &mut tail);
    // How the C++ scanner leaves the directive.
    let bytes = text.as_bytes();
    let mut end = end;
    match tail {
        Tail::Initial => {}
        // After an unquoted action list a line feed right after the last
        // action is not counted.
        Tail::BareActions(e) => {
            if bytes.get(base + e) == Some(&b'\n') {
                uncounted += 1;
            }
        }
        // After a rule without actions, the scanner reads the next line as
        // its actions: a blank line there is not counted.
        Tail::NoActions => {
            let blank = text[end..].bytes().take_while(|&b| b == b' ' || b == b'\t').count();
            if end > 0 && bytes[end - 1] == b'\n' && bytes.get(end + blank) == Some(&b'\n') {
                end += blank + 1;
                uncounted += 1;
            }
        }
        // After the variables of `SecRuleUpdateTargetBy...`, the scanner
        // skips `[ \t]*[\\\r\n]*[ \t]*` without counting lines.
        Tail::Variables(e) => {
            let rest = &bytes[base + e..];
            let a = rest.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
            let b = rest[a..].iter().take_while(|&&b| matches!(b, b'\\' | b'\r' | b'\n')).count();
            let c = rest[a + b..].iter().take_while(|&&b| b == b' ' || b == b'\t').count();
            // That may go past the statement (blank lines after it).
            end = end.max(base + e + a + b + c);
            uncounted += line_feeds(&text[base + e..end]);
        }
    }
    let statement = Statement {
        offset: start,
        directive,
        lines_before: line_feeds(&text[from..start]) - absorbed,
        lines_in: line_feeds(&text[start..end]) - uncounted,
    };
    (Some(statement), end)
}

/// The state the C++ scanner is in after a directive, when it matters for
/// line numbers. Offsets are relative to where the statement was read from.
enum Tail {
    Initial,
    /// Actions without quotes, ending at this offset.
    BareActions(usize),
    /// A `SecRule` without actions.
    NoActions,
    /// `SecRuleUpdateTargetBy...`: its variables end at this offset.
    Variables(usize),
}

fn line_feeds(s: &str) -> usize {
    s.bytes().filter(|&b| b == b'\n').count()
}

/// Reads `raw` as an operator parameter (quoted or not); `None` when it is
/// not one.
pub fn parse_param(raw: &str, quoted: bool) -> Option<Vec<Piece<'_>>> {
    let rule = if quoted { Rule::param_q } else { Rule::param_s };
    let pair = SecLang::parse(rule, raw).ok()?.next()?;
    if pair.as_span().end() != raw.len() {
        return None;
    }
    Some(pieces(pair))
}

fn syntax_error(text: &str, from: usize, e: &pest::error::Error<Rule>) -> SyntaxError {
    let offset = from
        + match e.location {
            pest::error::InputLocation::Pos(p) => p,
            pest::error::InputLocation::Span((s, _)) => s,
        };
    let rest: String = text[offset..].chars().take_while(|&c| c != '\n' && c != '\r').collect();
    let message =
        if rest.is_empty() { "Unexpected end of line.".to_string() } else { format!("Invalid input: {}", rest) };
    SyntaxError { offset, message }
}

/// `uncounted` gets the line feeds of the directive that the C++ scanner
/// does not count. `sub` is the text the pairs' spans are relative to.
fn directive<'a>(
    pair: Pair<'a, Rule>,
    sub: &'a str,
    from: usize,
    uncounted: &mut usize,
    tail: &mut Tail,
) -> Directive<'a> {
    let rule = pair.as_rule();
    let start = pair.as_span().start();
    let mut inner = pair.into_inner();
    // The line feeds between `a` and `b`, not counted.
    let gap = |a: usize, b: usize| line_feeds(&sub[a..b]);
    match rule {
        Rule::sec_rule => {
            let v = inner.next().expect("variables");
            let o = inner.next().expect("operator");
            *uncounted += gap(v.as_span().end(), o.as_span().start());
            let variables = targets(v);
            let operator = operator(o, uncounted);
            let actions = inner.next().map(|a| {
                if !a.as_str().starts_with('"') {
                    *tail = Tail::BareActions(a.as_span().end());
                }
                actions(a, from, uncounted)
            });
            if actions.is_none() {
                *tail = Tail::NoActions;
            }
            Directive::Rule { variables, operator, actions }
        }
        Rule::sec_rule_script => {
            let p = inner.next().expect("path");
            let path_end = p.as_span().end();
            let path = value(p);
            let actions = inner.next().map(|a| {
                *uncounted += gap(path_end, a.as_span().start());
                actions(a, from, uncounted)
            });
            Directive::RuleScript { path, actions }
        }
        Rule::sec_action | Rule::sec_default_action => {
            let a = inner.next().expect("actions");
            let keyword = if rule == Rule::sec_action { "SecAction" } else { "SecDefaultAction" };
            *uncounted += gap(start + keyword.len(), a.as_span().start());
            let list = actions(a, from, uncounted);
            if rule == Rule::sec_action { Directive::Action(list) } else { Directive::DefaultAction(list) }
        }
        Rule::update_target => {
            let by = match inner.next().expect("by").as_str().to_ascii_lowercase().as_str() {
                "id" => UpdateBy::Id,
                "tag" => UpdateBy::Tag,
                _ => UpdateBy::Msg,
            };
            let lead = &inner.next().expect("separator").as_str()[1..];
            let selector = Value { lead, ..value(inner.next().expect("selector")) };
            let v = inner.next().expect("variables");
            *tail = Tail::Variables(v.as_span().end());
            let variables = targets(v);
            Directive::UpdateTarget { by, selector, variables }
        }
        Rule::update_action => {
            let lead = &inner.next().expect("separator").as_str()[1..];
            let id = Value { lead, ..value(inner.next().expect("id")) };
            let a = inner.next().expect("actions");
            if !a.as_str().starts_with('"') {
                *tail = Tail::BareActions(a.as_span().end());
            }
            let actions = actions(a, from, uncounted);
            Directive::UpdateAction { id, actions }
        }
        Rule::setting => {
            let keyword = inner.next().expect("keyword").as_str();
            let rest = inner.next().map_or("", |r| r.as_str());
            Directive::Setting { keyword, rest }
        }
        r => unreachable!("not a directive: {r:?}"),
    }
}

/// `value`, `update_value`: the text, without quotes.
fn value(pair: Pair<'_, Rule>) -> Value<'_> {
    let inner = pair.into_inner().next().expect("a value");
    match inner.as_rule() {
        Rule::quoted => Value { text: inner.into_inner().next().map_or("", |t| t.as_str()), quoted: true, lead: "" },
        _ => Value { text: inner.as_str(), quoted: false, lead: "" },
    }
}

fn targets(pair: Pair<'_, Rule>) -> Vec<Target<'_>> {
    pair.into_inner()
        .map(|target| {
            let mut modifier = None;
            let mut var = None;
            for p in target.into_inner() {
                match p.as_rule() {
                    Rule::modifier => {
                        modifier = Some(if p.as_str() == "!" { Modifier::Exclusion } else { Modifier::Count })
                    }
                    _ => var = Some(var_ref(p)),
                }
            }
            Target { modifier, var: var.expect("a variable") }
        })
        .collect()
}

/// `var_ref` and `macro_var`.
fn var_ref(pair: Pair<'_, Rule>) -> VarRef<'_> {
    let mut inner = pair.into_inner();
    let name = inner.next().expect("a name").as_str();
    let selector = match inner.next() {
        None => Selector::None,
        Some(p) => match p.as_rule() {
            Rule::regex | Rule::regex_quoted | Rule::macro_regex => {
                Selector::Regex(p.into_inner().next().expect("regex text").as_str())
            }
            _ => Selector::Key(p.as_str()),
        },
    };
    VarRef { name, selector }
}

fn pieces(pair: Pair<'_, Rule>) -> Vec<Piece<'_>> {
    pair.into_inner()
        .map(|p| match p.as_rule() {
            Rule::macro_ref => Piece::Macro(var_ref(p.into_inner().next().expect("macro variable"))),
            _ => Piece::Text(p.as_str()),
        })
        .collect()
}

fn operator<'a>(pair: Pair<'a, Rule>, uncounted: &mut usize) -> Operator<'a> {
    let mut op = Operator { negated: false, name: None, param: Vec::new(), raw: "", quoted: false };
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::negated => op.negated = true,
            Rule::op_raw_q | Rule::op_raw_s => {
                op.quoted = p.as_rule() == Rule::op_raw_q;
                op.raw = p.as_str();
                *uncounted += line_feeds(op.raw);
                for q in p.into_inner() {
                    match q.as_rule() {
                        Rule::op_name => op.name = Some(q.into_inner().next().expect("operator name").as_str()),
                        _ => op.param = pieces(q),
                    }
                }
            }
            r => unreachable!("not part of an operator: {r:?}"),
        }
    }
    op
}

/// The actions; line feeds inside them (in quoted texts) are not counted.
fn actions<'a>(pair: Pair<'a, Rule>, from: usize, uncounted: &mut usize) -> Vec<Action<'a>> {
    pair.into_inner()
        .map(|p| {
            *uncounted += line_feeds(p.as_str());
            action(p, from)
        })
        .collect()
}

fn action(pair: Pair<'_, Rule>, from: usize) -> Action<'_> {
    let offset = from + pair.as_span().start();
    let kind = match pair.as_rule() {
        Rule::plain_action => {
            let name = pair.clone().into_inner().next().expect("an action name").as_str();
            ActionKind::Plain { name, text: pair.as_str() }
        }
        Rule::macro_action => {
            let mut inner = pair.into_inner();
            let name = inner.next().expect("an action name").as_str();
            ActionKind::Macro { name, value: inner.next().map(pieces).unwrap_or_default() }
        }
        Rule::initcol => {
            let whole = pair.as_str();
            let start = pair.as_span().start();
            let mut inner = pair.into_inner();
            inner.next(); // initcol:
            let col = inner.next().expect("a collection");
            // `initcol:COLLECTION=`
            let head = &whole[..col.as_span().end() + 1 - start];
            ActionKind::InitCol { text: head, value: inner.next().map(pieces).unwrap_or_default() }
        }
        Rule::setvar => {
            let body = pair.into_inner().next().expect("setvar body");
            let mut unset = false;
            let mut collection = "";
            let mut key = Vec::new();
            let mut op_kind = None;
            let mut op_value = Vec::new();
            for p in body.into_inner() {
                match p.as_rule() {
                    Rule::unset => unset = true,
                    Rule::setvar_target | Rule::setvar_target_q => {
                        let mut t = p.into_inner();
                        collection = t.next().expect("a collection").as_str();
                        key = pieces(t.next().expect("a key"));
                    }
                    Rule::setvar_op => {
                        op_kind = Some(match p.as_str() {
                            "=+" => SetVarOp::Add,
                            "=-" => SetVarOp::Subtract,
                            _ => SetVarOp::Set,
                        })
                    }
                    _ => op_value = pieces(p),
                }
            }
            ActionKind::SetVar { unset, collection, key, op: op_kind.map(|o| (o, op_value)) }
        }
        r => unreachable!("not an action: {r:?}"),
    };
    Action { kind, offset }
}
