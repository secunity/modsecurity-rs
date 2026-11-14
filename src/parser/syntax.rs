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
#[derive(Debug)]
pub struct Statement<'a> {
    pub offset: usize,
    pub directive: Directive<'a>,
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
    let statements =
        file.into_iter().next().expect("a file").into_inner().filter(|p| p.as_rule() == Rule::directive_statement);
    Ok(statements.map(|p| statement_from_pair(0, p)))
}

/// Reads the next statement of `text` from byte offset `from`. Returns the
/// statement (`None` at the end of the text) and the offset after it.
pub fn parse_statement(text: &str, from: usize) -> Result<(Option<Statement<'_>>, usize), SyntaxError> {
    let mut pairs = SecLang::parse(Rule::statement, &text[from..]).map_err(|e| syntax_error(text, from, &e))?;
    Ok(statement_from_pair(from, pairs.next().expect("a statement")))
}

/// A statement from its pair, whose spans are relative to `base`.
fn statement_from_pair(base: usize, statement: Pair<'_, Rule>) -> (Option<Statement<'_>>, usize) {
    let end = base + statement.as_span().end();
    let inner = statement.into_inner().find(|p| {
        matches!(
            p.as_rule(),
            Rule::sec_rule
                | Rule::sec_rule_script
                | Rule::sec_action
                | Rule::sec_default_action
                | Rule::update_target
                | Rule::update_action
                | Rule::setting
        )
    });
    let Some(inner) = inner else {
        return (None, end);
    };
    let offset = base + inner.as_span().start();
    (Some(Statement { offset, directive: directive(inner, base) }), end)
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

/// The directive of a statement. `from` is the offset the pairs' spans are
/// relative to.
fn directive(pair: Pair<'_, Rule>, from: usize) -> Directive<'_> {
    let rule = pair.as_rule();
    let mut inner = pair.into_inner();
    match rule {
        Rule::sec_rule => {
            let variables = targets(inner.next().expect("variables"));
            let operator = operator(inner.next().expect("operator"));
            let actions = inner.next().map(|a| actions(a, from));
            Directive::Rule { variables, operator, actions }
        }
        Rule::sec_rule_script => {
            let path = value(inner.next().expect("path"));
            let actions = inner.next().map(|a| actions(a, from));
            Directive::RuleScript { path, actions }
        }
        Rule::sec_action | Rule::sec_default_action => {
            let list = actions(inner.next().expect("actions"), from);
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
            let variables = targets(inner.next().expect("variables"));
            Directive::UpdateTarget { by, selector, variables }
        }
        Rule::update_action => {
            let lead = &inner.next().expect("separator").as_str()[1..];
            let id = Value { lead, ..value(inner.next().expect("id")) };
            let actions = actions(inner.next().expect("actions"), from);
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

/// The value of a `value` or `update_value` pair: the text, without
/// quotes.
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

/// The variable reference of a `var_ref` or `macro_var` pair.
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

fn operator(pair: Pair<'_, Rule>) -> Operator<'_> {
    let mut op = Operator { negated: false, name: None, param: Vec::new(), raw: "", quoted: false };
    for p in pair.into_inner() {
        match p.as_rule() {
            Rule::negated => op.negated = true,
            Rule::op_raw_q | Rule::op_raw_s => {
                op.quoted = p.as_rule() == Rule::op_raw_q;
                op.raw = p.as_str();
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

fn actions(pair: Pair<'_, Rule>, from: usize) -> Vec<Action<'_>> {
    pair.into_inner().map(|p| action(p, from)).collect()
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
