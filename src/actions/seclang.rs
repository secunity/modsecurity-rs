//! The actions by their SecLang names: what the configuration parser
//! builds from `name` or `name:value`.
//!
//! [`plain`] has the actions with a plain value (and those without one),
//! [`with_macros`] the ones whose value is a string with macros. `setvar`
//! and `initcol` have a grammar of their own and are built by the parser.

use crate::actions::action::{InertAction, name_and_payload};
use crate::actions::rule_action::RuleAction;
use crate::actions::transformation::{Transformation, TransformationKind};
use crate::actions::{self, ctl, data, disruptive};
use crate::audit_log::AuditLogStatus;
use crate::parser::syntax::value::is_audit_part;
use crate::rule::RuleProperty;
use crate::rules_set::properties::{ParseXmlIntoArgs, RuleEngine};
use crate::run_time_string::RunTimeString;

/// An action of a rule as the parser builds it: a property of the rule
/// (`id`, `phase`, ...), a transformation, or any other action.
#[derive(Debug)]
pub(crate) enum ParsedAction {
    Property(RuleProperty),
    Action(RuleAction),
    Transformation(Transformation),
}

#[cfg(test)]
impl ParsedAction {
    /// The name, as written in the rule.
    pub(crate) fn name(&self) -> &str {
        match self {
            ParsedAction::Property(p) => &p.name,
            ParsedAction::Action(a) => a.name(),
            ParsedAction::Transformation(t) => crate::actions::action::Action::name(t),
        }
    }
}

/// An action (not a transformation) as the parser builds it.
pub(crate) fn other(a: impl Into<RuleAction>) -> ParsedAction {
    ParsedAction::Action(a.into())
}

/// The actions of a rule, sorted: its properties, its run time actions
/// and its transformations.
#[derive(Debug, Default)]
pub(crate) struct RuleActions {
    pub(crate) properties: Vec<RuleProperty>,
    pub(crate) actions: Vec<RuleAction>,
    pub(crate) transformations: Vec<Transformation>,
}

/// Sorts the actions of a rule.
pub(crate) fn split_actions(list: Vec<ParsedAction>) -> RuleActions {
    let mut out = RuleActions::default();
    for i in list {
        match i {
            ParsedAction::Property(p) => out.properties.push(p),
            ParsedAction::Action(a) => out.actions.push(a),
            ParsedAction::Transformation(t) => out.transformations.push(t),
        }
    }
    out
}

/// The action `name` whose value is the string with macros `z` (`msg`,
/// `logdata`, `tag`, `setenv`, `setrsc`, `setsid`, `setuid`, `expirevar`,
/// `redirect`: the names of the grammar's `macro_name`).
pub(crate) fn with_macros(name: &str, z: RunTimeString) -> ParsedAction {
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

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Whether an action takes the value written after its name (`None`: the
/// name alone).
type Accepts = fn(Option<&str>) -> bool;

/// Builds the action from its name as written and its payload (the value
/// without its quotes, see [`name_and_payload`]); the error is the message
/// to report.
type Build = fn(&str, &str) -> Result<ParsedAction, String>;

/// The text of a quoted value (`'...'`).
fn unquote(v: &str) -> Option<&str> {
    v.strip_prefix('\'')?.strip_suffix('\'')
}

/// The value without its quotes, when it has them.
fn unquoted(v: &str) -> &str {
    unquote(v).unwrap_or(v)
}

fn is_number(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit())
}

/// No value.
fn bare(value: Option<&str>) -> bool {
    value.is_none()
}

/// A number, not quoted.
fn number(value: Option<&str>) -> bool {
    value.is_some_and(is_number)
}

/// A number, quoted or not.
fn number_or_quoted(value: Option<&str>) -> bool {
    value.is_some_and(|v| is_number(unquoted(v)))
}

/// Some text, quoted or not.
fn text(value: Option<&str>) -> bool {
    value.is_some_and(|v| !unquoted(v).is_empty())
}

/// Some text in quotes.
fn quoted_text(value: Option<&str>) -> bool {
    value.and_then(unquote).is_some_and(|q| !q.is_empty())
}

/// Some text that does not start with a quote.
fn word(value: Option<&str>) -> bool {
    value.is_some_and(|v| !v.is_empty() && !v.starts_with('\''))
}

/// A number or one of `names`, quoted or not.
fn number_or_name(value: Option<&str>, names: &[&str]) -> bool {
    value.is_some_and(|v| {
        let v = unquoted(v);
        is_number(v) || names.iter().any(|n| v.eq_ignore_ascii_case(n))
    })
}

fn unsupported(name: &'static str) -> Result<ParsedAction, String> {
    Err(format!("Action: {} is not yet supported.", name))
}

/// The actions with a plain value: the name (lower case), the values it
/// takes and how it is built.
const PLAIN: &[(&str, Accepts, Build)] = &[
    ("accuracy", text, |n, p| RuleProperty::accuracy(n, p).map(ParsedAction::Property)),
    (
        "allow",
        |v| v.is_none_or(|v| v.eq_ignore_ascii_case("request") || v.eq_ignore_ascii_case("phase")),
        |n, p| disruptive::allow::Allow::new(n, p).map(other),
    ),
    ("append", bare, |_, _| unsupported("Append")),
    ("auditlog", bare, |n, _| Ok(other(actions::audit_log::AuditLog::new(n)))),
    ("block", bare, |n, _| Ok(other(actions::block::Block::new(n)))),
    ("capture", bare, |n, _| Ok(other(actions::capture::Capture::new(n)))),
    ("chain", bare, |n, _| Ok(ParsedAction::Property(RuleProperty::chain(n)))),
    ("deny", bare, |n, _| Ok(other(disruptive::deny::Deny::new(n)))),
    ("deprecatevar", bare, |_, _| unsupported("DeprecateVar")),
    ("drop", bare, |n, _| Ok(other(disruptive::drop::Drop::new(n)))),
    ("exec", |v| quoted_text(v) || word(v), |n, p| actions::exec::Exec::new(n, p).map(other)),
    ("id", number_or_quoted, |n, p| RuleProperty::id(n, p).map(ParsedAction::Property)),
    ("log", bare, |n, _| Ok(other(actions::log::Log::new(n)))),
    ("maturity", text, |n, p| RuleProperty::maturity(n, p).map(ParsedAction::Property)),
    ("multimatch", bare, |n, _| Ok(other(actions::multi_match::MultiMatch::new(n)))),
    ("noauditlog", bare, |n, _| Ok(other(actions::no_audit_log::NoAuditLog::new(n)))),
    ("nolog", bare, |n, _| Ok(other(actions::no_log::NoLog::new(n)))),
    ("pass", bare, |n, _| Ok(other(disruptive::pass::Pass::new(n)))),
    ("pause", bare, |_, _| unsupported("Pause")),
    (
        "phase",
        |v| number_or_name(v, &["request", "response", "logging"]),
        |n, p| RuleProperty::phase(n, p).map(ParsedAction::Property),
    ),
    ("prepend", bare, |_, _| unsupported("Prepend")),
    ("proxy", bare, |_, _| unsupported("Proxy")),
    (
        "rev",
        |v| text(v) && !v.is_some_and(|v| unquoted(v).contains([',', '\''])),
        |n, p| Ok(ParsedAction::Property(RuleProperty::rev(n, p))),
    ),
    ("sanitisearg", bare, |_, _| unsupported("SanitiseArg")),
    ("sanitisematched", bare, |_, _| unsupported("SanitiseMatched")),
    ("sanitisematchedbytes", bare, |_, _| unsupported("SanitiseMatchedBytes")),
    ("sanitiserequestheader", bare, |_, _| unsupported("SanitiseRequestHeader")),
    ("sanitiseresponseheader", bare, |_, _| unsupported("SanitiseResponseHeader")),
    (
        "severity",
        |v| number_or_name(v, &["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"]),
        |n, p| actions::severity::Severity::new(n, p).map(other),
    ),
    ("skip", number, |n, p| actions::skip::Skip::new(n, p).map(other)),
    ("skipafter", word, |n, p| Ok(other(actions::skip_after::SkipAfter::new(n, p)))),
    ("status", number, |n, p| data::status::Status::new(n, p).map(other)),
    ("ver", quoted_text, |n, p| Ok(ParsedAction::Property(RuleProperty::ver(n, p)))),
    ("xmlns", word, |n, p| actions::xmlns::XmlNS::new(n, p).map(other)),
];

/// An action other than `setvar`, `initcol` and the actions with macros:
/// `text` is the whole action as written (`name` or `name:value`). The
/// error is the message to report: the action is unknown, its value is
/// not one it takes, or the action itself refuses it.
pub(crate) fn plain(name: &str, text: &str) -> Result<ParsedAction, String> {
    let value = text.split_once(':').map(|(_, v)| v);
    let invalid = || format!("Expecting an action, got: {}", text);
    // The name as the action keeps it (`t:lowercase` for a transformation)
    // and the value without its quotes.
    let (written, payload) = name_and_payload(text);
    let name = name.to_ascii_lowercase();
    match name.as_str() {
        "t" => {
            let kind = value.and_then(TransformationKind::from_name).ok_or_else(invalid)?;
            Ok(ParsedAction::Transformation(Transformation::new(kind, written)))
        }
        "ctl" => ctl_action(written, payload, value.unwrap_or("")).ok_or_else(invalid)?,
        _ => match PLAIN.iter().find(|(n, ..)| *n == name) {
            Some((_, accepts, build)) if accepts(value) => build(written, payload),
            _ => Err(invalid()),
        },
    }
}

/// Whether `c` may appear in the value of a `ctl:ruleRemoveById`,
/// `ctl:ruleRemoveByTag`, `ctl:ruleRemoveTargetById` or
/// `ctl:ruleRemoveTargetByTag` action.
fn is_remove_rule_by(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"_-.*/:;$@=()[]'".contains(&c)
}

/// `ctl:<option>`, where `option` is `<name>=<value>`; `None` when the
/// name is not a `ctl` option or does not take the value. `ctl` is the
/// action name as written, `payload` the option as the actions read it.
fn ctl_action(ctl: &str, payload: &str, option: &str) -> Option<Result<ParsedAction, String>> {
    let (name, value) = option.split_once('=')?;
    let is = |v: &str| value.eq_ignore_ascii_case(v);
    let on_off = || is("on") || is("off");
    let a = match name.to_ascii_lowercase().as_str() {
        "auditengine" => other(ctl::audit_engine::AuditEngine::new(if is("on") {
            AuditLogStatus::On
        } else if is("off") {
            AuditLogStatus::Off
        } else if is("relevantonly") {
            AuditLogStatus::RelevantOnly
        } else {
            return None;
        })),
        "auditlogparts"
            if value.len() >= 2
                && matches!(value.as_bytes()[0], b'+' | b'|' | b'-')
                && value[1..].bytes().all(is_audit_part) =>
        {
            other(ctl::audit_log_parts::AuditLogParts::new(ctl, payload))
        }
        "requestbodyprocessor" if is("json") => {
            other(ctl::request_body_processor_json::RequestBodyProcessorJSON::new(ctl))
        }
        "requestbodyprocessor" if is("xml") => {
            other(ctl::request_body_processor_xml::RequestBodyProcessorXML::new(ctl))
        }
        "requestbodyprocessor" if is("urlencoded") => {
            other(ctl::request_body_processor_urlencoded::RequestBodyProcessorURLENCODED::new(ctl))
        }
        "forcerequestbodyvariable" if on_off() => other(InertAction::new(ctl)),
        "parsexmlintoargs" => other(ctl::parse_xml_into_args::ParseXmlIntoArgs::new(if is("on") {
            ParseXmlIntoArgs::On
        } else if is("off") {
            ParseXmlIntoArgs::Off
        } else if is("onlyargs") {
            ParseXmlIntoArgs::OnlyArgs
        } else {
            return None;
        })),
        "requestbodyaccess" if on_off() => other(ctl::request_body_access::RequestBodyAccess::new(ctl, is("on"))),
        "ruleengine" => other(ctl::rule_engine::RuleEngine::new(if is("on") {
            RuleEngine::Enabled
        } else if is("off") {
            RuleEngine::Disabled
        } else if is("detectiononly") {
            RuleEngine::DetectionOnly
        } else {
            return None;
        })),
        by @ ("ruleremovebyid" | "ruleremovebytag" | "ruleremovetargetbyid" | "ruleremovetargetbytag")
            if !value.is_empty() && value.bytes().all(is_remove_rule_by) =>
        {
            return Some(match by {
                "ruleremovebyid" => ctl::rule_remove_by_id::RuleRemoveById::new(ctl, payload).map(other),
                "ruleremovebytag" => ctl::rule_remove_by_tag::RuleRemoveByTag::new(ctl, payload).map(other),
                "ruleremovetargetbyid" => {
                    ctl::rule_remove_target_by_id::RuleRemoveTargetById::new(ctl, payload).map(other)
                }
                _ => ctl::rule_remove_target_by_tag::RuleRemoveTargetByTag::new(ctl, payload).map(other),
            });
        }
        _ => return None,
    };
    Some(Ok(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sorted_and_lower_case() {
        let names: Vec<&str> = PLAIN.iter().map(|(n, ..)| *n).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted);
        assert!(names.iter().all(|n| n.bytes().all(|c| c.is_ascii_lowercase())));
    }

    #[test]
    fn values_an_action_takes() {
        let built = |name: &str, text: &str| plain(name, text).map(|a| a.name().to_string());
        let invalid = |text: &str| Err(format!("Expecting an action, got: {text}"));
        assert_eq!(built("deny", "deny"), Ok("deny".to_string()));
        assert_eq!(built("DENY", "DENY"), Ok("DENY".to_string()));
        assert_eq!(built("deny", "deny:1"), invalid("deny:1"));
        assert_eq!(built("status", "status:403"), Ok("status".to_string()));
        assert_eq!(built("status", "status:'403'"), invalid("status:'403'"));
        assert_eq!(built("id", "id:'7'"), Ok("id".to_string()));
        assert_eq!(built("ver", "ver:1"), invalid("ver:1"));
        assert_eq!(built("rev", "rev:'a,b'"), invalid("rev:'a,b'"));
        assert_eq!(built("t", "t:lowercase"), Ok("t:lowercase".to_string()));
        assert_eq!(built("t", "t:nosuch"), invalid("t:nosuch"));
        assert_eq!(built("pause", "pause"), Err("Action: Pause is not yet supported.".to_string()));
        assert_eq!(built("pause", "pause:1"), invalid("pause:1"));
        assert_eq!(built("nosuch", "nosuch"), invalid("nosuch"));
        assert_eq!(built("ctl", "ctl:ruleEngine=Off"), Ok("ctl".to_string()));
        assert_eq!(built("ctl", "ctl:ruleEngine=Maybe"), invalid("ctl:ruleEngine=Maybe"));
        assert_eq!(built("ctl", "ctl:ruleEngine"), invalid("ctl:ruleEngine"));
        assert_eq!(built("ctl", "ctl:auditLogParts=+E"), Ok("ctl".to_string()));
        assert_eq!(built("ctl", "ctl:auditLogParts=E"), invalid("ctl:auditLogParts=E"));
    }
}
