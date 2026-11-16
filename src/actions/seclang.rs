//! The actions by their SecLang names: what the configuration parser
//! builds from `name` or `name:value`.
//!
//! [`plain`] has the actions with a plain value (and those without one),
//! [`with_macros`] the ones whose value is a string with macros. `setvar`
//! and `initcol` have a grammar of their own and are built by the parser.

use crate::actions::action::InertAction;
use crate::actions::rule_action::RuleAction;
use crate::actions::transformation::{Transformation, TransformationKind};
use crate::actions::{self, ctl, data, disruptive};
use crate::audit_log::AuditLogStatus;
use crate::rules_set::properties::{ParseXmlIntoArgs, RuleEngine};
use crate::run_time_string::RunTimeString;

/// An action of a rule as the parser builds it: the C++ code keeps both
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

/// An action (not a transformation) as the parser builds it.
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
/// name alone). These are the token shapes of the C++ scanner.
type Accepts = fn(Option<&str>) -> bool;

/// Builds the action from its whole text (`name` or `name:value`, quotes
/// included); the error is the message to report.
type Build = fn(&str) -> Result<ParsedAction, String>;

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
    ("accuracy", text, |s| actions::accuracy::Accuracy::new(s).map(other)),
    (
        "allow",
        |v| v.is_none_or(|v| v.eq_ignore_ascii_case("request") || v.eq_ignore_ascii_case("phase")),
        |s| disruptive::allow::Allow::new(s).map(other),
    ),
    ("append", bare, |_| unsupported("Append")),
    ("auditlog", bare, |s| Ok(other(actions::audit_log::AuditLog::new(s)))),
    ("block", bare, |s| Ok(other(actions::block::Block::new(s)))),
    ("capture", bare, |s| Ok(other(actions::capture::Capture::new(s)))),
    ("chain", bare, |s| Ok(other(actions::chain::Chain::new(s)))),
    ("deny", bare, |s| Ok(other(disruptive::deny::Deny::new(s)))),
    ("deprecatevar", bare, |_| unsupported("DeprecateVar")),
    ("drop", bare, |s| Ok(other(disruptive::drop::Drop::new(s)))),
    ("exec", |v| quoted_text(v) || word(v), |s| actions::exec::Exec::new(s).map(other)),
    ("id", number_or_quoted, |s| actions::rule_id::RuleId::new(s).map(other)),
    ("log", bare, |s| Ok(other(actions::log::Log::new(s)))),
    ("maturity", text, |s| actions::maturity::Maturity::new(s).map(other)),
    ("multimatch", bare, |s| Ok(other(actions::multi_match::MultiMatch::new(s)))),
    ("noauditlog", bare, |s| Ok(other(actions::no_audit_log::NoAuditLog::new(s)))),
    ("nolog", bare, |s| Ok(other(actions::no_log::NoLog::new(s)))),
    ("pass", bare, |s| Ok(other(disruptive::pass::Pass::new(s)))),
    ("pause", bare, |_| unsupported("Pause")),
    ("phase", |v| number_or_name(v, &["request", "response", "logging"]), |s| actions::phase::Phase::new(s).map(other)),
    ("prepend", bare, |_| unsupported("Prepend")),
    ("proxy", bare, |_| unsupported("Proxy")),
    (
        "rev",
        |v| text(v) && !v.is_some_and(|v| unquoted(v).contains([',', '\''])),
        |s| Ok(other(actions::rev::Rev::new(s))),
    ),
    ("sanitisearg", bare, |_| unsupported("SanitiseArg")),
    ("sanitisematched", bare, |_| unsupported("SanitiseMatched")),
    ("sanitisematchedbytes", bare, |_| unsupported("SanitiseMatchedBytes")),
    ("sanitiserequestheader", bare, |_| unsupported("SanitiseRequestHeader")),
    ("sanitiseresponseheader", bare, |_| unsupported("SanitiseResponseHeader")),
    (
        "severity",
        |v| number_or_name(v, &["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"]),
        |s| actions::severity::Severity::new(s).map(other),
    ),
    ("skip", number, |s| actions::skip::Skip::new(s).map(other)),
    ("skipafter", word, |s| Ok(other(actions::skip_after::SkipAfter::new(s)))),
    ("status", number, |s| data::status::Status::new(s).map(other)),
    ("ver", quoted_text, |s| Ok(other(actions::ver::Ver::new(s)))),
    ("xmlns", word, |s| actions::xmlns::XmlNS::new(s).map(other)),
];

/// An action other than `setvar`, `initcol` and the actions with macros:
/// `text` is the whole action as written (`name` or `name:value`). The
/// error is the message to report: the action is unknown, its value is
/// not one it takes, or the action itself refuses it.
pub(crate) fn plain(name: &str, text: &str) -> Result<ParsedAction, String> {
    let value = text.split_once(':').map(|(_, v)| v);
    let invalid = || format!("Expecting an action, got: {}", text);
    let name = name.to_ascii_lowercase();
    match name.as_str() {
        "t" => {
            let kind = value.and_then(TransformationKind::from_name).ok_or_else(invalid)?;
            Ok(ParsedAction::Transformation(Transformation::new(kind, text)))
        }
        "ctl" => ctl_action(text, value.unwrap_or("")).ok_or_else(invalid)?,
        _ => match PLAIN.iter().find(|(n, ..)| *n == name) {
            Some((_, accepts, build)) if accepts(value) => build(text),
            _ => Err(invalid()),
        },
    }
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

/// `ctl:<option>`, where `option` is `<name>=<value>`; `None` when the
/// name is not a `ctl` option or does not take the value.
fn ctl_action(text: &str, option: &str) -> Option<Result<ParsedAction, String>> {
    let (name, value) = option.split_once('=')?;
    // `ctl:<name>=`, what the actions with a value token are built from.
    let head = &text[..text.len() - value.len()];
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
            other(ctl::audit_log_parts::AuditLogParts::new(text))
        }
        "requestbodyprocessor" if is("json") => {
            other(ctl::request_body_processor_json::RequestBodyProcessorJSON::new(text))
        }
        "requestbodyprocessor" if is("xml") => {
            other(ctl::request_body_processor_xml::RequestBodyProcessorXML::new(text))
        }
        "requestbodyprocessor" if is("urlencoded") => {
            other(ctl::request_body_processor_urlencoded::RequestBodyProcessorURLENCODED::new(text))
        }
        "forcerequestbodyvariable" if on_off() => other(InertAction::new(head)),
        "parsexmlintoargs" => other(ctl::parse_xml_into_args::ParseXmlIntoArgs::new(if is("on") {
            ParseXmlIntoArgs::On
        } else if is("off") {
            ParseXmlIntoArgs::Off
        } else if is("onlyargs") {
            ParseXmlIntoArgs::OnlyArgs
        } else {
            return None;
        })),
        "requestbodyaccess" if on_off() => other(ctl::request_body_access::RequestBodyAccess::new(head, is("on"))),
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
                "ruleremovebyid" => ctl::rule_remove_by_id::RuleRemoveById::new(text).map(other),
                "ruleremovebytag" => ctl::rule_remove_by_tag::RuleRemoveByTag::new(text).map(other),
                "ruleremovetargetbyid" => ctl::rule_remove_target_by_id::RuleRemoveTargetById::new(text).map(other),
                _ => ctl::rule_remove_target_by_tag::RuleRemoveTargetByTag::new(text).map(other),
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
        let built = |name: &str, text: &str| plain(name, text).map(|a| a.into_action().name().to_string());
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
