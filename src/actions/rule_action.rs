//! [`RuleAction`]: the closed set of SecLang actions.
//!
//! Every action the parser can build is one variant, holding the action's
//! own type. Code that needs to know which action it has (a transformation,
//! an `xmlns`, `block`) matches on the variant; the operations every
//! action has ([`Action`]: name, kind, configure, evaluate) are dispatched
//! by a `match` as well, so no action is behind a trait object.

use crate::actions::action::{Action, Kind};
use crate::actions::context::ActionContext;
use crate::actions::{self, ctl, data, disruptive};
use crate::rule::Rule;

/// Declares [`RuleAction`] with one variant per action type, the
/// `From` conversions, and the dispatch of the [`Action`] operations.
macro_rules! rule_actions {
    ($($variant:ident($ty:ty),)*) => {
        /// A SecLang action of a rule, a `SecDefaultAction` or a
        /// `SecRuleUpdateActionById`.
        pub enum RuleAction {
            $($variant($ty),)*
        }

        $(
            impl From<$ty> for RuleAction {
                fn from(a: $ty) -> Self {
                    RuleAction::$variant(a)
                }
            }
        )*

        impl RuleAction {
            /// The action name, as written in the rule.
            pub fn name(&self) -> &str {
                match self { $(RuleAction::$variant(a) => a.name(),)* }
            }

            /// When the action runs.
            pub fn kind(&self) -> Kind {
                match self { $(RuleAction::$variant(a) => a.kind(),)* }
            }

            pub fn is_disruptive(&self) -> bool {
                match self { $(RuleAction::$variant(a) => a.is_disruptive(),)* }
            }

            /// Applies a [`Kind::Configuration`] action to its rule.
            pub fn configure(&self, rule: &mut Rule) {
                match self { $(RuleAction::$variant(a) => a.configure(rule),)* }
            }

            /// Runs the action.
            pub fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
                match self { $(RuleAction::$variant(a) => a.evaluate(cx),)* }
            }
        }

        /// The action's own `Debug` (the variant adds nothing).
        impl std::fmt::Debug for RuleAction {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self { $(RuleAction::$variant(a) => a.fmt(f),)* }
            }
        }
    };
}

rule_actions! {
    Accuracy(actions::accuracy::Accuracy),
    Allow(disruptive::allow::Allow),
    AuditLog(actions::audit_log::AuditLog),
    Block(actions::block::Block),
    Capture(actions::capture::Capture),
    Chain(actions::chain::Chain),
    CtlAuditEngine(ctl::audit_engine::AuditEngine),
    CtlAuditLogParts(ctl::audit_log_parts::AuditLogParts),
    CtlParseXmlIntoArgs(ctl::parse_xml_into_args::ParseXmlIntoArgs),
    CtlRequestBodyAccess(ctl::request_body_access::RequestBodyAccess),
    CtlRequestBodyProcessorJson(ctl::request_body_processor_json::RequestBodyProcessorJSON),
    CtlRequestBodyProcessorUrlencoded(ctl::request_body_processor_urlencoded::RequestBodyProcessorURLENCODED),
    CtlRequestBodyProcessorXml(ctl::request_body_processor_xml::RequestBodyProcessorXML),
    CtlRuleEngine(ctl::rule_engine::RuleEngine),
    CtlRuleRemoveById(ctl::rule_remove_by_id::RuleRemoveById),
    CtlRuleRemoveByTag(ctl::rule_remove_by_tag::RuleRemoveByTag),
    CtlRuleRemoveTargetById(ctl::rule_remove_target_by_id::RuleRemoveTargetById),
    CtlRuleRemoveTargetByTag(ctl::rule_remove_target_by_tag::RuleRemoveTargetByTag),
    Deny(disruptive::deny::Deny),
    Drop(disruptive::drop::Drop),
    Exec(actions::exec::Exec),
    ExpireVar(actions::expire_var::ExpireVar),
    Inert(actions::action::InertAction),
    InitCol(actions::init_col::InitCol),
    Log(actions::log::Log),
    LogData(actions::log_data::LogData),
    Maturity(actions::maturity::Maturity),
    Msg(actions::msg::Msg),
    MultiMatch(actions::multi_match::MultiMatch),
    NoAuditLog(actions::no_audit_log::NoAuditLog),
    NoLog(actions::no_log::NoLog),
    Pass(disruptive::pass::Pass),
    Phase(actions::phase::Phase),
    Redirect(disruptive::redirect::Redirect),
    Rev(actions::rev::Rev),
    RuleId(actions::rule_id::RuleId),
    SetEnv(actions::set_env::SetENV),
    SetRsc(actions::set_rsc::SetRSC),
    SetSid(actions::set_sid::SetSID),
    SetUid(actions::set_uid::SetUID),
    SetVar(actions::set_var::SetVar),
    Severity(actions::severity::Severity),
    Skip(actions::skip::Skip),
    SkipAfter(actions::skip_after::SkipAfter),
    Status(data::status::Status),
    Tag(actions::tag::Tag),
    Transformation(actions::transformation::Transformation),
    Ver(actions::ver::Ver),
    XmlNs(actions::xmlns::XmlNS),
}

impl RuleAction {
    /// The transformation, if this action is one.
    pub fn as_transformation(&self) -> Option<&actions::transformation::Transformation> {
        match self {
            RuleAction::Transformation(t) => Some(t),
            _ => None,
        }
    }

    /// Whether this is `t:none`.
    pub fn is_transformation_none(&self) -> bool {
        self.as_transformation().is_some_and(actions::transformation::Transformation::is_none)
    }
}
