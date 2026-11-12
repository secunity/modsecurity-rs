//! Port of `src/actions/ctl/rule_engine.cc`, `src/actions/ctl/rule_engine.h`.
//!
//! `ctl:ruleEngine=On|Off|DetectionOnly` — overrides `SecRuleEngine` for
//! the transaction.

use crate::actions::action::Action;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::rules_set_properties::{self, rule_engine_state_string};
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct RuleEngine {
    state: rules_set_properties::RuleEngine,
}

impl RuleEngine {
    pub fn new(state: rules_set_properties::RuleEngine) -> Self {
        RuleEngine { state }
    }
}

impl Action for RuleEngine {
    fn name(&self) -> &str {
        "ctl"
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(
            t,
            8,
            "Setting SecRuleEngine to {} as requested by a ctl:ruleEngine action",
            rule_engine_state_string(Some(self.state))
        );
        t.sec_rule_engine = Some(self.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::block::test_support::*;
    use crate::actions::ctl::audit_engine::AuditEngine;
    use crate::actions::ctl::audit_log_parts::AuditLogParts;
    use crate::actions::ctl::parse_xml_into_args::ParseXmlIntoArgs;
    use crate::actions::ctl::request_body_access::RequestBodyAccess;
    use crate::actions::ctl::request_body_processor_json::RequestBodyProcessorJSON;
    use crate::actions::ctl::request_body_processor_urlencoded::RequestBodyProcessorURLENCODED;
    use crate::actions::ctl::request_body_processor_xml::RequestBodyProcessorXML;
    use crate::audit_log::{AuditLogStatus, PartsChange};
    use crate::modsecurity::ModSecurity;
    use crate::rules_set_properties::ParseXmlIntoArgs as ParseXmlIntoArgsState;
    use crate::transaction::RequestBodyType;

    fn run(a: &dyn Action, t: &mut Transaction<'_>) {
        let r = rule(vec![]);
        let mut rm = RuleMessage::new(&r);
        a.evaluate(&r, t, &mut rm);
    }

    /// The ctl actions that change transaction settings.
    #[test]
    fn settings() {
        let ms = ModSecurity::new();
        let rules = rules();
        let mut t = Transaction::new(&ms, &rules, None);

        let engine = RuleEngine::new(rules_set_properties::RuleEngine::DetectionOnly);
        assert_eq!(engine.name(), "ctl");
        run(&engine, &mut t);
        assert_eq!(t.sec_rule_engine, Some(rules_set_properties::RuleEngine::DetectionOnly));
        assert!(has_log(&t, "Setting SecRuleEngine to DetectionOnly as requested by a ctl:ruleEngine action"));

        run(&AuditEngine::new(AuditLogStatus::RelevantOnly), &mut t);
        assert_eq!(t.ctl_audit_engine, Some(AuditLogStatus::RelevantOnly));
        assert!(has_log(&t, "Setting SecAuditEngine to 3 as requested by a ctl:auditEngine action"));

        run(&ParseXmlIntoArgs::new(ParseXmlIntoArgsState::OnlyArgs), &mut t);
        assert_eq!(t.sec_xml_parse_xml_into_args, Some(ParseXmlIntoArgsState::OnlyArgs));
        assert!(has_log(&t, "Setting SecParseXmlIntoArgs to OnlyArgs as requested by a ctl:parseXmlIntoArgs action"));

        // The name keeps the spelling of the rule.
        let access = RequestBodyAccess::new("CTL:requestBodyAccess=", false);
        assert_eq!(access.name(), "CTL");
        run(&access, &mut t);
        assert_eq!(t.request_body_access, Some(false));
        run(&RequestBodyAccess::new("ctl:requestBodyAccess=", true), &mut t);
        assert_eq!(t.request_body_access, Some(true));

        run(&AuditLogParts::new("ctl:auditLogParts=+E"), &mut t);
        run(&AuditLogParts::new("ctl:auditLogParts=-HK"), &mut t);
        assert_eq!(
            t.audit_log_modifier,
            vec![(PartsChange::Add, "E".to_string()), (PartsChange::Remove, "HK".to_string())]
        );

        run(&RequestBodyProcessorJSON::new("ctl:requestBodyProcessor=JSON"), &mut t);
        assert_eq!(t.request_body_processor, RequestBodyType::JSONRequestBody);
        assert_eq!(t.vars.reqbody_processor.evaluate(), b"JSON");
        run(&RequestBodyProcessorXML::new("ctl:requestBodyProcessor=XML"), &mut t);
        assert_eq!(t.request_body_processor, RequestBodyType::XMLRequestBody);
        run(&RequestBodyProcessorURLENCODED::new("ctl:requestBodyProcessor=URLENCODED"), &mut t);
        assert_eq!(t.request_body_type, RequestBodyType::WWWFormUrlEncoded);
        assert_eq!(t.vars.reqbody_processor.evaluate(), b"URLENCODED");
    }
}
