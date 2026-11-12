//! Port of `src/actions/ctl/rule_engine.cc`, `src/actions/ctl/rule_engine.h`.
//!
//! `ctl:ruleEngine=On|Off|DetectionOnly` — overrides `SecRuleEngine` for
//! the transaction.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::rules_set_properties::{self, rule_engine_state_string};
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct RuleEngine {
    pub base: ActionBase,
    pub rule_engine: Option<rules_set_properties::RuleEngine>,
}

impl RuleEngine {
    pub fn new(action: &str) -> Self {
        RuleEngine { base: ActionBase::new(action), rule_engine: None }
    }
}

impl Action for RuleEngine {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        // The parser builds the payload as `RuleEngine=<value>`.
        let what = self.base.parser_payload.get(11..).unwrap_or("");
        self.rule_engine = match what {
            "on" => Some(rules_set_properties::RuleEngine::Enabled),
            "off" => Some(rules_set_properties::RuleEngine::Disabled),
            "detectiononly" => Some(rules_set_properties::RuleEngine::DetectionOnly),
            _ => {
                return Err(format!(
                    "Internal error. Expected: On, Off or DetectionOnly; got: {}",
                    self.base.parser_payload
                ));
            }
        };
        Ok(())
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(
            t,
            8,
            "Setting SecRuleEngine to {} as requested by a ctl:ruleEngine action",
            rule_engine_state_string(self.rule_engine)
        );
        t.sec_rule_engine = self.rule_engine;
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
    use crate::audit_log::audit_log::AuditLogStatus;
    use crate::modsecurity::ModSecurity;
    use crate::rules_set_properties::ParseXmlIntoArgs as ParseXmlIntoArgsState;
    use crate::transaction::RequestBodyType;

    fn run(a: &mut dyn Action, t: &mut Transaction<'_>) {
        a.init().unwrap();
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

        run(&mut RuleEngine::new("ctl:RuleEngine=detectiononly"), &mut t);
        assert_eq!(t.sec_rule_engine, Some(rules_set_properties::RuleEngine::DetectionOnly));
        assert!(has_log(&t, "Setting SecRuleEngine to DetectionOnly as requested by a ctl:ruleEngine action"));
        assert_eq!(
            RuleEngine::new("ctl:RuleEngine=x").init(),
            Err("Internal error. Expected: On, Off or DetectionOnly; got: RuleEngine=x".to_string())
        );

        run(&mut AuditEngine::new("ctl:auditengine=relevantonly"), &mut t);
        assert_eq!(t.ctl_audit_engine, AuditLogStatus::RelevantOnlyAuditLogStatus);
        assert!(has_log(&t, "Setting SecAuditEngine to 3 as requested by a ctl:auditEngine action"));
        assert_eq!(
            AuditEngine::new("ctl:auditengine=x").init(),
            Err("Internal error. Expected: On, Off or RelevantOnly; got: auditengine=x".to_string())
        );

        run(&mut ParseXmlIntoArgs::new("ctl:parseXmlIntoArgs=onlyargs"), &mut t);
        assert_eq!(t.sec_xml_parse_xml_into_args, Some(ParseXmlIntoArgsState::OnlyArgs));
        assert!(has_log(&t, "Setting SecParseXmlIntoArgs to OnlyArgs as requested by a ctl:parseXmlIntoArgs action"));

        run(&mut RequestBodyAccess::new("ctl:requestBodyAccess=false"), &mut t);
        assert_eq!(t.request_body_access, Some(false));
        run(&mut RequestBodyAccess::new("ctl:requestBodyAccess=true"), &mut t);
        assert_eq!(t.request_body_access, Some(true));
        assert_eq!(
            RequestBodyAccess::new("ctl:requestBodyAccess=on").init(),
            Err("Internal error. Expected: true or false, got: requestBodyAccess=on".to_string())
        );

        run(&mut AuditLogParts::new("ctl:auditLogParts=+E"), &mut t);
        run(&mut AuditLogParts::new("ctl:auditLogParts=-HK"), &mut t);
        assert_eq!(t.audit_log_modifier, vec![(0, "E".to_string()), (1, "HK".to_string())]);

        run(&mut RequestBodyProcessorJSON::new("ctl:requestBodyProcessor=JSON"), &mut t);
        assert_eq!(t.request_body_processor, RequestBodyType::JSONRequestBody);
        assert_eq!(t.vars.reqbody_processor.evaluate(), b"JSON");
        run(&mut RequestBodyProcessorXML::new("ctl:requestBodyProcessor=XML"), &mut t);
        assert_eq!(t.request_body_processor, RequestBodyType::XMLRequestBody);
        run(&mut RequestBodyProcessorURLENCODED::new("ctl:requestBodyProcessor=URLENCODED"), &mut t);
        assert_eq!(t.request_body_type, RequestBodyType::WWWFormUrlEncoded);
        assert_eq!(t.vars.reqbody_processor.evaluate(), b"URLENCODED");
    }
}
