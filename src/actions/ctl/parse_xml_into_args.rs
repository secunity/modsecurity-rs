//! Port of `src/actions/ctl/parse_xml_into_args.cc`, `src/actions/ctl/parse_xml_into_args.h`.
//!
//! `ctl:parseXmlIntoArgs=On|Off|OnlyArgs` — overrides
//! `SecParseXmlIntoArgs` for the transaction.

use crate::actions::action::Action;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::rules_set_properties::{self, config_xml_parse_xml_into_args_string};
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct ParseXmlIntoArgs {
    value: rules_set_properties::ParseXmlIntoArgs,
}

impl ParseXmlIntoArgs {
    pub fn new(value: rules_set_properties::ParseXmlIntoArgs) -> Self {
        ParseXmlIntoArgs { value }
    }
}

impl Action for ParseXmlIntoArgs {
    fn name(&self) -> &str {
        "ctl"
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        crate::ms_dbg_a!(
            t,
            8,
            "Setting SecParseXmlIntoArgs to {} as requested by a ctl:parseXmlIntoArgs action",
            config_xml_parse_xml_into_args_string(Some(self.value))
        );
        t.sec_xml_parse_xml_into_args = Some(self.value);
    }
}
