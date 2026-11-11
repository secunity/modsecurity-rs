//! Port of `src/actions/ctl/parse_xml_into_args.cc`, `src/actions/ctl/parse_xml_into_args.h`.
//!
//! `ctl:parseXmlIntoArgs=On|Off|OnlyArgs` — overrides
//! `SecParseXmlIntoArgs` for the transaction.

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::rules_set_properties::{ConfigXMLParseXmlIntoArgs, config_xml_parse_xml_into_args_string};
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct ParseXmlIntoArgs {
    pub base: ActionBase,
    pub sec_xml_parse_xml_into_args: ConfigXMLParseXmlIntoArgs,
}

impl ParseXmlIntoArgs {
    pub fn new(action: &str) -> Self {
        ParseXmlIntoArgs {
            base: ActionBase::new(action),
            sec_xml_parse_xml_into_args: ConfigXMLParseXmlIntoArgs::PropertyNotSetConfigXMLParseXmlIntoArgs,
        }
    }
}

impl Action for ParseXmlIntoArgs {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        // The parser builds the payload as `parseXmlIntoArgs=<value>`.
        let what = self.base.parser_payload.get(17..).unwrap_or("");
        self.sec_xml_parse_xml_into_args = match what {
            "on" => ConfigXMLParseXmlIntoArgs::TrueConfigXMLParseXmlIntoArgs,
            "off" => ConfigXMLParseXmlIntoArgs::FalseConfigXMLParseXmlIntoArgs,
            "onlyargs" => ConfigXMLParseXmlIntoArgs::OnlyArgsConfigXMLParseXmlIntoArgs,
            _ => {
                return Err(format!(
                    "Internal error. Expected: On, Off or OnlyArgs; got: {}",
                    self.base.parser_payload
                ));
            }
        };
        Ok(())
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) -> bool {
        crate::ms_dbg_a!(
            t,
            8,
            "Setting SecParseXmlIntoArgs to {} as requested by a ctl:parseXmlIntoArgs action",
            config_xml_parse_xml_into_args_string(self.sec_xml_parse_xml_into_args)
        );
        t.sec_xml_parse_xml_into_args = self.sec_xml_parse_xml_into_args;
        true
    }
}
