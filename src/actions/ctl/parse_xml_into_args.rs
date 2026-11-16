//! `ctl:parseXmlIntoArgs=On|Off|OnlyArgs` — overrides
//! `SecParseXmlIntoArgs` for the transaction.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::rules_set::properties::{self, config_xml_parse_xml_into_args_string};

#[derive(Debug)]
pub struct ParseXmlIntoArgs {
    value: properties::ParseXmlIntoArgs,
}

impl ParseXmlIntoArgs {
    pub fn new(value: properties::ParseXmlIntoArgs) -> Self {
        ParseXmlIntoArgs { value }
    }
}

impl Action for ParseXmlIntoArgs {
    fn name(&self) -> &str {
        "ctl"
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        crate::act_dbg!(
            cx,
            8,
            "Setting SecParseXmlIntoArgs to {} as requested by a ctl:parseXmlIntoArgs action",
            config_xml_parse_xml_into_args_string(Some(self.value))
        );
        cx.set_parse_xml_into_args(self.value);
    }
}
