//! Port of `src/actions/set_rsc.cc`, `src/actions/set_rsc.h`.
//!
//! `setrsc:'...'` — sets the key of the RESOURCE collection (the C++ action
//! name is `setsrc`; kept as is).

use crate::actions::action::Action;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::lossy;

#[derive(Debug)]
pub struct SetRSC {
    pub string: RunTimeString,
}

impl SetRSC {
    pub fn with_rts(z: RunTimeString) -> Self {
        SetRSC { string: z }
    }
}

impl Action for SetRSC {
    fn name(&self) -> &str {
        "setsrc"
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        let col_name_expanded = self.string.evaluate(Some(t));
        crate::ms_dbg_a!(t, 8, "RESOURCE initiated with value: '{}'.", lossy(&col_name_expanded));
        t.collections.resource_collection_key.clone_from(&col_name_expanded);
        let offset = t.vars.offset;
        t.vars.resource.set(&col_name_expanded, offset);
    }
}
