//! Port of `src/actions/set_uid.cc`, `src/actions/set_uid.h`.
//!
//! `setuid:'...'` — sets the user id (USER collection key and USERID).

use crate::actions::action::{Action, ActionBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::lossy;

#[derive(Debug)]
pub struct SetUID {
    pub base: ActionBase,
    pub string: RunTimeString,
}

impl SetUID {
    pub fn with_rts(z: RunTimeString) -> Self {
        SetUID { base: ActionBase::new("setuid"), string: z }
    }
}

impl Action for SetUID {
    crate::action_base_accessors!();

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, _rm: &mut RuleMessage<'_>) {
        let col_name_expanded = self.string.evaluate(Some(t));
        crate::ms_dbg_a!(t, 8, "User collection initiated with value: '{}'.", lossy(&col_name_expanded));
        t.collections.user_collection_key.clone_from(&col_name_expanded);
        let offset = t.vars.offset;
        t.vars.user_id.set(&col_name_expanded, offset);
    }
}
