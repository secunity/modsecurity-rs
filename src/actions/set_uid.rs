//! `setuid:'...'` — sets the user id (USER collection key and USERID).

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::run_time_string::RunTimeString;
use crate::utils::string::lossy;

#[derive(Debug)]
pub struct SetUID {
    pub string: RunTimeString,
}

impl SetUID {
    pub fn with_rts(z: RunTimeString) -> Self {
        SetUID { string: z }
    }
}

impl Action for SetUID {
    fn name(&self) -> &str {
        "setuid"
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        let col_name_expanded = cx.expand(&self.string);
        crate::act_dbg!(cx, 8, "User collection initiated with value: '{}'.", lossy(&col_name_expanded));
        cx.set_user_id(col_name_expanded);
    }
}
