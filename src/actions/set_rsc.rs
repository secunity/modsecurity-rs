//! `setrsc:'...'` — sets the key of the RESOURCE collection. (The action
//! reports its name as `setsrc`.)

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::run_time_string::RunTimeString;

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

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        let col_name_expanded = cx.expand(&self.string);
        crate::ms_dbg!(cx, 8, "RESOURCE initiated with value: '{}'.", String::from_utf8_lossy(&col_name_expanded));
        cx.set_resource(col_name_expanded);
    }
}
