//! `logdata:'...'` — data (with macro expansion) logged with the rule
//! match.

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct LogData {
    pub string: RunTimeString,
}

impl LogData {
    pub fn with_rts(z: RunTimeString) -> Self {
        LogData { string: z }
    }

    pub fn data(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.string.expand(t, None).into_owned()
    }
}

impl Action for LogData {
    fn name(&self) -> &str {
        "logdata"
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        cx.set_log_data(cx.expand(&self.string));
    }
}
