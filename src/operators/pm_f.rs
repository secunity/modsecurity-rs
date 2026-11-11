//! Port of `src/operators/pm_f.h` (`@pmf`, an alias of `@pmFromFile`).

use crate::operators::operator::{Operator, OperatorBase};
use crate::operators::pm_from_file::PmFromFile;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct PmF {
    pub from_file: PmFromFile,
}

impl PmF {
    pub fn new(param: RunTimeString) -> Self {
        // The C++ operator name is "PmFromF".
        PmF { from_file: PmFromFile::with_name("PmFromF", param) }
    }
}

impl Operator for PmF {
    fn base(&self) -> &OperatorBase {
        self.from_file.base()
    }
    fn base_mut(&mut self) -> &mut OperatorBase {
        self.from_file.base_mut()
    }

    fn init(&mut self, config: &str) -> Result<(), String> {
        self.from_file.init(config)
    }

    fn evaluate(
        &self,
        t: Option<&mut Transaction<'_>>,
        rule: Option<&RuleWithActions>,
        input: &[u8],
        rm: Option<&mut RuleMessage<'_>>,
    ) -> bool {
        self.from_file.evaluate(t, rule, input, rm)
    }
}
