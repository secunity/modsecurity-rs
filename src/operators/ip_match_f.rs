//! Port of `src/operators/ip_match_f.cc`, `src/operators/ip_match_f.h`
//! (`@ipMatchF`, an alias of `@ipMatchFromFile`).

use crate::operators::ip_match_from_file::IpMatchFromFile;
use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct IpMatchF {
    pub from_file: IpMatchFromFile,
}

impl IpMatchF {
    pub fn new(param: RunTimeString) -> Self {
        // As in C++, the operator keeps the "IpMatchFromFile" name.
        IpMatchF { from_file: IpMatchFromFile::new(param) }
    }
}

impl Operator for IpMatchF {
    fn base(&self) -> &OperatorBase {
        self.from_file.base()
    }
    fn base_mut(&mut self) -> &mut OperatorBase {
        self.from_file.base_mut()
    }

    fn init(&mut self, file: &str) -> Result<(), String> {
        self.from_file.init(file)
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
