//! Port of `headers/modsecurity/rule_unconditional.h` and
//! `src/rule_unconditional.cc` (`SecAction`).

use crate::rule_message::RuleMessage;
use crate::rule_with_actions::{LogPoint, RuleWithActions};
use crate::transaction::Transaction;

/// `RuleUnconditional::evaluate`
pub fn evaluate<'a>(rule: &'a RuleWithActions, t: &mut Transaction<'a>, rm: &mut RuleMessage<'a>) -> bool {
    rule.evaluate_base(t);
    // FIXME (C++): This needs to be removed on the runtime exception review.

    crate::ms_dbg_a!(t, 4, "(Rule: {}) Executing unconditional rule...", rule.rule_id);
    let contains_block = rule.execute_actions_independent_of_chained_rule_result(t, rm);
    rule.execute_actions_after_full_match(t, contains_block, rm);
    rule.perform_logging(t, rm, LogPoint::UnconditionalEnd);
    true
}
