//! The evaluation of a `SecAction`: a rule without an operator.

use crate::rule::message::RuleMessage;
use crate::rule::{LogPoint, Rule};
use crate::transaction::Transaction;

/// Evaluates a `SecAction`: runs its actions and logs it. It always
/// matches.
pub fn evaluate<'a>(rule: &'a Rule, t: &mut Transaction<'a>, rm: &mut RuleMessage<'a>) -> bool {
    rule.evaluate_base(t);
    // FIXME (C++): This needs to be removed on the runtime exception review.

    crate::ms_dbg!(t, 4, "(Rule: {}) Executing unconditional rule...", rule.rule_id);
    let contains_block = rule.execute_actions_independent_of_chained_rule_result(t, rm);
    rule.execute_actions_after_full_match(t, contains_block, rm);
    rule.perform_logging(t, rm, LogPoint::UnconditionalEnd);
    true
}
