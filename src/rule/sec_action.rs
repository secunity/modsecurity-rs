//! The evaluation of a `SecAction`: a rule without an operator.

use crate::rule::message::RuleMessage;
use crate::rule::{LogPoint, Rule};
use crate::rules_set::plan::Link;
use crate::transaction::Transaction;

/// Evaluates a `SecAction`: runs its actions and logs it. It always
/// matches.
pub fn evaluate<'a>(rule: &'a Rule, link: &'a Link, t: &mut Transaction<'a>, rm: &mut RuleMessage<'a>) -> bool {
    rule.evaluate_base(t);

    crate::ms_dbg!(t, 4, "(Rule: {}) Executing unconditional rule...", rule.logged_id());
    rule.execute_actions_independent_of_chained_rule_result(t, rm);
    rule.execute_actions_after_full_match(link, t, rm);
    rule.perform_logging(t, rm, LogPoint::UnconditionalEnd);
    true
}
