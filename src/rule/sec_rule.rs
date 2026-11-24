//! The evaluation of a `SecRule`: its targets are resolved, transformed
//! and passed to its operator.

use crate::eval::EvalScratch;
use crate::operators::operator::RuleOperator;
use crate::rule::message::{Matched, RuleMessage};
use crate::rule::{LogPoint, Rule, TransformationPath};
use crate::rules_set::plan::Link;
use crate::transaction::Transaction;
use crate::utils::string::{limit_to, to_hex_if_needed};
use crate::variables::variable::{Variable, variables_to_string};

/// The `SecRule` specific part of a rule: its targets and its operator.
#[derive(Debug)]
pub struct SecRule {
    pub variables: Vec<Variable>,
    pub operator: RuleOperator,
}

impl SecRule {
    pub fn new(op: RuleOperator, mut variables: Vec<Variable>) -> Self {
        // The list is final: give back what the parser over-allocated.
        variables.shrink_to_fit();
        SecRule { variables, operator: op }
    }

    /// The operator name (`rx`, `pm`, ...).
    pub fn operator_name(&self) -> &str {
        self.operator.op.name()
    }

    /// Runs the operator on one (transformed) target value.
    fn execute_operator_at<'a>(
        &'a self,
        rule: &'a Rule,
        t: &mut Transaction<'a>,
        key: &[u8],
        value: &[u8],
        rm: &mut RuleMessage<'a>,
    ) -> bool {
        crate::ms_dbg!(
            t,
            9,
            "Target value: \"{}\" (Variable: {})",
            String::from_utf8_lossy(&limit_to(80, to_hex_if_needed(value, false).as_bytes())),
            String::from_utf8_lossy(key)
        );
        self.operator.evaluate(t, rule, value, rm)
    }

    /// The targets to inspect: the ones of the rule's plan, minus the
    /// ones the transaction removed (`ctl:ruleRemoveTargetById` and
    /// `...ByTag`, which only remove targets the rule was written with).
    fn targets<'a>(&'a self, rule: &'a Rule, link: &'a Link, t: &Transaction<'a>, vars: &mut Vec<&'a Variable>) {
        for variable in link.targets.iter().map(|&i| &self.variables[i]) {
            if !t.ctl.removes_target(rule, variable.full_name().as_bytes(), t) {
                vars.push(variable);
            }
        }
        vars.extend(link.added_targets.iter().map(|v| v.as_ref()));
    }

    /// Evaluates the rule: runs the operator on every transformed target
    /// value, then the chained rule and the actions. Returns whether the
    /// rule (with its chain) matched; `true` also for a rule removed by
    /// `ctl:ruleRemoveById`.
    pub fn evaluate<'a>(
        &'a self,
        rule: &'a Rule,
        chain: &'a [Link],
        t: &mut Transaction<'a>,
        rm: &mut RuleMessage<'a>,
    ) -> bool {
        let (link, chained) = chain.split_first().expect("the plan of the rule");
        let mut global_ret = false;

        rule.evaluate_base(t);

        if t.ctl.removes_rule_id(rule.rule_id) {
            crate::ms_dbg!(t, 9, "Rule id: {} was skipped due to a ruleRemoveById action...", rule.logged_id());
            return true;
        }

        // Only needed for the debug log, so it is built on demand.
        let vars_str = || variables_to_string(&self.variables);
        if let Some(s) = &self.operator.param {
            if crate::DebugSink::debug_enabled(t, 4) {
                let mut eparam = s.evaluate(Some(t));
                if s.contains_macro() {
                    let mut e = b"\"".to_vec();
                    e.extend_from_slice(&eparam);
                    e.extend_from_slice(b"\" Was: \"");
                    e.extend_from_slice(&s.evaluate(None));
                    e.push(b'"');
                    eparam = e;
                } else {
                    let mut e = b"\"".to_vec();
                    e.extend_from_slice(&eparam);
                    e.push(b'"');
                    eparam = e;
                }
                crate::ms_dbg!(
                    t,
                    4,
                    "(Rule: {}) Executing operator \"{}\" with param {} against {}.",
                    rule.logged_id(),
                    self.operator_name(),
                    String::from_utf8_lossy(&eparam),
                    vars_str()
                );
            }
        } else {
            crate::ms_dbg!(
                t,
                4,
                "(Rule: {}) Executing operator \"{} against {}.",
                rule.logged_id(),
                self.operator_name(),
                vars_str()
            );
        }

        // The transaction's buffers, reused by every rule (a chained rule
        // evaluated below gets fresh ones); given back after the loop.
        let EvalScratch { mut vars, mut e, mut values } = std::mem::take(&mut t.eval.scratch);
        vars.clear();
        self.targets(rule, link, t, &mut vars);

        for &var in &vars {
            e.clear();
            var.evaluate(t, Some(rule), &mut e);
            for v in e.drain(..) {
                let value = v.value();
                let key = v.key_with_collection();

                // A value is removed like a target (`ARGS:name`).
                if link.excludes_value(&v) || t.ctl.removes_target(rule, key, t) {
                    continue;
                }

                rule.execute_transformations(t, &link.transformations, value, &mut values);

                for (value_after_trans, path) in &values {
                    let ret = self.execute_operator_at(rule, t, key, value_after_trans, rm);
                    if ret {
                        let operator = &self.operator.op;
                        let param = self.operator.message_param(t);
                        rm.matched = Some(Matched { operator, param, value: v.clone() });
                        for i in v.origin() {
                            rm.reference.extend_from_slice(i.to_text().as_bytes());
                        }
                        match path {
                            TransformationPath::Step(p) => rm.reference.extend_from_slice(p.as_bytes()),
                            TransformationPath::Full => {
                                rm.reference.extend_from_slice(link.transformation_path.as_bytes())
                            }
                        }
                        crate::ms_dbg!(t, 9, "Matched vars updated.");
                        t.vars.record_match(key, value_after_trans);
                        rule.execute_actions_independent_of_chained_rule_result(t, rm);
                        rule.perform_logging(t, rm, LogPoint::EachMatch);
                        global_ret = true;
                    }
                }
            }
        }
        vars.clear();
        t.eval.scratch = EvalScratch { vars, e, values };

        if !global_ret {
            crate::ms_dbg!(t, 4, "Rule returned 0.");
            return false;
        }
        crate::ms_dbg!(t, 4, "Rule returned 1.");

        if rule.is_chained() {
            let Some(child) = rule.chained_rule_child.as_deref() else {
                // A rule marked as chained without a rule after it does not match.
                crate::ms_dbg!(t, 4, "Rule is marked as chained but there isn't a subsequent rule.");
                return false;
            };
            crate::ms_dbg!(t, 4, "Executing chained rule.");
            t.eval.chained_rule_parents.push(rule);
            let recursive_global_ret = child.evaluate_with_message(chained, t, rm);
            t.eval.chained_rule_parents.pop();
            if !recursive_global_ret {
                return false;
            }
        }

        rule.execute_actions_after_full_match(link, t, rm);
        // last rule in the chain.
        rule.perform_logging(t, rm, LogPoint::RuleEnd);
        true
    }
}
