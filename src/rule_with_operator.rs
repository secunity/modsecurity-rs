//! Port of `headers/modsecurity/rule_with_operator.h` and
//! `src/rule_with_operator.cc`.

use crate::operators::operator::RuleOperator;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::{LogPoint, RuleWithActions, TransformationPath};
use crate::transaction::EvalScratch;
use crate::transaction::Transaction;
use crate::utils::string::{limit_to, to_hex_if_needed};
use crate::variables::variable::{Variable, Variables, variables_to_string};

/// The `SecRule` specific part of a rule: its targets and its operator.
#[derive(Debug)]
pub struct RuleWithOperator {
    pub variables: Vec<Box<dyn Variable>>,
    pub operator: RuleOperator,
}

impl RuleWithOperator {
    pub fn new(op: RuleOperator, variables: Vec<Box<dyn Variable>>) -> Self {
        RuleWithOperator { variables, operator: op }
    }

    /// `getOperatorName`
    pub fn get_operator_name(&self) -> &str {
        self.operator.op.name()
    }

    /// `updateMatchedVars`
    pub fn update_matched_vars(t: &mut Transaction<'_>, key: &[u8], value: &[u8]) {
        crate::ms_dbg_a!(t, 9, "Matched vars updated.");
        let off = t.vars.offset;
        t.vars.matched_var.set(value, off);
        t.vars.matched_var_name.set(key, off);
        t.vars.matched_vars.set(key, value, off);
        t.vars.matched_vars_names.set(key, key, off);
    }

    /// `executeOperatorAt`
    fn execute_operator_at<'a>(
        &'a self,
        rule: &'a RuleWithActions,
        t: &mut Transaction<'a>,
        key: &[u8],
        value: &[u8],
        rm: &mut RuleMessage<'a>,
    ) -> bool {
        crate::ms_dbg_a!(
            t,
            9,
            "Target value: \"{}\" (Variable: {})",
            String::from_utf8_lossy(&limit_to(80, to_hex_if_needed(value, false).as_bytes())),
            String::from_utf8_lossy(key)
        );
        self.operator.evaluate(t, rule, value, rm)
    }

    /// `getVariablesExceptions`
    fn get_variables_exceptions<'a>(
        rule: &'a RuleWithActions,
        t: &Transaction<'a>,
        exclusion: &mut Variables<'a>,
        addition: &mut Variables<'a>,
    ) {
        let ex = &t.rules.properties.exceptions;
        let mut helper = |v: &'a dyn Variable| match v.exclusion_base() {
            Some(base) => exclusion.push(base),
            None => addition.push(v),
        };
        for (tag, v) in &ex.variable_update_target_by_tag {
            if rule.contains_tag(tag, t) {
                helper(v.as_ref());
            }
        }
        for (msg, v) in &ex.variable_update_target_by_msg {
            if rule.contains_msg(msg, t) {
                helper(v.as_ref());
            }
        }
        for v in ex.variable_update_target_by_id.for_id(rule.rule_id as f64) {
            helper(v.as_ref());
        }
    }

    /// `getFinalVars`
    fn get_final_vars<'a>(
        &'a self,
        rule: &'a RuleWithActions,
        t: &Transaction<'a>,
        vars: &mut Vec<&'a dyn Variable>,
        exclusion: &mut Variables<'a>,
    ) {
        let mut addition = Variables::new();
        Self::get_variables_exceptions(rule, t, exclusion, &mut addition);
        for variable in &self.variables {
            let variable: &dyn Variable = variable.as_ref();
            if exclusion.contains_var(variable) {
                continue;
            }
            if t.rule_remove_target_by_id
                .iter()
                .any(|(id, target)| *id as i64 == rule.rule_id && target.eq_ignore_ascii_case(variable.full_name()))
            {
                continue;
            }
            if t.rule_remove_target_by_tag
                .iter()
                .any(|(tag, target)| target == variable.full_name() && rule.contains_tag(tag, t))
            {
                continue;
            }
            vars.push(variable);
        }
        for v in addition.0 {
            vars.push(v);
        }
    }

    /// `RuleWithOperator::evaluate(transaction, ruleMessage)`
    pub fn evaluate<'a>(
        &'a self,
        rule: &'a RuleWithActions,
        t: &mut Transaction<'a>,
        rm: &mut RuleMessage<'a>,
    ) -> bool {
        let mut global_ret = false;
        let mut contains_block = rule.has_block_action();

        rule.evaluate_base(t);

        for &i in &t.rule_remove_by_id {
            if rule.rule_id != i as i64 {
                continue;
            }
            crate::ms_dbg_a!(t, 9, "Rule id: {} was skipped due to a ruleRemoveById action...", rule.rule_id);
            return true;
        }
        for &(a, b) in &t.rule_remove_by_id_range {
            if !(a as i64 <= rule.rule_id && b as i64 >= rule.rule_id) {
                continue;
            }
            crate::ms_dbg_a!(t, 9, "Rule id: {} was skipped due to a ruleRemoveById action...", rule.rule_id);
            return true;
        }

        // Only needed for the debug log (C++ builds it unconditionally).
        let vars_str = || variables_to_string(self.variables.iter().map(|v| v.as_ref()));
        if let Some(s) = self.operator.op.param().map(|p| &p.string) {
            if t.debug_enabled(4) {
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
                crate::ms_dbg_a!(
                    t,
                    4,
                    "(Rule: {}) Executing operator \"{}\" with param {} against {}.",
                    rule.rule_id,
                    self.get_operator_name(),
                    String::from_utf8_lossy(&eparam),
                    vars_str()
                );
            }
        } else {
            crate::ms_dbg_a!(
                t,
                4,
                "(Rule: {}) Executing operator \"{} against {}.",
                rule.rule_id,
                self.get_operator_name(),
                vars_str()
            );
        }

        // The transaction's buffers, reused by every rule (a chained rule
        // evaluated below gets fresh ones); given back after the loop.
        let EvalScratch { mut vars, mut e, mut values } = std::mem::take(&mut t.eval_scratch);
        vars.clear();
        let mut exclusion = Variables::new();
        self.get_final_vars(rule, t, &mut vars, &mut exclusion);

        for &var in &vars {
            e.clear();
            var.evaluate(t, Some(rule), &mut e);
            for v in e.drain(..) {
                let value = v.value();
                let key = v.key_with_collection();

                if exclusion.contains_value(&v)
                    || t.rule_remove_target_by_id
                        .iter()
                        .any(|(id, target)| *id as i64 == rule.rule_id && target.as_bytes() == v.key_with_collection())
                {
                    continue;
                }
                if exclusion.contains_value(&v)
                    || t.rule_remove_target_by_tag
                        .iter()
                        .any(|(tag, target)| target.as_bytes() == v.key_with_collection() && rule.contains_tag(tag, t))
                {
                    continue;
                }

                rule.execute_transformations(t, value, &mut values);

                for (value_after_trans, path) in &values {
                    let ret = self.execute_operator_at(rule, t, key, value_after_trans, rm);
                    if ret {
                        rm.match_ = self.operator.op.resolve_match_message(t, key, value);
                        for i in v.origin() {
                            rm.reference.extend_from_slice(i.to_text().as_bytes());
                        }
                        match path {
                            TransformationPath::Step(p) => rm.reference.extend_from_slice(p.as_bytes()),
                            TransformationPath::Full => {
                                rm.reference.extend_from_slice(rule.transformation_path(t).as_bytes())
                            }
                        }
                        Self::update_matched_vars(t, key, value_after_trans);
                        contains_block |= rule.execute_actions_independent_of_chained_rule_result(t, rm);
                        rule.perform_logging(t, rm, LogPoint::EachMatch);
                        global_ret = true;
                    }
                }
            }
        }
        vars.clear();
        t.eval_scratch = EvalScratch { vars, e, values };

        if !global_ret {
            crate::ms_dbg_a!(t, 4, "Rule returned 0.");
            return false;
        }
        crate::ms_dbg_a!(t, 4, "Rule returned 1.");

        if rule.is_chained() {
            let Some(child) = rule.chained_rule_child.as_deref() else {
                // FIXME (C++): this check should happen on the parser.
                crate::ms_dbg_a!(t, 4, "Rule is marked as chained but there isn't a subsequent rule.");
                return false;
            };
            crate::ms_dbg_a!(t, 4, "Executing chained rule.");
            t.chained_rule_parents.push(rule);
            let recursive_global_ret = child.evaluate_with_message(t, rm);
            t.chained_rule_parents.pop();
            if !recursive_global_ret {
                return false;
            }
        }

        rule.execute_actions_after_full_match(t, contains_block, rm);
        // last rule in the chain.
        rule.perform_logging(t, rm, LogPoint::RuleEnd);
        true
    }
}
