//! The evaluation of a `SecRule`: its targets are resolved, transformed
//! and passed to its operator.

use super::EvalScratch;
use super::rule::RuleRun;
use crate::rule::message::Matched;
use crate::rule::sec_rule::SecRule;
use crate::rule::{LogPoint, TransformationPath};
use crate::utils::string::{limit_to, to_hex_if_needed};
use crate::variables::variable::{Variable, variables_to_string};

impl<'a> RuleRun<'_, 'a> {
    /// Evaluates a `SecRule`: runs the operator on every transformed
    /// target value, then the chained rule and the actions. Returns whether
    /// the rule (with its chain) matched; `true` also for a rule removed by
    /// `ctl:ruleRemoveById`.
    pub(super) fn sec_rule(&mut self, sec_rule: &'a SecRule) -> bool {
        let rule = self.rule;
        let link = self.link;
        let mut global_ret = false;

        self.clear_matched();

        if self.t.ctl.removes_rule_id(rule.rule_id) {
            crate::ms_dbg!(self.t, 9, "Rule id: {} was skipped due to a ruleRemoveById action...", rule.logged_id());
            return true;
        }

        self.log_operator(sec_rule);

        // The transaction's buffers, reused by every rule (a chained rule
        // evaluated below gets fresh ones); given back after the loop.
        let EvalScratch { mut vars, mut e, mut values } = std::mem::take(&mut self.t.eval.scratch);
        vars.clear();
        self.targets(sec_rule, &mut vars);

        for &var in &vars {
            e.clear();
            var.evaluate(self.t, Some(rule), &mut e);
            for v in e.drain(..) {
                let value = v.value();
                let key = v.key_with_collection();

                // A value is removed like a target (`ARGS:name`).
                if link.excludes_value(&v) || self.t.ctl.removes_target(rule, key, self.t) {
                    continue;
                }

                self.transform(&link.transformations, value, &mut values);

                for (value_after_trans, path) in &values {
                    crate::ms_dbg!(
                        self.t,
                        9,
                        "Target value: \"{}\" (Variable: {})",
                        String::from_utf8_lossy(&limit_to(80, to_hex_if_needed(value_after_trans, false).as_bytes())),
                        String::from_utf8_lossy(key)
                    );
                    if sec_rule.operator.evaluate(self.t, rule, value_after_trans, self.rm) {
                        let operator = &sec_rule.operator.op;
                        let param = sec_rule.operator.message_param(self.t);
                        self.rm.matched = Some(Matched { operator, param, value: v.clone() });
                        for i in v.origin() {
                            self.rm.reference.extend_from_slice(i.to_text().as_bytes());
                        }
                        match path {
                            TransformationPath::Step(p) => self.rm.reference.extend_from_slice(p.as_bytes()),
                            TransformationPath::Full => {
                                self.rm.reference.extend_from_slice(link.transformation_path.as_bytes())
                            }
                        }
                        crate::ms_dbg!(self.t, 9, "Matched vars updated.");
                        self.t.vars.record_match(key, value_after_trans);
                        self.run_actions_on_match();
                        self.log(LogPoint::EachMatch);
                        global_ret = true;
                    }
                }
            }
        }
        vars.clear();
        self.t.eval.scratch = EvalScratch { vars, e, values };

        if !global_ret {
            crate::ms_dbg!(self.t, 4, "Rule returned 0.");
            return false;
        }
        crate::ms_dbg!(self.t, 4, "Rule returned 1.");

        if rule.chain.continued {
            let Some(child) = rule.chain.next.as_deref() else {
                // A rule marked as chained without a rule after it does not match.
                crate::ms_dbg!(self.t, 4, "Rule is marked as chained but there isn't a subsequent rule.");
                return false;
            };
            crate::ms_dbg!(self.t, 4, "Executing chained rule.");
            self.t.eval.chained_rule_parents.push(rule);
            let recursive_global_ret = RuleRun::new(child, self.chained, self.t, self.rm).run();
            self.t.eval.chained_rule_parents.pop();
            if !recursive_global_ret {
                return false;
            }
        }

        self.run_actions_on_chain_match();
        // The chain matched from this rule on. Only its first rule logs the
        // message (see `log`).
        self.log(LogPoint::RuleEnd);
        true
    }

    /// Writes the operator, its parameter and the targets to the debug log.
    fn log_operator(&self, sec_rule: &SecRule) {
        let (t, rule) = (&*self.t, self.rule);
        // Only needed for the debug log, so it is built on demand.
        let vars_str = || variables_to_string(&sec_rule.variables);
        if let Some(s) = &sec_rule.operator.param {
            if crate::DebugSink::debug_enabled(t, 4) {
                // `"expanded"`, and `Was: "as written"` after it for a
                // parameter with macros.
                let mut eparam = [&b"\""[..], &s.expand(t, None), b"\""].concat();
                if s.contains_macro() {
                    eparam.extend_from_slice(b" Was: \"");
                    eparam.extend_from_slice(&s.text());
                    eparam.push(b'"');
                }
                crate::ms_dbg!(
                    t,
                    4,
                    "(Rule: {}) Executing operator \"{}\" with param {} against {}.",
                    rule.logged_id(),
                    sec_rule.operator_name(),
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
                sec_rule.operator_name(),
                vars_str()
            );
        }
    }

    /// The targets to inspect: the ones of the rule's plan, minus the
    /// ones the transaction removed (`ctl:ruleRemoveTargetById` and
    /// `...ByTag`, which only remove targets the rule was written with).
    fn targets(&self, sec_rule: &'a SecRule, vars: &mut Vec<&'a Variable>) {
        let (t, rule, link) = (&*self.t, self.rule, self.link);
        for variable in link.targets.iter().map(|&i| &sec_rule.variables[i]) {
            if !t.ctl.removes_target(rule, variable.full_name().as_bytes(), t) {
                vars.push(variable);
            }
        }
        vars.extend(link.added_targets.iter().map(|v| v.as_ref()));
    }
}
