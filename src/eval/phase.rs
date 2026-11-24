//! The rules of one phase: which run, and what stops them.

use crate::actions::disruptive::allow::AllowType;
use crate::phases::Phases;
use crate::rules_set::RulesSet;
use crate::rules_set::plan::Step;
use crate::transaction::Transaction;

/// Runs the rules of `phase`, honouring `allow`, `skip`, `skipAfter`,
/// the rule removals and a disruptive intervention.
pub(crate) fn run<'a>(rules: &'a RulesSet, phase: Phases, t: &mut Transaction<'a>) {
    crate::ms_dbg!(t, 9, "This phase consists of {} rule(s).", rules.rules_set_phases.for_phase(phase).len());

    if t.eval.allow_type == Some(AllowType::FromNowOn) && phase != Phases::Logging {
        crate::ms_dbg!(
            t,
            9,
            "Skipping all rules evaluation on this phase as request through the utilization of an `allow' action."
        );
        return;
    }
    if t.eval.allow_type == Some(AllowType::Request) && phase <= Phases::RequestBody {
        crate::ms_dbg!(
            t,
            9,
            "Skipping all rules evaluation on this phase as request through the utilization of an `allow' action."
        );
        return;
    }
    t.eval.allow_type = None;

    for step in rules.plan().for_phase(phase) {
        let (rule, chain, removed) = match step {
            Step::Marker(marker) => {
                // The marker the transaction is skipping to ends the skip
                // (not written to the debug log).
                if let Some(m) = marker.as_marker()
                    && t.eval.marker.as_deref() == Some(m.name.as_str())
                {
                    t.eval.marker = None;
                }
                continue;
            }
            Step::Rule { rule, chain } => (rule, chain.as_slice(), None),
            Step::Removed { rule, by } => (rule, &[][..], Some(*by)),
        };
        let Some(r) = rule.as_rule() else { continue };

        if let Some(marker) = &t.eval.marker {
            crate::ms_dbg!(t, 9, "Skipped rule id '{}' due to a SecMarker: {}", rule.reference(), marker);
        } else if t.eval.skip_next > 0 {
            t.eval.skip_next -= 1;
            crate::ms_dbg!(
                t,
                9,
                "Skipped rule id '{}' due to a `skip' action. Still {} to be skipped.",
                rule.reference(),
                t.eval.skip_next
            );
        } else if t.eval.allow_type.is_some() {
            // Sic: "trough". The regression test action-allow.json
            // looks for this text in the debug log.
            crate::ms_dbg!(
                t,
                9,
                "Skipped rule id '{}' as request trough the utilization of an `allow' action.",
                rule.reference()
            );
        } else if let Some(by) = removed {
            crate::ms_dbg!(t, 9, "Skipped rule id '{}'. Removed by {} directive.", rule.reference(), by.directive());
        } else if t.ctl.removes_rule_by_tag(r, t) {
            crate::ms_dbg!(t, 9, "Skipped rule id '{}'. Skipped due to a ruleRemoveByTag action.", r.reference());
        } else {
            r.evaluate(chain, t);
            crate::ms_dbg!(t, 9, "Matched vars cleaned.");
            t.vars.clear_matches();

            if t.outcome.intervention.is_disruptive() {
                crate::ms_dbg!(t, 8, "Skipping this phase as this request was already intercepted.");
                break;
            }
        }
    }

    // A `skipAfter` whose marker is in no phase list (every marker is in
    // all of them) ends with its phase instead of skipping every later
    // rule. Such a rule set still loads: nginx loads the rules of a
    // location before merging those of the server, where the marker
    // may be.
    if let Some(name) = t.eval.marker.clone() {
        let known = rules
            .plan()
            .for_phase(phase)
            .iter()
            .any(|step| matches!(step, Step::Marker(m) if m.as_marker().is_some_and(|m| m.name == *name)));
        if !known {
            crate::ms_dbg!(t, 9, "No SecMarker named '{}': the skip ends with this phase.", name);
            t.eval.marker = None;
        }
    }
}
