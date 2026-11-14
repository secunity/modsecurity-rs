//! Port of `headers/modsecurity/rules_set.h` and `src/rules_set.cc`.

use crate::actions::disruptive::allow::AllowType;
use crate::debug_log::DebugLog;
use crate::modsecurity::Phases;
use crate::parser::driver::Driver;
use crate::rules_set_phases::RulesSetPhases;
use crate::rules_set_properties::RulesSetProperties;
use crate::transaction::Transaction;
use crate::utils::https_client::HttpsClient;

/// A loaded configuration: the rules of every phase plus the configuration
/// properties (`RulesSet : RulesSetProperties` in C++).
pub struct RulesSet {
    pub properties: RulesSetProperties,
    pub rules_set_phases: RulesSetPhases,
}

impl Default for RulesSet {
    fn default() -> Self {
        Self::new()
    }
}

impl RulesSet {
    pub fn new() -> Self {
        RulesSet { properties: RulesSetProperties::new(), rules_set_phases: RulesSetPhases::default() }
    }

    /// `RulesSet(DebugLog *customLog)`
    pub fn with_debug_log(custom_log: Box<dyn DebugLog>) -> Self {
        RulesSet {
            properties: RulesSetProperties::with_debug_log(custom_log),
            rules_set_phases: RulesSetPhases::default(),
        }
    }

    /// The error of a failed load or merge: all the parser errors collected
    /// so far (as the C API reports them, see [`RulesSet::parser_error`]).
    fn failed<T>(&self) -> Result<T, String> {
        Err(self.properties.parser_error.clone())
    }

    /// `loadFromUri`: loads the rules of a file. Returns the number of rules
    /// loaded.
    pub fn load_from_uri(&mut self, uri: &str) -> Result<usize, String> {
        let mut driver = Driver::new();
        if !driver.parse_file(uri) {
            self.properties.parser_error.push_str(&driver.properties.parser_error);
            return self.failed();
        }
        self.merge_driver(&mut driver)
    }

    /// `load(rules, ref)`
    pub fn load_with_ref(&mut self, rules: &str, reference: &str) -> Result<usize, String> {
        let mut driver = Driver::new();
        if !driver.parse(rules, reference) {
            self.properties.parser_error.push_str(&driver.properties.parser_error);
            return self.failed();
        }
        self.merge_driver(&mut driver).or_else(|_| {
            // The C++ code appends the parser errors once more here.
            self.properties.parser_error.push_str(&driver.properties.parser_error);
            self.failed()
        })
    }

    /// `loadRemote`
    pub fn load_remote(&mut self, key: &str, uri: &str) -> Result<usize, String> {
        let mut client = HttpsClient::new();
        client.set_key(key);
        if client.download(uri) {
            let content = String::from_utf8_lossy(&client.content).into_owned();
            return self.load_with_ref(&content, uri);
        }
        self.failed()
    }

    /// `load(plainRules)`
    pub fn load(&mut self, plain_rules: &str) -> Result<usize, String> {
        self.load_with_ref(plain_rules, "")
    }

    pub fn parser_error(&self) -> String {
        self.properties.parser_error.clone()
    }

    /// `cleanMatchedVars`
    pub fn clean_matched_vars(t: &mut Transaction<'_>) {
        crate::ms_dbg_a!(t, 9, "Matched vars cleaned.");
        // Every match adds to MATCHED_VARS, so when that is empty no rule
        // matched since the last cleaning and there is nothing to unset
        // (this runs after every rule).
        if t.vars.matched_vars.is_empty() {
            return;
        }
        t.vars.matched_var.unset();
        t.vars.matched_vars.unset();
        t.vars.matched_var_name.unset();
        t.vars.matched_vars_names.unset();
    }

    /// `evaluate(phase, transaction)`
    pub fn evaluate<'a>(&'a self, phase: Phases, t: &mut Transaction<'a>) {
        let rules = self.rules_set_phases.for_phase(phase);
        crate::ms_dbg_a!(t, 9, "This phase consists of {} rule(s).", rules.len());

        if t.allow_type == Some(AllowType::FromNowOn) && phase != Phases::Logging {
            crate::ms_dbg_a!(
                t,
                9,
                "Skipping all rules evaluation on this phase as request through the utilization of an `allow' action."
            );
            return;
        }
        if t.allow_type == Some(AllowType::Request) && phase <= Phases::RequestBody {
            crate::ms_dbg_a!(
                t,
                9,
                "Skipping all rules evaluation on this phase as request through the utilization of an `allow' action."
            );
            return;
        }
        t.allow_type = None;

        let ex = &self.properties.exceptions;
        for rule in rules {
            let rule: &'a crate::rule::Rule = rule.as_ref();
            if t.is_inside_a_marker() && !rule.is_marker() {
                crate::ms_dbg_a!(
                    t,
                    9,
                    "Skipped rule id '{}' due to a SecMarker: {}",
                    rule.reference(),
                    t.current_marker().unwrap_or_default()
                );
            } else if rule.is_marker() {
                rule.evaluate(t);
            } else if t.skip_next > 0 {
                t.skip_next -= 1;
                crate::ms_dbg_a!(
                    t,
                    9,
                    "Skipped rule id '{}' due to a `skip' action. Still {} to be skipped.",
                    rule.reference(),
                    t.skip_next
                );
            } else if t.allow_type.is_some() {
                crate::ms_dbg_a!(
                    t,
                    9,
                    "Skipped rule id '{}' as request trough the utilization of an `allow' action.",
                    rule.reference()
                );
            } else {
                let rwa = rule.as_rule_with_actions();
                // FIXME (C++): Those should be treated inside the rule itself
                if let Some(r) = rwa {
                    if ex.contains(r.rule_id as i32) {
                        crate::ms_dbg_a!(
                            t,
                            9,
                            "Skipped rule id '{}'. Removed by an SecRuleRemove directive.",
                            rule.reference()
                        );
                        continue;
                    }
                    if ex.remove_rule_by_msg.iter().any(|z| r.contains_msg(z, t)) {
                        crate::ms_dbg_a!(
                            t,
                            9,
                            "Skipped rule id '{}'. Removed by a SecRuleRemoveByMsg directive.",
                            r.reference()
                        );
                        continue;
                    }
                    if ex.remove_rule_by_tag.iter().any(|z| r.contains_tag(z, t)) {
                        crate::ms_dbg_a!(
                            t,
                            9,
                            "Skipped rule id '{}'. Removed by a SecRuleRemoveByTag directive.",
                            r.reference()
                        );
                        continue;
                    }
                    if t.rule_remove_by_tag.iter().any(|z| r.contains_tag(z, t)) {
                        crate::ms_dbg_a!(
                            t,
                            9,
                            "Skipped rule id '{}'. Skipped due to a ruleRemoveByTag action.",
                            r.reference()
                        );
                        continue;
                    }
                }

                rule.evaluate(t);
                Self::clean_matched_vars(t);

                if t.intervention.disruptive {
                    crate::ms_dbg_a!(t, 8, "Skipping this phase as this request was already intercepted.");
                    break;
                }
            }
        }
    }

    /// `merge(Parser::Driver *from)`
    pub fn merge_driver(&mut self, from: &mut Driver) -> Result<usize, String> {
        self.merge_parts(&from.rules_set_phases, &mut from.properties)
    }

    /// `merge(RulesSet *from)`: appends the rules of `from` and merges its
    /// properties. Returns the number of rules appended.
    pub fn merge(&mut self, from: &mut RulesSet) -> Result<usize, String> {
        self.merge_parts(&from.rules_set_phases, &mut from.properties)
    }

    /// The two `merge` overloads. The properties are merged even when the
    /// rules could not be (duplicated id), and a failure to merge them is
    /// only recorded in the parser errors; both as in C++.
    fn merge_parts(&mut self, phases: &RulesSetPhases, properties: &mut RulesSetProperties) -> Result<usize, String> {
        let appended = self.rules_set_phases.append(phases);
        if let Err(e) = &appended {
            self.properties.parser_error.push_str(e);
        }
        if let Err(e) = RulesSetProperties::merge_properties(properties, &mut self.properties) {
            self.properties.parser_error.push_str(&e);
        }
        appended.or_else(|_| self.failed())
    }

    /// `debug(level, id, uri, msg)`
    pub fn debug(&self, level: i32, id: &str, uri: &str, msg: &str) {
        self.properties.debug_log.write_ctx(level, id, uri, msg);
    }

    pub fn dump(&self) {
        self.rules_set_phases.dump();
    }
}
