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

/// The libmodsecurity C API for rule sets (`msc_create_rules_set`, ...).
pub mod c_api {
    use super::RulesSet;
    use std::ffi::{CStr, CString, c_char, c_int};

    fn set_error(error: *mut *const c_char, msg: String) {
        if !error.is_null() {
            let c = CString::new(msg.replace('\0', "")).unwrap_or_default();
            // SAFETY: the caller passes a valid out-pointer; ownership of the
            // string goes to the caller (free with msc_rules_error_cleanup).
            unsafe { *error = c.into_raw() };
        }
    }

    /// The C API result of a load or merge: the number of rules, or -1 with
    /// the parser errors handed to the caller through `error`.
    fn c_result(result: Result<usize, String>, error: *mut *const c_char) -> c_int {
        match result {
            Ok(n) => c_int::try_from(n).unwrap_or(c_int::MAX),
            Err(e) => {
                set_error(error, e);
                -1
            }
        }
    }

    unsafe fn cstr<'a>(p: *const c_char) -> &'a str {
        if p.is_null() {
            return "";
        }
        // SAFETY: the C API contract: NUL terminated strings.
        unsafe { CStr::from_ptr(p) }.to_str().unwrap_or("")
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn msc_create_rules_set() -> *mut RulesSet {
        Box::into_raw(Box::new(RulesSet::new()))
    }

    /// # Safety
    /// `rules` must come from `msc_create_rules_set`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_rules_dump(rules: *const RulesSet) {
        if let Some(r) = unsafe { rules.as_ref() } {
            r.dump();
        }
    }

    /// # Safety
    /// Both pointers must come from `msc_create_rules_set`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_rules_merge(
        rules_dst: *mut RulesSet,
        rules_from: *mut RulesSet,
        error: *mut *const c_char,
    ) -> c_int {
        let (Some(dst), Some(from)) = (unsafe { rules_dst.as_mut() }, unsafe { rules_from.as_mut() }) else {
            return -1;
        };
        c_result(dst.merge(from), error)
    }

    /// # Safety
    /// `rules` must come from `msc_create_rules_set`; strings are C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_rules_add_remote(
        rules: *mut RulesSet,
        key: *const c_char,
        uri: *const c_char,
        error: *mut *const c_char,
    ) -> c_int {
        let Some(r) = (unsafe { rules.as_mut() }) else {
            return -1;
        };
        c_result(r.load_remote(unsafe { cstr(key) }, unsafe { cstr(uri) }), error)
    }

    /// # Safety
    /// `rules` must come from `msc_create_rules_set`; `file` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_rules_add_file(
        rules: *mut RulesSet,
        file: *const c_char,
        error: *mut *const c_char,
    ) -> c_int {
        let Some(r) = (unsafe { rules.as_mut() }) else {
            return -1;
        };
        c_result(r.load_from_uri(unsafe { cstr(file) }), error)
    }

    /// # Safety
    /// `rules` must come from `msc_create_rules_set`; `plain_rules` is a C
    /// string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_rules_add(
        rules: *mut RulesSet,
        plain_rules: *const c_char,
        error: *mut *const c_char,
    ) -> c_int {
        let Some(r) = (unsafe { rules.as_mut() }) else {
            return -1;
        };
        c_result(r.load(unsafe { cstr(plain_rules) }), error)
    }

    /// # Safety
    /// `error` must come from one of the `msc_rules_*` functions.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_rules_error_cleanup(error: *const c_char) {
        if !error.is_null() {
            drop(unsafe { CString::from_raw(error as *mut c_char) });
        }
    }

    /// # Safety
    /// `rules` must come from `msc_create_rules_set` and not be used after.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn msc_rules_cleanup(rules: *mut RulesSet) -> c_int {
        if !rules.is_null() {
            drop(unsafe { Box::from_raw(rules) });
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::c_api::*;
    use super::*;
    use crate::rules_set_properties::RuleEngine;
    use std::ffi::{CStr, CString, c_char};

    /// `msc_rules_add`: the number of rules, or -1 with the error text.
    fn add(rules: *mut RulesSet, text: &str) -> (i32, Option<String>) {
        let text = CString::new(text).unwrap();
        let mut error: *const c_char = std::ptr::null();
        // SAFETY: valid rule set, string and out-pointer.
        let n = unsafe { msc_rules_add(rules, text.as_ptr(), &mut error) };
        let error = (!error.is_null()).then(|| {
            // SAFETY: set by msc_rules_add, released right after.
            let e = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
            unsafe { msc_rules_error_cleanup(error) };
            e
        });
        (n, error)
    }

    #[test]
    fn c_api_load_and_merge() {
        let a = msc_create_rules_set();
        assert_eq!(add(a, "SecRule ARGS \"@rx a\" \"id:1,phase:2,pass\"\nSecAction \"id:2,phase:1,pass\""), (2, None));

        let (n, error) = add(a, "SecRuleEngine Bogus");
        assert_eq!(n, -1);
        let first = error.unwrap();
        assert!(first.starts_with("Rules error. File: <<reference missing or not informed>>. Line: 1."), "{first}");
        // The errors accumulate: the next failure reports both.
        let (n, error) = add(a, "SecRuleEngine Bogus");
        assert_eq!(n, -1);
        assert!(error.unwrap().starts_with(&first));

        // Merging a duplicated id fails, but the properties are merged.
        let b = msc_create_rules_set();
        assert_eq!(add(b, "SecRuleEngine On\nSecRule ARGS \"@rx b\" \"id:1,phase:2,pass\""), (1, None));
        let mut error: *const c_char = std::ptr::null();
        // SAFETY: valid rule sets and out-pointer.
        assert_eq!(unsafe { msc_rules_merge(a, b, &mut error) }, -1);
        // SAFETY: set by msc_rules_merge.
        let e = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
        unsafe { msc_rules_error_cleanup(error) };
        assert!(e.ends_with("Rule id: 1 is duplicated\n"), "{e}");
        // SAFETY: `a` is live.
        assert_eq!(unsafe { &*a }.properties.sec_rule_engine, Some(RuleEngine::Enabled));

        // SAFETY: created above.
        unsafe {
            msc_rules_cleanup(a);
            msc_rules_cleanup(b);
        }
    }
}
