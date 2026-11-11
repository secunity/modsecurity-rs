//! Port of `headers/modsecurity/rules_set.h` and `src/rules_set.cc`.

use crate::actions::disruptive::allow::AllowType;
use crate::debug_log::debug_log::DebugLog;
use crate::modsecurity::{NUMBER_OF_PHASES, Phases};
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

    /// `loadFromUri`: loads the rules of a file. Returns the number of rules
    /// loaded or -1 (see [`RulesSet::get_parser_error`]).
    pub fn load_from_uri(&mut self, uri: &str) -> i32 {
        let mut driver = Driver::new();
        if driver.parse_file(uri) == 0 {
            self.properties.parser_error.push_str(&driver.properties.parser_error);
            return -1;
        }
        self.merge_driver(&mut driver)
    }

    /// `load(rules, ref)`
    pub fn load_with_ref(&mut self, rules: &str, reference: &str) -> i32 {
        let mut driver = Driver::new();
        if driver.parse(rules, reference) == 0 {
            self.properties.parser_error.push_str(&driver.properties.parser_error);
            return -1;
        }
        let rules = self.merge_driver(&mut driver);
        if rules == -1 {
            self.properties.parser_error.push_str(&driver.properties.parser_error);
            return -1;
        }
        rules
    }

    /// `loadRemote`
    pub fn load_remote(&mut self, key: &str, uri: &str) -> i32 {
        let mut client = HttpsClient::new();
        client.set_key(key);
        if client.download(uri) {
            let content = String::from_utf8_lossy(&client.content).into_owned();
            return self.load_with_ref(&content, uri);
        }
        -1
    }

    /// `load(plainRules)`
    pub fn load(&mut self, plain_rules: &str) -> i32 {
        self.load_with_ref(plain_rules, "")
    }

    pub fn get_parser_error(&self) -> String {
        self.properties.parser_error.clone()
    }

    /// `cleanMatchedVars`
    pub fn clean_matched_vars(t: &mut Transaction<'_>) {
        crate::ms_dbg_a!(t, 9, "Matched vars cleaned.");
        t.vars.matched_var.unset();
        t.vars.matched_vars.unset();
        t.vars.matched_var_name.unset();
        t.vars.matched_vars_names.unset();
    }

    /// `evaluate(phase, transaction)`
    pub fn evaluate<'a>(&'a self, phase: i32, t: &mut Transaction<'a>) -> i32 {
        if phase < 0 || phase as usize >= NUMBER_OF_PHASES {
            return 0;
        }
        let rules = self.rules_set_phases.at(phase as usize);
        crate::ms_dbg_a!(t, 9, "This phase consists of {} rule(s).", rules.size());

        if t.allow_type == AllowType::FromNowOnAllowType && phase != Phases::LoggingPhase as i32 {
            crate::ms_dbg_a!(
                t,
                9,
                "Skipping all rules evaluation on this phase as request through the utilization of an `allow' action."
            );
            return 1;
        }
        if t.allow_type == AllowType::RequestAllowType && phase <= Phases::RequestBodyPhase as i32 {
            crate::ms_dbg_a!(
                t,
                9,
                "Skipping all rules evaluation on this phase as request through the utilization of an `allow' action."
            );
            return 1;
        }
        t.allow_type = AllowType::NoneAllowType;

        let ex = &self.properties.exceptions;
        for rule in &rules.rules {
            let rule: &'a crate::rule::Rule = rule.as_ref();
            if t.is_inside_a_marker() && !rule.is_marker() {
                crate::ms_dbg_a!(
                    t,
                    9,
                    "Skipped rule id '{}' due to a SecMarker: {}",
                    rule.get_reference(),
                    t.get_current_marker().unwrap_or_default()
                );
            } else if rule.is_marker() {
                rule.evaluate(t);
            } else if t.skip_next > 0 {
                t.skip_next -= 1;
                crate::ms_dbg_a!(
                    t,
                    9,
                    "Skipped rule id '{}' due to a `skip' action. Still {} to be skipped.",
                    rule.get_reference(),
                    t.skip_next
                );
            } else if t.allow_type != AllowType::NoneAllowType {
                crate::ms_dbg_a!(
                    t,
                    9,
                    "Skipped rule id '{}' as request trough the utilization of an `allow' action.",
                    rule.get_reference()
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
                            rule.get_reference()
                        );
                        continue;
                    }
                    if ex.remove_rule_by_msg.iter().any(|z| r.contains_msg(z, t)) {
                        crate::ms_dbg_a!(
                            t,
                            9,
                            "Skipped rule id '{}'. Removed by a SecRuleRemoveByMsg directive.",
                            r.get_reference()
                        );
                        continue;
                    }
                    if ex.remove_rule_by_tag.iter().any(|z| r.contains_tag(z, t)) {
                        crate::ms_dbg_a!(
                            t,
                            9,
                            "Skipped rule id '{}'. Removed by a SecRuleRemoveByTag directive.",
                            r.get_reference()
                        );
                        continue;
                    }
                    if t.rule_remove_by_tag.iter().any(|z| r.contains_tag(z, t)) {
                        crate::ms_dbg_a!(
                            t,
                            9,
                            "Skipped rule id '{}'. Skipped due to a ruleRemoveByTag action.",
                            r.get_reference()
                        );
                        continue;
                    }
                }

                rule.evaluate(t);
                Self::clean_matched_vars(t);

                if t.it.disruptive != 0 {
                    crate::ms_dbg_a!(t, 8, "Skipping this phase as this request was already intercepted.");
                    break;
                }
            }
        }
        1
    }

    /// `merge(Parser::Driver *from)`
    pub fn merge_driver(&mut self, from: &mut Driver) -> i32 {
        let amount_of_rules = self.rules_set_phases.append(&from.rules_set_phases, &mut self.properties.parser_error);
        let mut err = String::new();
        RulesSetProperties::merge_properties(&mut from.properties, &mut self.properties, &mut err);
        self.properties.parser_error.push_str(&err);
        amount_of_rules
    }

    /// `merge(RulesSet *from)`
    pub fn merge(&mut self, from: &mut RulesSet) -> i32 {
        let amount_of_rules = self.rules_set_phases.append(&from.rules_set_phases, &mut self.properties.parser_error);
        let mut err = String::new();
        RulesSetProperties::merge_properties(&mut from.properties, &mut self.properties, &mut err);
        self.properties.parser_error.push_str(&err);
        amount_of_rules
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
        let ret = dst.merge(from);
        if ret < 0 {
            set_error(error, dst.get_parser_error());
        }
        ret
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
        let ret = r.load_remote(unsafe { cstr(key) }, unsafe { cstr(uri) });
        if ret < 0 {
            set_error(error, r.get_parser_error());
        }
        ret
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
        let ret = r.load_from_uri(unsafe { cstr(file) });
        if ret < 0 {
            set_error(error, r.get_parser_error());
        }
        ret
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
        let ret = r.load(unsafe { cstr(plain_rules) });
        if ret < 0 {
            set_error(error, r.get_parser_error());
        }
        ret
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
