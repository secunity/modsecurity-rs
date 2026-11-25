//! A loaded rule set: loading and merging. `crate::eval` runs it.

pub mod entry;
pub mod exceptions;
pub mod marker;
pub mod phases;
pub mod plan;
pub mod properties;

use crate::debug_log::DebugLog;
use crate::parser::driver::Driver;
use crate::rules_set::phases::RulesSetPhases;
use crate::rules_set::plan::Plan;
use crate::rules_set::properties::RulesSetProperties;
use crate::utils::https_client::HttpsClient;
use std::sync::OnceLock;

/// Rules that could not be loaded or merged.
///
/// The message holds every parser error the rule set has collected so far,
/// as the C API reports them (`msc_rules_add*`): loading more rules after
/// an error reports the earlier errors again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    message: String,
}

impl LoadError {
    /// The parser errors.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message.trim_end())
    }
}

impl std::error::Error for LoadError {}

/// A loaded configuration: the rules of every phase plus the configuration
/// properties.
pub struct RulesSet {
    pub(crate) properties: RulesSetProperties,
    pub(crate) rules_set_phases: RulesSetPhases,
    /// See [`RulesSet::plan`].
    plan: OnceLock<Plan>,
}

impl Default for RulesSet {
    fn default() -> Self {
        Self::new()
    }
}

impl RulesSet {
    pub fn new() -> Self {
        RulesSet {
            properties: RulesSetProperties::new(),
            rules_set_phases: RulesSetPhases::default(),
            plan: OnceLock::new(),
        }
    }

    /// An empty rule set that writes its debug log to `custom_log`.
    pub fn with_debug_log(custom_log: Box<dyn DebugLog>) -> Self {
        RulesSet {
            properties: RulesSetProperties::with_debug_log(custom_log),
            rules_set_phases: RulesSetPhases::default(),
            plan: OnceLock::new(),
        }
    }

    /// The error of a failed load or merge: all the parser errors collected
    /// so far (as the C API reports them, see [`RulesSet::parser_error`]).
    fn failed<T>(&self) -> Result<T, LoadError> {
        Err(LoadError { message: self.properties.parser_error.clone() })
    }

    /// A driver to load rules into this rule set.
    fn driver(&self) -> Driver {
        let mut driver = Driver::new();
        driver.default_actions_taken = self.properties.default_actions.each_ref().map(|list| !list.is_empty());
        driver
    }

    /// Loads the rules of a file. Returns the number of rules loaded.
    pub fn load_from_uri(&mut self, uri: &str) -> Result<usize, LoadError> {
        let mut driver = self.driver();
        if !driver.parse_file(uri) {
            self.properties.parser_error.push_str(&driver.rules.properties.parser_error);
            return self.failed();
        }
        self.merge(&mut driver.rules)
    }

    /// Loads the rules of the file at `path`, which need not be UTF-8 (the
    /// messages show it with its invalid bytes replaced). Returns the number
    /// of rules loaded.
    pub fn load_file(&mut self, path: &std::path::Path) -> Result<usize, LoadError> {
        if let Some(uri) = path.to_str() {
            return self.load_from_uri(uri);
        }
        let reference = path.to_string_lossy();
        let content = if path.is_file() { std::fs::read(path).ok() } else { None };
        let Some(content) = content else {
            self.properties.parser_error.push_str(&format!("Failed to open the file: {}\n", reference));
            return self.failed();
        };
        self.load_bytes(&content, &reference)
    }

    /// Loads rules from text; `reference` names their origin in messages
    /// (a file name or URL). Returns the number of rules loaded.
    pub fn load_with_ref(&mut self, rules: &str, reference: &str) -> Result<usize, LoadError> {
        self.load_bytes(rules.as_bytes(), reference)
    }

    /// Loads rules from bytes, which need not be UTF-8: a rule can match
    /// any byte (`@rx \xe9` written in Latin-1, for example). `reference`
    /// names their origin in messages (a file name or URL). Returns the
    /// number of rules loaded.
    pub fn load_bytes(&mut self, rules: &[u8], reference: &str) -> Result<usize, LoadError> {
        let mut driver = self.driver();
        if !driver.parse_bytes(rules, reference) {
            self.properties.parser_error.push_str(&driver.rules.properties.parser_error);
            return self.failed();
        }
        self.merge(&mut driver.rules).or_else(|_| {
            // The parser errors of the driver are added to the merge error.
            self.properties.parser_error.push_str(&driver.rules.properties.parser_error);
            self.failed()
        })
    }

    /// Downloads rules from `uri`, sending `key` as `SecRemoteRules` does,
    /// and loads them. Returns the number of rules loaded.
    pub fn load_remote(&mut self, key: &str, uri: &str) -> Result<usize, LoadError> {
        let mut client = HttpsClient::new();
        client.set_key(key);
        if client.download(uri) {
            let content = std::mem::take(&mut client.content);
            return self.load_bytes(&content, uri);
        }
        self.failed()
    }

    /// Loads rules from text. Returns the number of rules loaded.
    pub fn load(&mut self, plain_rules: &str) -> Result<usize, LoadError> {
        self.load_with_ref(plain_rules, "")
    }

    /// The parser errors collected so far (empty without errors).
    pub fn parser_error(&self) -> String {
        self.properties.parser_error.clone()
    }

    /// The plan of the rule set, compiled the first time it is needed
    /// after the rules changed.
    pub(crate) fn plan(&self) -> &Plan {
        self.plan.get_or_init(|| Plan::compile(self))
    }

    /// Appends the rules of `from` and merges its properties. Returns the
    /// number of rules appended. The properties are merged even when the
    /// rules could not be (a duplicated id), and a failure to merge them is
    /// only recorded in the parser errors.
    pub fn merge(&mut self, from: &mut RulesSet) -> Result<usize, LoadError> {
        // The rules change: so does the plan.
        self.plan = OnceLock::new();
        let appended = self.rules_set_phases.append(&from.rules_set_phases);
        if let Err(e) = &appended {
            self.properties.parser_error.push_str(e);
        }
        if let Err(e) = RulesSetProperties::merge_properties(&mut from.properties, &mut self.properties) {
            self.properties.parser_error.push_str(&e);
        }
        appended.or_else(|_| self.failed())
    }

    /// Writes `msg` to the debug log for the transaction `id` handling
    /// `uri`.
    pub(crate) fn debug(&self, level: u8, id: &str, uri: &str, msg: &str) {
        self.properties.debug_log.write_ctx(level, id, uri, msg);
    }

    pub fn dump(&self) {
        self.rules_set_phases.dump();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phases::Phases;
    use crate::transaction::Transaction;

    #[test]
    fn load_errors() {
        let mut rules = RulesSet::new();
        assert_eq!(rules.load("SecRuleEngine On\n"), Ok(0));

        let first = rules.load("SecRuleEngine Maybe\n").unwrap_err();
        assert!(first.message().starts_with("Rules error. "), "{first}");
        // Display leaves out the trailing whitespace.
        assert_eq!(first.to_string(), first.message().trim_end());
        assert_eq!(rules.parser_error(), first.message());

        // The errors accumulate, as with msc_rules_add.
        let second = rules.load("SecNoSuchDirective\n").unwrap_err();
        assert!(second.message().starts_with(first.message()));
        assert!(second.message().len() > first.message().len());

        let boxed: Box<dyn std::error::Error> = Box::new(second);
        assert!(!boxed.to_string().is_empty());
    }

    /// A Latin-1 rule: `@rx \xe9t\xe9` ("été" in Latin-1).
    const LATIN1_RULES: &[u8] = b"SecRuleEngine On\nSecRule ARGS \"@rx \xe9t\xe9\" \"id:1,phase:1,deny,status:403\"\n";

    /// The status a `GET` of `uri` is denied with.
    fn denied(rules: &RulesSet, uri: &[u8]) -> Option<u16> {
        let ms = crate::ModSecurity::new();
        let mut t = Transaction::new(&ms, rules, None);
        t.process_connection("127.0.0.1", 1, "127.0.0.1", 80);
        t.process_uri(uri, b"GET", b"1.1");
        t.process_request_headers();
        t.intervention().map(|it| it.status)
    }

    #[test]
    fn rules_that_are_not_utf8_load_and_match_their_bytes() {
        let mut rules = RulesSet::new();
        assert_eq!(rules.load_bytes(LATIN1_RULES, "latin1.conf"), Ok(1));
        assert_eq!(denied(&rules, b"/?a=%E9t%E9"), Some(403));
        assert_eq!(denied(&rules, b"/?a=%C3%A9t%C3%A9"), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_of_rules_that_are_not_utf8_at_a_path_that_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("modsec-latin1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(std::ffi::OsStr::from_bytes(b"r\xe8gles.conf"));
        std::fs::write(&path, LATIN1_RULES).unwrap();

        let mut rules = RulesSet::new();
        let loaded = rules.load_file(&path);
        let missing = RulesSet::new().load_file(&dir.join(std::ffi::OsStr::from_bytes(b"absent\xe8.conf")));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(loaded, Ok(1));
        assert_eq!(denied(&rules, b"/?a=%E9t%E9"), Some(403));
        let missing = missing.unwrap_err();
        assert!(missing.message().starts_with("Failed to open the file: "), "{missing}");
        assert!(missing.message().ends_with("absent\u{fffd}.conf\n"), "{missing}");
    }

    /// The status of the intervention after phase 2 for `/?a=x`.
    fn status_of(rules: &RulesSet) -> Option<u16> {
        let ms = crate::ModSecurity::new();
        let mut t = Transaction::new(&ms, rules, None);
        t.process_uri(b"/?a=x", b"GET", b"1.1");
        t.process_request_headers();
        t.process_request_body();
        t.intervention().map(|it| it.status)
    }

    /// A `skipAfter` whose marker is not found skips the rest of its phase
    /// only.
    #[test]
    fn a_skip_after_without_its_marker_ends_with_the_phase() {
        let mut rules = RulesSet::new();
        rules
            .load(
                "SecRuleEngine On\n\
                 SecAction \"id:1,phase:1,pass,nolog,skipAfter:NOWHERE\"\n\
                 SecRule ARGS \"@rx x\" \"id:2,phase:1,deny,status:401\"\n\
                 SecRule ARGS \"@rx x\" \"id:3,phase:2,deny,status:403\"\n",
            )
            .unwrap();
        // Rule 2 is skipped; rule 3, in the next phase, is not.
        assert_eq!(status_of(&rules), Some(403));
    }

    #[test]
    fn a_skip_after_goes_on_to_its_marker_in_a_later_phase() {
        // The marker is before the skipping rule: in phase 2 it comes after
        // rule 3, which is skipped.
        let mut rules = RulesSet::new();
        rules
            .load(
                "SecRuleEngine On\n\
                 SecRule ARGS \"@rx x\" \"id:3,phase:2,deny,status:403\"\n\
                 SecMarker END\n\
                 SecAction \"id:1,phase:1,pass,nolog,skipAfter:END\"\n",
            )
            .unwrap();
        assert_eq!(status_of(&rules), None);
    }

    /// A merged rule set keeps the `SecDefaultAction` of the configuration
    /// it is merged into for a phase that has one, and takes the other's
    /// for the other phases.
    #[test]
    fn merged_default_actions_come_from_one_configuration() {
        let rule = "SecRuleEngine On\nSecRule ARGS \"@rx x\" \"id:1,phase:2,block\"\n";
        let mut child = RulesSet::new();
        child.load(&format!("SecDefaultAction \"phase:2,log,deny,status:403\"\n{rule}")).unwrap();
        let mut parent = RulesSet::new();
        parent.load("SecDefaultAction \"phase:2,log,pass\"\n").unwrap();
        child.merge(&mut parent).unwrap();
        assert_eq!(status_of(&child), Some(403));
        assert_eq!(child.properties.default_actions[Phases::RequestBody.index()].len(), 3, "log, deny, status");

        // Without one of its own, the child takes the parent's.
        let mut child = RulesSet::new();
        child.load(rule).unwrap();
        let mut parent = RulesSet::new();
        parent.load("SecDefaultAction \"phase:2,log,deny,status:401\"\n").unwrap();
        child.merge(&mut parent).unwrap();
        assert_eq!(status_of(&child), Some(401));
    }

    /// A second `SecDefaultAction` for a phase is refused in a later load
    /// into the same rule set as it is within one load.
    #[test]
    fn default_actions_once_per_phase_across_loads() {
        let mut rules = RulesSet::new();
        rules.load("SecDefaultAction \"phase:2,log,deny,status:403\"\n").unwrap();
        // Another phase is fine.
        rules.load("SecDefaultAction \"phase:1,log,pass\"\n").unwrap();
        let error = rules.load("SecDefaultAction \"phase:2,log,pass\"\n").unwrap_err();
        assert!(
            error.message().contains(
                "SecDefaultActions can only be placed once per phase and configuration context. Phase 2 was informed already."
            ),
            "{error}"
        );
        // The first one stays.
        rules.load("SecRuleEngine On\nSecRule ARGS \"@rx x\" \"id:1,phase:2,block\"\n").unwrap();
        assert_eq!(status_of(&rules), Some(403));
    }
}
