//! The driver loads SecLang configurations (`build.rs`) and collects what
//! they produce: the configuration properties and the rules of every phase.

use std::sync::Arc;

use crate::phases::Phases;
use crate::rule::Rule;
use crate::rules_set::entry::Entry;
use crate::rules_set::marker::Marker;
use crate::rules_set::phases::RulesSetPhases;
use crate::rules_set::properties::RulesSetProperties;
use crate::utils::system::is_file;

/// A position in a configuration file, for error messages: the file (an
/// index in the driver's file names), and 1-based line and column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub file: usize,
    pub line: usize,
    pub column: usize,
}

/// Where the last `SecRule` lives: the rule at `index` of phase `phase`,
/// followed `depth` times through its chained children.
#[derive(Debug, Clone, Copy)]
struct LastRule {
    phase: Phases,
    index: usize,
    depth: usize,
}

pub struct Driver {
    pub properties: RulesSetProperties,
    pub rules_set_phases: RulesSetPhases,

    /// The file names referenced by the locations.
    filenames: Vec<String>,

    /// The last `SecRule` added, which a chained rule attaches to.
    last_rule: Option<LastRule>,
}

impl Default for Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver {
    pub fn new() -> Self {
        Driver {
            properties: RulesSetProperties::new(),
            rules_set_phases: RulesSetPhases::default(),
            filenames: Vec::new(),
            last_rule: None,
        }
    }

    /// Records a file name and returns its index.
    pub(crate) fn add_filename(&mut self, name: String) -> usize {
        self.filenames.push(name);
        self.filenames.len() - 1
    }

    pub(crate) fn filename(&self, index: usize) -> &str {
        self.filenames.get(index).map(String::as_str).unwrap_or("")
    }

    /// Adds a `SecMarker` to every phase.
    pub fn add_sec_marker(&mut self, marker: &str, file_name: &str, line_number: i32) -> i32 {
        // FIXME (C++): we might move this to the parser.
        for phase in Phases::ALL {
            let mut rule = Marker::new(marker, file_name, line_number);
            rule.phase = phase;
            self.rules_set_phases.insert(Arc::new(Entry::Marker(rule)));
        }
        0
    }

    /// Adds a `SecAction` rule.
    pub fn add_sec_action(&mut self, rule: Rule) -> bool {
        self.rules_set_phases.insert(Arc::new(Entry::Rule(rule)));
        true
    }

    /// Adds a `SecRuleScript` rule.
    pub fn add_sec_rule_script(&mut self, rule: Rule) -> bool {
        self.rules_set_phases.insert(Arc::new(Entry::Rule(rule)));
        true
    }

    /// The rule `last_rule` points to.
    fn last_rule_mut(&mut self) -> Option<&mut Rule> {
        let lr = self.last_rule?;
        let arc = self.rules_set_phases.for_phase_mut(lr.phase).get_mut(lr.index)?;
        // While parsing, the driver holds the only reference to its rules.
        let mut r = Arc::get_mut(arc)?.as_rule_mut()?;
        for _ in 0..lr.depth {
            r = r.chained_rule_child.as_deref_mut()?;
        }
        Some(r)
    }

    /// Adds a `SecRule`, or chains it to the previous one
    /// when that one has the `chain` action.
    pub fn add_sec_rule(&mut self, mut r: Rule) -> bool {
        // is it a chained rule?
        if let Some(last) = self.last_rule_mut()
            && last.is_chained()
        {
            r.set_phase(last.phase());
            if r.has_disruptive_action() {
                self.properties
                    .parser_error
                    .push_str("Disruptive actions can only be specified by chain starter rules.");
                return false;
            }
            r.chained_rule_parent = true;
            last.chained_rule_child = Some(Box::new(r));
            if let Some(lr) = self.last_rule.as_mut() {
                lr.depth += 1;
            }
            return true;
        }

        // Checking if the rule has an ID and also checking if this ID is
        // not used by other rule
        if r.rule_id.get() == 0 {
            self.properties
                .parser_error
                .push_str(&format!("Rules must have an ID. File: {} at line: {}\n", r.file_name, r.line_number));
            return false;
        }

        for phase in Phases::ALL {
            let rules = self.rules_set_phases.for_phase(phase);
            for lr in rules {
                if lr.sec_rule_id() == Some(r.rule_id.get()) {
                    self.properties.parser_error.push_str(&format!("Rule id: {} is duplicated\n", r.rule_id));
                    return false;
                }
            }
        }

        // A rule without a phase (unknown `phase:<name>`) is dropped.
        let phase = r.phase();
        if let Some(phase) = phase
            && self.rules_set_phases.insert(Arc::new(Entry::Rule(r)))
        {
            let index = self.rules_set_phases.for_phase(phase).len() - 1;
            self.last_rule = Some(LastRule { phase, index, depth: 0 });
        } else {
            self.last_rule = None;
        }
        true
    }

    /// Parses the rules in `f`; `reference` names their
    /// origin in the error messages. Returns whether the rules were valid
    /// (the errors are in `properties.parser_error`).
    pub fn parse(&mut self, f: &str, reference: &str) -> bool {
        self.parse_bytes(f.as_bytes(), reference)
    }

    pub(crate) fn parse_bytes(&mut self, f: &[u8], reference: &str) -> bool {
        self.last_rule = None;
        let idx = self.add_filename(Self::reference_name(reference));
        crate::parser::build::load(self, f, idx).is_ok()
    }

    fn reference_name(reference: &str) -> String {
        if reference.is_empty() { "<<reference missing or not informed>>".to_string() } else { reference.to_string() }
    }

    /// `parse_bytes`, reading the statements of the top file one by one (the
    /// way used after a syntax error), for the tests.
    #[cfg(test)]
    pub(crate) fn parse_bytes_incremental(&mut self, f: &[u8], reference: &str) -> bool {
        self.last_rule = None;
        let idx = self.add_filename(Self::reference_name(reference));
        crate::parser::build::load_with(self, f, idx, false).is_ok()
    }

    /// Parses the rules of the file `f`.
    pub fn parse_file(&mut self, f: &str) -> bool {
        let content = if is_file(f) { std::fs::read(f).ok() } else { None };
        let Some(content) = content else {
            self.properties.parser_error.push_str(&format!("Failed to open the file: {}\n", f));
            return false;
        };
        self.parse_bytes(&content, f)
    }

    /// Appends the error message `m` and its context `c` to the parser
    /// errors; the first error also writes the position header.
    pub(crate) fn error(&mut self, at: Position, m: &str, c: &str) {
        if self.properties.parser_error.is_empty() {
            let header =
                format!("Rules error. File: {}. Line: {}. Column: {}. ", self.filename(at.file), at.line, at.column);
            self.properties.parser_error.push_str(&header);
        }
        if !m.is_empty() {
            self.properties.parser_error.push_str(m);
            self.properties.parser_error.push(' ');
        }
        if !c.is_empty() {
            self.properties.parser_error.push_str(c);
        }
    }
}
