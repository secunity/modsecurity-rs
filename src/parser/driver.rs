//! Port of `src/parser/driver.cc`, `src/parser/driver.h`.
//!
//! The driver runs the SecLang scanner and parser over a configuration and
//! collects what they produce: the configuration properties (C++ `Driver`
//! derives from `RulesSetProperties`) and the rules of every phase.

use std::sync::Arc;

use crate::modsecurity::NUMBER_OF_PHASES;
use crate::parser::seclang_parser::{Location, SeclangParser};
use crate::parser::seclang_scanner::Scanner;
use crate::rule::Rule;
use crate::rule_marker::RuleMarker;
use crate::rule_with_actions::RuleWithActions;
use crate::rules_set_phases::RulesSetPhases;
use crate::rules_set_properties::RulesSetProperties;
use crate::utils::system::is_file;

/// Where the last `SecRule` lives (C++ `m_lastRule`, a raw pointer): the
/// rule at `index` of phase `phase`, followed `depth` times through its
/// chained children.
#[derive(Debug, Clone, Copy)]
struct LastRule {
    phase: usize,
    index: usize,
    depth: usize,
}

pub struct Driver {
    pub properties: RulesSetProperties,
    pub rules_set_phases: RulesSetPhases,

    /// `file`: name given to the location of the parser's initial state
    /// (never set by the C++ code, hence empty).
    pub file: String,

    /// `loc`: one location per scanner buffer (the configuration, then the
    /// included files and downloaded rules being scanned).
    pub(crate) loc: Vec<Location>,

    /// `m_filenames`: the file names referenced by the locations.
    filenames: Vec<String>,

    /// `m_lastRule`
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
            file: String::new(),
            loc: Vec::new(),
            filenames: Vec::new(),
            last_rule: None,
        }
    }

    /// Records a file name (`m_filenames.push_back`) and returns its index.
    pub(crate) fn add_filename(&mut self, name: String) -> usize {
        self.filenames.push(name);
        self.filenames.len() - 1
    }

    pub(crate) fn filename(&self, index: usize) -> &str {
        self.filenames.get(index).map(String::as_str).unwrap_or("")
    }

    /// `*driver.loc.back()`
    pub(crate) fn loc_back(&self) -> &Location {
        self.loc.last().expect("the driver always has a location while parsing")
    }

    pub(crate) fn loc_back_mut(&mut self) -> &mut Location {
        self.loc.last_mut().expect("the driver always has a location while parsing")
    }

    /// `addSecMarker`
    pub fn add_sec_marker(&mut self, marker: &str, file_name: &str, line_number: i32) -> i32 {
        // FIXME (C++): we might move this to the parser.
        for i in 0..NUMBER_OF_PHASES {
            let mut rule = RuleMarker::new(marker, file_name, line_number);
            rule.phase = i as i32;
            self.rules_set_phases.insert(Arc::new(Rule::Marker(rule)));
        }
        0
    }

    /// `addSecAction`
    pub fn add_sec_action(&mut self, rule: RuleWithActions) -> bool {
        if rule.get_phase() >= NUMBER_OF_PHASES as i32 {
            self.properties.parser_error.push_str(&format!("Unknown phase: {}\n", rule.get_phase()));
            return false;
        }
        self.rules_set_phases.insert(Arc::new(Rule::WithActions(rule)));
        true
    }

    /// `addSecRuleScript`
    pub fn add_sec_rule_script(&mut self, rule: RuleWithActions) -> bool {
        self.rules_set_phases.insert(Arc::new(Rule::WithActions(rule)));
        true
    }

    /// The rule `m_lastRule` points to.
    fn last_rule_mut(&mut self) -> Option<&mut RuleWithActions> {
        let lr = self.last_rule?;
        let arc = self.rules_set_phases.at_mut(lr.phase).rules.get_mut(lr.index)?;
        // While parsing, the driver holds the only reference to its rules.
        let mut r = Arc::get_mut(arc)?.as_rule_with_actions_mut()?;
        for _ in 0..lr.depth {
            r = r.chained_rule_child.as_deref_mut()?;
        }
        Some(r)
    }

    /// `addSecRule`: adds a `SecRule`, or chains it to the previous one
    /// when that one has the `chain` action.
    pub fn add_sec_rule(&mut self, mut r: RuleWithActions) -> bool {
        if r.get_phase() >= NUMBER_OF_PHASES as i32 {
            self.properties.parser_error.push_str(&format!("Unknown phase: {}\n", r.get_phase()));
            return false;
        }

        // is it a chained rule?
        if let Some(last) = self.last_rule_mut()
            && last.is_chained()
        {
            r.set_phase(last.get_phase());
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
        if r.rule_id == 0 {
            self.properties
                .parser_error
                .push_str(&format!("Rules must have an ID. File: {} at line: {}\n", r.file_name, r.line_number));
            return false;
        }

        for i in 0..NUMBER_OF_PHASES {
            let rules = self.rules_set_phases.at(i);
            for lr in &rules.rules {
                if lr.rule_with_operator_id() == Some(r.rule_id) {
                    self.properties.parser_error.push_str(&format!("Rule id: {} is duplicated\n", r.rule_id));
                    return false;
                }
            }
        }

        let phase = r.get_phase() as usize;
        if self.rules_set_phases.insert(Arc::new(Rule::WithActions(r))) {
            let index = self.rules_set_phases.at(phase).rules.len() - 1;
            self.last_rule = Some(LastRule { phase, index, depth: 0 });
        } else {
            self.last_rule = None;
        }
        true
    }

    /// `parse(f, ref)`: parses the rules in `f`; `reference` names their
    /// origin in the error messages. Returns 0 on failure (see
    /// `properties.parser_error`).
    pub fn parse(&mut self, f: &str, reference: &str) -> i32 {
        self.parse_bytes(f.as_bytes(), reference)
    }

    fn parse_bytes(&mut self, f: &[u8], reference: &str) -> i32 {
        self.last_rule = None;
        let name = if reference.is_empty() {
            "<<reference missing or not informed>>".to_string()
        } else {
            reference.to_string()
        };
        let idx = self.add_filename(name);
        self.loc.push(Location::new(idx));

        if f.is_empty() {
            return 1;
        }

        // scan_begin
        let mut scanner = Scanner::new(f);
        let res = SeclangParser::parse(self, &mut scanner);
        // scan_end: the scanner (and its buffers) goes away here.
        drop(scanner);

        // need to check for rules marked as chained but without
        // a chained rule.
        //
        // (Disabled in C++: "Last rule is marked as chained but there
        // isn't a subsequent rule.")

        i32::from(res == 0)
    }

    /// `parseFile`
    pub fn parse_file(&mut self, f: &str) -> i32 {
        if !is_file(f) {
            self.properties.parser_error.push_str(&format!("Failed to open the file: {}\n", f));
            return 0;
        }
        let Ok(content) = std::fs::read(f) else {
            self.properties.parser_error.push_str(&format!("Failed to open the file: {}\n", f));
            return 0;
        };
        self.parse_bytes(&content, f)
    }

    /// `error(location, message, context)`: the first error also writes the
    /// position header.
    pub(crate) fn error(&mut self, l: &Location, m: &str, c: &str) {
        if self.properties.parser_error.is_empty() {
            let header = format!(
                "Rules error. File: {}. Line: {}. Column: {}. ",
                self.filename(l.end.filename),
                l.end.line,
                l.end.column - 1
            );
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
