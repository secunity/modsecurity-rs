//! Port of `src/variables/modsec_build.cc`, `src/variables/modsec_build.h`.
//!
//! `MODSEC_BUILD`: the library version as `MMmmPPTT` (major, minor, patch
//! level and tag number, each zero padded to at least two digits).

use crate::modsecurity::{MODSECURITY_MAJOR, MODSECURITY_MINOR, MODSECURITY_PATCHLEVEL, MODSECURITY_TAG_NUM};
use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `ModsecBuild`
#[derive(Debug)]
pub struct ModsecBuild {
    pub base: VariableBase,
    pub build: String,
    pub ret_name: String,
}

impl ModsecBuild {
    /// `ModsecBuild(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        // `std::setw(2) << std::setfill('0')` for each part.
        let build = format!(
            "{:0>2}{:0>2}{:0>2}{:0>2}",
            MODSECURITY_MAJOR, MODSECURITY_MINOR, MODSECURITY_PATCHLEVEL, MODSECURITY_TAG_NUM
        );
        ModsecBuild { base: VariableBase::new(name), build, ret_name: "MODSEC_BUILD".to_string() }
    }
}

impl Variable for ModsecBuild {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, _t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        l.push(VariableValue::new(self.ret_name.as_bytes(), self.build.as_bytes()));
    }
}
