//! Port of `src/variables/tx.cc`, `src/variables/tx.h`.
//!
//! The per transaction `TX` collection: `TX`, `TX:key`, `TX:/regex/` and
//! `TX:%{macro}` (the `Tx_DynamicElement` used by `setvar`). Unlike the
//! persistent collections, `TX` keys are not compartmentalised.

use crate::collection::collection::Collection;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase, VariableRegex};

/// `Tx_DictElement`
#[derive(Debug)]
pub struct TxDictElement {
    pub base: VariableBase,
    pub dict_element: String,
}

impl TxDictElement {
    pub fn new(dict_element: &str) -> Self {
        TxDictElement {
            base: VariableBase::new(&format!("TX:{}", dict_element)),
            dict_element: format!("TX:{}", dict_element),
        }
    }
}

impl Variable for TxDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        t.collections.tx_collection.resolve_multi_matches(self.base.name.as_bytes(), l, &self.base.key_exclusion);
    }
}

/// `Tx_NoDictElement`
#[derive(Debug)]
pub struct TxNoDictElement {
    pub base: VariableBase,
}

impl TxNoDictElement {
    pub fn new() -> Self {
        TxNoDictElement { base: VariableBase::new("TX") }
    }
}

impl Default for TxNoDictElement {
    fn default() -> Self {
        Self::new()
    }
}

impl Variable for TxNoDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        t.collections.tx_collection.resolve_multi_matches(b"", l, &self.base.key_exclusion);
    }
}

/// `Tx_DictElementRegexp`
#[derive(Debug)]
pub struct TxDictElementRegexp {
    pub base: VariableRegex,
    pub dict_element: String,
}

impl TxDictElementRegexp {
    pub fn new(dict_element: &str) -> Self {
        TxDictElementRegexp { base: VariableRegex::new("TX", dict_element), dict_element: dict_element.to_string() }
    }
}

impl Variable for TxDictElementRegexp {
    fn base(&self) -> &VariableBase {
        &self.base.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        // The pattern was compiled with the options the C++ code uses for
        // every evaluation.
        t.collections.tx_collection.resolve_regex(&self.base.r, l, &self.base.base.key_exclusion);
    }
    fn regex(&self) -> Option<&crate::utils::regex::Regex> {
        Some(&self.base.r)
    }
}

/// `Tx_DynamicElement`: `TX:%{...}`, the key is a macro expanded at run
/// time.
#[derive(Debug)]
pub struct TxDynamicElement {
    pub base: VariableBase,
    pub string: RunTimeString,
}

impl TxDynamicElement {
    pub fn new(dict_element: RunTimeString) -> Self {
        TxDynamicElement { base: VariableBase::new("TX:dynamic"), string: dict_element }
    }

    /// `Tx_DynamicElement::del` (static in C++).
    pub fn del(t: &Transaction<'_>, k: &[u8]) {
        t.collections.tx_collection.del(k);
    }

    /// `Tx_DynamicElement::storeOrUpdateFirst` (static in C++).
    pub fn store_or_update_first(t: &Transaction<'_>, var: &[u8], value: &[u8]) {
        t.collections.tx_collection.store_or_update_first(var, value);
    }
}

impl Variable for TxDynamicElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let string = self.string.evaluate(Some(t));
        t.collections.tx_collection.resolve_multi_matches(&string, l, &self.base.key_exclusion);
    }
    fn dynamic_name(&self) -> Option<&RunTimeString> {
        Some(&self.string)
    }
    fn dynamic_del(&self, t: &Transaction<'_>, key: &[u8]) {
        Self::del(t, key);
    }
    fn dynamic_store_or_update_first(&self, t: &Transaction<'_>, key: &[u8], value: &[u8]) {
        Self::store_or_update_first(t, key, value);
    }
}
