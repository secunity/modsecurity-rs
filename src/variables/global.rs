//! Port of `src/variables/global.h`.
//!
//! The `GLOBAL` persistent collection: `GLOBAL`, `GLOBAL:key`, `GLOBAL:/regex/`
//! and `GLOBAL:%{macro}` (the `Global_DynamicElement` used by `setvar`,
//! `expirevar`, ...). Keys are compartmentalised with the collection key set
//! by `initcol`/`setsid`/`setuid` and the `SecWebAppId`.

use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase, VariableRegex};

/// `Global_DictElement`
#[derive(Debug)]
pub struct GlobalDictElement {
    pub base: VariableBase,
    pub dict_element: String,
}

impl GlobalDictElement {
    pub fn new(dict_element: &str) -> Self {
        GlobalDictElement {
            base: VariableBase::new(&format!("GLOBAL:{}", dict_element)),
            dict_element: format!("GLOBAL:{}", dict_element),
        }
    }
}

impl Variable for GlobalDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.global_collection.resolve_multi_matches_c(
            self.base.name.as_bytes(),
            &c.global_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
    }
}

/// `Global_NoDictElement`
#[derive(Debug)]
pub struct GlobalNoDictElement {
    pub base: VariableBase,
}

impl GlobalNoDictElement {
    pub fn new() -> Self {
        GlobalNoDictElement { base: VariableBase::new("GLOBAL") }
    }
}

impl Default for GlobalNoDictElement {
    fn default() -> Self {
        Self::new()
    }
}

impl Variable for GlobalNoDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.global_collection.resolve_multi_matches_c(
            b"",
            &c.global_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
    }
}

/// `Global_DictElementRegexp`
#[derive(Debug)]
pub struct GlobalDictElementRegexp {
    pub base: VariableRegex,
    pub dict_element: String,
}

impl GlobalDictElementRegexp {
    pub fn new(dict_element: &str) -> Self {
        GlobalDictElementRegexp {
            base: VariableRegex::new("GLOBAL", dict_element),
            dict_element: dict_element.to_string(),
        }
    }
}

impl Variable for GlobalDictElementRegexp {
    fn base(&self) -> &VariableBase {
        &self.base.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.global_collection.resolve_regular_expression_c(
            self.dict_element.as_bytes(),
            &c.global_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.base.key_exclusion,
        );
    }
    fn regex(&self) -> Option<&crate::utils::regex::Regex> {
        Some(&self.base.r)
    }
}

/// `Global_DynamicElement`: `GLOBAL:%{...}`, the key is a macro expanded
/// at run time.
#[derive(Debug)]
pub struct GlobalDynamicElement {
    pub base: VariableBase,
    pub string: RunTimeString,
}

impl GlobalDynamicElement {
    pub fn new(dict_element: RunTimeString) -> Self {
        GlobalDynamicElement { base: VariableBase::new("GLOBAL:dynamic"), string: dict_element }
    }

    /// `Global_DynamicElement::del` (static in C++).
    pub fn del(t: &Transaction<'_>, k: &[u8]) {
        let c = &t.collections;
        c.global_collection.del_c(
            k,
            &c.global_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
        );
    }

    /// `Global_DynamicElement::setExpiry` (static in C++; used by `expirevar`).
    pub fn set_expiry(t: &Transaction<'_>, k: &[u8], expiry_seconds: i32) {
        let c = &t.collections;
        c.global_collection.set_expiry_c(
            k,
            &c.global_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            expiry_seconds,
        );
    }

    /// `Global_DynamicElement::storeOrUpdateFirst` (static in C++).
    pub fn store_or_update_first(t: &Transaction<'_>, var: &[u8], value: &[u8]) {
        let c = &t.collections;
        c.global_collection.store_or_update_first_c(
            var,
            &c.global_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            value,
        );
    }
}

impl Variable for GlobalDynamicElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let string = self.string.evaluate(Some(t));
        let c = &t.collections;
        c.global_collection.resolve_multi_matches_c(
            &string,
            &c.global_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
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
