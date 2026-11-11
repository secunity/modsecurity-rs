//! Port of `src/variables/resource.h`.
//!
//! The `RESOURCE` persistent collection: `RESOURCE`, `RESOURCE:key`, `RESOURCE:/regex/`
//! and `RESOURCE:%{macro}` (the `Resource_DynamicElement` used by `setvar`,
//! `expirevar`, ...). Keys are compartmentalised with the collection key set
//! by `initcol`/`setsid`/`setuid` and the `SecWebAppId`.

use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase, VariableRegex};

/// `Resource_DictElement`
#[derive(Debug)]
pub struct ResourceDictElement {
    pub base: VariableBase,
    pub dict_element: String,
}

impl ResourceDictElement {
    pub fn new(dict_element: &str) -> Self {
        ResourceDictElement {
            base: VariableBase::new(&format!("RESOURCE:{}", dict_element)),
            dict_element: format!("RESOURCE:{}", dict_element),
        }
    }
}

impl Variable for ResourceDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.resource_collection.resolve_multi_matches_c(
            self.base.name.as_bytes(),
            &c.resource_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
    }
}

/// `Resource_NoDictElement`
#[derive(Debug)]
pub struct ResourceNoDictElement {
    pub base: VariableBase,
}

impl ResourceNoDictElement {
    pub fn new() -> Self {
        ResourceNoDictElement { base: VariableBase::new("RESOURCE") }
    }
}

impl Default for ResourceNoDictElement {
    fn default() -> Self {
        Self::new()
    }
}

impl Variable for ResourceNoDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        // `m_name`, which is empty for `RESOURCE`.
        c.resource_collection.resolve_multi_matches_c(
            self.base.name.as_bytes(),
            &c.resource_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
    }
}

/// `Resource_DictElementRegexp`
#[derive(Debug)]
pub struct ResourceDictElementRegexp {
    pub base: VariableRegex,
    pub dict_element: String,
}

impl ResourceDictElementRegexp {
    pub fn new(dict_element: &str) -> Self {
        // Note: the C++ code passes "RESOURCE:" (with the colon), so the
        // variable is named `RESOURCE::regex(...)`; kept as is.
        ResourceDictElementRegexp {
            base: VariableRegex::new("RESOURCE:", dict_element),
            dict_element: dict_element.to_string(),
        }
    }
}

impl Variable for ResourceDictElementRegexp {
    fn base(&self) -> &VariableBase {
        &self.base.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.resource_collection.resolve_regular_expression_c(
            self.dict_element.as_bytes(),
            &c.resource_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.base.key_exclusion,
        );
    }
    fn regex(&self) -> Option<&crate::utils::regex::Regex> {
        Some(&self.base.r)
    }
}

/// `Resource_DynamicElement`: `RESOURCE:%{...}`, the key is a macro expanded
/// at run time.
#[derive(Debug)]
pub struct ResourceDynamicElement {
    pub base: VariableBase,
    pub string: RunTimeString,
}

impl ResourceDynamicElement {
    pub fn new(dict_element: RunTimeString) -> Self {
        ResourceDynamicElement { base: VariableBase::new("RESOURCE:dynamic"), string: dict_element }
    }

    /// `Resource_DynamicElement::del` (static in C++).
    pub fn del(t: &Transaction<'_>, k: &[u8]) {
        let c = &t.collections;
        c.resource_collection.del_c(
            k,
            &c.resource_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
        );
    }

    /// `Resource_DynamicElement::setExpiry` (static in C++; used by `expirevar`).
    pub fn set_expiry(t: &Transaction<'_>, k: &[u8], expiry_seconds: i32) {
        let c = &t.collections;
        c.resource_collection.set_expiry_c(
            k,
            &c.resource_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            expiry_seconds,
        );
    }

    /// `Resource_DynamicElement::storeOrUpdateFirst` (static in C++).
    pub fn store_or_update_first(t: &Transaction<'_>, var: &[u8], value: &[u8]) {
        let c = &t.collections;
        c.resource_collection.store_or_update_first_c(
            var,
            &c.resource_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            value,
        );
    }
}

impl Variable for ResourceDynamicElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let string = self.string.evaluate(Some(t));
        let c = &t.collections;
        c.resource_collection.resolve_multi_matches_c(
            &string,
            &c.resource_collection_key,
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
