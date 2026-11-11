//! Port of `src/variables/ip.h`.
//!
//! The `IP` persistent collection: `IP`, `IP:key`, `IP:/regex/`
//! and `IP:%{macro}` (the `Ip_DynamicElement` used by `setvar`,
//! `expirevar`, ...). Keys are compartmentalised with the collection key set
//! by `initcol`/`setsid`/`setuid` and the `SecWebAppId`.

use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase, VariableRegex};

/// `Ip_DictElement`
#[derive(Debug)]
pub struct IpDictElement {
    pub base: VariableBase,
    pub dict_element: String,
}

impl IpDictElement {
    pub fn new(dict_element: &str) -> Self {
        IpDictElement {
            base: VariableBase::new(&format!("IP:{}", dict_element)),
            dict_element: format!("IP:{}", dict_element),
        }
    }
}

impl Variable for IpDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.ip_collection.resolve_multi_matches_c(
            self.base.name.as_bytes(),
            &c.ip_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
    }
}

/// `Ip_NoDictElement`
#[derive(Debug)]
pub struct IpNoDictElement {
    pub base: VariableBase,
}

impl IpNoDictElement {
    pub fn new() -> Self {
        IpNoDictElement { base: VariableBase::new("IP") }
    }
}

impl Default for IpNoDictElement {
    fn default() -> Self {
        Self::new()
    }
}

impl Variable for IpNoDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.ip_collection.resolve_multi_matches_c(
            b"",
            &c.ip_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
    }
}

/// `Ip_DictElementRegexp`
#[derive(Debug)]
pub struct IpDictElementRegexp {
    pub base: VariableRegex,
    pub dict_element: String,
}

impl IpDictElementRegexp {
    pub fn new(dict_element: &str) -> Self {
        IpDictElementRegexp { base: VariableRegex::new("IP", dict_element), dict_element: dict_element.to_string() }
    }
}

impl Variable for IpDictElementRegexp {
    fn base(&self) -> &VariableBase {
        &self.base.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.ip_collection.resolve_regular_expression_c(
            self.dict_element.as_bytes(),
            &c.ip_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.base.key_exclusion,
        );
    }
    fn regex(&self) -> Option<&crate::utils::regex::Regex> {
        Some(&self.base.r)
    }
}

/// `Ip_DynamicElement`: `IP:%{...}`, the key is a macro expanded
/// at run time.
#[derive(Debug)]
pub struct IpDynamicElement {
    pub base: VariableBase,
    pub string: RunTimeString,
}

impl IpDynamicElement {
    pub fn new(dict_element: RunTimeString) -> Self {
        IpDynamicElement { base: VariableBase::new("IP:dynamic"), string: dict_element }
    }

    /// `Ip_DynamicElement::del` (static in C++).
    pub fn del(t: &Transaction<'_>, k: &[u8]) {
        let c = &t.collections;
        c.ip_collection.del_c(k, &c.ip_collection_key, Some(t.rules.properties.sec_web_app_id.value.as_bytes()));
    }

    /// `Ip_DynamicElement::setExpiry` (static in C++; used by `expirevar`).
    pub fn set_expiry(t: &Transaction<'_>, k: &[u8], expiry_seconds: i32) {
        let c = &t.collections;
        c.ip_collection.set_expiry_c(
            k,
            &c.ip_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            expiry_seconds,
        );
    }

    /// `Ip_DynamicElement::storeOrUpdateFirst` (static in C++).
    pub fn store_or_update_first(t: &Transaction<'_>, var: &[u8], value: &[u8]) {
        let c = &t.collections;
        c.ip_collection.store_or_update_first_c(
            var,
            &c.ip_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            value,
        );
    }
}

impl Variable for IpDynamicElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let string = self.string.evaluate(Some(t));
        let c = &t.collections;
        c.ip_collection.resolve_multi_matches_c(
            &string,
            &c.ip_collection_key,
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
