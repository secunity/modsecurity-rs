//! Port of `src/variables/session.h`.
//!
//! The `SESSION` persistent collection: `SESSION`, `SESSION:key`, `SESSION:/regex/`
//! and `SESSION:%{macro}` (the `Session_DynamicElement` used by `setvar`,
//! `expirevar`, ...). Keys are compartmentalised with the collection key set
//! by `initcol`/`setsid`/`setuid` and the `SecWebAppId`.

use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase, VariableRegex};

/// `Session_DictElement`
#[derive(Debug)]
pub struct SessionDictElement {
    pub base: VariableBase,
    pub dict_element: String,
}

impl SessionDictElement {
    pub fn new(dict_element: &str) -> Self {
        SessionDictElement {
            base: VariableBase::new(&format!("SESSION:{}", dict_element)),
            dict_element: format!("SESSION:{}", dict_element),
        }
    }
}

impl Variable for SessionDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.session_collection.resolve_multi_matches_c(
            self.base.name.as_bytes(),
            &c.session_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
    }
}

/// `Session_NoDictElement`
#[derive(Debug)]
pub struct SessionNoDictElement {
    pub base: VariableBase,
}

impl SessionNoDictElement {
    pub fn new() -> Self {
        SessionNoDictElement { base: VariableBase::new("SESSION") }
    }
}

impl Default for SessionNoDictElement {
    fn default() -> Self {
        Self::new()
    }
}

impl Variable for SessionNoDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        // `m_name`, which is empty for `SESSION`.
        c.session_collection.resolve_multi_matches_c(
            self.base.name.as_bytes(),
            &c.session_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
    }
}

/// `Session_DictElementRegexp`
#[derive(Debug)]
pub struct SessionDictElementRegexp {
    pub base: VariableRegex,
    pub dict_element: String,
}

impl SessionDictElementRegexp {
    pub fn new(dict_element: &str) -> Self {
        SessionDictElementRegexp {
            base: VariableRegex::new("SESSION", dict_element),
            dict_element: dict_element.to_string(),
        }
    }
}

impl Variable for SessionDictElementRegexp {
    fn base(&self) -> &VariableBase {
        &self.base.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.session_collection.resolve_regular_expression_c(
            self.dict_element.as_bytes(),
            &c.session_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.base.key_exclusion,
        );
    }
    fn regex(&self) -> Option<&crate::utils::regex::Regex> {
        Some(&self.base.r)
    }
}

/// `Session_DynamicElement`: `SESSION:%{...}`, the key is a macro expanded
/// at run time.
#[derive(Debug)]
pub struct SessionDynamicElement {
    pub base: VariableBase,
    pub string: RunTimeString,
}

impl SessionDynamicElement {
    pub fn new(dict_element: RunTimeString) -> Self {
        SessionDynamicElement { base: VariableBase::new("SESSION:dynamic"), string: dict_element }
    }

    /// `Session_DynamicElement::del` (static in C++).
    pub fn del(t: &Transaction<'_>, k: &[u8]) {
        let c = &t.collections;
        // Note: the C++ code uses the IP collection key (not the web app id)
        // as the second compartment here; kept as is.
        c.session_collection.del_c(k, &c.session_collection_key, Some(&c.ip_collection_key));
    }

    /// `Session_DynamicElement::setExpiry` (static in C++; used by `expirevar`).
    pub fn set_expiry(t: &Transaction<'_>, k: &[u8], expiry_seconds: i32) {
        let c = &t.collections;
        c.session_collection.set_expiry_c(
            k,
            &c.session_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            expiry_seconds,
        );
    }

    /// `Session_DynamicElement::storeOrUpdateFirst` (static in C++).
    pub fn store_or_update_first(t: &Transaction<'_>, var: &[u8], value: &[u8]) {
        let c = &t.collections;
        c.session_collection.store_or_update_first_c(
            var,
            &c.session_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            value,
        );
    }
}

impl Variable for SessionDynamicElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let string = self.string.evaluate(Some(t));
        let c = &t.collections;
        c.session_collection.resolve_multi_matches_c(
            &string,
            &c.session_collection_key,
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
