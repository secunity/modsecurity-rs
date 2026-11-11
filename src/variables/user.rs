//! Port of `src/variables/user.h`.
//!
//! The `USER` persistent collection: `USER`, `USER:key`, `USER:/regex/`
//! and `USER:%{macro}` (the `User_DynamicElement` used by `setvar`,
//! `expirevar`, ...). Keys are compartmentalised with the collection key set
//! by `initcol`/`setsid`/`setuid` and the `SecWebAppId`.

use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase, VariableRegex};

/// `User_DictElement`
#[derive(Debug)]
pub struct UserDictElement {
    pub base: VariableBase,
    pub dict_element: String,
}

impl UserDictElement {
    pub fn new(dict_element: &str) -> Self {
        UserDictElement {
            base: VariableBase::new(&format!("USER:{}", dict_element)),
            dict_element: format!("USER:{}", dict_element),
        }
    }
}

impl Variable for UserDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.user_collection.resolve_multi_matches_c(
            self.base.name.as_bytes(),
            &c.user_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
    }
}

/// `User_NoDictElement`
#[derive(Debug)]
pub struct UserNoDictElement {
    pub base: VariableBase,
}

impl UserNoDictElement {
    pub fn new() -> Self {
        UserNoDictElement { base: VariableBase::new("USER") }
    }
}

impl Default for UserNoDictElement {
    fn default() -> Self {
        Self::new()
    }
}

impl Variable for UserNoDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.user_collection.resolve_multi_matches_c(
            b"",
            &c.user_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.key_exclusion,
        );
    }
}

/// `User_DictElementRegexp`
#[derive(Debug)]
pub struct UserDictElementRegexp {
    pub base: VariableRegex,
    pub dict_element: String,
}

impl UserDictElementRegexp {
    pub fn new(dict_element: &str) -> Self {
        UserDictElementRegexp { base: VariableRegex::new("USER", dict_element), dict_element: dict_element.to_string() }
    }
}

impl Variable for UserDictElementRegexp {
    fn base(&self) -> &VariableBase {
        &self.base.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let c = &t.collections;
        c.user_collection.resolve_regular_expression_c(
            self.dict_element.as_bytes(),
            &c.user_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            l,
            &self.base.base.key_exclusion,
        );
    }
    fn regex(&self) -> Option<&crate::utils::regex::Regex> {
        Some(&self.base.r)
    }
}

/// `User_DynamicElement`: `USER:%{...}`, the key is a macro expanded
/// at run time.
#[derive(Debug)]
pub struct UserDynamicElement {
    pub base: VariableBase,
    pub string: RunTimeString,
}

impl UserDynamicElement {
    pub fn new(dict_element: RunTimeString) -> Self {
        UserDynamicElement { base: VariableBase::new("USER:dynamic"), string: dict_element }
    }

    /// `User_DynamicElement::del` (static in C++).
    pub fn del(t: &Transaction<'_>, k: &[u8]) {
        let c = &t.collections;
        c.user_collection.del_c(k, &c.user_collection_key, Some(t.rules.properties.sec_web_app_id.value.as_bytes()));
    }

    /// `User_DynamicElement::setExpiry` (static in C++; used by `expirevar`).
    pub fn set_expiry(t: &Transaction<'_>, k: &[u8], expiry_seconds: i32) {
        let c = &t.collections;
        c.user_collection.set_expiry_c(
            k,
            &c.user_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            expiry_seconds,
        );
    }

    /// `User_DynamicElement::storeOrUpdateFirst` (static in C++).
    pub fn store_or_update_first(t: &Transaction<'_>, var: &[u8], value: &[u8]) {
        let c = &t.collections;
        c.user_collection.store_or_update_first_c(
            var,
            &c.user_collection_key,
            Some(t.rules.properties.sec_web_app_id.value.as_bytes()),
            value,
        );
    }
}

impl Variable for UserDynamicElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let string = self.string.evaluate(Some(t));
        let c = &t.collections;
        c.user_collection.resolve_multi_matches_c(
            &string,
            &c.user_collection_key,
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
