//! Port of `src/variables/global.h`, `ip.h`, `resource.h`, `session.h` and
//! `user.h`.
//!
//! The persistent collections (`GLOBAL`, `IP`, `RESOURCE`, `SESSION`,
//! `USER`): `COL`, `COL:key`, `COL:/regex/` and `COL:%{macro}` (the
//! `*_DynamicElement` used by `setvar`, `expirevar`, ...). Keys are
//! compartmentalised with the collection key set by
//! `initcol`/`setsid`/`setuid` and the `SecWebAppId`.
//!
//! The C++ code has one set of four classes per collection; they only
//! differ by the collection they use and two quirks, both kept (see
//! [`Persistent::regex_name`] and [`Persistent::del`]).

use crate::collection::collection::Collection;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::regex::Regex;
use crate::variable_value::VariableValue;
use crate::variables::VariableSelector;
use crate::variables::variable::{Variable, VariableBase, VariableRegex};

/// One of the persistent collections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persistent {
    Global,
    Ip,
    Resource,
    Session,
    User,
}

impl Persistent {
    /// The collection name (`IP`, ...).
    pub fn name(self) -> &'static str {
        match self {
            Persistent::Global => "GLOBAL",
            Persistent::Ip => "IP",
            Persistent::Resource => "RESOURCE",
            Persistent::Session => "SESSION",
            Persistent::User => "USER",
        }
    }

    /// The name given to `COL:/regex/` variables. Sic: the C++ code names
    /// the `RESOURCE` one `RESOURCE:` (so it shows as `RESOURCE::regex(..)`).
    fn regex_name(self) -> &'static str {
        match self {
            Persistent::Resource => "RESOURCE:",
            _ => self.name(),
        }
    }

    /// The collection and its key (the first compartment) in `t`.
    fn of<'t>(self, t: &'t Transaction<'_>) -> (&'t dyn Collection, &'t [u8]) {
        let c = &t.collections;
        match self {
            Persistent::Global => (c.global_collection, &c.global_collection_key),
            Persistent::Ip => (c.ip_collection, &c.ip_collection_key),
            Persistent::Resource => (c.resource_collection, &c.resource_collection_key),
            Persistent::Session => (c.session_collection, &c.session_collection_key),
            Persistent::User => (c.user_collection, &c.user_collection_key),
        }
    }

    /// `*_DynamicElement::del` (static in C++). Sic: `SESSION` uses the IP
    /// collection key (not the web app id) as second compartment, so it
    /// does not remove what was stored.
    pub fn del(self, t: &Transaction<'_>, k: &[u8]) {
        let (col, key) = self.of(t);
        let second = match self {
            Persistent::Session => &t.collections.ip_collection_key[..],
            _ => t.rules.properties.web_app_id(),
        };
        col.del_c(k, key, Some(second));
    }

    /// `*_DynamicElement::setExpiry` (static in C++; used by `expirevar`).
    pub fn set_expiry(self, t: &Transaction<'_>, k: &[u8], expiry_seconds: i32) {
        let (col, key) = self.of(t);
        col.set_expiry_c(k, key, Some(t.rules.properties.web_app_id()), expiry_seconds);
    }

    /// `*_DynamicElement::storeOrUpdateFirst` (static in C++).
    pub fn store_or_update_first(self, t: &Transaction<'_>, var: &[u8], value: &[u8]) {
        let (col, key) = self.of(t);
        col.store_or_update_first_c(var, key, Some(t.rules.properties.web_app_id()), value);
    }

    /// `resolveMultiMatches(var, collectionKey, webAppId)`
    fn resolve_multi_matches(self, t: &Transaction<'_>, var: &[u8], l: &mut Vec<VariableValue>, base: &VariableBase) {
        let (col, key) = self.of(t);
        col.resolve_multi_matches_c(var, key, Some(t.rules.properties.web_app_id()), l, &base.key_exclusion);
    }

    /// The variable of this collection with `selector`.
    pub fn variable(self, selector: VariableSelector) -> Box<dyn Variable> {
        match selector {
            VariableSelector::None => Box::new(PersistentNoDictElement::new(self)),
            VariableSelector::DictElement(e) => Box::new(PersistentDictElement::new(self, &e)),
            VariableSelector::Regexp(r) => Box::new(PersistentDictElementRegexp::new(self, &r)),
            VariableSelector::Dynamic(m) => Box::new(PersistentDynamicElement::new(self, m)),
        }
    }
}

/// `*_NoDictElement`: `COL`.
#[derive(Debug)]
pub struct PersistentNoDictElement {
    pub base: VariableBase,
    collection: Persistent,
}

impl PersistentNoDictElement {
    pub fn new(collection: Persistent) -> Self {
        PersistentNoDictElement { base: VariableBase::new(collection.name()), collection }
    }
}

impl Variable for PersistentNoDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        // The key is `m_name`, which is empty for these variables.
        self.collection.resolve_multi_matches(t, self.base.name.as_bytes(), l, &self.base);
    }
}

/// `*_DictElement`: `COL:key`.
#[derive(Debug)]
pub struct PersistentDictElement {
    pub base: VariableBase,
    collection: Persistent,
}

impl PersistentDictElement {
    pub fn new(collection: Persistent, dict_element: &str) -> Self {
        PersistentDictElement {
            base: VariableBase::new(&format!("{}:{}", collection.name(), dict_element)),
            collection,
        }
    }
}

impl Variable for PersistentDictElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        self.collection.resolve_multi_matches(t, self.base.name.as_bytes(), l, &self.base);
    }
}

/// `*_DictElementRegexp`: `COL:/regex/`.
#[derive(Debug)]
pub struct PersistentDictElementRegexp {
    pub base: VariableRegex,
    collection: Persistent,
}

impl PersistentDictElementRegexp {
    pub fn new(collection: Persistent, dict_element: &str) -> Self {
        PersistentDictElementRegexp { base: VariableRegex::new(collection.regex_name(), dict_element), collection }
    }
}

impl Variable for PersistentDictElementRegexp {
    fn base(&self) -> &VariableBase {
        &self.base.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        // The pattern is compiled per evaluation, prefixed with the
        // compartments, as in C++.
        let (col, key) = self.collection.of(t);
        col.resolve_regular_expression_c(
            self.base.regex.as_bytes(),
            key,
            Some(t.rules.properties.web_app_id()),
            l,
            &self.base.base.key_exclusion,
        );
    }
    fn regex(&self) -> Option<&Regex> {
        Some(&self.base.r)
    }
}

/// `*_DynamicElement`: `COL:%{...}`, the key is a macro expanded at run
/// time.
#[derive(Debug)]
pub struct PersistentDynamicElement {
    pub base: VariableBase,
    pub string: RunTimeString,
    collection: Persistent,
}

impl PersistentDynamicElement {
    pub fn new(collection: Persistent, dict_element: RunTimeString) -> Self {
        PersistentDynamicElement {
            base: VariableBase::new(&format!("{}:dynamic", collection.name())),
            string: dict_element,
            collection,
        }
    }
}

impl Variable for PersistentDynamicElement {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let string = self.string.evaluate(Some(t));
        self.collection.resolve_multi_matches(t, &string, l, &self.base);
    }
    fn dynamic_name(&self) -> Option<&RunTimeString> {
        Some(&self.string)
    }
    fn dynamic_del(&self, t: &Transaction<'_>, key: &[u8]) {
        self.collection.del(t, key);
    }
    fn dynamic_store_or_update_first(&self, t: &Transaction<'_>, key: &[u8], value: &[u8]) {
        self.collection.store_or_update_first(t, key, value);
    }
}
