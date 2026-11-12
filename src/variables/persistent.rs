//! Port of `src/variables/global.h`, `ip.h`, `resource.h`, `session.h` and
//! `user.h`.
//!
//! The persistent collections (`GLOBAL`, `IP`, `RESOURCE`, `SESSION`,
//! `USER`): `COL`, `COL:key`, `COL:/regex/` and `COL:%{macro}` (the
//! `*_DynamicElement` used by `setvar`, `expirevar`, ...). Keys are
//! compartmentalised with the collection key set by
//! `initcol`/`setsid`/`setuid` and the `SecWebAppId`.
//!
//! The C++ code has one set of four classes per collection; here the
//! collection is a value and the variables are built by
//! [`Persistent::variable`]. Two quirks of the C++ classes are kept (see
//! [`Persistent::regex_name`] and [`Persistent::del`]).

use crate::collection::Collection;
use crate::transaction::Transaction;
use crate::utils::regex::Regex;
use crate::variable_value::VariableValue;
use crate::variables::VariableSelector;
use crate::variables::variable::{CollectionKey, KeyExclusions, Source, Variable, regex_name};

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
    pub(crate) fn resolve_multi_matches(
        self,
        t: &Transaction<'_>,
        var: &[u8],
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) {
        let (col, key) = self.of(t);
        col.resolve_multi_matches_c(var, key, Some(t.rules.properties.web_app_id()), l, ke);
    }

    /// `COL:/regex/`: the pattern is compiled per evaluation, prefixed
    /// with the compartments, as in C++.
    pub(crate) fn resolve_regular_expression(
        self,
        t: &Transaction<'_>,
        pattern: &[u8],
        l: &mut Vec<VariableValue>,
        ke: &KeyExclusions,
    ) {
        let (col, key) = self.of(t);
        col.resolve_regular_expression_c(pattern, key, Some(t.rules.properties.web_app_id()), l, ke);
    }

    /// The variable of this collection with `selector`: `COL`, `COL:key`,
    /// `COL:/regex/` or `COL:%{macro}`.
    pub fn variable(self, selector: VariableSelector) -> Variable {
        let (name, key) = match selector {
            VariableSelector::None => (self.name().to_string(), CollectionKey::All),
            VariableSelector::DictElement(e) => (format!("{}:{}", self.name(), e), CollectionKey::Key),
            VariableSelector::Regexp(r) => {
                (regex_name(self.regex_name(), &r), CollectionKey::Regex(Regex::new_case(&r, true), r))
            }
            VariableSelector::Dynamic(m) => (format!("{}:dynamic", self.name()), CollectionKey::Dynamic(m)),
        };
        Variable::new(&name, Source::Persistent(self, key))
    }
}
