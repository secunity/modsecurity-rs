//! The variables of the persistent collections (`GLOBAL`, `IP`,
//! `RESOURCE`, `SESSION`, `USER`): `COL`, `COL:key`, `COL:/regex/` and
//! `COL:%{macro}` (the form `setvar`, `expirevar`, ... write to). Keys are
//! compartmentalised with the collection key set by
//! `initcol`/`setsid`/`setuid` and the `SecWebAppId`.
//!
//! The C++ code has one set of four classes per collection; here the
//! collection is a value and the variables are built by [`variable`].
//! The RESOURCE regex naming quirk is retained; the SESSION deletion quirk
//! is handled by the writable target in `variable.rs`.

use crate::variables::VariableSelector;
use crate::variables::variable::{CollectionKey, Source, Variable};
use modsecurity_native::regex::Regex;

pub use crate::collection::Persistent;

/// The name given to `COL:/regex/` variables. Sic: the C++ code names
/// the `RESOURCE` one `RESOURCE:` (so it shows as `RESOURCE::regex(..)`).
fn regex_name(collection: Persistent) -> &'static str {
    match collection {
        Persistent::Resource => "RESOURCE:",
        _ => collection.name(),
    }
}

/// The variable of `collection` with `selector`: `COL`, `COL:key`,
/// `COL:/regex/` or `COL:%{macro}`.
pub fn variable(collection: Persistent, selector: VariableSelector) -> Variable {
    let name = collection.name();
    let (name, key) = match selector {
        VariableSelector::None => (name.to_string(), CollectionKey::All),
        VariableSelector::DictElement(e) => (format!("{}:{}", name, e), CollectionKey::Key),
        VariableSelector::Regexp(r) => (
            crate::variables::variable::regex_name(regex_name(collection), &r),
            CollectionKey::Regex(Regex::new_case(&r, true), r),
        ),
        VariableSelector::Dynamic(m) => (format!("{}:dynamic", name), CollectionKey::Dynamic(m)),
    };
    Variable::new(&name, Source::Persistent(collection, key))
}
