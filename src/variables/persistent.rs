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
//! [`Persistent::variable`]. The RESOURCE regex naming quirk is retained; the SESSION deletion
//! quirk is handled by the writable target in `variable.rs`.

use crate::utils::regex::Regex;
use crate::variables::VariableSelector;
use crate::variables::variable::{CollectionKey, Source, Variable, regex_name};

pub use crate::collection::Persistent;

impl Persistent {
    /// The name given to `COL:/regex/` variables. Sic: the C++ code names
    /// the `RESOURCE` one `RESOURCE:` (so it shows as `RESOURCE::regex(..)`).
    fn regex_name(self) -> &'static str {
        match self {
            Persistent::Resource => "RESOURCE:",
            _ => self.name(),
        }
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
