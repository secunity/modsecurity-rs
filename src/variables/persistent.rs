//! The variables of the persistent collections (`GLOBAL`, `IP`,
//! `RESOURCE`, `SESSION`, `USER`): `COL`, `COL:key`, `COL:/regex/` and
//! `COL:%{macro}` (the form `setvar`, `expirevar`, ... write to). Keys are
//! compartmentalised with the collection key set by
//! `initcol`/`setsid`/`setuid` and the `SecWebAppId`.
//!
//! The collection is a value ([`Persistent`]) and the variables of all
//! five are built by [`variable`]. The `RESOURCE` regex naming quirk is
//! kept (`regex_name`). C++'s `SESSION` deletion quirk is not: a value is
//! removed where it was stored (`MIGRATION.md`).

use crate::variables::variable::{CollectionKey, Source, Variable};
use crate::variables::{VariableError, VariableSelector, selector_regex};

pub use crate::collection::Persistent;

/// The name given to `COL:/regex/` variables. Sic: the `RESOURCE` one
/// is named `RESOURCE:` (so it shows as `RESOURCE::regex(..)`).
fn regex_name(collection: Persistent) -> &'static str {
    match collection {
        Persistent::Resource => "RESOURCE:",
        _ => collection.name(),
    }
}

/// The variable of `collection` with `selector`: `COL`, `COL:key`,
/// `COL:/regex/` or `COL:%{macro}`.
pub fn variable(collection: Persistent, selector: VariableSelector) -> Result<Variable, VariableError> {
    let name = collection.name();
    let (name, key) = match selector {
        VariableSelector::None => (name.to_string(), CollectionKey::All),
        VariableSelector::DictElement(e) => (format!("{}:{}", name, e), CollectionKey::Key),
        VariableSelector::Regexp(r) => (
            crate::variables::variable::regex_name(regex_name(collection), &r),
            CollectionKey::Regex(selector_regex(&r)?),
        ),
        VariableSelector::Dynamic(m) => (format!("{}:dynamic", name), CollectionKey::Dynamic(m)),
    };
    Ok(Variable::new(&name, Source::Persistent(collection, key)))
}

#[cfg(test)]
mod tests {
    use crate::{ModSecurity, RulesSet, Transaction};

    /// Whether a request from `client` is denied by `rule`, after the
    /// collection of `client` got `IP.id_a`.
    fn denied(ms: &ModSecurity, client: &str, rule: &str) -> bool {
        let mut rules = RulesSet::new();
        rules
            .load(&format!(
                "SecRuleEngine On\n\
                 SecAction \"id:1,phase:1,pass,nolog,initcol:ip=%{{REMOTE_ADDR}}\"\n\
                 SecAction \"id:3,phase:1,pass,nolog,setvar:ip.id_a=1\"\n{rule}\n"
            ))
            .unwrap();
        let mut t = Transaction::new(ms, &rules, None);
        t.process_connection(client, 1234, "127.0.0.1", 80);
        t.process_uri(b"/", b"GET", b"1.1");
        t.process_request_headers();
        t.intervention().is_some_and(|it| it.status == 403)
    }

    /// `initcol`, `setvar`, `expirevar` and the targets name a collection
    /// in any case. (`initcol` and `expirevar` used to know only lowercase
    /// names: `expirevar:IP.id_a=0` did nothing.)
    #[test]
    fn collection_names_ignore_case() {
        let ms = ModSecurity::new();
        let rule = "SecRule Ip:id_a \"@eq 1\" \"id:2,phase:1,deny,status:403\"";
        assert!(denied(&ms, "10.0.0.3", rule));
        let mut rules = RulesSet::new();
        rules
            .load(&format!(
                "SecRuleEngine On\n\
                 SecAction \"id:1,phase:1,pass,nolog,initcol:IP=%{{REMOTE_ADDR}},setvar:Ip.id_a=1,expirevar:IP.id_a=0\"\n{rule}\n"
            ))
            .unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_connection("10.0.0.4", 1234, "127.0.0.1", 80);
        t.process_uri(b"/", b"GET", b"1.1");
        t.process_request_headers();
        assert!(t.intervention().is_none(), "the variable expired");
    }

    /// `IP:/regex/` is matched with the names of the keys of the
    /// transaction's own collection. (The compartment used to be part of
    /// the expression, searched in the keys of every compartment: an
    /// anchored expression never matched, and one address could select
    /// another's keys.)
    #[test]
    fn regex_keys_of_a_persistent_collection() {
        let ms = ModSecurity::new();
        let rule = |selector: &str| format!("SecRule {selector} \"@eq 1\" \"id:2,phase:1,deny,status:403\"");
        assert!(denied(&ms, "10.0.0.1", &rule("IP:/id_a$/")));
        assert!(denied(&ms, "10.0.0.1", &rule("IP:/^ID_/")));
        assert!(!denied(&ms, "10.0.0.1", &rule("IP:/^d_a/")));

        // The collection of 10.0.0.1 has the key; that of 1000001 has not,
        // although "10.0.0.1" as an expression matches "1000001".
        let other = "SecRule IP:/id_/ \"@eq 1\" \"id:2,phase:1,deny,status:403\"";
        let mut rules = RulesSet::new();
        rules
            .load(&format!("SecRuleEngine On\nSecAction \"id:1,phase:1,pass,nolog,initcol:ip=10.0.0.1\"\n{other}\n"))
            .unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_connection("10.0.0.2", 1234, "127.0.0.1", 80);
        t.process_uri(b"/", b"GET", b"1.1");
        t.process_request_headers();
        assert!(t.intervention().is_some_and(|it| it.status == 403), "the key set above is seen");

        let mut rules = RulesSet::new();
        rules
            .load(&format!("SecRuleEngine On\nSecAction \"id:1,phase:1,pass,nolog,initcol:ip=10x0y0z1\"\n{other}\n"))
            .unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_connection("10.0.0.2", 1234, "127.0.0.1", 80);
        t.process_uri(b"/", b"GET", b"1.1");
        t.process_request_headers();
        assert!(t.intervention().is_none(), "another compartment");
    }
}
