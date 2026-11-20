//! SecRule targets and the resolution of variables by name.
//!
//! [`Variable`] is a SecRule target (`ARGS`, `TX:foo`, `&ARGS`,
//! `!ARGS:id`, ...). Every target is the same struct: its name, its key
//! exclusions and a [`Source`]
//! saying where the values come from.

use crate::rule::Rule;
use crate::run_time_string::RunTimeString;
use crate::transaction::{Transaction, TransactionAnchoredVariables};
use crate::variables::anchored_set_variable::AnchoredSetVariable;
use crate::variables::anchored_set_variable_translation_proxy::AnchoredSetVariableTranslationProxy;
use crate::variables::anchored_variable::AnchoredVariable;
use crate::variables::computed::Computed;
use crate::variables::persistent::Persistent;
use crate::variables::variable_value::VariableValue;
use crate::variables::{VariableSelector, env, rule, xml};
use modsecurity_native::regex::Regex;

pub use modsecurity_types::key_exclusions::{KeyExclusion, KeyExclusions};

// ---------------------------------------------------------------------------
// Variable
// ---------------------------------------------------------------------------

type Vars = TransactionAnchoredVariables;

/// Which entries of a multi valued variable are selected: `ARGS`,
/// `ARGS:key` or `ARGS:/regex/`.
#[derive(Debug)]
pub(crate) enum Selector {
    All,
    Key(String),
    Regex(Regex),
}

/// Which entries of a collection (`TX`, `IP`, ...) are selected. `Key` is
/// the variable's name; `Dynamic` is a key built from macros
/// (`TX:%{...}`), which is also what `setvar` & co. write to.
#[derive(Debug)]
pub(crate) enum CollectionKey {
    All,
    Key,
    /// The compiled regex and its text as written.
    Regex(Regex),
    Dynamic(RunTimeString),
}

/// Where the values of a variable come from.
#[derive(Debug)]
pub(crate) enum Source {
    /// A single valued variable of the transaction (`REQUEST_METHOD`).
    Single(fn(&Vars) -> &AnchoredVariable),
    /// A multi valued variable of the transaction (`ARGS`).
    Set(fn(&Vars) -> &AnchoredSetVariable, Selector),
    /// The names of a multi valued variable (`ARGS_NAMES`): the proxy and
    /// the variable it translates.
    Names(fn(&Vars) -> (&AnchoredSetVariableTranslationProxy, &AnchoredSetVariable), Selector),
    /// The `TX` collection.
    Tx(CollectionKey),
    /// A persistent collection (`IP`, `GLOBAL`, ...).
    Persistent(Persistent, CollectionKey),
    /// Properties of the rule being evaluated (`RULE:id`).
    Rule(Selector),
    /// The environment (`ENV`, `ENV:name`).
    Env,
    /// `XML`: the whole document, as a placeholder value.
    XmlDocument,
    /// `XML:/xpath`.
    XmlPath,
    /// A value computed on evaluation (`TIME`, `DURATION`, ...).
    Computed(Computed),
    /// `!VAR`: evaluates like `VAR`; rules subtract it from their targets.
    Exclusion(Box<Variable>),
    /// `&VAR`: the number of values of `VAR`.
    Count(Box<Variable>),
}

/// The writable portion of a variable, selected once rather than checked
/// again through separate dynamic-name/store/delete hooks.
pub(crate) enum WriteTarget<'v> {
    Transaction(&'v RunTimeString),
    Persistent { collection: Persistent, name: &'v RunTimeString },
}

impl WriteTarget<'_> {
    pub(crate) fn name(&self) -> &RunTimeString {
        match self {
            Self::Transaction(name) | Self::Persistent { name, .. } => name,
        }
    }

    pub(crate) fn store(&self, t: &mut Transaction<'_>, key: &[u8], value: Vec<u8>) {
        match self {
            Self::Transaction(_) => t.collections.tx.set(key, value),
            Self::Persistent { collection, .. } => {
                let stored = t.collections.persistent(*collection).set(key, t.rules.properties.web_app_id(), &value);
                t.stored(stored);
            }
        }
    }

    pub(crate) fn remove(&self, t: &mut Transaction<'_>, key: &[u8]) {
        match self {
            Self::Transaction(_) => t.collections.tx.remove(key),
            Self::Persistent { collection, .. } => {
                // Compatibility: SESSION deletion uses the IP key as its
                // second compartment, unlike storage and other collections.
                let second = if *collection == Persistent::Session {
                    &t.collections.ip.key
                } else {
                    t.rules.properties.web_app_id()
                };
                let removed = t.collections.persistent(*collection).remove(key, second);
                t.stored(removed);
            }
        }
    }
}

/// A SecRule target: its name, the keys excluded from it and where its
/// values come from.
#[derive(Debug)]
pub struct Variable {
    /// The part after the `:` (`foo` of `ARGS:foo`); empty without one.
    name: String,
    collection_name: String,
    full_name: String,
    key_exclusion: KeyExclusions,
    source: Source,
}

impl Variable {
    /// A variable called `name`: `COLLECTION:name` (or `COLLECTION.name`)
    /// is split, anything else is a collection without a name.
    pub(crate) fn new(name: &str, source: Source) -> Self {
        let (collection_name, short, full_name) = match name.find(':').or_else(|| name.find('.')) {
            Some(a) => {
                let collection = name[..a].to_ascii_uppercase();
                let short = &name[a + 1..];
                let full = format!("{}:{}", collection, short);
                (collection, short.to_string(), full)
            }
            None => (name.to_string(), String::new(), name.to_string()),
        };
        Variable { name: short, collection_name, full_name, key_exclusion: KeyExclusions::new(), source }
    }

    /// The multi valued variable `name` (`ARGS`), narrowed by `selector`.
    /// Returns the name the variable gets and the selector.
    pub(crate) fn selected(name: &str, selector: VariableSelector) -> Option<(String, Selector)> {
        match selector {
            VariableSelector::None => Some((name.to_string(), Selector::All)),
            VariableSelector::DictElement(e) => Some((format!("{}:{}", name, e), Selector::Key(e))),
            VariableSelector::Regexp(r) => Some((regex_name(name, &r), Selector::Regex(Regex::new_case(&r, true)))),
            VariableSelector::Dynamic(_) => None,
        }
    }

    /// `!var`, named like `var`.
    pub fn exclusion(var: Variable) -> Self {
        Self::wrapping(var, Source::Exclusion)
    }

    /// `&var`, named like `var`.
    pub fn count(var: Variable) -> Self {
        Self::wrapping(var, Source::Count)
    }

    /// A variable named like `var` (without its key exclusions).
    fn wrapping(var: Variable, source: fn(Box<Variable>) -> Source) -> Self {
        Variable {
            name: var.name.clone(),
            collection_name: var.collection_name.clone(),
            full_name: var.full_name.clone(),
            key_exclusion: KeyExclusions::new(),
            source: source(Box::new(var)),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn collection_name(&self) -> &str {
        &self.collection_name
    }

    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    pub fn key_exclusion(&self) -> &KeyExclusions {
        &self.key_exclusion
    }

    /// Resolves the variable for `t`, appending the values to `l`. `rule`
    /// is the rule being evaluated, when there is one.
    pub fn evaluate(&self, t: &Transaction<'_>, rule: Option<&Rule>, l: &mut Vec<VariableValue>) {
        let ke = &self.key_exclusion;
        match &self.source {
            Source::Single(get) => get(&t.vars).evaluate_into(l),
            Source::Set(get, selector) => {
                let set = get(&t.vars);
                match selector {
                    Selector::All => set.resolve_with_exclusions(l, ke, Some(t)),
                    Selector::Key(key) => set.resolve_key(key.as_bytes(), l),
                    Selector::Regex(r) => set.resolve_regular_expression_with_exclusions(r, l, ke, Some(t)),
                }
            }
            Source::Names(get, selector) => {
                let (names, fount) = get(&t.vars);
                match selector {
                    Selector::All => names.resolve_with_exclusions(fount, l, ke, Some(t)),
                    Selector::Key(key) => names.resolve_key(fount, key.as_bytes(), l),
                    Selector::Regex(r) => names.resolve_regular_expression_with_exclusions(fount, r, l, ke, Some(t)),
                }
            }
            Source::Tx(key) => {
                let tx = &t.collections.tx;
                match key {
                    // The key is the name, which is empty for `TX`.
                    CollectionKey::All | CollectionKey::Key => tx.resolve_multi_matches(self.name.as_bytes(), l, ke),
                    CollectionKey::Regex(r) => tx.resolve_regex(r, l, ke),
                    CollectionKey::Dynamic(string) => tx.resolve_multi_matches(&string.evaluate(Some(t)), l, ke),
                }
            }
            Source::Persistent(collection, key) => {
                let binding = t.collections.persistent(*collection);
                let app = t.rules.properties.web_app_id();
                match key {
                    CollectionKey::All | CollectionKey::Key => {
                        t.stored(binding.resolve(self.name.as_bytes(), app, l, ke))
                    }
                    CollectionKey::Regex(regex) => t.stored(binding.resolve_regex(regex, app, l, ke)),
                    CollectionKey::Dynamic(string) => t.stored(binding.resolve(&string.evaluate(Some(t)), app, l, ke)),
                }
            }
            Source::Rule(selector) => rule::evaluate(selector, t, rule, l),
            Source::Env => env::evaluate(self, t, l),
            // The key is the variable's (empty) name.
            Source::XmlDocument => l.push(VariableValue::new(self.name.as_bytes(), b"[XML document tree]")),
            Source::XmlPath => xml::evaluate_xpath(self, t, rule, l),
            Source::Computed(c) => c.evaluate(self, t, l),
            Source::Exclusion(var) => var.evaluate(t, rule, l),
            Source::Count(var) => {
                let mut values = Vec::new();
                var.evaluate(t, rule, &mut values);
                l.push(VariableValue::new(self.full_name.as_bytes(), values.len().to_string().as_bytes()));
            }
        }
    }

    /// The selection regex, if this is a `COLLECTION:/regex/` variable.
    pub fn regex(&self) -> Option<&Regex> {
        match &self.source {
            Source::Set(_, Selector::Regex(r))
            | Source::Names(_, Selector::Regex(r))
            | Source::Rule(Selector::Regex(r)) => Some(r),
            Source::Tx(CollectionKey::Regex(r)) | Source::Persistent(_, CollectionKey::Regex(r)) => Some(r),
            _ => None,
        }
    }

    /// The variable `!var` excludes, if this is an exclusion.
    pub fn exclusion_base(&self) -> Option<&Variable> {
        match &self.source {
            Source::Exclusion(var) => Some(var),
            _ => None,
        }
    }

    /// A writable collection target exists only for dynamic-key selectors.
    /// Ordinary rule targets (including literal TX selectors) remain read-only.
    pub(crate) fn write_target(&self) -> Option<WriteTarget<'_>> {
        match &self.source {
            Source::Tx(CollectionKey::Dynamic(name)) => Some(WriteTarget::Transaction(name)),
            Source::Persistent(collection, CollectionKey::Dynamic(name)) => {
                Some(WriteTarget::Persistent { collection: *collection, name })
            }
            _ => None,
        }
    }

    /// Whether `var` is in the same collection: this variable's collection
    /// name, upper-cased, equals the one of `var`.
    pub fn belongs_to_collection(&self, var: &Variable) -> bool {
        let a = self.collection_name.as_bytes();
        let b = var.collection_name.as_bytes();
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_uppercase() == *y)
    }

    /// If `v` is an exclusion (`!ARGS:foo`), records its
    /// key (or regex) as excluded from this variable.
    pub fn adds_key_exclusion(&mut self, v: &Variable) {
        let Some(base) = v.exclusion_base() else {
            return;
        };
        let r = match base.regex() {
            None => KeyExclusion::string(v.name()),
            Some(re) => KeyExclusion::regex(&re.pattern),
        };
        self.key_exclusion.push(r);
    }

    /// Whether `b` is the same target: same collection, name and full
    /// name.
    pub fn same_as(&self, b: &Variable) -> bool {
        self.collection_name == b.collection_name && self.name == b.name && self.full_name == b.full_name
    }

    /// Excludes `key` from this variable (test helper).
    #[cfg(test)]
    pub(crate) fn exclude(&mut self, key: KeyExclusion) {
        self.key_exclusion.push(key);
    }
}

/// The name of a `COLLECTION:/regex/` variable.
pub(crate) fn regex_name(collection: &str, regex: &str) -> String {
    format!("{}:regex({})", collection, regex)
}

/// The full names of `vars` joined by `|`.
pub fn variables_to_string<'a, I>(vars: I) -> String
where
    I: IntoIterator<Item = &'a Variable>,
{
    let mut joined = String::new();
    for v in vars {
        if !joined.is_empty() {
            joined.push('|');
        }
        joined.push_str(v.full_name());
    }
    joined
}

// ---------------------------------------------------------------------------
// Resolution of a variable given by name (`m.getvar` of the Lua engine)
// ---------------------------------------------------------------------------

#[cfg(feature = "lua")]
/// Error raised by the by-name resolution helpers: no variable has the
/// name given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableNotFound;

#[cfg(feature = "lua")]
impl std::fmt::Display for VariableNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Variable not found.")
    }
}

#[cfg(feature = "lua")]
impl std::error::Error for VariableNotFound {}

#[cfg(feature = "lua")]
/// Whether `a` upper-cased equals `b`.
#[inline]
pub fn comp(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).all(|(x, y)| x.to_ascii_uppercase() == y)
}

#[cfg(feature = "lua")]
/// The multi valued variable `col` of the shared table, as Lua looks it
/// up: `whole` is the name as given, key included (see
/// [`names::Set::lua_whole_name`](crate::variables::names::Set)).
fn lua_set(col: &str, whole: &str) -> Option<&'static crate::variables::names::Set> {
    crate::variables::names::SETS.iter().find(|v| comp(if v.lua_whole_name { whole } else { col }, v.token))
}

#[cfg(feature = "lua")]
/// Resolves a variable given by name, appending its values to `l` (used
/// by the Lua engine).
pub fn string_match_resolve_multi(
    t: &Transaction<'_>,
    variable: &str,
    l: &mut Vec<VariableValue>,
) -> Result<(), VariableNotFound> {
    let delim = variable.find('.').or_else(|| variable.find(':'));
    let (col, var) = match delim {
        None => (variable.to_string(), String::new()),
        Some(d) => (variable[..d].to_string(), variable[d + 1..].to_string()),
    };
    let v = &t.vars;
    if let Some(set) = lua_set(&col, variable) {
        let a = (set.get)(v);
        if delim.is_none() {
            a.resolve(l);
        } else {
            a.resolve_key(var.as_bytes(), l);
        }
        return Ok(());
    }
    if let Some(names) = crate::variables::names::NAMES.iter().find(|n| comp(&col, n.token)) {
        let (p, fount) = (names.get)(v);
        if delim.is_none() {
            p.resolve(fount, l);
        } else {
            p.resolve_key(fount, var.as_bytes(), l);
        }
        return Ok(());
    }
    if delim.is_some() {
        return Err(VariableNotFound);
    }
    match single_anchored(t, variable) {
        Some(a) => {
            a.evaluate_into(l);
            Ok(())
        }
        None => Err(VariableNotFound),
    }
}

#[cfg(feature = "lua")]
/// The single valued variable named `variable`, among the ones Lua knows.
fn single_anchored<'t>(
    t: &'t Transaction<'_>,
    variable: &str,
) -> Option<&'t crate::variables::anchored_variable::AnchoredVariable> {
    let v = crate::variables::names::SINGLE.iter().find(|v| v.lua && comp(variable, v.token))?;
    Some((v.get)(&t.vars))
}

#[cfg(feature = "lua")]
/// Resolves a variable given by name to its first value (empty if none).
pub fn string_match_resolve(t: &Transaction<'_>, variable: &str) -> Result<Vec<u8>, VariableNotFound> {
    let collection = variable.find('.').or_else(|| variable.find(':'));
    let web_app_id = t.rules.properties.web_app_id();
    let cols = &t.collections;
    let vv: Option<Vec<u8>> = match collection {
        None => {
            if let Some(a) = single_anchored(t, variable) {
                // RESOURCE is matched here, as the single variable set by
                // `setrsc`, and not as the persistent collection.
                a.resolve_first()
            } else if comp(variable, "TX") {
                cols.tx.get(b"").map(<[u8]>::to_vec)
            } else if comp(variable, "USER") {
                t.stored(cols.user.get(b"", web_app_id))
            } else if comp(variable, "SESSION") {
                t.stored(cols.session.get(b"", web_app_id))
            } else if comp(variable, "IP") {
                t.stored(cols.ip.get(b"", web_app_id))
            } else if comp(variable, "GLOBAL") {
                t.stored(cols.global.get(b"", web_app_id))
            } else {
                return Err(VariableNotFound);
            }
        }
        Some(c) => {
            let col = &variable[..c];
            let var = &variable.as_bytes()[c + 1..];
            // (The `*_NAMES` proxies are not found here: with a key, only
            // the multi valued variables and the collections are looked up.)
            if let Some(set) = lua_set(col, variable) {
                (set.get)(&t.vars).resolve_first(var)
            } else if comp(col, "TX") {
                cols.tx.get(var).map(<[u8]>::to_vec)
            } else if comp(col, "RESOURCE") {
                t.stored(cols.resource.get(var, web_app_id))
            } else if comp(col, "USER") {
                t.stored(cols.user.get(var, web_app_id))
            } else if comp(col, "SESSION") {
                t.stored(cols.session.get(var, web_app_id))
            } else if comp(col, "IP") {
                t.stored(cols.ip.get(var, web_app_id))
            } else if comp(col, "GLOBAL") {
                t.stored(cols.global.get(var, web_app_id))
            } else {
                return Err(VariableNotFound);
            }
        }
    };
    Ok(vv.unwrap_or_default())
}
