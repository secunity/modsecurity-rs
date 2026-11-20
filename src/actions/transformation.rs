//! The transformation action (`t:xxx`): a transformation of the
//! `modsecurity-transformations` crate, as an action of a rule.

use modsecurity_transformations::Context;
pub use modsecurity_transformations::Transformation as TransformationKind;

use crate::actions::action::{Action, Kind};
use crate::transaction::Transaction;

/// A transformation (`t:xxx`): an action of kind
/// `Kind::RunTimeBeforeMatchAttempt` that rewrites the target value.
#[derive(Debug, Clone)]
pub struct Transformation {
    /// The name as written in the rule (e.g. `t:lowerCase`), which the
    /// debug log and the transformation paths print.
    name: String,
    pub kind: TransformationKind,
}

impl Transformation {
    pub fn new(kind: TransformationKind, name: &str) -> Self {
        Transformation { name: name.to_string(), kind }
    }

    /// The transformation named `a` (`t:<name>`), looked up with
    /// [`TransformationKind::from_name_prefix`] on the text after the
    /// first two characters; unknown names do nothing.
    pub fn from_name(a: &str) -> Self {
        let kind = TransformationKind::from_name_prefix(a.as_bytes().get(2..).unwrap_or_default());
        Transformation::new(kind, a)
    }

    pub fn is_none(&self) -> bool {
        self.kind == TransformationKind::None
    }

    /// Transforms `value` in place. Only
    /// `urlDecodeUni` uses the transaction: for the map of
    /// `SecUnicodeMapFile`, when one is set with a code page (without a
    /// transaction no map is used).
    pub fn transform(&self, value: &mut Vec<u8>, t: Option<&Transaction<'_>>) {
        let unicode_map = t.and_then(|t| {
            let config = &t.rules.properties.unicode_map_table;
            if config.set && config.unicode_code_page > 0 { config.unicode_map_table.as_deref() } else { None }
        });
        self.kind.apply(value, &Context { unicode_map });
    }
}

impl Action for Transformation {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::RunTimeBeforeMatchAttempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::ModSecurity;
    use crate::rules_set::RulesSet;
    use crate::rules_set::properties::UnicodeMapHolder;
    use std::sync::Arc;

    #[test]
    fn names() {
        assert_eq!(Transformation::from_name("t:trimLeft").name(), "t:trimLeft");
        assert_eq!(Transformation::from_name("t:trimLeftX").kind, TransformationKind::TrimLeft);
        assert_eq!(Transformation::from_name("t:nosuch").kind, TransformationKind::Identity);
        assert!(Transformation::from_name("t:none").is_none());
        let mut v = b"aB".to_vec();
        Transformation::from_name("t:uppercase").transform(&mut v, None);
        assert_eq!(v, b"AB");
    }

    #[test]
    fn url_decode_uni_uses_the_configured_map() {
        let ms = ModSecurity::new();
        let mut rules = RulesSet::new();
        let mut table = UnicodeMapHolder::default();
        table.change(0x0391, i32::from(b'A'));
        let config = &mut rules.properties.unicode_map_table;
        config.set = true;
        config.unicode_code_page = 20127;
        config.unicode_map_table = Some(Arc::new(table));
        let tfn = Transformation::from_name("t:urlDecodeUni");
        {
            let t = Transaction::new(&ms, &rules, None);
            let mut v = b"%u0391".to_vec();
            tfn.transform(&mut v, Some(&t));
            assert_eq!(v, b"A");
            // Without a transaction no map is used.
            let mut v = b"%u0391".to_vec();
            tfn.transform(&mut v, None);
            assert_eq!(v, b"\x91");
        }

        // Without a code page the map is ignored.
        rules.properties.unicode_map_table.unicode_code_page = 0;
        let t = Transaction::new(&ms, &rules, None);
        let mut v = b"%u0391".to_vec();
        tfn.transform(&mut v, Some(&t));
        assert_eq!(v, b"\x91");
    }
}
