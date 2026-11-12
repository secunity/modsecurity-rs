//! Port of `src/actions/xmlns.cc`, `src/actions/xmlns.h`.
//!
//! `xmlns:prefix=http://...` — declares an XML namespace for the `XML`
//! variable's XPath expressions (read by that variable).

use crate::actions::action::{Action, name_and_payload};

#[derive(Debug)]
pub struct XmlNS {
    name: String,
    scope: String,
    href: String,
}

impl XmlNS {
    /// The payload is `<prefix>=<href>`.
    pub fn new(action: &str) -> Result<Self, String> {
        let (name, payload) = name_and_payload(action);
        let Some((scope, href)) = payload.split_once('=') else {
            return Err("XMLS: Bad format, missing equals sign.".to_string());
        };
        if href.is_empty() || scope.is_empty() {
            return Err("XMLS: XMLNS is invalid. Expecting a name=value format.".to_string());
        }
        let mut href = href.to_string();
        if href.starts_with('\'') && href.len() > 3 {
            href.remove(0);
            href.pop();
        }
        if !href.starts_with("http://") {
            return Err(format!("XMLS: Missing xmlns href for prefix: `{}'.", href));
        }
        Ok(XmlNS { name: name.to_string(), scope: scope.to_string(), href })
    }
}

impl Action for XmlNS {
    fn name(&self) -> &str {
        &self.name
    }

    fn xml_namespace(&self) -> Option<(&str, &str)> {
        Some((&self.scope, &self.href))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(p: &str) -> Result<(String, String), String> {
        XmlNS::new(&format!("xmlns:{}", p)).map(|a| (a.scope, a.href))
    }

    #[test]
    fn init() {
        assert_eq!(
            ns("soap=http://schemas.xmlsoap.org/soap/envelope/"),
            Ok(("soap".into(), "http://schemas.xmlsoap.org/soap/envelope/".into()))
        );
        assert_eq!(ns("a='http://x'"), Ok(("a".into(), "http://x".into())));
        assert_eq!(ns("soap"), Err("XMLS: Bad format, missing equals sign.".into()));
        assert_eq!(ns("=http://x"), Err("XMLS: XMLNS is invalid. Expecting a name=value format.".into()));
        assert_eq!(ns("a="), Err("XMLS: XMLNS is invalid. Expecting a name=value format.".into()));
        assert_eq!(ns("a=https://x"), Err("XMLS: Missing xmlns href for prefix: `https://x'.".into()));
    }
}
