//! Port of `src/actions/xmlns.cc`, `src/actions/xmlns.h`.
//!
//! `xmlns:prefix=http://...` — declares an XML namespace for the `XML`
//! variable's XPath expressions (read by that variable).

use crate::actions::action::{Action, ActionBase};

#[derive(Debug)]
pub struct XmlNS {
    pub base: ActionBase,
    pub scope: String,
    pub href: String,
}

impl XmlNS {
    pub fn new(action: &str) -> Self {
        XmlNS { base: ActionBase::new(action), scope: String::new(), href: String::new() }
    }
}

impl Action for XmlNS {
    crate::action_base_accessors!();

    fn init(&mut self) -> Result<(), String> {
        let http = "http://";
        let payload = &self.base.parser_payload;
        let Some(pos) = payload.find('=') else {
            return Err("XMLS: Bad format, missing equals sign.".to_string());
        };
        self.scope = payload[..pos].to_string();
        self.href = payload[pos + 1..].to_string();

        if self.href.is_empty() || self.scope.is_empty() {
            return Err("XMLS: XMLNS is invalid. Expecting a name=value format.".to_string());
        }

        if self.href.starts_with('\'') && self.href.len() > 3 {
            self.href.remove(0);
            self.href.pop();
        }

        if !self.href.starts_with(http) {
            return Err(format!("XMLS: Missing xmlns href for prefix: `{}'.", self.href));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(p: &str) -> Result<(String, String), String> {
        let mut a = XmlNS::new(&format!("xmlns:{}", p));
        a.init().map(|_| (a.scope, a.href))
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
