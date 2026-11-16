//! The `XML` variables: `XML` (the whole document, used as the target of
//! `@validateDTD` and `@validateSchema`) and `XML:/xpath` (the content of
//! the nodes the XPath expression selects in the document parsed by the XML
//! request body processor; namespaces come from the rule's `xmlns`
//! actions).

use crate::rule::Rule;
use crate::transaction::Transaction;
use crate::variables::variable::Variable;
use crate::variables::variable_value::VariableValue;

/// `XML:/xpath`: without libxml2 there is no document, so nothing is
/// resolved.
#[cfg(not(feature = "libxml2"))]
pub(crate) fn evaluate_xpath(_var: &Variable, _t: &Transaction<'_>, _rule: Option<&Rule>, _l: &mut Vec<VariableValue>) {
}

/// `XML:/xpath`: the content of the nodes the expression (the variable's
/// name) selects.
#[cfg(feature = "libxml2")]
pub(crate) fn evaluate_xpath(var: &Variable, t: &Transaction<'_>, rule: Option<&Rule>, l: &mut Vec<VariableValue>) {
    use crate::utils::libxml2::XPathError;

    // Is there an XML document tree at all?
    let Some(doc) = t.body.xml.as_ref().and_then(|x| x.document()) else {
        // Sorry, we've got nothing to give!
        return;
    };

    // The namespaces of the rule's `xmlns` actions.
    let mut namespaces: Vec<(String, String)> = Vec::new();
    if let Some(rule) = rule {
        for (prefix, href) in rule.xml_namespaces(t) {
            namespaces.push((prefix.to_string(), href.to_string()));
        }
    }
    let ns: Vec<(&[u8], &[u8])> = namespaces.iter().map(|(p, h)| (p.as_bytes(), h.as_bytes())).collect();

    // What was logged once the XPath context existed: the first `n`
    // namespaces registered.
    let registered = |n: usize| {
        if rule.is_none() {
            crate::ms_dbg!(t, 2, "XML: Can't look for xmlns, internal error.");
        }
        for (prefix, href) in &namespaces[..n] {
            crate::ms_dbg!(t, 4, "Registered XML namespace href \"{}\" prefix \"{}\"", href, prefix);
        }
    };
    match doc.xpath(var.name().as_bytes(), &ns) {
        Err(XPathError::Context) => crate::ms_dbg!(t, 1, "XML: Unable to create new XPath context. : "),
        Err(XPathError::Namespace(i)) => {
            registered(i);
            let (prefix, href) = &namespaces[i];
            crate::ms_dbg!(t, 1, "Failed to register XML namespace href \"{}\" prefix \"{}\".", href, prefix);
        }
        Err(XPathError::Eval) => {
            registered(namespaces.len());
            crate::ms_dbg!(t, 1, "XML: Unable to evaluate xpath expression.");
        }
        Ok(contents) => {
            registered(namespaces.len());
            // One variable for each node in the result.
            let full_name = var.full_name().as_bytes();
            if !var.key_exclusion().to_omit(full_name) {
                for content in contents {
                    l.push(VariableValue::new(full_name, &content));
                }
            }
        }
    }
}
