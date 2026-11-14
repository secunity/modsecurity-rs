//! Port of `src/variables/xml.cc`, `src/variables/xml.h`.
//!
//! `XML` (the whole document, used as the target of `@validateDTD` and
//! `@validateSchema`) and `XML:/xpath` (the content of the nodes the XPath
//! expression selects in the document parsed by the XML request body
//! processor; namespaces come from the rule's `xmlns` actions).

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::Variable;

/// `XML:/xpath`: without libxml2 there is no document, so nothing is
/// resolved.
#[cfg(not(feature = "libxml2"))]
pub(crate) fn evaluate_xpath(
    _var: &Variable,
    _t: &Transaction<'_>,
    _rule: Option<&RuleWithActions>,
    _l: &mut Vec<VariableValue>,
) {
}

/// `XML:/xpath`: the content of the nodes the expression (the variable's
/// name) selects.
#[cfg(feature = "libxml2")]
pub(crate) fn evaluate_xpath(
    var: &Variable,
    t: &Transaction<'_>,
    rule: Option<&RuleWithActions>,
    l: &mut Vec<VariableValue>,
) {
    use crate::utils::libxml2::XPathError;

    // Is there an XML document tree at all?
    let Some(doc) = t.xml.as_ref().and_then(|x| x.document()) else {
        // Sorry, we've got nothing to give!
        return;
    };

    // The namespaces of the rule's `xmlns` actions.
    let mut namespaces: Vec<(String, String)> = Vec::new();
    if let Some(rule) = rule {
        for x in rule.actions_by_name("xmlns", t) {
            if let Some((prefix, href)) = x.xml_namespace() {
                namespaces.push((prefix.to_string(), href.to_string()));
            }
        }
    }
    let ns: Vec<(&[u8], &[u8])> = namespaces.iter().map(|(p, h)| (p.as_bytes(), h.as_bytes())).collect();

    // What was logged once the XPath context existed: the first `n`
    // namespaces registered.
    let registered = |n: usize| {
        if rule.is_none() {
            crate::ms_dbg_a!(t, 2, "XML: Can't look for xmlns, internal error.");
        }
        for (prefix, href) in &namespaces[..n] {
            crate::ms_dbg_a!(t, 4, "Registered XML namespace href \"{}\" prefix \"{}\"", href, prefix);
        }
    };
    match doc.xpath(var.name().as_bytes(), &ns) {
        Err(XPathError::Context) => crate::ms_dbg_a!(t, 1, "XML: Unable to create new XPath context. : "),
        Err(XPathError::Namespace(i)) => {
            registered(i);
            let (prefix, href) = &namespaces[i];
            crate::ms_dbg_a!(t, 1, "Failed to register XML namespace href \"{}\" prefix \"{}\".", href, prefix);
        }
        Err(XPathError::Eval) => {
            registered(namespaces.len());
            crate::ms_dbg_a!(t, 1, "XML: Unable to evaluate xpath expression.");
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
