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
    use crate::request_body_processor::xml::ffi;

    let param = var.name();

    // Is there an XML document tree at all?
    let doc = t.xml.as_ref().map_or(std::ptr::null_mut(), |x| x.doc());
    if doc.is_null() {
        // Sorry, we've got nothing to give!
        return;
    }

    // Process the XPath expression.
    let xpath_expr = ffi::c_string(param.as_bytes());
    // SAFETY: doc is the live document owned by the transaction's XML
    // processor, which `t` keeps alive for this whole function.
    let xpath_ctx = unsafe { ffi::xmlXPathNewContext(doc) };
    if xpath_ctx.is_null() {
        crate::ms_dbg_a!(t, 1, "XML: Unable to create new XPath context. : ");
        return;
    }

    /// Frees the XPath context on every return path.
    struct CtxGuard(*mut ffi::xmlXPathContext);
    impl Drop for CtxGuard {
        fn drop(&mut self) {
            // SAFETY: the context was created above and is freed once.
            unsafe { ffi::xmlXPathFreeContext(self.0) };
        }
    }
    let _ctx_guard = CtxGuard(xpath_ctx);

    match rule {
        None => {
            crate::ms_dbg_a!(t, 2, "XML: Can't look for xmlns, internal error.");
        }
        Some(rule) => {
            for x in rule.actions_by_name("xmlns", t) {
                let Some((prefix, href)) = x.xml_namespace() else {
                    continue;
                };
                let scope = ffi::c_string(prefix.as_bytes());
                let href_c = ffi::c_string(href.as_bytes());
                // SAFETY: the context is live; prefix and URI are NUL
                // terminated (libxml2 copies them).
                let rc = unsafe {
                    ffi::xmlXPathRegisterNs(xpath_ctx, scope.as_ptr().cast::<u8>(), href_c.as_ptr().cast::<u8>())
                };
                if rc != 0 {
                    crate::ms_dbg_a!(t, 1, "Failed to register XML namespace href \"{}\" prefix \"{}\".", href, prefix);
                    return;
                }

                crate::ms_dbg_a!(t, 4, "Registered XML namespace href \"{}\" prefix \"{}\"", href, prefix);
            }
        }
    }

    // Initialise XPath expression.
    // SAFETY: the expression is NUL terminated and the context live.
    let xpath_obj = unsafe { ffi::xmlXPathEvalExpression(xpath_expr.as_ptr().cast::<u8>(), xpath_ctx) };
    if xpath_obj.is_null() {
        crate::ms_dbg_a!(t, 1, "XML: Unable to evaluate xpath expression.");
        return;
    }

    // SAFETY: xpath_obj is a live XPath object; its node set (when it
    // has one) holds `nodeNr` valid node pointers into the document.
    // Node contents are copies that are freed with xmlFree. The object
    // is freed once, after the last use.
    unsafe {
        // Evaluate XPath expression.
        let nodes = (*xpath_obj).nodesetval;
        if !nodes.is_null() {
            // Create one variable for each node in the result.
            let nr = usize::try_from((*nodes).nodeNr).unwrap_or(0);
            for i in 0..nr {
                let content = ffi::xmlNodeGetContent(*(*nodes).nodeTab.add(i));
                if !content.is_null() {
                    let a = ffi::c_bytes(content).to_vec();
                    let full_name = var.full_name().as_bytes();
                    if !var.key_exclusion().to_omit(full_name) {
                        l.push(VariableValue::new(full_name, &a));
                    }
                    ffi::xml_free(content as *mut std::ffi::c_void);
                }
            }
        }
        ffi::xmlXPathFreeObject(xpath_obj);
    }
}
