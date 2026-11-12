//! Port of `src/operators/validate_schema.cc`, `src/operators/validate_schema.h`.
//!
//! `@validateSchema`: validates the XML document parsed by the XML request
//! body processor against an XML Schema. Matches (returns true) when the
//! document is missing, not well formed or not valid.

use crate::operators::operator::{Operator, OperatorBase};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct ValidateSchema {
    pub base: OperatorBase,
    #[cfg(feature = "libxml2")]
    resource: String,
    /// `m_err`: the messages reported while loading the schema. As in the
    /// C++ code they accumulate over the lifetime of the operator (the C++
    /// member was written without synchronisation; a mutex is used here).
    #[cfg(feature = "libxml2")]
    err: std::sync::Mutex<String>,
}

impl ValidateSchema {
    pub fn new(param: RunTimeString) -> Self {
        ValidateSchema {
            base: OperatorBase::with_string("ValidateSchema", param),
            #[cfg(feature = "libxml2")]
            resource: String::new(),
            #[cfg(feature = "libxml2")]
            err: std::sync::Mutex::new(String::new()),
        }
    }
}

/// The libxml2 error callbacks shared with `@validateDTD`
/// (`ValidateSchema::callback_func` & co.).
#[cfg(feature = "libxml2")]
pub(crate) mod callbacks {
    use std::ffi::c_void;

    use crate::request_body_processor::xml::ffi;
    use crate::transaction::Transaction;

    pub const PREFIX_WARNING: &str = "XML Warning: ";
    pub const PREFIX_ERROR: &str = "XML Error: ";

    /// `callback_func`: the message (formatted by the C++ code into a 1024
    /// bytes buffer, hence at most 1023 bytes) prefixed by its level. `None`
    /// when the message is empty.
    ///
    /// # Safety
    /// `error` must point to a live libxml2 error.
    unsafe fn format(error: *const ffi::xmlError) -> Option<String> {
        if error.is_null() {
            return None;
        }
        // SAFETY: guaranteed by the caller; the message is NUL terminated.
        let (msg, level) = unsafe { (ffi::c_bytes((*error).message as *const u8), (*error).level) };
        let msg = &msg[..msg.len().min(1023)];
        if msg.is_empty() {
            return None;
        }
        let base_msg = if level == ffi::XML_ERR_WARNING { PREFIX_WARNING } else { PREFIX_ERROR };
        Some(format!("{}{}", base_msg, String::from_utf8_lossy(msg)))
    }

    /// `error_runtime` / `warn_runtime` (`log_msg`): logs the message to the
    /// transaction `ctx` points to.
    ///
    /// # Safety
    /// Called by libxml2 with `ctx` set to a `*const Transaction` that is
    /// alive for the duration of the validation.
    pub unsafe extern "C" fn log_msg(ctx: *mut c_void, error: *const ffi::xmlError) {
        // SAFETY: see above.
        unsafe {
            if let Some(msg) = format(error) {
                let t = &*(ctx as *const Transaction<'static>);
                crate::ms_dbg_a!(t, 4, "{}", msg);
            }
        }
    }

    /// `error_load` / `warn_load` (`append_msg`): appends the message to the
    /// `String` `ctx` points to.
    ///
    /// The C++ (non structured) callbacks only received the errors raised
    /// by the schema code; libxml2 also forwards the errors of the parser
    /// reading the schema document to a structured handler (the C++ build
    /// let those go to libxml2's default handler, i.e. stderr): only the
    /// schema errors are kept.
    ///
    /// # Safety
    /// Called by libxml2 with `ctx` set to a `*mut String` that is alive and
    /// not otherwise accessed during the schema parsing.
    pub unsafe extern "C" fn append_msg(ctx: *mut c_void, error: *const ffi::xmlError) {
        // SAFETY: see above.
        unsafe {
            if error.is_null() || !matches!((*error).domain, ffi::XML_FROM_SCHEMASP | ffi::XML_FROM_SCHEMASV) {
                return;
            }
            if let Some(msg) = format(error) {
                (*(ctx as *mut String)).push_str(&msg);
            }
        }
    }
}

impl Operator for ValidateSchema {
    crate::operator_base_accessors!();

    #[cfg(feature = "libxml2")]
    fn init(&mut self, file: &str) -> Result<(), String> {
        let param = String::from_utf8_lossy(&self.base.param).into_owned();
        let lookup = crate::utils::system::find_resource(&param, file);
        let Some(resource) = lookup.path else {
            return Err(format!("XML: File not found: {}. {}", param, lookup.looked_at));
        };
        self.resource = resource;
        Ok(())
    }

    /// Without libxml2 the C++ class only had the base `Operator::evaluate`.
    #[cfg(not(feature = "libxml2"))]
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        _input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        crate::ms_dbg_a!(t, 2, "Operator: {} is not implemented or malfunctioning.", self.base.op);
        true
    }

    #[cfg(feature = "libxml2")]
    fn evaluate(
        &self,
        t: &mut Transaction<'_>,
        _rule: &RuleWithActions,
        _input: &[u8],
        _rm: &mut RuleMessage<'_>,
    ) -> bool {
        use crate::request_body_processor::xml::ffi;
        use std::ffi::c_void;

        // (The C++ code needed a transaction: it dereferenced it.)
        let t: &Transaction<'_> = t;

        let (doc, well_formed) = match t.xml.as_ref() {
            Some(x) if x.has_doc() => (x.doc(), x.well_formed()),
            _ => {
                crate::ms_dbg_a!(t, 4, "XML document tree could not be found for schema validation.");
                return true;
            }
        };

        if well_formed != 1 {
            crate::ms_dbg_a!(t, 4, "XML: Schema validation failed because content is not well formed.");
            return true;
        }

        let mut m_err = self.err.lock().unwrap_or_else(|e| e.into_inner());

        let resource = ffi::c_string(self.resource.as_bytes());
        // SAFETY: the resource name is NUL terminated.
        let parser_ctx = unsafe { ffi::xmlSchemaNewParserCtxt(resource.as_ptr()) };
        if parser_ctx.is_null() {
            let mut err = format!("XML: Failed to load Schema from file: {}. ", self.resource);
            if !m_err.is_empty() {
                err.push_str(&m_err);
            }
            crate::ms_dbg_a!(t, 4, "{}", err);
            return true;
        }

        // SAFETY: parser_ctx is live; the error context is the locked
        // `m_err` string, alive (and not otherwise accessed) until the
        // parser context is freed below. The schema, the validation context
        // and the parser context are freed exactly once; `doc` is the live
        // document of the transaction's XML processor and the transaction
        // (the context of the runtime callbacks) outlives the validation.
        unsafe {
            ffi::xmlSchemaSetParserStructuredErrors(
                parser_ctx,
                Some(callbacks::append_msg),
                &mut *m_err as *mut String as *mut c_void,
            );

            let schema = ffi::xmlSchemaParse(parser_ctx);
            if schema.is_null() {
                let mut err = format!("XML: Failed to load Schema: {}.", self.resource);
                if !m_err.is_empty() {
                    err.push(' ');
                    err.push_str(&m_err);
                }
                crate::ms_dbg_a!(t, 4, "{}", err);
                ffi::xmlSchemaFreeParserCtxt(parser_ctx);
                return true;
            }

            let valid_ctx = ffi::xmlSchemaNewValidCtxt(schema);
            if valid_ctx.is_null() {
                // The C++ code wrote " " + m_err over the start of the
                // message (a std::stringstream constructed from a string
                // starts writing at its beginning).
                let mut err = b"XML: Failed to create validation context.".to_vec();
                if !m_err.is_empty() {
                    let over = format!(" {}", m_err).into_bytes();
                    let n = over.len().min(err.len());
                    err[..n].copy_from_slice(&over[..n]);
                    err.extend_from_slice(&over[n..]);
                }
                crate::ms_dbg_a!(t, 4, "{}", String::from_utf8_lossy(&err));
                ffi::xmlSchemaFree(schema);
                ffi::xmlSchemaFreeParserCtxt(parser_ctx);
                return true;
            }

            // Send validator errors/warnings to msr_log
            ffi::xmlSchemaSetValidStructuredErrors(
                valid_ctx,
                Some(callbacks::log_msg),
                t as *const Transaction<'_> as *mut c_void,
            );

            let rc = ffi::xmlSchemaValidateDoc(valid_ctx, doc);

            ffi::xmlSchemaFreeValidCtxt(valid_ctx);
            ffi::xmlSchemaFree(schema);
            ffi::xmlSchemaFreeParserCtxt(parser_ctx);
            if rc != 0 {
                crate::ms_dbg_a!(t, 4, "XML: Schema validation failed.");
                true // No match.
            } else {
                crate::ms_dbg_a!(t, 4, "XML: Successfully validated payload against Schema: {}", self.resource);
                false
            }
        }
    }
}
