//! Port of `src/operators/validate_dtd.cc`, `src/operators/validate_dtd.h`.
//!
//! `@validateDTD`: validates the XML document parsed by the XML request body
//! processor against a DTD. Matches (returns true) when the DTD cannot be
//! loaded or the document is missing, not well formed or not valid.

use crate::operators::operator::{Operator, Param};
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct ValidateDTD {
    param: Param,
    #[cfg(feature = "libxml2")]
    resource: String,
}

impl ValidateDTD {
    pub fn new(param: RunTimeString) -> Self {
        ValidateDTD {
            param: Param::new(param),
            #[cfg(feature = "libxml2")]
            resource: String::new(),
        }
    }
}

/// `XmlDtdPtrManager`: frees the DTD when going out of scope.
#[cfg(feature = "libxml2")]
struct XmlDtdPtrManager(*mut crate::request_body_processor::xml::ffi::xmlDtd);

#[cfg(feature = "libxml2")]
impl Drop for XmlDtdPtrManager {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the DTD was returned by xmlParseDTD and is freed once.
            unsafe { crate::request_body_processor::xml::ffi::xmlFreeDtd(self.0) };
        }
    }
}

impl Operator for ValidateDTD {
    fn name(&self) -> &'static str {
        "ValidateDTD"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    #[cfg(feature = "libxml2")]
    fn init(&mut self, file: &str) -> Result<(), String> {
        let param = self.param.literal_lossy();
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
        crate::ms_dbg_a!(t, 2, "Operator: {} is not implemented or malfunctioning.", self.name());
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
        use crate::operators::validate_schema::callbacks;
        use crate::request_body_processor::xml::ffi;
        use std::ffi::c_void;

        let resource = ffi::c_string(self.resource.as_bytes());
        // SAFETY: the system id is NUL terminated; the result is owned by
        // the manager.
        let dtd = XmlDtdPtrManager(unsafe { ffi::xmlParseDTD(std::ptr::null(), resource.as_ptr().cast::<u8>()) });

        // (The C++ code needed a transaction: it dereferenced it.)
        let t: &Transaction<'_> = t;

        if dtd.0.is_null() {
            crate::ms_dbg_a!(t, 4, "XML: Failed to load DTD: {}", self.resource);
            return true;
        }

        let (doc, well_formed) = match t.xml.as_ref() {
            Some(x) if x.has_doc() => (x.doc(), x.well_formed()),
            _ => {
                crate::ms_dbg_a!(t, 4, "XML document tree could not be found for DTD validation.");
                return true;
            }
        };

        if well_formed != 1 {
            crate::ms_dbg_a!(t, 4, "XML: DTD validation failed because content is not well formed.");
            return true;
        }

        // SAFETY: plain constructor; the context starts zeroed (no error
        // callbacks).
        let cvp = unsafe { ffi::xmlNewValidCtxt() };
        if cvp.is_null() {
            crate::ms_dbg_a!(t, 4, "XML: Failed to create a validation context.");
            return true;
        }

        // Send validator errors/warnings to msr_log. The C++ code installed
        // (variadic) callbacks in the validation context; with none there,
        // libxml2 reports the same messages to the thread's structured error
        // handler, which is pointed at the transaction for the duration of
        // the validation and then restored.
        // SAFETY: cvp is live and freed once; doc and the DTD are live; the
        // handler context is the transaction, alive for the whole
        // validation; the previous handler is restored before returning.
        let valid = unsafe {
            let prev_handler = *ffi::__xmlStructuredError();
            let prev_ctx = *ffi::__xmlStructuredErrorContext();
            ffi::xmlSetStructuredErrorFunc(t as *const Transaction<'_> as *mut c_void, Some(callbacks::log_msg));
            let valid = ffi::xmlValidateDtd(cvp, doc, dtd.0);
            ffi::xmlSetStructuredErrorFunc(prev_ctx, prev_handler);
            ffi::xmlFreeValidCtxt(cvp);
            valid
        };

        if valid == 0 {
            crate::ms_dbg_a!(t, 4, "XML: DTD validation failed.");
            return true;
        }

        crate::ms_dbg_a!(t, 4, "XML: Successfully validated payload against DTD: {}", self.resource);

        false
    }
}
