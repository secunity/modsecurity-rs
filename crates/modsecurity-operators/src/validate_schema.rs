//! The `@validateSchema` operator: validates the XML document parsed by
//! the XML request body processor against an XML Schema. Matches (returns
//! true) when the document is missing, not well formed or not valid.

use crate::{Context, Operator, Param};

#[derive(Debug)]
pub struct ValidateSchema {
    param: Param,
    #[cfg(feature = "libxml2")]
    resource: String,
    /// The messages reported while loading the schema. As in the
    /// C++ code they accumulate over the lifetime of the operator (the C++
    /// member was written without synchronisation; a mutex is used here).
    #[cfg(feature = "libxml2")]
    err: std::sync::Mutex<String>,
}

impl ValidateSchema {
    pub fn new(param: Param) -> Self {
        ValidateSchema {
            param,
            #[cfg(feature = "libxml2")]
            resource: String::new(),
            #[cfg(feature = "libxml2")]
            err: std::sync::Mutex::new(String::new()),
        }
    }
}

/// Formats a libxml2 message for the log (shared with `@validateDTD`):
/// the message (formatted by the C++ code into a 1024 bytes buffer, hence
/// at most 1023 bytes) prefixed by its level; `None` when it is empty.
#[cfg(feature = "libxml2")]
pub(crate) fn message(m: modsecurity_native::libxml2::Message<'_>) -> Option<String> {
    const PREFIX_WARNING: &str = "XML Warning: ";
    const PREFIX_ERROR: &str = "XML Error: ";
    let text = &m.text[..m.text.len().min(1023)];
    if text.is_empty() {
        return None;
    }
    let base_msg = if m.warning { PREFIX_WARNING } else { PREFIX_ERROR };
    Some(format!("{}{}", base_msg, String::from_utf8_lossy(text)))
}

impl Operator for ValidateSchema {
    fn name(&self) -> &'static str {
        "ValidateSchema"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    #[cfg(feature = "libxml2")]
    fn init(&mut self, file: &str, resources: &dyn crate::Resources) -> Result<(), String> {
        let param = self.param.literal_lossy();
        let lookup = resources.find(&param, file);
        let Some(resource) = lookup.path else {
            return Err(format!("XML: File not found: {}. {}", param, lookup.looked_at));
        };
        self.resource = resource;
        Ok(())
    }

    /// Without libxml2 the operator logs that it is not implemented and
    /// matches, as the base `Operator::evaluate` does in C++.
    #[cfg(not(feature = "libxml2"))]
    fn evaluate(&self, cx: &mut dyn Context, _input: &[u8]) -> bool {
        crate::ms_dbg!(cx, 2, "Operator: {} is not implemented or malfunctioning.", self.name());
        true
    }

    #[cfg(feature = "libxml2")]
    fn evaluate(&self, cx: &mut dyn Context, _input: &[u8]) -> bool {
        use modsecurity_native::libxml2::SchemaError;

        let Some((doc, well_formed)) = cx.xml_document() else {
            crate::ms_dbg!(cx, 4, "XML document tree could not be found for schema validation.");
            return true;
        };

        if well_formed != 1 {
            crate::ms_dbg!(cx, 4, "XML: Schema validation failed because content is not well formed.");
            return true;
        }

        // The errors of loading the schema accumulate in `m_err` (a member
        // of the C++ operator: across evaluations too). Only the errors of
        // the schema code are kept: the C++ (non structured) callbacks did
        // not receive those of the parser reading the schema document.
        let mut m_err = self.err.lock().unwrap_or_else(|e| e.into_inner());
        let result = doc.validate_schema(
            &self.resource,
            &mut |m| {
                if m.from_schema
                    && let Some(msg) = message(m)
                {
                    m_err.push_str(&msg);
                }
            },
            // Validator errors/warnings go to the debug log.
            &mut |m| {
                if let Some(msg) = message(m) {
                    crate::ms_dbg!(cx, 4, "{}", msg);
                }
            },
        );
        match result {
            Err(SchemaError::Load) => {
                let mut err = format!("XML: Failed to load Schema from file: {}. ", self.resource);
                if !m_err.is_empty() {
                    err.push_str(&m_err);
                }
                crate::ms_dbg!(cx, 4, "{}", err);
                true
            }
            Err(SchemaError::Parse) => {
                let mut err = format!("XML: Failed to load Schema: {}.", self.resource);
                if !m_err.is_empty() {
                    err.push(' ');
                    err.push_str(&m_err);
                }
                crate::ms_dbg!(cx, 4, "{}", err);
                true
            }
            Err(SchemaError::ValidationContext) => {
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
                crate::ms_dbg!(cx, 4, "{}", String::from_utf8_lossy(&err));
                true
            }
            Ok(false) => {
                crate::ms_dbg!(cx, 4, "XML: Schema validation failed.");
                true // No match.
            }
            Ok(true) => {
                crate::ms_dbg!(cx, 4, "XML: Successfully validated payload against Schema: {}", self.resource);
                false
            }
        }
    }
}
