//! The `@validateSchema` operator: validates the XML document parsed by
//! the XML request body processor against an XML Schema. Matches (returns
//! true) when the document is missing, not well formed or not valid.

use crate::{Context, Operator, Param};

#[derive(Debug)]
pub struct ValidateSchema {
    param: Param,
    #[cfg(feature = "libxml2")]
    resource: String,
}

impl ValidateSchema {
    pub fn new(param: Param) -> Self {
        ValidateSchema {
            param,
            #[cfg(feature = "libxml2")]
            resource: String::new(),
        }
    }
}

/// Formats a libxml2 message for the log (shared with `@validateDTD`):
/// the message (its first 1023 bytes at most) prefixed by its level;
/// `None` when it is empty.
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
    /// matches.
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

        // The errors of loading the schema, for the message of a failure
        // below. Only the errors of the schema code are kept, not those of
        // the parser reading the schema document.
        let mut m_err = String::new();
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
                // " " + m_err is written over the start of the message, not
                // appended to it: the debug log text of the original
                // ModSecurity, kept as it is.
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
