//! The `@validateSchema` operator: validates the XML document parsed by
//! the XML request body processor against an XML Schema. Matches (returns
//! true) when the schema cannot be loaded or the document is missing, not
//! well formed or not valid.

use crate::{Context, Operator, Param, Resources};

#[derive(Debug)]
pub struct ValidateSchema {
    param: Param,
    #[cfg(feature = "libxml2")]
    resource: String,
    /// The schema, parsed by the first evaluation that could load it. Each
    /// validation holds this lock: libxml2 does not say that a schema can
    /// be used by several validations at once.
    #[cfg(feature = "libxml2")]
    schema: std::sync::Mutex<Option<LoadedSchema>>,
}

/// A schema parsed once, with the messages of loading it (the message of
/// a failed validation context shows them).
#[cfg(feature = "libxml2")]
#[derive(Debug)]
struct LoadedSchema {
    schema: modsecurity_native::libxml2::Schema,
    load_errors: String,
}

impl ValidateSchema {
    /// Finds the file `param` names; `file` is the configuration file of
    /// the rule.
    #[cfg(feature = "libxml2")]
    pub fn new(param: Param, file: &str, resources: &dyn Resources) -> Result<Self, String> {
        let name = param.literal_lossy();
        let lookup = resources.find(&name, file);
        let Some(resource) = lookup.path else {
            return Err(format!("XML: File not found: {}. {}", name, lookup.looked_at));
        };
        Ok(ValidateSchema { param, resource, schema: Default::default() })
    }

    #[cfg(feature = "libxml2")]
    /// Parses the schema, keeping the messages of the schema code (not
    /// those of the parser reading the schema document) in `load_errors`.
    fn load(&self, load_errors: &mut String) -> Result<modsecurity_native::libxml2::Schema, String> {
        use modsecurity_native::libxml2::{Schema, SchemaError};
        let result = Schema::load(&self.resource, &mut |m| {
            if m.from_schema
                && let Some(msg) = message(m)
            {
                load_errors.push_str(&msg);
            }
        });
        result.map_err(|error| match error {
            SchemaError::Load => format!("XML: Failed to load Schema from file: {}. {}", self.resource, load_errors),
            SchemaError::Parse if load_errors.is_empty() => format!("XML: Failed to load Schema: {}.", self.resource),
            SchemaError::Parse => format!("XML: Failed to load Schema: {}. {}", self.resource, load_errors),
        })
    }

    /// Without libxml2 the file is not looked for.
    #[cfg(not(feature = "libxml2"))]
    pub fn new(param: Param, _file: &str, _resources: &dyn Resources) -> Result<Self, String> {
        Ok(ValidateSchema { param })
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

    /// Without libxml2 the operator logs that it is not implemented and
    /// matches.
    #[cfg(not(feature = "libxml2"))]
    fn evaluate(&self, cx: &mut dyn Context, _input: &[u8]) -> bool {
        crate::ms_dbg!(cx, 2, "Operator: {} is not implemented or malfunctioning.", self.name());
        true
    }

    #[cfg(feature = "libxml2")]
    fn evaluate(&self, cx: &mut dyn Context, _input: &[u8]) -> bool {
        use modsecurity_native::libxml2;

        let Some((doc, well_formed)) = cx.xml_document() else {
            crate::ms_dbg!(cx, 4, "XML document tree could not be found for schema validation.");
            return true;
        };

        if !well_formed {
            crate::ms_dbg!(cx, 4, "XML: Schema validation failed because content is not well formed.");
            return true;
        }

        // The schema is read where it is used: with `SecXMLExternalEntity
        // Off` libxml2 loads no file on this thread, and the load fails at
        // each evaluation. Otherwise it is parsed once and kept.
        let mut kept = self.schema.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let fresh;
        let loaded = if let Some(loaded) = kept.as_ref().filter(|_| libxml2::external_entities_allowed()) {
            loaded
        } else {
            let mut load_errors = String::new();
            let schema = match self.load(&mut load_errors) {
                Ok(schema) => LoadedSchema { schema, load_errors },
                Err(err) => {
                    crate::ms_dbg!(cx, 4, "{}", err);
                    return true;
                }
            };
            if libxml2::external_entities_allowed() {
                &*kept.insert(schema)
            } else {
                fresh = schema;
                &fresh
            }
        };

        // Validator errors/warnings go to the debug log.
        let result = doc.validate_schema(&loaded.schema, &mut |m| {
            if let Some(msg) = message(m) {
                crate::ms_dbg!(cx, 4, "{}", msg);
            }
        });
        match result {
            None => {
                // " " + the load errors is written over the start of the
                // message, not appended to it: the debug log text of the
                // original ModSecurity, kept as it is.
                let mut err = b"XML: Failed to create validation context.".to_vec();
                if !loaded.load_errors.is_empty() {
                    let over = format!(" {}", loaded.load_errors).into_bytes();
                    let n = over.len().min(err.len());
                    err[..n].copy_from_slice(&over[..n]);
                    err.extend_from_slice(&over[n..]);
                }
                crate::ms_dbg!(cx, 4, "{}", String::from_utf8_lossy(&err));
                true
            }
            Some(false) => {
                crate::ms_dbg!(cx, 4, "XML: Schema validation failed.");
                true
            }
            Some(true) => {
                crate::ms_dbg!(cx, 4, "XML: Successfully validated payload against Schema: {}", self.resource);
                false
            }
        }
    }
}
