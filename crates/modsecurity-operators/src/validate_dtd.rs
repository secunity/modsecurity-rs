//! The `@validateDTD` operator: validates the XML document parsed by the
//! XML request body processor against a DTD. Matches (returns true) when
//! the DTD cannot be loaded or the document is missing, not well formed or
//! not valid.

use crate::{Context, Operator, Param, Resources};

#[derive(Debug)]
pub struct ValidateDTD {
    param: Param,
    #[cfg(feature = "libxml2")]
    resource: String,
    /// The DTD, parsed by the first evaluation that could load it, and
    /// validated with under this lock (validating builds the content
    /// models of its element declarations).
    #[cfg(feature = "libxml2")]
    dtd: std::sync::Mutex<Option<modsecurity_native::libxml2::Dtd>>,
}

impl ValidateDTD {
    /// Finds the file `param` names; `file` is the configuration file of
    /// the rule.
    #[cfg(feature = "libxml2")]
    pub fn new(param: Param, file: &str, resources: &dyn Resources) -> Result<Self, String> {
        let name = param.literal_lossy();
        let lookup = resources.find(&name, file);
        let Some(resource) = lookup.path else {
            return Err(format!("XML: File not found: {}. {}", name, lookup.looked_at));
        };
        Ok(ValidateDTD { param, resource, dtd: Default::default() })
    }

    /// Without libxml2 the file is not looked for.
    #[cfg(not(feature = "libxml2"))]
    pub fn new(param: Param, _file: &str, _resources: &dyn Resources) -> Result<Self, String> {
        Ok(ValidateDTD { param })
    }
}

impl Operator for ValidateDTD {
    fn name(&self) -> &'static str {
        "ValidateDTD"
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
        use crate::validate_schema::message;
        use modsecurity_native::libxml2::{self, Dtd};

        // The DTD is read where it is used: with `SecXMLExternalEntity Off`
        // libxml2 loads no file on this thread, and the load fails at each
        // evaluation (`config-xml_external_entity.json`, "XXE 2").
        // Otherwise it is parsed once and kept.
        let mut kept = self.dtd.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let fresh;
        let dtd = if let Some(dtd) = kept.as_ref().filter(|_| libxml2::external_entities_allowed()) {
            dtd
        } else {
            let Some(dtd) = Dtd::load(&self.resource) else {
                crate::ms_dbg!(cx, 4, "XML: Failed to load DTD: {}", self.resource);
                return true;
            };
            if libxml2::external_entities_allowed() {
                &*kept.insert(dtd)
            } else {
                fresh = dtd;
                &fresh
            }
        };

        let Some((doc, well_formed)) = cx.xml_document() else {
            crate::ms_dbg!(cx, 4, "XML document tree could not be found for DTD validation.");
            return true;
        };

        if !well_formed {
            crate::ms_dbg!(cx, 4, "XML: DTD validation failed because content is not well formed.");
            return true;
        }

        // Validator errors/warnings go to the debug log.
        let Some(valid) = doc.validate_dtd(dtd, &mut |m| {
            if let Some(msg) = message(m) {
                crate::ms_dbg!(cx, 4, "{}", msg);
            }
        }) else {
            crate::ms_dbg!(cx, 4, "XML: Failed to create a validation context.");
            return true;
        };

        if !valid {
            crate::ms_dbg!(cx, 4, "XML: DTD validation failed.");
            return true;
        }

        crate::ms_dbg!(cx, 4, "XML: Successfully validated payload against DTD: {}", self.resource);

        false
    }
}
