//! The `@validateDTD` operator: validates the XML document parsed by the
//! XML request body processor against a DTD. Matches (returns true) when
//! the DTD cannot be loaded or the document is missing, not well formed or
//! not valid.

use crate::operators::operator::{MatchContext, Operator, Param};
#[cfg(feature = "libxml2")]
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct ValidateDTD {
    param: Param,
    #[cfg(feature = "libxml2")]
    resource: String,
}

impl ValidateDTD {
    pub fn new(param: Param) -> Self {
        ValidateDTD {
            param,
            #[cfg(feature = "libxml2")]
            resource: String::new(),
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

    /// Without libxml2 the operator logs that it is not implemented and
    /// matches, as the base `Operator::evaluate` does in C++.
    #[cfg(not(feature = "libxml2"))]
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, _input: &[u8]) -> bool {
        crate::op_dbg!(cx, 2, "Operator: {} is not implemented or malfunctioning.", self.name());
        true
    }

    #[cfg(feature = "libxml2")]
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, _input: &[u8]) -> bool {
        use crate::operators::validate_schema::message;
        use crate::utils::libxml2::Dtd;

        let dtd = Dtd::load(&self.resource);

        // (The C++ code needed a transaction: it dereferenced it.)
        let t: &Transaction<'_> = cx.transaction_ref();

        let Some(dtd) = dtd else {
            crate::op_dbg!(cx, 4, "XML: Failed to load DTD: {}", self.resource);
            return true;
        };

        let Some((doc, well_formed)) = t.body.xml.as_ref().and_then(|x| Some((x.document()?, x.well_formed()))) else {
            crate::op_dbg!(cx, 4, "XML document tree could not be found for DTD validation.");
            return true;
        };

        if well_formed != 1 {
            crate::op_dbg!(cx, 4, "XML: DTD validation failed because content is not well formed.");
            return true;
        }

        // Validator errors/warnings go to the debug log.
        let Some(valid) = doc.validate_dtd(&dtd, &mut |m| {
            if let Some(msg) = message(m) {
                crate::op_dbg!(cx, 4, "{}", msg);
            }
        }) else {
            crate::op_dbg!(cx, 4, "XML: Failed to create a validation context.");
            return true;
        };

        if !valid {
            crate::op_dbg!(cx, 4, "XML: DTD validation failed.");
            return true;
        }

        crate::op_dbg!(cx, 4, "XML: Successfully validated payload against DTD: {}", self.resource);

        false
    }
}
