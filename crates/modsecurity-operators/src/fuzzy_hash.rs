//! The `@fuzzyHash` operator: matches when the ssdeep hash of the input is
//! similar enough to one of the hashes listed in a file.
//!
//! ssdeep (libfuzzy) is called through `modsecurity_native::ssdeep` when
//! the `ssdeep` feature is enabled. Without it the operator cannot be
//! built.

use crate::{Context, Operator, Param, Resources};

#[derive(Debug)]
pub struct FuzzyHash {
    param: Param,
    #[cfg(feature = "ssdeep")]
    threshold: i32,
    /// The hashes of the file, one per line.
    #[cfg(feature = "ssdeep")]
    chunks: Vec<std::ffi::CString>,
}

impl FuzzyHash {
    /// Reads the hashes of the file `param` names (`file threshold`);
    /// `param2` is the configuration file of the rule.
    #[cfg(feature = "ssdeep")]
    pub fn new(param: Param, param2: &str, resources: &dyn Resources) -> Result<Self, String> {
        let Some(pos) = param.literal.iter().rposition(|&c| c == b' ') else {
            return Err("Please use @fuzzyHash with filename and value".to_string());
        };
        let digit = &param.literal[pos + 1..];
        let file = String::from_utf8_lossy(&param.literal[..pos]).into_owned();
        let threshold = std::str::from_utf8(digit).ok().filter(|d| d.bytes().all(|c| c.is_ascii_digit()));
        let Some(threshold) = threshold.and_then(|d| d.parse().ok()) else {
            return Err(format!("Expecting a digit, got: {}", String::from_utf8_lossy(digit)));
        };

        let lookup = resources.find(&file, param2);
        // A file that cannot be read completely is not used at all.
        let Ok(content) = std::fs::read(lookup.path.unwrap_or_default()) else {
            return Err(format!(
                "Failed to open file: {}. {}",
                String::from_utf8_lossy(&param.literal),
                lookup.looked_at
            ));
        };

        let mut lines: Vec<&[u8]> = content.split(|&c| c == b'\n').collect();
        if content.is_empty() || content.ends_with(b"\n") {
            lines.pop();
        }
        // A hash is a C string for ssdeep: the line up to its first NUL byte.
        let chunks = lines
            .into_iter()
            .map(|line| std::ffi::CString::new(modsecurity_compat::chars::c_str(line)).unwrap_or_default())
            .collect();

        Ok(FuzzyHash { param, threshold, chunks })
    }

    /// Without ssdeep there is no such operator.
    #[cfg(not(feature = "ssdeep"))]
    pub fn new(_param: Param, _param2: &str, _resources: &dyn Resources) -> Result<Self, String> {
        Err("@fuzzyHash: SSDEEP support was not enabled during the compilation.".to_string())
    }
}

impl Operator for FuzzyHash {
    fn name(&self) -> &'static str {
        "FuzzyHash"
    }

    fn param(&self) -> Option<&Param> {
        Some(&self.param)
    }

    #[cfg(feature = "ssdeep")]
    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        let Some(result) = modsecurity_native::ssdeep::hash(input) else {
            crate::ms_dbg!(cx, 4, "Problems generating fuzzy hash");
            return false;
        };

        for chunk in &self.chunks {
            let i = modsecurity_native::ssdeep::compare(chunk, &result);
            if i >= self.threshold {
                crate::ms_dbg!(cx, 4, "Fuzzy hash: matched with score: {}.", i);
                return true;
            }
        }

        false
    }

    /// Never called: without ssdeep the operator cannot be built.
    #[cfg(not(feature = "ssdeep"))]
    fn evaluate(&self, _cx: &mut dyn Context, _input: &[u8]) -> bool {
        false
    }
}

#[cfg(all(test, feature = "ssdeep"))]
mod tests {
    use super::*;
    use crate::test_support::{LocalFiles, eval};

    #[test]
    fn param_errors() {
        assert_eq!(
            FuzzyHash::new(Param::from_text("nospace"), "", &LocalFiles).unwrap_err(),
            "Please use @fuzzyHash with filename and value"
        );
        assert_eq!(
            FuzzyHash::new(Param::from_text("file x"), "", &LocalFiles).unwrap_err(),
            "Expecting a digit, got: x"
        );
    }

    #[test]
    fn matches_similar_data() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let body = std::fs::read(format!("{}/modsecurity.conf-recommended", root)).unwrap();
        let param = Param::from_text(&format!("{}/test/test-cases/data/ssdeep.txt 1", root));
        let op = FuzzyHash::new(param, "", &LocalFiles).unwrap();
        assert!(eval(&op, &body));
        let param = Param::from_text(&format!("{}/test/test-cases/data/ssdeep.txt 100", root));
        let op = FuzzyHash::new(param, "", &LocalFiles).unwrap();
        assert!(!eval(&op, &body));
    }
}
