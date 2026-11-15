//! The `@fuzzyHash` operator: matches when the ssdeep hash of the input is
//! similar enough to one of the hashes listed in a file.
//!
//! ssdeep (libfuzzy) is bound through a small `extern "C"` block when the
//! `ssdeep` feature is enabled (C++ `WITH_SSDEEP`; build.rs links the
//! library). Without it the operator fails to initialise and never
//! matches, like the C++ build without ssdeep.

use crate::operators::operator::{MatchContext, Operator, Param};
use crate::run_time_string::RunTimeString;

#[derive(Debug)]
pub struct FuzzyHash {
    param: Param,
    #[cfg(feature = "ssdeep")]
    threshold: i32,
    /// The hashes of the file (`fuzzy_hash_chunk` list), one per line.
    #[cfg(feature = "ssdeep")]
    chunks: Vec<std::ffi::CString>,
}

impl FuzzyHash {
    pub fn new(param: RunTimeString) -> Self {
        FuzzyHash {
            param: Param::new(param),
            #[cfg(feature = "ssdeep")]
            threshold: 0,
            #[cfg(feature = "ssdeep")]
            chunks: Vec::new(),
        }
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
    fn init(&mut self, param2: &str) -> Result<(), String> {
        use crate::operators::eq::stoi;
        use crate::utils::system::find_resource;
        use std::io::Read;

        let param = self.param.literal.clone();
        let Some(pos) = param.iter().rposition(|&c| c == b' ') else {
            return Err("Please use @fuzzyHash with filename and value".to_string());
        };
        let digit = &param[pos + 1..];
        let file = String::from_utf8_lossy(&param[..pos]).into_owned();
        let Some(threshold) = stoi(digit) else {
            return Err(format!("Expecting a digit, got: {}", String::from_utf8_lossy(digit)));
        };
        self.threshold = threshold;

        let lookup = find_resource(&file, param2);
        let Ok(mut f) = std::fs::File::open(lookup.path.unwrap_or_default()) else {
            return Err(format!("Failed to open file: {}. {}", String::from_utf8_lossy(&param), lookup.looked_at));
        };
        let mut content = Vec::new();
        // A read error ends the stream, like a failing std::getline.
        let _ = f.read_to_end(&mut content);

        let mut lines: Vec<&[u8]> = content.split(|&c| c == b'\n').collect();
        if content.is_empty() || content.ends_with(b"\n") {
            lines.pop();
        }
        for line in lines {
            // strdup(line.c_str()): up to the first NUL byte.
            let end = line.iter().position(|&c| c == 0).unwrap_or(line.len());
            self.chunks.push(std::ffi::CString::new(&line[..end]).unwrap_or_default());
        }

        Ok(())
    }

    #[cfg(not(feature = "ssdeep"))]
    fn init(&mut self, _param2: &str) -> Result<(), String> {
        Err("@fuzzyHash: SSDEEP support was not enabled during the compilation.".to_string())
    }

    #[cfg(feature = "ssdeep")]
    fn evaluate(&self, cx: &mut MatchContext<'_, '_, '_>, input: &[u8]) -> bool {
        let Some(result) = modsecurity_native::ssdeep::hash(input) else {
            crate::op_dbg!(cx, 4, "Problems generating fuzzy hash");
            return false;
        };

        for chunk in &self.chunks {
            let i = modsecurity_native::ssdeep::compare(chunk, &result);
            if i >= self.threshold {
                crate::op_dbg!(cx, 4, "Fuzzy hash: matched with score: {}.", i);
                return true;
            }
        }

        // No match.
        false
    }

    #[cfg(not(feature = "ssdeep"))]
    fn evaluate(&self, _cx: &mut MatchContext<'_, '_, '_>, _input: &[u8]) -> bool {
        // No match.
        false
    }
}

#[cfg(all(test, feature = "ssdeep"))]
mod tests {
    use super::*;
    use crate::operators::operator::test_support::eval;

    #[test]
    fn param_errors() {
        let mut op = FuzzyHash::new(RunTimeString::from_text("nospace"));
        assert_eq!(op.init("").unwrap_err(), "Please use @fuzzyHash with filename and value");
        let mut op = FuzzyHash::new(RunTimeString::from_text("file x"));
        assert_eq!(op.init("").unwrap_err(), "Expecting a digit, got: x");
    }

    #[test]
    fn matches_similar_data() {
        let root = env!("CARGO_MANIFEST_DIR");
        let body = std::fs::read(format!("{}/modsecurity.conf-recommended", root)).unwrap();
        let mut op = FuzzyHash::new(RunTimeString::from_text(&format!("{}/test/test-cases/data/ssdeep.txt 1", root)));
        op.init("").unwrap();
        assert!(eval(&op, &body));
        let mut op = FuzzyHash::new(RunTimeString::from_text(&format!("{}/test/test-cases/data/ssdeep.txt 100", root)));
        op.init("").unwrap();
        assert!(!eval(&op, &body));
    }
}
