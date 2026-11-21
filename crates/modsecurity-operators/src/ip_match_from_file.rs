//! The `@ipMatchFromFile` (`@ipMatchF`) operator.

use crate::ip_match::IpMatch;
use crate::ip_set::IpSet;
use crate::{Context, Operator, Param, Resources};

/// `@ipMatchFromFile`: like `@ipMatch`, with the entries read from a local
/// file or an `https://` resource.
#[derive(Debug)]
pub struct IpMatchFromFile {
    pub ip_match: IpMatch,
}

impl IpMatchFromFile {
    /// Reads the entries of the file or URL `param` names; `file` is the
    /// configuration file of the rule.
    pub fn new(param: Param, file: &str, resources: &dyn Resources) -> Result<Self, String> {
        let name = param.literal_lossy();
        let mut tree = IpSet::new();

        if name.starts_with("https://") {
            let content = resources.download(&name)?;
            tree.add_from_content(&content)?;
        } else {
            let lookup = resources.find(&name, file);
            let Some(resf) = lookup.path else {
                return Err(lookup.looked_at);
            };
            tree.add_from_file(&resf)?;
        }

        Ok(IpMatchFromFile { ip_match: IpMatch::with_set("IpMatchFromFile", param, tree) })
    }
}

impl Operator for IpMatchFromFile {
    fn name(&self) -> &'static str {
        self.ip_match.name()
    }

    fn param(&self) -> Option<&Param> {
        self.ip_match.param()
    }

    fn evaluate(&self, cx: &mut dyn Context, input: &[u8]) -> bool {
        self.ip_match.evaluate(cx, input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{LocalFiles, eval};

    #[test]
    fn from_file() {
        let config = format!("{}/test/test-cases/regression/x.json", concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
        let op = IpMatchFromFile::new(Param::from_text("../data/ipMatchFromFile.txt"), &config, &LocalFiles).unwrap();
        assert!(eval(&op, b"200.249.12.31"));
        assert!(eval(&op, b"::1"));
        assert!(!eval(&op, b"200.249.12.32"));

        // A missing file fails with the places the resources looked at.
        let param = Param::from_text("file-not-found.txt");
        let error = IpMatchFromFile::new(param, "operator-ipMatchFromFile.json", &LocalFiles).unwrap_err();
        assert!(error.starts_with("Looking at: 'file-not-found.txt'"), "{error}");
    }
}
