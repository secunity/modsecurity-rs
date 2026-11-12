//! Port of `headers/modsecurity/variable_origin.h`.

/// Where (offset/length) a value was found in the original request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VariableOrigin {
    pub length: usize,
    pub offset: usize,
}

impl VariableOrigin {
    pub fn new(length: usize, offset: usize) -> Self {
        VariableOrigin { length, offset }
    }

    /// `toText`: `v<offset>,<length>`.
    pub fn to_text(self) -> String {
        format!("v{},{}", self.offset, self.length)
    }
}
