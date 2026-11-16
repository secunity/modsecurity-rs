//! Where a variable value was found in the request.

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

    /// The origin as the logs write it: `v<offset>,<length>`.
    pub fn to_text(self) -> String {
        format!("v{},{}", self.offset, self.length)
    }
}
