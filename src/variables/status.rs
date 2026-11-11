//! Port of `src/variables/status.h`.
//!
//! `DEFINE_VARIABLE(Status, STATUS, m_variableResponseStatus)`

crate::define_variable!(Status, "STATUS", response_status);
