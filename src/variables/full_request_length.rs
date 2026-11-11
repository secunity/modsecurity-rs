//! Port of `src/variables/full_request_length.h`.
//!
//! `DEFINE_VARIABLE(FullRequestLength, FULL_REQUEST_LENGTH, m_variableFullRequestLength)`

crate::define_variable!(FullRequestLength, "FULL_REQUEST_LENGTH", full_request_length);
