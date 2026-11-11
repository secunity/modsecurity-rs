//! Port of `src/variables/request_body_length.h`.
//!
//! `DEFINE_VARIABLE(RequestBodyLength, REQUEST_BODY_LENGTH, m_variableRequestBodyLength)`

crate::define_variable!(RequestBodyLength, "REQUEST_BODY_LENGTH", request_body_length);
