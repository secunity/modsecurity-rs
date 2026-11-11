//! Port of `src/variables/response_content_length.h`.
//!
//! `DEFINE_VARIABLE(ResponseContentLength, RESPONSE_CONTENT_LENGTH, m_variableResponseContentLength)`

crate::define_variable!(ResponseContentLength, "RESPONSE_CONTENT_LENGTH", response_content_length);
