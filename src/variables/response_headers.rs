//! Port of `src/variables/response_headers.h`.
//!
//! `DEFINE_VARIABLE_DICT(ResponseHeaders, RESPONSE_HEADERS, m_variableResponseHeaders)`

crate::define_variable_dict!(ResponseHeaders, "RESPONSE_HEADERS", response_headers);
