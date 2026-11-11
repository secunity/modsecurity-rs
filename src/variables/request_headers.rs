//! Port of `src/variables/request_headers.h`.
//!
//! `DEFINE_VARIABLE_DICT(RequestHeaders, REQUEST_HEADERS, m_variableRequestHeaders)`

crate::define_variable_dict!(RequestHeaders, "REQUEST_HEADERS", request_headers);
