//! Port of `src/variables/request_headers_names.h`.
//!
//! `DEFINE_VARIABLE_DICT(RequestHeadersNames, REQUEST_HEADERS_NAMES, m_variableRequestHeadersNames)`

crate::define_variable_dict!(RequestHeadersNames, "REQUEST_HEADERS_NAMES", request_headers_names);
