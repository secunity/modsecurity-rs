//! Port of `src/variables/response_headers_names.h`.
//!
//! `DEFINE_VARIABLE_DICT(ResponseHeadersNames, RESPONSE_HEADERS_NAMES, m_variableResponseHeadersNames)`

crate::define_variable_dict!(ResponseHeadersNames, "RESPONSE_HEADERS_NAMES", response_headers_names);
