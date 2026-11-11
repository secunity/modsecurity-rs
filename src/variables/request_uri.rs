//! Port of `src/variables/request_uri.h`.
//!
//! `DEFINE_VARIABLE(RequestURI, REQUEST_URI, m_variableRequestURI)`

crate::define_variable!(RequestURI, "REQUEST_URI", request_uri);
