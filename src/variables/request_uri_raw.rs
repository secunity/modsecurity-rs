//! Port of `src/variables/request_uri_raw.h`.
//!
//! `DEFINE_VARIABLE(RequestURIRaw, REQUEST_URI_RAW, m_variableRequestURIRaw)`

crate::define_variable!(RequestURIRaw, "REQUEST_URI_RAW", request_uri_raw);
