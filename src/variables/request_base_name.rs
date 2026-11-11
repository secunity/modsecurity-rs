//! Port of `src/variables/request_base_name.h`.
//!
//! `DEFINE_VARIABLE(RequestBasename, REQUEST_BASENAME, m_variableRequestBasename)`

crate::define_variable!(RequestBasename, "REQUEST_BASENAME", request_basename);
