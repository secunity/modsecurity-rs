//! Port of `src/variables/query_string.h`.
//!
//! `DEFINE_VARIABLE(QueryString, QUERY_STRING, m_variableQueryString)`

crate::define_variable!(QueryString, "QUERY_STRING", query_string);
