//! Port of `src/variables/request_cookies_names.h`.
//!
//! `DEFINE_VARIABLE_DICT(RequestCookiesNames, REQUEST_COOKIES_NAMES, m_variableRequestCookiesNames)`

crate::define_variable_dict!(RequestCookiesNames, "REQUEST_COOKIES_NAMES", request_cookies_names);
