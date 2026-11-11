//! Port of `src/variables/request_cookies.h`.
//!
//! `DEFINE_VARIABLE_DICT(RequestCookies, REQUEST_COOKIES, m_variableRequestCookies)`

crate::define_variable_dict!(RequestCookies, "REQUEST_COOKIES", request_cookies);
