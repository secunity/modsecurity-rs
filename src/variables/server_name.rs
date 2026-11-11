//! Port of `src/variables/server_name.h`.
//!
//! `DEFINE_VARIABLE(ServerName, SERVER_NAME, m_variableServerName)`

crate::define_variable!(ServerName, "SERVER_NAME", server_name);
