//! Port of `src/variables/server_port.h`.
//!
//! `DEFINE_VARIABLE(ServerPort, SERVER_PORT, m_variableServerPort)`

crate::define_variable!(ServerPort, "SERVER_PORT", server_port);
