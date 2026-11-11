//! Port of `src/variables/server_addr.h`.
//!
//! `DEFINE_VARIABLE(ServerAddr, SERVER_ADDR, m_variableServerAddr)`

crate::define_variable!(ServerAddr, "SERVER_ADDR", server_addr);
