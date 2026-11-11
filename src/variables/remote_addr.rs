//! Port of `src/variables/remote_addr.h`.
//!
//! `DEFINE_VARIABLE(RemoteAddr, REMOTE_ADDR, m_variableRemoteAddr)`

crate::define_variable!(RemoteAddr, "REMOTE_ADDR", remote_addr);
