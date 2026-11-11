//! Port of `src/variables/session_id.h`.
//!
//! `DEFINE_VARIABLE(SessionID, SESSIONID, m_variableSessionID)`

crate::define_variable!(SessionID, "SESSIONID", session_id);
