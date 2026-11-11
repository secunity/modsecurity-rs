//! Port of `src/variables/user_id.h`.
//!
//! `DEFINE_VARIABLE(UserID, USERID, m_variableUserID)`

crate::define_variable!(UserID, "USERID", user_id);
