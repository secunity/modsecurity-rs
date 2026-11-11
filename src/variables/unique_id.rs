//! Port of `src/variables/unique_id.h`.
//!
//! `DEFINE_VARIABLE(UniqueID, UNIQUEID, m_variableUniqueID)`

crate::define_variable!(UniqueID, "UNIQUEID", unique_id);
