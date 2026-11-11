//! Port of `src/variables/reqbody_processor_error_msg.h`.
//!
//! `DEFINE_VARIABLE(ReqbodyProcessorErrorMsg, PROCESSOR_ERROR_MSG, m_variableReqbodyProcessorErrorMsg)`
//!
//! Note: the C++ header names this variable `PROCESSOR_ERROR_MSG` (not
//! `REQBODY_PROCESSOR_ERROR_MSG`); kept as is. The values it produces are
//! named by the anchored variable (`REQBODY_PROCESSOR_ERROR_MSG`).

crate::define_variable!(ReqbodyProcessorErrorMsg, "PROCESSOR_ERROR_MSG", reqbody_processor_error_msg);
