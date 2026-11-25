//! The SecLang actions: one module per action, the closed set of them
//! ([`rule_action::RuleAction`]), what an action may do ([`context`]) and
//! how the parser builds one by name ([`seclang`]).

pub mod action;
pub mod audit_log;
pub mod block;
pub mod capture;
pub mod context;
pub mod ctl;
pub mod data;
pub mod disruptive;
pub mod exec;
pub mod expire_var;
pub mod init_col;
pub mod log;
pub mod log_data;
pub mod msg;
pub mod multi_match;
pub mod no_audit_log;
pub mod no_log;
pub mod rule_action;
pub mod seclang;
pub mod set_env;
pub mod set_rsc;
pub mod set_sid;
pub mod set_uid;
pub mod set_var;
pub mod severity;
pub mod skip;
pub mod skip_after;
pub mod tag;
pub mod transformation;
pub mod xmlns;
