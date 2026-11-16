//! The values ModSecurity resolves variables to, shared by the engine and
//! the collection backends: [`VariableValue`] (collection, key, value and
//! where in the request it was found, [`VariableOrigin`]) and the
//! [`KeyExclusions`] of a variable (`!ARGS:foo`, `!ARGS:/regex/`).

#![forbid(unsafe_code)]

pub mod key_exclusions;
pub mod variable_origin;
pub mod variable_value;

pub use key_exclusions::{KeyExclusion, KeyExclusions};
pub use variable_origin::VariableOrigin;
pub use variable_value::VariableValue;
