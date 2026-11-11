//! Port of `src/variables/remote_user.cc`, `src/variables/remote_user.h`.
//!
//! `REMOTE_USER`: the user name of an HTTP `Basic` `Authorization` request
//! header. The C++ code stored the name in `m_variableRemoteUser` (which the
//! audit log index also printed); here it is computed on demand, see
//! [`RemoteUser::compute`].

use crate::rule_with_actions::RuleWithActions;
use crate::transaction::Transaction;
use crate::variable_value::VariableValue;
use crate::variables::variable::{Variable, VariableBase};

/// `RemoteUser`
#[derive(Debug)]
pub struct RemoteUser {
    pub base: VariableBase,
    pub ret_name: String,
}

impl RemoteUser {
    /// `RemoteUser(name)`: `name` is the token as written in the rule.
    pub fn new(name: &str) -> Self {
        RemoteUser { base: VariableBase::new(name), ret_name: "REMOTE_USER".to_string() }
    }

    /// The `REMOTE_USER` value of `t` (empty when there is none): the value
    /// the C++ code left in `m_variableRemoteUser`.
    pub fn compute(t: &Transaction<'_>) -> Vec<u8> {
        Self::resolve(t).map(|(_, user)| user).unwrap_or_default()
    }

    /// The first `Authorization` header and the user name decoded from it.
    fn resolve(t: &Transaction<'_>) -> Option<(VariableValue, Vec<u8>)> {
        let mut l2 = Vec::new();
        t.vars.request_headers.resolve_key(b"authorization", &mut l2);
        let v = l2.into_iter().next()?;
        let header = v.value();

        let base64: &[u8] = if header.starts_with(b"Basic ") { &header[6..] } else { b"" };
        let decoded = crate::utils::base64::Base64::decode(base64)?;
        let pos = decoded.iter().position(|&c| c == b':')?;
        let user = decoded[..pos].to_vec();
        Some((v, user))
    }
}

impl Variable for RemoteUser {
    fn base(&self) -> &VariableBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut VariableBase {
        &mut self.base
    }
    fn evaluate(&self, t: &Transaction<'_>, _rule: Option<&RuleWithActions>, l: &mut Vec<VariableValue>) {
        let Some((v, user)) = Self::resolve(t) else {
            return;
        };
        let mut var = VariableValue::new(v.key_with_collection(), &user);
        var.reserve_origin(v.origin().len());
        for i in v.origin() {
            var.add_origin(*i);
        }
        l.push(var);
    }
}
