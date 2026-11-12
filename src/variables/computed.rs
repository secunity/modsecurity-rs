//! The variables whose value is computed when they are evaluated: `TIME*`,
//! `DURATION`, `MODSEC_BUILD`, `HIGHEST_SEVERITY`, `REMOTE_USER` and
//! `WEBAPPID` (C++ `src/variables/time*.cc`, `duration.cc`,
//! `modsec_build.cc`, `highest_severity.cc`, `remote_user.cc`,
//! `web_app_id.h`).

use crate::modsecurity::{MODSECURITY_MAJOR, MODSECURITY_MINOR, MODSECURITY_PATCHLEVEL, MODSECURITY_TAG_NUM};
use crate::transaction::Transaction;
use crate::utils::system::{cpu_seconds, localtime, now, strftime_local};
use crate::variable_value::VariableValue;
use crate::variables::variable::Variable;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Computed {
    /// CPU seconds since the transaction was created.
    Duration,
    ModsecBuild,
    HighestSeverity,
    RemoteUser,
    WebAppId,
    /// `TIME`: `HH:MM:SS`.
    Time,
    TimeDay,
    TimeEpoch,
    TimeHour,
    TimeMin,
    /// The month, 1 to 12, not zero padded.
    TimeMon,
    TimeSec,
    TimeWDay,
    TimeYear,
}

impl Computed {
    pub(crate) fn evaluate(self, var: &Variable, t: &Transaction<'_>, l: &mut Vec<VariableValue>) {
        let local = |fmt: &str| strftime_local(now(), fmt);
        // The C++ classes name their value with a constant, whatever the
        // spelling of the variable in the rule.
        let (key, value): (&str, String) = match self {
            // `std::to_string(double)` formats with "%f".
            Computed::Duration => ("DURATION", format!("{:.6}", cpu_seconds() - t.creation_time_stamp)),
            // `std::setw(2) << std::setfill('0')` for each part.
            Computed::ModsecBuild => (
                "MODSEC_BUILD",
                format!(
                    "{:0>2}{:0>2}{:0>2}{:0>2}",
                    MODSECURITY_MAJOR, MODSECURITY_MINOR, MODSECURITY_PATCHLEVEL, MODSECURITY_TAG_NUM
                ),
            ),
            // This one is named as written in the rule.
            Computed::HighestSeverity => (var.full_name(), t.highest_severity_action.to_string()),
            Computed::RemoteUser => {
                if let Some((header, user)) = remote_user(t) {
                    let mut value = VariableValue::new(header.key_with_collection(), &user);
                    value.reserve_origin(header.origin().len());
                    for origin in header.origin() {
                        value.add_origin(*origin);
                    }
                    l.push(value);
                }
                return;
            }
            Computed::WebAppId => {
                // Sic: the C++ code names the value with `m_name`, which is
                // empty for `WEBAPPID` (there is no `:` in the name).
                l.push(VariableValue::new(var.name().as_bytes(), t.rules.properties.web_app_id()));
                return;
            }
            Computed::Time => ("TIME", local("%H:%M:%S")),
            Computed::TimeDay => ("TIME_DAY", local("%d")),
            Computed::TimeEpoch => ("TIME_EPOCH", now().to_string()),
            Computed::TimeHour => ("TIME_HOUR", local("%H")),
            Computed::TimeMin => ("TIME_MIN", local("%M")),
            // `tm_mon + 1` in C++: jiff months are already 1 to 12.
            Computed::TimeMon => ("TIME_MON", localtime(now()).month().to_string()),
            Computed::TimeSec => ("TIME_SEC", local("%S")),
            Computed::TimeWDay => ("TIME_WDAY", local("%u")),
            Computed::TimeYear => ("TIME_YEAR", local("%Y")),
        };
        l.push(VariableValue::new(key.as_bytes(), value.as_bytes()));
    }
}

/// The first `Authorization` header and the user name decoded from it
/// (HTTP Basic authentication).
fn remote_user(t: &Transaction<'_>) -> Option<(VariableValue, Vec<u8>)> {
    let mut headers = Vec::new();
    t.vars.request_headers.resolve_key(b"authorization", &mut headers);
    let header = headers.into_iter().next()?;
    let value = header.value();
    let base64: &[u8] = if value.starts_with(b"Basic ") { &value[6..] } else { b"" };
    let decoded = crate::utils::base64::Base64::decode(base64)?;
    let pos = decoded.iter().position(|&c| c == b':')?;
    let user = decoded[..pos].to_vec();
    Some((header, user))
}

/// The `REMOTE_USER` value of `t` (empty when there is none), for the
/// audit log.
pub(crate) fn remote_user_name(t: &Transaction<'_>) -> Vec<u8> {
    remote_user(t).map(|(_, user)| user).unwrap_or_default()
}
