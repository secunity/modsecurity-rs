//! The phases of a transaction ([`Phases`]), in which rules run.

/// The Phases enumerator consists in mapping the different stages of a given
/// request. ModSecurity is expected to inspect data based on those "phases".
/// It is mandatory to call all the phases, even if you don't have this
/// phases segmented in your end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum Phases {
    /// The very first information that ModSecurity can inspect, right
    /// after a connection is established.
    Connection = 0,
    /// Happens just after the server has the full request URI.
    Uri = 1,
    /// The server has all the request headers (before the body).
    RequestHeaders = 2,
    /// Request body inspection.
    RequestBody = 3,
    /// Just before the response headers are delivered.
    ResponseHeaders = 4,
    /// Response body inspection.
    ResponseBody = 5,
    /// Logging; no disruptive action can happen here.
    Logging = 6,
}

impl Phases {
    /// Every phase, in order.
    pub const ALL: [Phases; NUMBER_OF_PHASES] = [
        Phases::Connection,
        Phases::Uri,
        Phases::RequestHeaders,
        Phases::RequestBody,
        Phases::ResponseHeaders,
        Phases::ResponseBody,
        Phases::Logging,
    ];

    /// The position of the phase in per-phase tables.
    pub(crate) fn index(self) -> usize {
        self as usize
    }
}

/// Just a marking for the expected number of phases.
pub const NUMBER_OF_PHASES: usize = 7;
