//! The phases of a transaction ([`Phases`]), in which rules run.

/// The stages of an HTTP exchange at which the rules inspect what is known
/// so far. A connector must go through every phase, even when its server
/// does not tell some of them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

    /// The number rules and logs know the phase by (`phase:2`); 0 for the
    /// two that precede the request headers.
    pub fn number(self) -> u8 {
        match self {
            Phases::Connection | Phases::Uri => 0,
            Phases::RequestHeaders => 1,
            Phases::RequestBody => 2,
            Phases::ResponseHeaders => 3,
            Phases::ResponseBody => 4,
            Phases::Logging => 5,
        }
    }
}

/// The number of [`Phases`].
pub const NUMBER_OF_PHASES: usize = 7;
