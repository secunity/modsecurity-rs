//! The inspection of one HTTP exchange, stage by stage.
//!
//! A [`Transaction`] can be driven in any order, and nothing makes its
//! caller look at the outcome of a phase. This module puts types on the
//! order: each stage is a value with the one step that comes next, the
//! step consumes it, and it answers with the next stage or with
//! [`Blocked`], the decision of the rules to interrupt the exchange.
//!
//! ```
//! use modsecurity::inspection::{Blocked, Inspection};
//! use modsecurity::{ModSecurity, RulesSet};
//!
//! let engine = ModSecurity::new();
//! let mut rules = RulesSet::new();
//! rules
//!     .load("SecRuleEngine On\nSecRule ARGS \"@contains evil\" \"id:1,phase:2,deny,status:403\"")
//!     .unwrap();
//!
//! // The status to answer with.
//! let status = (|| {
//!     let client = "192.0.2.7:4711".parse().unwrap();
//!     let server = "192.0.2.1:80".parse().unwrap();
//!     let head = Inspection::new(&engine, &rules).connection(client, server)?;
//!     let body = head.request_head(b"POST", b"/search?q=evil", b"1.1", [("Host", "example.com")])?;
//!     let response = body.write(b"a=1")?.finish()?;
//!     // ... the application answers ...
//!     let response_body = response.response_head(200, "HTTP 1.1", [("Content-Type", "text/plain")])?;
//!     response_body.write(b"hello")?.finish()?;
//!     Ok::<_, Blocked<'_>>(200)
//! })()
//! .unwrap_or_else(|blocked| blocked.intervention().status);
//! assert_eq!(status, 403);
//! ```
//!
//! The logging phase (the audit log) runs when the last value of the
//! exchange is dropped, whichever stage that is: after
//! [`ResponseBody::finish`], when a [`Blocked`] goes away, or when a stage
//! is abandoned because the connection was lost.
//!
//! [`Transaction`] remains for callers that hold the state themselves (the
//! C API is one).

use std::net::SocketAddr;

use crate::instance::ModSecurity;
use crate::intervention::Intervention;
use crate::rules_set::RulesSet;
use crate::transaction::Transaction;

/// The transaction of an exchange; its logging phase runs when it is
/// dropped. (Behind a pointer: a transaction is large, and a stage is
/// moved at every step.)
struct Exchange<'a>(Box<Transaction<'a>>);

impl Drop for Exchange<'_> {
    fn drop(&mut self) {
        self.0.process_logging();
    }
}

impl<'a> Exchange<'a> {
    /// `next` with this exchange, unless the rules interrupted it.
    fn proceed<Next>(mut self, next: impl FnOnce(Exchange<'a>) -> Next) -> Result<Next, Blocked<'a>> {
        match self.0.intervention() {
            None => Ok(next(self)),
            // Nothing to answer with (status 200 and no redirect): the
            // exchange goes on, as with the nginx connector.
            Some(intervention) if intervention.url.is_none() && intervention.status == 200 => Ok(next(self)),
            Some(intervention) => {
                // The status that will be answered, unless the answer is
                // a redirect.
                if intervention.url.is_none() {
                    self.0.update_status_code(intervention.status);
                }
                Err(Blocked { exchange: self, intervention })
            }
        }
    }
}

/// What every stage offers besides its step.
macro_rules! stage {
    ($name:ident) => {
        impl std::fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name)).field("transaction", &self.0.0.id).finish_non_exhaustive()
            }
        }

        impl<'a> $name<'a> {
            /// The transaction, to read what the rules found so far
            /// ([`Transaction::rule_messages`]).
            pub fn transaction(&self) -> &Transaction<'a> {
                &self.0.0
            }

            /// Ends the exchange because the server answers with `status`
            /// for a reason of its own (a body that cannot be read, a
            /// backend that fails): records the status and runs the
            /// logging phase.
            pub fn abort(mut self, status: u16) {
                self.0.0.update_status_code(status.into());
            }
        }
    };
}

/// The start of an inspection: a new exchange, before anything is known
/// about it.
pub struct Inspection<'a>(Exchange<'a>);
stage!(Inspection);

impl<'a> Inspection<'a> {
    /// A new exchange inspected with `rules`, on behalf of `engine`.
    pub fn new(engine: &'a ModSecurity, rules: &'a RulesSet) -> Self {
        Inspection(Exchange(Box::new(Transaction::new(engine, rules, None))))
    }

    /// The same for a transaction made by the caller (with an id of its
    /// own, or data for the log callback).
    pub fn of(transaction: Transaction<'a>) -> Self {
        Inspection(Exchange(Box::new(transaction)))
    }

    /// The connection the request arrived on (phase 0).
    pub fn connection(mut self, client: SocketAddr, server: SocketAddr) -> Result<RequestHead<'a>, Blocked<'a>> {
        self.0.0.process_connection_addrs(client, server);
        self.0.proceed(RequestHead)
    }
}

/// The request line and headers are next.
pub struct RequestHead<'a>(Exchange<'a>);
stage!(RequestHead);

impl<'a> RequestHead<'a> {
    /// The request line and the headers (phase 1). `http_version` is the
    /// number alone (`1.1`).
    pub fn request_head<N: AsRef<[u8]>, V: AsRef<[u8]>>(
        mut self,
        method: &[u8],
        uri: &[u8],
        http_version: &[u8],
        headers: impl IntoIterator<Item = (N, V)>,
    ) -> Result<RequestBody<'a>, Blocked<'a>> {
        let t = &mut self.0.0;
        t.process_uri(uri, method, http_version);
        for (name, value) in headers {
            t.add_request_header(name.as_ref(), value.as_ref());
        }
        t.process_request_headers();
        self.0.proceed(RequestBody)
    }

    /// The head of an `http` request (see
    /// [`Transaction::process_request_head`]).
    #[cfg(feature = "http")]
    pub fn request<B>(mut self, request: &http::Request<B>) -> Result<RequestBody<'a>, Blocked<'a>> {
        self.0.0.process_request_head(request);
        self.0.proceed(RequestBody)
    }
}

/// The request body is next (none is fine).
pub struct RequestBody<'a>(Exchange<'a>);
stage!(RequestBody);

impl<'a> RequestBody<'a> {
    /// A piece of the request body. The rules can interrupt here when the
    /// body exceeds `SecRequestBodyLimit` and the limit rejects.
    pub fn write(mut self, piece: &[u8]) -> Result<Self, Blocked<'a>> {
        self.0.0.append_request_body(piece);
        self.0.proceed(RequestBody)
    }

    /// The end of the request body (phase 2). The request can go to the
    /// application.
    pub fn finish(mut self) -> Result<ResponseHead<'a>, Blocked<'a>> {
        self.0.0.process_request_body();
        self.0.proceed(ResponseHead)
    }
}

/// The request was let through; the status line and headers of the
/// response are next.
pub struct ResponseHead<'a>(Exchange<'a>);
stage!(ResponseHead);

impl<'a> ResponseHead<'a> {
    /// The status and the headers of the response (phase 3). `protocol`
    /// is written as the nginx connector does (`HTTP 1.1`).
    pub fn response_head<N: AsRef<[u8]>, V: AsRef<[u8]>>(
        mut self,
        status: u16,
        protocol: &str,
        headers: impl IntoIterator<Item = (N, V)>,
    ) -> Result<ResponseBody<'a>, Blocked<'a>> {
        let t = &mut self.0.0;
        for (name, value) in headers {
            t.add_response_header(name.as_ref(), value.as_ref());
        }
        t.process_response_headers(status.into(), protocol);
        self.0.proceed(ResponseBody)
    }

    /// The head of an `http` response (see
    /// [`Transaction::process_response_head`]).
    #[cfg(feature = "http")]
    pub fn response<B>(mut self, response: &http::Response<B>) -> Result<ResponseBody<'a>, Blocked<'a>> {
        self.0.0.process_response_head(response);
        self.0.proceed(ResponseBody)
    }
}

/// The response body is next (none is fine).
pub struct ResponseBody<'a>(Exchange<'a>);
stage!(ResponseBody);

impl<'a> ResponseBody<'a> {
    /// Whether the rules look at the response body
    /// (`SecResponseBodyAccess On`, and a rule engine that is not off):
    /// when they do not, the body need not be given to [`Self::write`]
    /// and can be sent as it comes.
    pub fn is_inspected(&self) -> bool {
        use crate::rules_set::properties::RuleEngine;
        let t = self.transaction();
        t.rules.properties.settings.sec_response_body_access == Some(true)
            && t.rule_engine_state() != Some(RuleEngine::Disabled)
    }

    /// A piece of the response body.
    pub fn write(mut self, piece: &[u8]) -> Result<Self, Blocked<'a>> {
        self.0.0.append_response_body(piece);
        self.0.proceed(ResponseBody)
    }

    /// The end of the response body (phase 4). The response can be sent;
    /// the exchange is over (the logging phase runs).
    pub fn finish(mut self) -> Result<(), Blocked<'a>> {
        self.0.0.process_response_body();
        self.0.proceed(drop)
    }
}

/// The rules interrupted the exchange: answer with the
/// [intervention](Self::intervention) instead of going on. The logging
/// phase runs when this is dropped.
pub struct Blocked<'a> {
    exchange: Exchange<'a>,
    intervention: Intervention,
}

impl<'a> Blocked<'a> {
    /// What to answer: a status, or a redirect.
    pub fn intervention(&self) -> &Intervention {
        &self.intervention
    }

    /// The transaction, to read what the rules found
    /// ([`Transaction::rule_messages`]).
    pub fn transaction(&self) -> &Transaction<'a> {
        &self.exchange.0
    }
}

impl std::fmt::Debug for Blocked<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blocked").field("intervention", &self.intervention).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::{AuditLog, AuditLogStatus, AuditLogType};

    const ADDRESS: &str = "192.0.2.7:4711";

    fn rules(conf: &str) -> RulesSet {
        let mut rules = RulesSet::new();
        rules.load(&format!("SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n{conf}")).unwrap();
        rules
    }

    /// Runs a whole exchange; the stage at which the rules interrupted
    /// it, with the status.
    fn run(rules: &RulesSet) -> Result<(), (&'static str, i32)> {
        let engine = ModSecurity::new();
        let at = |stage: &'static str| move |b: Blocked<'_>| (stage, b.intervention().status);
        let address = ADDRESS.parse().unwrap();
        let head = Inspection::new(&engine, rules).connection(address, address).map_err(at("connection"))?;
        let body = head
            .request_head(b"POST", b"/path?q=1", b"1.1", [("Host", "example.com"), ("Content-Type", "text/plain")])
            .map_err(at("request head"))?;
        let body = body.write(b"request ").map_err(at("request body"))?;
        let response = body.write(b"body").and_then(RequestBody::finish).map_err(at("request body"))?;
        let response_body =
            response.response_head(200, "HTTP 1.1", [("Content-Type", "text/plain")]).map_err(at("response head"))?;
        assert!(response_body.is_inspected());
        response_body.write(b"response body").and_then(ResponseBody::finish).map_err(at("response body"))
    }

    #[test]
    fn each_stage_can_block() {
        assert_eq!(run(&rules("")), Ok(()));
        for (rule, stage) in [
            ("SecRule REMOTE_ADDR \"@ipMatch 192.0.2.0/24\" \"id:1,phase:1,deny,status:401\"", "request head"),
            ("SecRule REQUEST_HEADERS:Host \"@streq example.com\" \"id:1,phase:1,deny,status:401\"", "request head"),
            ("SecRule REQUEST_BODY \"@contains body\" \"id:1,phase:2,deny,status:401\"", "request body"),
            ("SecRule RESPONSE_STATUS \"@eq 200\" \"id:1,phase:3,deny,status:401\"", "response head"),
            ("SecRule RESPONSE_BODY \"@contains response\" \"id:1,phase:4,deny,status:401\"", "response body"),
        ] {
            assert_eq!(run(&rules(rule)), Err((stage, 401)), "{rule}");
        }
        // A body over a limit that rejects is refused as it is written.
        assert_eq!(run(&rules("SecRequestBodyLimit 10\nSecRequestBodyLimitAction Reject")), Err(("request body", 403)));
    }

    /// The logging phase runs once, wherever the exchange ends: the audit
    /// log has one entry with the status that was answered.
    #[test]
    fn the_exchange_is_logged_where_it_ends() {
        let dir = std::env::temp_dir().join(format!("msrs-inspection-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let logged = |name: &str, conf: &str, end: &dyn Fn(&ModSecurity, &RulesSet)| {
            let file = dir.join(name);
            let mut rules = rules(conf);
            let mut audit = AuditLog::new();
            audit.set_status(AuditLogStatus::On);
            audit.set_type(AuditLogType::Serial);
            audit.set_parts("ABFHZ");
            audit.set_file_path1(file.to_str().unwrap());
            rules.properties.audit_log.merge(&audit).unwrap();
            end(&ModSecurity::new(), &rules);
            let log = std::fs::read_to_string(&file).unwrap();
            (log.matches("-A--").count(), log)
        };
        fn head<'a>(engine: &'a ModSecurity, rules: &'a RulesSet) -> Result<RequestBody<'a>, Blocked<'a>> {
            let address: SocketAddr = ADDRESS.parse().unwrap();
            let head = Inspection::new(engine, rules).connection(address, address).unwrap();
            head.request_head(b"GET", b"/", b"1.1", [("Host", "example.com")])
        }

        // Blocked: the status of the intervention.
        let deny = "SecRule REQUEST_URI \"@streq /\" \"id:1,phase:1,deny,status:418\"";
        let (entries, log) = logged("blocked", deny, &|engine, rules| {
            let blocked = head(engine, rules).unwrap_err();
            assert_eq!(blocked.transaction().rule_messages().len(), 1);
        });
        assert_eq!(entries, 1);
        assert!(log.contains("HTTP/1.1 418"), "{log}");

        // Aborted by the server.
        let (entries, log) = logged("aborted", "", &|engine, rules| head(engine, rules).unwrap().abort(502));
        assert_eq!(entries, 1);
        assert!(log.contains("HTTP/1.1 502"), "{log}");

        // Abandoned (the client went away), and completed.
        assert_eq!(logged("abandoned", "", &|engine, rules| drop(head(engine, rules))).0, 1);
        let (entries, _) = logged("completed", "", &|engine, rules| {
            let response = head(engine, rules).unwrap().finish().unwrap();
            response.response_head(204, "HTTP 1.1", [("Server", "x")]).unwrap().finish().unwrap();
        });
        assert_eq!(entries, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
