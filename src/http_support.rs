//! Requests and responses of the `http` crate in, interventions out (the
//! `http` feature).

use http::header::{HOST, LOCATION};
use http::{HeaderValue, Request, Response, StatusCode, Version};

use crate::intervention::Intervention;
use crate::transaction::Transaction;

/// The HTTP version as connectors pass it to [`Transaction::process_uri`]
/// (`1.1`).
fn version_number(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "1.1",
    }
}

impl Transaction<'_> {
    /// Runs the head of `request`: [`Self::process_uri`] with its target,
    /// method and version, [`Self::add_request_header`] for each header,
    /// then phase 1 ([`Self::process_request_headers`]). The body is left
    /// to the caller.
    ///
    /// The `http` crate keeps header names in lower case, so that is how
    /// `REQUEST_HEADERS_NAMES` sees them (header lookups ignore case
    /// anyway). For HTTP/2 and HTTP/3, the target is the path and query
    /// (`:path`), and a `Host` header is added from the authority when
    /// there is none, as nginx does.
    pub fn process_request_head<B>(&mut self, request: &Request<B>) {
        let uri = request.uri();
        let modern = request.version() >= Version::HTTP_2;
        let target = match uri.path_and_query() {
            Some(pq) if modern => pq.as_str().to_string(),
            _ => uri.to_string(),
        };
        self.process_uri(
            target.as_bytes(),
            request.method().as_str().as_bytes(),
            version_number(request.version()).as_bytes(),
        );
        if modern
            && !request.headers().contains_key(HOST)
            && let Some(authority) = uri.authority()
        {
            self.add_request_header(b"host", authority.as_str().as_bytes());
        }
        for (name, value) in request.headers() {
            self.add_request_header(name.as_str().as_bytes(), value.as_bytes());
        }
        self.process_request_headers();
    }

    /// Runs the head of `response`: [`Self::add_response_header`] for each
    /// header, then phase 3 ([`Self::process_response_headers`]) with its
    /// status and protocol (`HTTP 1.1`, written as the nginx connector
    /// does). The body is left to the caller.
    pub fn process_response_head<B>(&mut self, response: &Response<B>) {
        for (name, value) in response.headers() {
            self.add_response_header(name.as_str().as_bytes(), value.as_bytes());
        }
        let protocol = format!("HTTP {}", version_number(response.version()));
        self.process_response_headers(response.status().as_u16().into(), &protocol);
    }
}

impl Intervention {
    /// The response to send instead of serving the request, built as the
    /// nginx connector does: a redirect to `url` (up to a NUL byte) with
    /// the intervention's status, or else an empty response with that
    /// status. `None` when there is nothing to send: status 200 and no
    /// URL. A status that is not a valid HTTP status code (or a URL that
    /// is not a valid header value) gives a 500 response.
    pub fn to_response<B: Default>(&self) -> Option<Response<B>> {
        let url = self.url.as_deref().map(modsecurity_compat::chars::c_str);
        if url.is_none() && self.status == 200 {
            return None;
        }
        let mut response = Response::new(B::default());
        let status = u16::try_from(self.status).ok().and_then(|s| StatusCode::from_u16(s).ok());
        *response.status_mut() = status.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if let Some(url) = url {
            match HeaderValue::from_bytes(url) {
                Ok(location) => {
                    response.headers_mut().insert(LOCATION, location);
                }
                Err(_) => *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR,
            }
        }
        Some(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance::ModSecurity;
    use crate::rules_set::RulesSet;

    fn rules(conf: &str) -> RulesSet {
        let mut rules = RulesSet::new();
        rules.load(&format!("SecRuleEngine On\n{conf}")).unwrap();
        rules
    }

    #[test]
    fn request_head() {
        let ms = ModSecurity::new();
        let rules = rules(
            "SecRule REQUEST_LINE \"@streq POST /a?b=c HTTP/1.0\" \"id:1,phase:1,deny,status:401\"\n\
             SecRule REQUEST_HEADERS:X-Test \"@streq yes\" \"id:2,phase:1,deny,status:402\"\n",
        );
        let request = |version, header| {
            let mut b = Request::post("/a?b=c").version(version);
            if header {
                b = b.header("X-Test", "yes");
            }
            b.body(()).unwrap()
        };

        let mut t = Transaction::new(&ms, &rules, None);
        t.process_request_head(&request(Version::HTTP_10, false));
        assert_eq!(t.intervention().map(|it| it.status), Some(401));

        let mut t = Transaction::new(&ms, &rules, None);
        t.process_request_head(&request(Version::HTTP_11, true));
        assert_eq!(t.intervention().map(|it| it.status), Some(402));

        let mut t = Transaction::new(&ms, &rules, None);
        t.process_request_head(&request(Version::HTTP_11, false));
        assert_eq!(t.intervention(), None);
    }

    #[test]
    fn http2_target_and_host() {
        let ms = ModSecurity::new();
        let rules = rules(
            "SecRule REQUEST_URI \"@streq /p?q=1\" \"id:1,phase:1,pass,setvar:tx.uri=1\"\n\
             SecRule REQUEST_HEADERS:Host \"@streq example.com\" \"id:2,phase:1,pass,setvar:tx.host=1\"\n\
             SecRule TX:URI \"@eq 1\" \"id:3,phase:1,chain,deny,status:418\"\n\
             SecRule TX:HOST \"@eq 1\" \"\"\n",
        );
        let request = Request::get("https://example.com/p?q=1").version(Version::HTTP_2).body(()).unwrap();
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_request_head(&request);
        assert_eq!(t.intervention().map(|it| it.status), Some(418));
    }

    #[test]
    fn response_head() {
        let ms = ModSecurity::new();
        let rules = rules(
            "SecRule RESPONSE_STATUS \"@streq 404\" \"id:1,phase:3,chain,deny,status:403\"\n\
             SecRule RESPONSE_PROTOCOL \"@streq HTTP 2.0\" \"chain\"\n\
             SecRule RESPONSE_HEADERS:Content-Type \"@streq text/plain\" \"\"\n",
        );
        let mut t = Transaction::new(&ms, &rules, None);
        let response = Response::builder()
            .status(404)
            .version(Version::HTTP_2)
            .header("Content-Type", "text/plain")
            .body(())
            .unwrap();
        t.process_response_head(&response);
        assert_eq!(t.intervention().map(|it| it.status), Some(403));
    }

    #[test]
    fn interventions_as_responses() {
        let it = |status, url: Option<&[u8]>| Intervention {
            status,
            url: url.map(<[u8]>::to_vec),
            log: None,
            disruptive: true,
        };
        let r: Response<()> = it(403, None).to_response().unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(r.headers().is_empty());

        assert!(it(200, None).to_response::<()>().is_none());

        let r: Response<()> = it(302, Some(b"https://example.com/\0rest")).to_response().unwrap();
        assert_eq!(r.status(), StatusCode::FOUND);
        assert_eq!(r.headers()[LOCATION], "https://example.com/");

        let r: Response<()> = it(1000, None).to_response().unwrap();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let r: Response<()> = it(302, Some(b"bad\nurl")).to_response().unwrap();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
