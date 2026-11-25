//! The request as the connector reports it: the connection, the URI, the
//! headers and the body, each step followed by the rules of its phase.

use super::arguments::ArgumentOrigin;
use super::{BodyDirection, RequestBodyType, Transaction};
use crate::phases::Phases;
use crate::rules_set::properties::RuleEngine;
use crate::utils::string::{is_space, split, ssplit};
use modsecurity_transformations::url::uri_decode;

impl Transaction<'_> {
    /// [`Self::process_connection`] with socket addresses. IPv6 addresses
    /// are written without brackets (`::1`), as servers report them.
    pub fn process_connection_addrs(&mut self, client: std::net::SocketAddr, server: std::net::SocketAddr) {
        let (c, s) = (client.ip().to_string(), server.ip().to_string());
        self.process_connection(&c, client.port(), &s, server.port());
    }

    /// Records the client and server addresses and ports and runs the
    /// rules of the connection phase.
    pub fn process_connection(&mut self, client: &str, c_port: u16, server: &str, s_port: u16) {
        self.http.client_ip_address = client.to_string();
        self.http.server_ip_address = server.to_string();
        if self.http.request_host_name.is_empty() {
            self.http.request_host_name = server.to_string();
        }
        self.http.client_port = c_port;
        self.http.server_port = s_port;
        crate::ms_dbg!(self, 4, "Transaction context created.");
        crate::ms_dbg!(self, 4, "Starting phase CONNECTION. (SecRules 0)");

        let off = self.vars.offset;
        self.vars.remote_host.set(self.http.client_ip_address.as_bytes(), off);
        self.vars.unique_id.set(self.id.as_bytes(), off);
        self.vars.remote_addr.set(self.http.client_ip_address.as_bytes(), off);
        self.vars.server_addr.set(self.http.server_ip_address.as_bytes(), off);
        self.vars.server_port.set(self.http.server_port.to_string().as_bytes(), off);
        self.vars.remote_port.set(self.http.client_port.to_string().as_bytes(), off);
        self.evaluate_phase(Phases::Connection);
    }

    /// Records the request line (URI, method, HTTP version) and fills the
    /// URI variables and the query string arguments. No rules run here.
    pub fn process_uri(&mut self, uri: &[u8], method: &[u8], http_version: &[u8]) {
        crate::ms_dbg!(self, 4, "Starting phase URI. (SecRules 0 + 1/2)");
        self.http.http_version = String::from_utf8_lossy(http_version).into_owned();
        self.http.uri = uri.to_vec();
        let mut uri_s: &[u8] = uri;

        // any uri-fragment that was received should only be retained in
        // `http.uri`, REQUEST_URI_RAW and REQUEST_LINE.
        if let Some(pos) = uri_s.iter().position(|&c| c == b'#') {
            uri_s = &uri_s[..pos];
        }

        let pos_raw_query = uri_s.iter().position(|&c| c == b'?');
        let path_info_raw = match pos_raw_query {
            None => uri_s,
            Some(p) => &uri_s[..p],
        };
        let path_info = uri_decode(path_info_raw);
        self.http.uri_decoded = uri_decode(uri_s);

        let off = self.vars.offset;
        self.vars.request_method.set(method, 0);

        // `METHOD URI HTTP/VERSION`: REQUEST_LINE, and REQUEST_PROTOCOL at
        // its end.
        let request_line_len = method.len() + 1 + uri.len();
        let mut rl = Vec::with_capacity(request_line_len + 6 + http_version.len());
        rl.extend_from_slice(method);
        rl.push(b' ');
        rl.extend_from_slice(uri);
        rl.extend_from_slice(b" HTTP/");
        rl.extend_from_slice(http_version);
        self.vars.request_line.set(&rl, off);
        self.vars.request_protocol.set(&rl[request_line_len + 1..], off + request_line_len + 1);

        let query = pos_raw_query.map(|p| (&uri_s[p + 1..], p + 1 + method.len() + 1));
        if let Some((qry, qry_offset)) = query {
            self.vars.query_string.set(qry, qry_offset);
        }

        let var_size = pos_raw_query.unwrap_or(uri_s.len());
        self.vars.path_info.set_with_len(&path_info, off + method.len() + 1, var_size);
        self.vars.request_filename.set_with_len(&path_info, off + method.len() + 1, var_size);

        if let Some(o) = path_info.iter().rposition(|&c| c == b'/' || c == b'\\')
            && path_info.len() > o + 1
        {
            self.vars.request_basename.set(&path_info[o + 1..], off + method.len() + 1 + o + 1);
        }
        self.http.uri_no_query_string_decoded = path_info;
        self.vars.offset = self.vars.request_line.value().len();

        // REQUEST_URI: the decoded URI without its scheme and host, when it
        // has them. The more popular case is without domain.
        let d = &self.http.uri_decoded;
        let mut path_start = 0;
        if !d.is_empty() && d[0] != b'/' {
            // The position after the first `:`, 0 when there is none.
            let scheme = d.iter().position(|&c| c == b':').map(|p| p + 1).unwrap_or(0);
            // The position after the next `//`, 1 when there is none.
            let netloc = crate::utils::string::find_from(d, b"//", scheme).map(|p| p + 2).unwrap_or(1);
            if netloc == scheme + 2
                && let Some(path) = d.iter().skip(netloc).position(|&c| c == b'/').map(|p| p + netloc)
            {
                path_start = path;
            }
        }
        self.vars.request_uri.set_with_len(&self.http.uri_decoded[path_start..], method.len() + 1, uri_s.len());
        self.vars.request_uri_raw.set(uri, method.len() + 1);

        match query {
            // The query string of this URI, as QUERY_STRING has it.
            Some((qry, qry_offset)) => {
                if !qry.is_empty() {
                    self.extract_arguments(ArgumentOrigin::Get, qry, qry_offset);
                }
            }
            // No query string: QUERY_STRING keeps what an earlier URI of
            // the transaction set, and its arguments are added again.
            None => {
                if !self.vars.query_string.value().is_empty() {
                    let qs = self.vars.query_string.value().to_vec();
                    let qo = self.vars.query_string.offset();
                    self.extract_arguments(ArgumentOrigin::Get, &qs, qo);
                }
            }
        }

        self.vars.offset += 1;
    }

    /// Phase 1: runs the request headers rules.
    pub fn process_request_headers(&mut self) {
        crate::ms_dbg!(self, 4, "Starting phase REQUEST_HEADERS.  (SecRules 1)");
        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg!(self, 4, "Rule engine disabled, returning...");
            return;
        }
        self.evaluate_phase(Phases::RequestHeaders);
    }

    /// Adds a request header (`REQUEST_HEADERS`, `AUTH_TYPE`).
    pub fn add_request_header(&mut self, key: &[u8], value: &[u8]) {
        let off = self.vars.offset;
        self.vars.request_headers_names.set(key, key, off);
        self.vars.offset = off + key.len() + 2;
        let off = self.vars.offset;
        self.vars.request_headers.set(key, value, off);

        let is = |name: &[u8]| key.eq_ignore_ascii_case(name);
        if is(b"authorization") {
            let ty = split(value, b' ');
            self.vars.auth_type.set(&ty[0], off);
        }

        if is(b"cookie") {
            let mut local_offset = off;
            let mut cookies = ssplit(value, b';');
            if let Some(final_cookie_pair) = cookies.last_mut() {
                // Get rid of any optional whitespace after the cookie-string
                while final_cookie_pair.last().is_some_and(|&c| is_space(c)) {
                    final_cookie_pair.pop();
                }
            }
            for c in &cookies {
                // skip empty substring, eg "Cookie: ;;foo=bar"
                if c.is_empty() {
                    local_offset += 1;
                    continue;
                }
                let (mut ckey, cval) = match c.iter().position(|&x| x == b'=') {
                    None => (c.clone(), Vec::new()),
                    Some(p) => (c[..p].to_vec(), c[p + 1..].to_vec()),
                };
                // ltrim the key - following the modsec v2 way
                while !ckey.is_empty() && is_space(ckey[0]) {
                    ckey.remove(0);
                    local_offset += 1;
                }
                if ckey.is_empty() {
                    local_offset = local_offset + c.len() + 1;
                    continue;
                }
                self.vars.request_cookies_names.set(&ckey, &ckey, local_offset);
                local_offset = local_offset + ckey.len() + 1;
                self.vars.request_cookies.set(&ckey, &cval, local_offset);
                local_offset = local_offset + cval.len() + 1;
            }
        }

        if is(b"content-type") {
            let l = value.to_ascii_lowercase();
            if l.starts_with(b"multipart/form-data") {
                self.body.request_body_type = Some(RequestBodyType::Multipart);
                self.vars.reqbody_processor.set(b"MULTIPART", off);
            }
            if l.starts_with(b"application/x-www-form-urlencoded") {
                self.body.request_body_type = Some(RequestBodyType::UrlEncoded);
                self.vars.reqbody_processor.set(b"URLENCODED", off);
            }
        }

        if is(b"host") {
            let host = split(value, b':');
            self.vars.server_name.set(&host[0], off);
        }
        self.vars.offset = off + value.len() + 1;
    }

    /// Phase 2: parses the request body with its body processor and runs
    /// the request body rules.
    pub fn process_request_body(&mut self) {
        crate::ms_dbg!(self, 4, "Starting phase REQUEST_BODY. (SecRules 2)");

        if self.rule_engine_state() == Some(RuleEngine::Disabled) {
            crate::ms_dbg!(self, 4, "Rule engine disabled, returning...");
            return;
        }

        if self.vars.inbound_data_error.value().is_empty() {
            self.vars.inbound_data_error.set(b"0", 0);
        }

        // The body is parsed even when the rules are not given it.
        self.parse_request_body();
        if !self.request_body_access() {
            return;
        }
        self.set_request_body_variables();

        self.evaluate_phase(Phases::RequestBody);
    }

    /// [`Self::append_request_body`] with the content of a file.
    ///
    /// With a `SecRequestBodyLimit`, at most one byte more than the limit is
    /// read: that byte tells [`Self::append_request_body`] that the body is
    /// over the limit, and the rest is cut off or rejected anyway.
    pub fn request_body_from_file(&mut self, path: &str) -> std::io::Result<bool> {
        use std::io::Read;
        let limit = self.rules.properties.settings.request_body_limit.unwrap_or(0);
        let read = || -> std::io::Result<(u64, Vec<u8>)> {
            let file = std::fs::File::open(path)?;
            let size = file.metadata()?.len();
            let max = if limit > 0 { limit.saturating_add(1) } else { u64::MAX };
            let mut s = Vec::with_capacity(usize::try_from(size.min(max)).unwrap_or(0));
            file.take(max).read_to_end(&mut s)?;
            Ok((size, s))
        };
        let (size, s) = read().inspect_err(|_| {
            crate::ms_dbg!(self, 3, "Failed to open request body at: {}", path);
        })?;
        crate::ms_dbg!(self, 9, "Adding request body: {} bytes. Limit set to: {}", size, limit);
        Ok(self.append_request_body(&s))
    }

    /// Adds `buf` to the request body, within `SecRequestBodyLimit`.
    /// Returns `false` when the body limit was hit and only a part was kept
    /// (`SecRequestBodyLimitAction ProcessPartial`); see
    /// `append_body` for the limit actions.
    pub fn append_request_body(&mut self, buf: &[u8]) -> bool {
        crate::ms_dbg!(
            self,
            9,
            "Appending request body: {} bytes. Limit set to: {}",
            buf.len(),
            self.rules.properties.settings.request_body_limit.unwrap_or(0)
        );
        self.append_body(BodyDirection::Request, buf)
    }

    /// Whether the request body went past `SecRequestBodyLimit`: no more
    /// of it is kept for the rules.
    pub(crate) fn request_body_limit_reached(&self) -> bool {
        self.vars.inbound_data_error.value() == b"1"
    }

    /// The length of the request body kept so far.
    pub fn request_body_length(&self) -> usize {
        self.http.request_body.len()
    }

    /// Sets the host name the logs report (ignored when empty).
    pub fn set_request_host_name(&mut self, hostname: &str) {
        if !hostname.is_empty() {
            self.http.request_host_name = hostname.to_string();
        }
    }
}
