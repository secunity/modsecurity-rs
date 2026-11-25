//! A minimal HTTP(S) client used by `SecRemoteRules`, the remote
//! `@pmFromFile`/`@ipMatchFromFile` resources and the HTTPS audit log
//! writer. Built on `ureq` with rustls (the `https-client` feature), which
//! trusts the certificates the platform trusts, as libcurl does.

#[derive(Debug, Default)]
pub struct HttpsClient {
    /// The downloaded body.
    pub content: Vec<u8>,
    /// Why the last `download` failed.
    pub error: String,
    /// The value of the `ModSec-key` header (none when empty).
    key: String,
    request_body: Vec<u8>,
    request_type: String,
}

impl HttpsClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_key(&mut self, key: &str) {
        self.key = key.to_string();
    }

    pub fn set_request_body(&mut self, request_body: &[u8]) {
        self.request_body = request_body.to_vec();
    }

    pub fn set_request_type(&mut self, request_type: &str) {
        self.request_type = request_type.to_string();
    }

    /// Fetches `uri` (POSTing the request body, if any) into `content`.
    /// An HTTP error status fails it too. On failure `error` says why.
    #[cfg(feature = "https-client")]
    pub fn download(&mut self, uri: &str) -> bool {
        match self.perform(uri) {
            Ok(content) => {
                self.content = content;
                true
            }
            Err(e) => {
                self.error = e.to_string();
                false
            }
        }
    }

    #[cfg(feature = "https-client")]
    fn perform(&self, uri: &str) -> Result<Vec<u8>, ureq::Error> {
        use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

        // rustls speaks TLS 1.2 and 1.3 only; certificates are checked
        // against the platform's trust store. A proxy is taken from the
        // environment (`https_proxy`, ...), as libcurl takes it.
        let tls = TlsConfig::builder().provider(TlsProvider::Rustls).root_certs(RootCerts::PlatformVerifier).build();
        let agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .user_agent("ModSecurity3")
            .http_status_as_error(true)
            .build()
            .new_agent();

        let server_id = crate::server_id::server_id();
        let status = crate::instance::MODSECURITY_VERSION_NUM.to_string();
        let mut response = if self.request_body.is_empty() {
            let mut request = agent.get(uri).header("ModSec-unique-id", server_id).header("ModSec-status", &status);
            if !self.request_type.is_empty() {
                request = request.header("Content-Type", &self.request_type);
            }
            if !self.key.is_empty() {
                request = request.header("ModSec-key", &self.key);
            }
            request.call()?
        } else {
            // The type of a form when none is given, as libcurl sends it.
            let content_type =
                if self.request_type.is_empty() { "application/x-www-form-urlencoded" } else { &self.request_type };
            let mut request = agent
                .post(uri)
                .header("ModSec-unique-id", server_id)
                .header("ModSec-status", &status)
                .header("Content-Type", content_type);
            if !self.key.is_empty() {
                request = request.header("ModSec-key", &self.key);
            }
            request.send(&self.request_body[..])?
        };
        // The whole body, whatever its size (ureq limits it to 10 MB by
        // default; a rule set or a list can be larger).
        response.body_mut().with_config().limit(u64::MAX).read_to_vec()
    }

    /// Without the HTTPS client nothing can be downloaded.
    #[cfg(not(feature = "https-client"))]
    pub fn download(&mut self, _uri: &str) -> bool {
        self.error = "Not compiled with HTTPS client support".to_string();
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setters() {
        let mut c = HttpsClient::new();
        c.set_key("abc");
        assert_eq!(c.key, "abc");
        c.set_request_type("application/json");
        c.set_request_body(b"{}");
        assert_eq!(c.request_body, b"{}");
    }

    #[cfg(not(feature = "https-client"))]
    #[test]
    fn nothing_is_downloaded_without_the_client() {
        let mut c = HttpsClient::new();
        assert!(!c.download("https://localhost/"));
        assert_eq!(c.error, "Not compiled with HTTPS client support");
    }

    /// A server for one request: answers `status` with `body`, and gives
    /// back the request it read (head and body).
    #[cfg(feature = "https-client")]
    fn serve_once(status: &str, body: Vec<u8>) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/rules.conf", listener.local_addr().unwrap());
        let status = status.to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 4096];
            // The head, then as much body as its Content-Length says.
            loop {
                let n = stream.read(&mut buf).unwrap();
                request.extend_from_slice(&buf[..n]);
                let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map_or(0, |v| v.trim().parse::<usize>().unwrap());
                if request.len() >= end + 4 + length || n == 0 {
                    break;
                }
            }
            let head = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
            request
        });
        (url, server)
    }

    /// A GET sends the `ModSec-*` headers and the user agent, and the
    /// whole body is kept, beyond `ureq`'s default limit of 10 MB.
    #[cfg(feature = "https-client")]
    #[test]
    fn download() {
        let body = vec![b'x'; 11 << 20];
        let (url, server) = serve_once("200 OK", body.clone());
        let mut c = HttpsClient::new();
        c.set_key("secret");
        assert!(c.download(&url), "{}", c.error);
        assert!(c.content == body);
        let request = String::from_utf8(server.join().unwrap()).unwrap().to_ascii_lowercase();
        assert!(request.starts_with("get /rules.conf http/1.1\r\n"), "{request}");
        for header in
            ["modsec-key: secret", "modsec-status: 30170100", "user-agent: modsecurity3", "modsec-unique-id: "]
        {
            assert!(request.contains(header), "{header} in {request}");
        }
    }

    /// A request body is POSTed with its type, without `Expect:
    /// 100-continue`.
    #[cfg(feature = "https-client")]
    #[test]
    fn post() {
        let (url, server) = serve_once("200 OK", b"ok".to_vec());
        let mut c = HttpsClient::new();
        c.set_request_type("application/json");
        c.set_request_body(b"{\"a\":1}");
        assert!(c.download(&url), "{}", c.error);
        let request = String::from_utf8(server.join().unwrap()).unwrap();
        let lower = request.to_ascii_lowercase();
        assert!(lower.starts_with("post /rules.conf http/1.1\r\n"), "{request}");
        assert!(lower.contains("content-type: application/json\r\n"), "{request}");
        assert!(!lower.contains("expect:"), "{request}");
        assert!(request.ends_with("\r\n\r\n{\"a\":1}"), "{request}");
    }

    /// An HTTP error status fails the download, as a scheme the client
    /// does not know does.
    #[cfg(feature = "https-client")]
    #[test]
    fn failures() {
        let (url, server) = serve_once("404 Not Found", b"missing".to_vec());
        let mut c = HttpsClient::new();
        assert!(!c.download(&url));
        assert!(c.error.contains("404"), "{}", c.error);
        server.join().unwrap();

        let mut c = HttpsClient::new();
        assert!(!c.download("nosuchscheme://localhost/"));
        assert!(!c.error.is_empty());
    }
}
