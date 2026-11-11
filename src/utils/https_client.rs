//! Port of `src/utils/https_client.cc`, `src/utils/https_client.h`.
//!
//! Minimal HTTP(S) client used by `SecRemoteRules`, the remote
//! `@pmFromFile`/`@ipMatchFromFile` resources and the HTTPS audit log
//! writer. Built on libcurl (the `curl` feature, C++ `MSC_WITH_CURL`).

#[derive(Debug, Default)]
pub struct HttpsClient {
    /// The downloaded body.
    pub content: Vec<u8>,
    /// The libcurl error of the last failed `download`.
    pub error: String,
    key: String,
    request_body: Vec<u8>,
    request_type: String,
}

impl HttpsClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// `handle_impl`: the libcurl write callback, accumulates the body.
    #[cfg(any(feature = "curl", test))]
    fn handle_impl(&mut self, data: &[u8]) -> usize {
        self.content.extend_from_slice(data);
        data.len()
    }

    pub fn set_key(&mut self, key: &str) {
        self.key = format!("ModSec-key: {}", key);
    }

    pub fn set_request_body(&mut self, request_body: &[u8]) {
        self.request_body = request_body.to_vec();
    }

    pub fn set_request_type(&mut self, request_type: &str) {
        self.request_type = request_type.to_string();
    }

    /// Fetches `uri` (POSTing the request body, if any) into `content`.
    /// On failure `error` holds the libcurl error text.
    #[cfg(feature = "curl")]
    pub fn download(&mut self, uri: &str) -> bool {
        match self.perform(uri) {
            Ok(()) => true,
            Err(e) => {
                // curl_easy_strerror(res)
                self.error = e.description().to_string();
                false
            }
        }
    }

    #[cfg(feature = "curl")]
    fn perform(&mut self, uri: &str) -> Result<(), curl::Error> {
        use curl::easy::{Easy, List, SslVersion};

        let unique_id = format!("ModSec-unique-id: {}", crate::unique_id::UniqueId::unique_id());
        let status = format!("ModSec-status: {}", crate::modsecurity::MODSECURITY_VERSION_NUM);

        let mut curl = Easy::new();
        let mut headers_chunk = List::new();
        curl.url(uri)?;

        headers_chunk.append(&unique_id)?;
        headers_chunk.append(&status)?;

        if !self.request_type.is_empty() {
            headers_chunk.append(&format!("Content-Type: {}", self.request_type))?;
        }

        if !self.key.is_empty() {
            headers_chunk.append(&self.key)?;
        }

        // Make it TLS 1.2 at least.
        curl.ssl_version(SslVersion::Tlsv12)?;

        // those are the default options, but lets make sure
        curl.ssl_verify_peer(true)?;
        curl.ssl_verify_host(true)?;

        curl.useragent("ModSecurity3")?;

        // We want Curl to return error in case there is an HTTP error code
        curl.fail_on_error(true)?;

        if !self.request_body.is_empty() {
            // The C++ code hands the body to CURLOPT_POSTFIELDS as a C
            // string: it is sent up to its first NUL byte.
            let len = self.request_body.iter().position(|&c| c == 0).unwrap_or(self.request_body.len());
            curl.post_fields_copy(&self.request_body[..len])?;
            // Disable Expect: 100-continue
            headers_chunk.append("Expect:")?;
        }

        // set HTTP headers for request
        curl.http_headers(headers_chunk)?;

        let mut transfer = curl.transfer();
        // send all data to this function
        transfer.write_function(|data| Ok(self.handle_impl(data)))?;
        transfer.perform()
    }

    /// Without libcurl support nothing can be downloaded.
    #[cfg(not(feature = "curl"))]
    pub fn download(&mut self, _uri: &str) -> bool {
        self.error = "Not compiled with libcurl support".to_string();
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
        assert_eq!(c.key, "ModSec-key: abc");
        c.set_request_type("application/json");
        c.set_request_body(b"{}");
        assert_eq!(c.request_body, b"{}");
        assert_eq!(c.handle_impl(b"xy"), 2);
        assert_eq!(c.content, b"xy");
    }

    #[cfg(feature = "curl")]
    #[test]
    fn download_failure_sets_error() {
        let mut c = HttpsClient::new();
        // Unsupported scheme: fails before any network access.
        assert!(!c.download("nosuchscheme://localhost/"));
        assert!(!c.error.is_empty());
    }
}
