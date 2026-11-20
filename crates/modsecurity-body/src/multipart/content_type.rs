//! The boundary, from the Content-Type header of the request.

use modsecurity_compat::chars::is_space;
use modsecurity_types::ms_dbg;

use super::{Context, Multipart, find};

/// Why a Content-Type header was refused: with the message to report, or
/// silently (an empty boundary, which is refused without a message).
pub(super) type Refused = Option<&'static str>;

impl Multipart {
    /// Whether `c` is an RFC 2616 token character (no control, separator or
    /// non-ASCII byte).
    pub fn is_token_char(c: u8) -> bool {
        // CTLs not allowed
        if c <= 32 || c >= 127 {
            return false;
        }
        !matches!(
            c,
            b'(' | b')' | b'<' | b'>' | b'@' | b',' | b';' | b':' | b'\\' | b'"' | b'/' | b'[' | b']' | b'?' | b'='
        )
    }

    /// Whether the boundary only uses the characters RFC 2046 allows (a
    /// space only before the last character).
    pub fn boundary_characters_valid(boundary: &[u8]) -> bool {
        boundary.iter().enumerate().all(|(i, &c)| {
            // Check against allowed list defined in RFC2046 page 22
            c.is_ascii_alphanumeric()
                // space allowed, but not as last character
                || (c == b' ' && i + 1 < boundary.len())
                || matches!(c, b'\'' | b'(' | b')' | b'+' | b'_' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?')
        })
    }

    /// How many times the word "boundary" followed (anywhere later) by `=`
    /// appears, case insensitively.
    pub fn count_boundary_params(str_header_value: &[u8]) -> usize {
        let lower = str_header_value.to_ascii_lowercase();
        let mut s = &lower[..];
        let mut count = 0;
        while let Some(p) = find(s, b"boundary") {
            s = &s[p + 8..];
            if s.contains(&b'=') {
                count += 1;
            }
        }
        count
    }

    /// Validates the Content-Type header and takes the boundary from it,
    /// flagging what is unusual about how it is written.
    pub(super) fn read_boundary(&mut self, cx: &dyn Context) -> Result<(), Refused> {
        if self.header.is_empty() {
            return Err(Some("Multipart: Content-Type header not available."));
        }
        if self.header.len() > 1024 {
            return Err(Some("Multipart: Invalid boundary in C-T (length)."));
        }

        let header = self.header.clone();

        if header.len() < 19 || !header[..19].eq_ignore_ascii_case(b"multipart/form-data") {
            return Err(Some("Multipart: Invalid MIME type."));
        }

        // Count how many times the word "boundary" appears in the C-T
        // header.
        if Self::count_boundary_params(&header) > 1 {
            return Err(Some("Multipart: Multiple boundary parameters in C-T."));
        }

        let Some(name) = find(&header, b"boundary") else {
            // Test for case-insensitive boundary. Allowed by the RFC but
            // highly unusual.
            if Self::count_boundary_params(&header) > 0 {
                return Err(Some("Multipart: Invalid boundary in C-T (case sensitivity)."));
            }
            return Err(Some("Multipart: Boundary not found in C-T."));
        };
        let after_name = name + 8;

        // Check for extra characters before the boundary: one semicolon
        // is fine.
        let mut seen_semicolon = false;
        for &c in &header[19..name] {
            if is_space(c) {
                continue;
            }
            if seen_semicolon || c != b';' {
                return Err(Some("Multipart: Invalid boundary in C-T (malformed)."));
            }
            seen_semicolon = true;
        }
        if !seen_semicolon {
            self.flags.missing_semicolon = true;
        }

        let Some(eq) = header[after_name..].iter().position(|&c| c == b'=') else {
            return Err(Some("Multipart: Invalid boundary in C-T (malformed)."));
        };
        let eq = after_name + eq;

        // Check parameter name ends well: only whitespace between the name
        // and the = character.
        for &c in &header[after_name..eq] {
            if !is_space(c) {
                return Err(Some("Multipart: Invalid boundary in C-T (parameter name)."));
            }
            self.flags.boundary_whitespace = true;
        }

        let value = &header[eq + 1..];
        let len = value.len();

        // Flag for whitespace before parameter value.
        if value.first().is_some_and(|&c| is_space(c)) {
            self.flags.boundary_whitespace = true;
        }

        // Is the boundary quoted?
        if len >= 2 && value[0] == b'"' && value[len - 1] == b'"' {
            self.boundary = value[1..len - 1].to_vec();
            if self.boundary.is_empty() {
                return Err(None);
            }
            self.flags.boundary_quoted = true;
        } else {
            // Test for partial quoting.
            if value.first() == Some(&b'"') || (len >= 2 && value[len - 1] == b'"') {
                return Err(Some("Multipart: Invalid boundary in C-T (quote)."));
            }
            self.boundary = value.to_vec();
            if self.boundary.is_empty() {
                return Err(None);
            }
        }

        // Case-insensitive test for the string "boundary" in the boundary.
        if Self::count_boundary_params(&self.boundary) != 0 {
            return Err(Some("Multipart: Invalid boundary in C-T (content)."));
        }

        // Some frameworks are known to incorrectly include a charset=
        // parameter after the boundary. Doing so is not RFC-compliant, but
        // we will tolerate it.
        if !Self::boundary_characters_valid(&self.boundary)
            && let Some(semicolon_after_boundary) = self.boundary.iter().position(|&c| c == b';')
        {
            ms_dbg!(cx, 3, "Multipart: Invalid parameter after boundary in C-T (tolerated).");
            self.boundary.truncate(semicolon_after_boundary);
        }
        // Validate the characters used in the boundary.
        if !Self::boundary_characters_valid(&self.boundary) {
            return Err(Some("Multipart: Invalid boundary in C-T (characters)."));
        }

        ms_dbg!(
            cx,
            9,
            "Multipart: Boundary{}: {}",
            if self.flags.boundary_quoted { " (quoted)" } else { "" },
            String::from_utf8_lossy(&self.boundary)
        );

        if self.boundary.is_empty() {
            return Err(Some("Multipart: Invalid boundary in C-T (empty)."));
        }
        Ok(())
    }
}
