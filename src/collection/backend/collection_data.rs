//! Port of `src/collection/backend/collection_data.h` /
//! `src/collection/backend/collection_data.cc`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default)]
pub struct CollectionData {
    has_value: bool,
    has_expiry_time: bool,
    value: Vec<u8>,
    expiry_time: Option<SystemTime>,
}

impl CollectionData {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_value(value: &[u8]) -> Self {
        CollectionData { has_value: true, has_expiry_time: false, value: value.to_vec(), expiry_time: None }
    }

    pub fn set_value(&mut self, value: &[u8]) {
        self.value = value.to_vec();
        self.has_value = true;
    }

    pub fn has_value(&self) -> bool {
        self.has_value
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn set_expiry(&mut self, seconds_until_expiry: i32) {
        let now = SystemTime::now();
        self.expiry_time = Some(if seconds_until_expiry >= 0 {
            now + Duration::from_secs(seconds_until_expiry as u64)
        } else {
            now - Duration::from_secs((-(seconds_until_expiry as i64)) as u64)
        });
        self.has_expiry_time = true;
    }

    pub fn has_expiry(&self) -> bool {
        self.has_expiry_time
    }

    pub fn is_expired(&self) -> bool {
        if !self.has_expiry_time {
            return false;
        }
        match self.expiry_time {
            Some(t) => SystemTime::now() >= t,
            None => false,
        }
    }

    /// `getSerialized`
    pub fn serialize(&self) -> Vec<u8> {
        let mut s = b"{".to_vec();
        if self.has_expiry() {
            s.extend_from_slice(b"\"__expire_\":");
            let secs =
                self.expiry_time.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
            s.extend_from_slice(secs.to_string().as_bytes());
            if self.has_value() {
                s.push(b',');
            }
        }
        if self.has_value() {
            s.extend_from_slice(b"\"__value_\":\"");
            s.extend_from_slice(&self.value);
            s.push(b'"');
        }
        s.push(b'}');
        s
    }

    /// `setFromSerialized`
    pub fn deserialize(&mut self, data: &[u8]) {
        const EXPIRY_PREFIX: &[u8] = b"\"__expire_\":";
        const VALUE_PREFIX: &[u8] = b"\"__value_\":\"";
        self.has_value = false;
        self.has_expiry_time = false;
        let s = data;
        let find_at = |needle: &[u8], pos: usize| -> bool {
            s.len() >= pos + needle.len() && &s[pos..pos + needle.len()] == needle
        };
        if !s.is_empty() && s[0] == b'{' && s[s.len() - 1] == b'}' {
            let mut current = 1usize;
            let mut expiry: u64 = 0;
            let mut invalid = false;
            let mut done = false;
            if find_at(EXPIRY_PREFIX, current) {
                current += EXPIRY_PREFIX.len();
                let end = (current + 10).min(s.len());
                let digits = &s[current.min(s.len())..end];
                if digits.iter().all(|c| c.is_ascii_digit()) {
                    expiry = std::str::from_utf8(digits).ok().and_then(|d| d.parse().ok()).unwrap_or(0);
                } else {
                    invalid = true;
                }
                current += 10;
            }
            if !invalid && expiry > 0 {
                if find_at(b",", current) {
                    current += 1;
                } else if current == s.len() - 1 {
                    done = true;
                } else {
                    invalid = true;
                }
            }
            if !invalid && !done {
                if find_at(VALUE_PREFIX, current) {
                    current += VALUE_PREFIX.len();
                    let expected_close = s.len().wrapping_sub(2);
                    if s.len() >= 2 && s[expected_close] == b'"' && expected_close >= current {
                        self.value = s[current..expected_close].to_vec();
                        self.has_value = true;
                    } else {
                        invalid = true;
                    }
                } else {
                    invalid = true;
                }
            }
            if !invalid && expiry > 0 {
                self.expiry_time = Some(UNIX_EPOCH + Duration::from_secs(expiry));
                self.has_expiry_time = true;
            }
            if !invalid {
                return;
            }
        }
        // Residual case: the whole string is a plain value (content stored
        // before serialization support existed).
        self.value = data.to_vec();
        self.has_value = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut d = CollectionData::with_value(b"abc");
        d.set_expiry(100);
        let s = d.serialize();
        let mut e = CollectionData::new();
        e.deserialize(&s);
        assert!(e.has_value() && e.has_expiry());
        assert_eq!(e.value(), b"abc");
        let mut f = CollectionData::new();
        f.deserialize(b"plain");
        assert_eq!(f.value(), b"plain");
    }
}
