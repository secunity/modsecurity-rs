//! Values and optional expiry times stored by the collection backends.
//!
//! The persistent format resembles JSON but deliberately stores unescaped
//! bytes. Its decoder also accepts legacy plain values; do not substitute
//! a JSON parser or relax its fixed-width timestamp rules.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Default)]
pub struct CollectionData {
    pub value: Option<Vec<u8>>,
    pub expiry: Option<SystemTime>,
}

impl CollectionData {
    pub fn with_value(value: &[u8]) -> Self {
        Self { value: Some(value.to_vec()), expiry: None }
    }

    pub fn set_value(&mut self, value: &[u8]) {
        self.value = Some(value.to_vec());
    }

    pub fn set_expiry(&mut self, seconds_until_expiry: i32) {
        self.set_expiry_at(SystemTime::now(), seconds_until_expiry);
    }

    fn set_expiry_at(&mut self, now: SystemTime, seconds: i32) {
        let duration = Duration::from_secs(u64::from(seconds.unsigned_abs()));
        self.expiry = Some(if seconds >= 0 { now + duration } else { now - duration });
    }

    pub fn is_expired(&self) -> bool {
        self.expiry.is_some() && self.is_expired_at(SystemTime::now())
    }

    fn is_expired_at(&self, now: SystemTime) -> bool {
        self.expiry.is_some_and(|expiry| now >= expiry)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut s = b"{".to_vec();
        if let Some(expiry) = self.expiry {
            s.extend_from_slice(b"\"__expire_\":");
            let secs = expiry.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            s.extend_from_slice(secs.to_string().as_bytes());
            if self.value.is_some() {
                s.push(b',');
            }
        }
        if let Some(value) = &self.value {
            s.extend_from_slice(b"\"__value_\":\"");
            s.extend_from_slice(value);
            s.push(b'"');
        }
        s.push(b'}');
        s
    }

    /// Decodes a serialized record, falling back to the entire input as a
    /// plain value on any format mismatch (including `{}`).
    pub fn from_bytes(data: &[u8]) -> Self {
        Self::decode_record(data).unwrap_or_else(|| Self::with_value(data))
    }

    fn decode_record(data: &[u8]) -> Option<Self> {
        let mut rest = data.strip_prefix(b"{")?.strip_suffix(b"}")?;
        let mut expiry = None;
        if let Some(after_prefix) = rest.strip_prefix(b"\"__expire_\":") {
            // Exactly ten decimal digits are consumed. Zero is treated as
            // absent and, unusually, does not consume a following comma.
            let digits = after_prefix.get(..10)?;
            if !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            let seconds: u64 = std::str::from_utf8(digits).ok()?.parse().ok()?;
            rest = &after_prefix[10..];
            if seconds > 0 {
                expiry = Some(UNIX_EPOCH + Duration::from_secs(seconds));
                if rest.is_empty() {
                    return Some(Self { value: None, expiry });
                }
                rest = rest.strip_prefix(b",")?;
            }
        }
        let value = rest.strip_prefix(b"\"__value_\":\"")?.strip_suffix(b"\"")?;
        Some(Self { value: Some(value.to_vec()), expiry })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut record = CollectionData::with_value(b"abc");
        record.set_expiry(100);
        let decoded = CollectionData::from_bytes(&record.serialize());
        assert_eq!(decoded.value.as_deref(), Some(&b"abc"[..]));
        assert!(decoded.expiry.is_some());
        assert_eq!(CollectionData::from_bytes(b"plain").value.as_deref(), Some(&b"plain"[..]));
    }

    #[test]
    fn serialized_bytes_and_legacy_fallback() {
        let expiry = UNIX_EPOCH + Duration::from_secs(1_234_567_890);
        for (input, value, expires) in [
            (&b"plain"[..], Some(&b"plain"[..]), None),
            (b"", Some(&b""[..]), None),
            (b"{}", Some(&b"{}"[..]), None),
            (b"{\"__value_\":\"\"}", Some(&b""[..]), None),
            (b"{\"__value_\":\"a\xff\0\"b\"}", Some(&b"a\xff\0\"b"[..]), None),
            (b"{\"__expire_\":1234567890}", None, Some(expiry)),
            (b"{\"__expire_\":1234567890,\"__value_\":\"abc\"}", Some(&b"abc"[..]), Some(expiry)),
            (b"{\"__expire_\":0000000000\"__value_\":\"abc\"}", Some(&b"abc"[..]), None),
        ] {
            let record = CollectionData::from_bytes(input);
            assert_eq!(record.value.as_deref(), value, "{input:?}");
            assert_eq!(record.expiry, expires, "{input:?}");
        }
        for input in [
            &b"{\"__expire_\":123456789}"[..],
            b"{\"__expire_\":12345678901}",
            b"{\"__expire_\":123456789x}",
            b"{\"__expire_\":0000000000}",
            b"{\"__expire_\":0000000000,\"__value_\":\"x\"}",
            b"{\"__expire_\":1234567890,}",
            b"{\"__value_\":\"x\",\"__expire_\":1234567890}",
            b"{\"__value_\":x}",
        ] {
            let record = CollectionData::from_bytes(input);
            assert_eq!(record.value.as_deref(), Some(input));
            assert_eq!(record.expiry, None);
        }
        let record = CollectionData { value: Some(b"a\xff\0\"b".to_vec()), expiry: Some(expiry) };
        assert_eq!(record.serialize(), b"{\"__expire_\":1234567890,\"__value_\":\"a\xff\0\"b\"}");
        assert_eq!(CollectionData::default().serialize(), b"{}");
        let before_epoch = CollectionData { value: None, expiry: Some(UNIX_EPOCH - Duration::from_secs(1)) };
        assert_eq!(before_epoch.serialize(), b"{\"__expire_\":0}");
    }

    #[test]
    fn expiry_boundaries_and_value_updates() {
        let now = UNIX_EPOCH + Duration::from_secs(3_000_000_000);
        let mut record = CollectionData::default();
        assert!(!record.is_expired_at(now));
        for seconds in [i32::MIN, -1, 0, 1, i32::MAX] {
            record.set_expiry_at(now, seconds);
            assert_eq!(record.is_expired_at(now), seconds <= 0);
            let expiry = record.expiry.unwrap();
            assert!(record.is_expired_at(expiry));
            assert!(!record.is_expired_at(expiry - Duration::from_nanos(1)));
            record.set_value(b"");
            assert_eq!(record.value.as_deref(), Some(&b""[..]));
            assert_eq!(record.expiry, Some(expiry));
        }
    }
}
