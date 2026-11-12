//! Port of `headers/modsecurity/audit_log.h`, `src/audit_log/audit_log.cc`.

use crate::audit_log::writer::writer::Writer;
use crate::transaction::Transaction;
use crate::utils::regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLogType {
    NotSetAuditLogType,
    SerialAuditLogType,
    ParallelAuditLogType,
    HttpsAuditLogType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLogStatus {
    NotSetLogStatus,
    OnAuditLogStatus,
    OffAuditLogStatus,
    RelevantOnlyAuditLogStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditLogFormat {
    NotSetAuditLogFormat,
    JSONAuditLogFormat,
    NativeAuditLogFormat,
}

/// `SecAuditLogRelevantStatus`: the pattern and its compiled regex (C++
/// compiles it for every transaction).
#[derive(Debug)]
struct RelevantStatus {
    pattern: String,
    re: Regex,
}

impl RelevantStatus {
    /// `None` for an empty pattern, which matches no status.
    fn new(pattern: &str) -> Option<Self> {
        (!pattern.is_empty()).then(|| RelevantStatus { pattern: pattern.to_string(), re: Regex::new(pattern) })
    }
}

/// The audit log configuration (`SecAuditEngine`, `SecAuditLog*`) and the
/// writer that saves the relevant transactions.
#[derive(Debug)]
pub struct AuditLog {
    pub path1: String,
    pub path2: String,
    pub storage_dir: String,
    pub prefix: String,
    pub format: AuditLogFormat,

    parts: i32,
    default_parts: i32,

    file_permission: i32,
    default_file_permission: i32,

    directory_permission: i32,
    default_directory_permission: i32,

    status: AuditLogStatus,
    audit_type: AuditLogType,
    /// `SecAuditLogRelevantStatus` (`None` when not set or empty).
    relevant: Option<RelevantStatus>,

    /// The C++ writer keeps a back pointer (`m_audit`) to its `AuditLog`;
    /// here the owner passes itself to every writer call instead.
    writer: Option<Writer>,
    /// Rules have at least one `ctl:auditEngine` action On or RelevantOnly.
    ctl_audit_engine_active: bool,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        self.discard_writer();
    }
}

/// `PARTS_CONSTAINS` / `PARTS_CONSTAINS_REM`: the parts whose letter
/// (either case) appears anywhere in `new_parts`.
fn parts_in(new_parts: &str) -> i32 {
    const LETTERS: [(u8, i32); 12] = [
        (b'A', AuditLog::A_AUDIT_LOG_PART),
        (b'B', AuditLog::B_AUDIT_LOG_PART),
        (b'C', AuditLog::C_AUDIT_LOG_PART),
        (b'D', AuditLog::D_AUDIT_LOG_PART),
        (b'E', AuditLog::E_AUDIT_LOG_PART),
        (b'F', AuditLog::F_AUDIT_LOG_PART),
        (b'G', AuditLog::G_AUDIT_LOG_PART),
        (b'H', AuditLog::H_AUDIT_LOG_PART),
        (b'I', AuditLog::I_AUDIT_LOG_PART),
        (b'J', AuditLog::J_AUDIT_LOG_PART),
        (b'K', AuditLog::K_AUDIT_LOG_PART),
        (b'Z', AuditLog::Z_AUDIT_LOG_PART),
    ];
    let b = new_parts.as_bytes();
    LETTERS.iter().filter(|(c, _)| b.contains(c) || b.contains(&c.to_ascii_lowercase())).fold(0, |acc, (_, p)| acc | p)
}

impl AuditLog {
    /// Audit log header (mandatory).
    pub const A_AUDIT_LOG_PART: i32 = 2;
    /// Request headers.
    pub const B_AUDIT_LOG_PART: i32 = 4;
    /// Request body (present only if the request body exists and ModSecurity
    /// is configured to intercept it).
    pub const C_AUDIT_LOG_PART: i32 = 8;
    /// Reserved for intermediary response headers; not implemented yet.
    pub const D_AUDIT_LOG_PART: i32 = 16;
    /// Intermediary response body (present only if ModSecurity is configured
    /// to intercept response bodies, and if the audit log engine is
    /// configured to record it). Intermediary response body is the same as
    /// the actual response body unless ModSecurity intercepts the
    /// intermediary response body, in which case the actual response body
    /// will contain the error message (either the Apache default error
    /// message, or the ErrorDocument page).
    pub const E_AUDIT_LOG_PART: i32 = 32;
    /// Final response headers (excluding the Date and Server headers, which
    /// are always added by Apache in the late stage of content delivery).
    pub const F_AUDIT_LOG_PART: i32 = 64;
    /// Reserved for the actual response body; not implemented yet.
    pub const G_AUDIT_LOG_PART: i32 = 128;
    /// Audit log trailer.
    pub const H_AUDIT_LOG_PART: i32 = 256;
    /// This part is a replacement for part C. It will log the same data as C
    /// in all cases except when multipart/form-data encoding in used. In this
    /// case, it will log a fake application/x-www-form-urlencoded body that
    /// contains the information about parameters but not about the files.
    /// This is handy if you don't want to have (often large) files stored in
    /// your audit logs.
    pub const I_AUDIT_LOG_PART: i32 = 512;
    /// This part contains information about the files uploaded using
    /// multipart/form-data encoding.
    pub const J_AUDIT_LOG_PART: i32 = 1024;
    /// This part contains a full list of every rule that matched (one per
    /// line) in the order they were matched. The rules are fully qualified
    /// and will thus show inherited actions and default operators.
    pub const K_AUDIT_LOG_PART: i32 = 2048;
    /// Final boundary, signifies the end of the entry (mandatory).
    pub const Z_AUDIT_LOG_PART: i32 = 4096;

    pub fn new() -> Self {
        AuditLog {
            path1: String::new(),
            path2: String::new(),
            storage_dir: String::new(),
            prefix: String::new(),
            format: AuditLogFormat::NotSetAuditLogFormat,
            parts: -1,
            default_parts: Self::A_AUDIT_LOG_PART
                | Self::B_AUDIT_LOG_PART
                | Self::C_AUDIT_LOG_PART
                | Self::F_AUDIT_LOG_PART
                | Self::H_AUDIT_LOG_PART
                | Self::Z_AUDIT_LOG_PART,
            file_permission: -1,
            default_file_permission: 0o640,
            directory_permission: -1,
            default_directory_permission: 0o750,
            status: AuditLogStatus::NotSetLogStatus,
            audit_type: AuditLogType::NotSetAuditLogType,
            relevant: None,
            writer: None,
            ctl_audit_engine_active: false,
        }
    }

    pub fn set_storage_dir_mode(&mut self, permission: i32) -> bool {
        self.directory_permission = permission;
        true
    }

    pub fn set_file_mode(&mut self, permission: i32) -> bool {
        self.file_permission = permission;
        true
    }

    pub fn set_status(&mut self, new_status: AuditLogStatus) -> bool {
        self.status = new_status;
        true
    }

    pub fn set_relevant_status(&mut self, new_relevant_status: &str) -> bool {
        self.relevant = RelevantStatus::new(new_relevant_status);
        true
    }

    pub fn set_file_path1(&mut self, path: &str) -> bool {
        self.path1 = path.to_string();
        true
    }

    pub fn set_file_path2(&mut self, path: &str) -> bool {
        self.path2 = path.to_string();
        true
    }

    pub fn set_storage_dir(&mut self, path: &str) -> bool {
        self.storage_dir = path.to_string();
        true
    }

    pub fn set_prefix(&mut self, prefix: &str) -> bool {
        self.prefix = prefix.to_string();
        true
    }

    pub fn set_format(&mut self, fmt: AuditLogFormat) -> bool {
        self.format = fmt;
        true
    }

    pub fn get_directory_permission(&self) -> i32 {
        if self.directory_permission == -1 {
            return self.default_directory_permission;
        }
        self.directory_permission
    }

    pub fn get_file_permission(&self) -> i32 {
        if self.file_permission == -1 {
            return self.default_file_permission;
        }
        self.file_permission
    }

    pub fn get_parts(&self) -> i32 {
        if self.parts == -1 {
            return self.default_parts;
        }
        self.parts
    }

    pub fn set_parts(&mut self, new_parts: &str) -> bool {
        self.parts = parts_in(new_parts);
        true
    }

    pub fn set_type(&mut self, audit_type: AuditLogType) -> bool {
        self.audit_type = audit_type;
        true
    }

    /// The C++ `delete m_writer`: the writer releases its files through the
    /// *current* configuration, as the C++ destructors read
    /// `m_audit->m_path1/2` at that moment.
    fn discard_writer(&mut self) {
        if let Some(w) = self.writer.take() {
            w.close(self);
        }
    }

    /// `init`: (re)creates the writer for the configured type. The `Err`
    /// carries the C++ `std::string *error`.
    pub fn init(&mut self) -> Result<(), String> {
        if (self.status == AuditLogStatus::OffAuditLogStatus || self.status == AuditLogStatus::NotSetLogStatus)
            && !self.ctl_audit_engine_active
        {
            self.discard_writer();
            return Ok(());
        }

        let tmp_writer = Writer::for_type(self.audit_type);

        if let Err(e) = tmp_writer.init(self) {
            // `delete tmp_writer`: its destructor releases what it opened.
            tmp_writer.close(self);
            return Err(e);
        }

        // Quirk (C++): the previous writer is deleted after the
        // configuration was merged, so its destructor closes the paths of
        // the new configuration.
        self.discard_writer();
        self.writer = Some(tmp_writer);
        Ok(())
    }

    pub fn close(&mut self) -> bool {
        true
    }

    /// `saveIfRelevant(transaction, parts)`; `parts == -1` stands for the
    /// configured parts (the raw `m_parts`, itself -1 when never set).
    pub fn save_if_relevant(&self, t: &Transaction<'_>, parts: i32) -> bool {
        let mut parts = parts;

        let mut transaction_audit_log_status = self.status;
        if t.ctl_audit_engine != AuditLogStatus::NotSetLogStatus {
            transaction_audit_log_status = t.ctl_audit_engine;
        }

        if transaction_audit_log_status == AuditLogStatus::OffAuditLogStatus
            || transaction_audit_log_status == AuditLogStatus::NotSetLogStatus
        {
            crate::ms_dbg_a!(t, 5, "Audit log engine was not set.");
            return true;
        }

        let save_anyway = t.rules_messages.iter().any(|i| !i.no_audit_log);

        if transaction_audit_log_status == AuditLogStatus::RelevantOnlyAuditLogStatus
            && !self.is_relevant(t.http_code_returned)
            && !save_anyway
        {
            crate::ms_dbg_a!(
                t,
                9,
                "Return code `{}' is not interesting to audit logs, relevant code(s): `{}'.",
                t.http_code_returned,
                self.relevant.as_ref().map_or("", |r| r.pattern.as_str())
            );
            return false;
        }

        if parts == -1 {
            parts = self.parts;
        }
        crate::ms_dbg_a!(t, 5, "Saving this request as part of the audit logs.");
        match &self.writer {
            None => {
                crate::ms_dbg_a!(t, 1, "Internal error, audit log writer is null");
            }
            Some(w) => {
                if let Err(error) = w.write(self, t, parts) {
                    crate::ms_dbg_a!(t, 1, "Cannot save the audit log: {}", error);
                    return false;
                }
            }
        }

        true
    }

    pub fn is_relevant(&self, status: i32) -> bool {
        self.relevant.as_ref().is_some_and(|r| r.re.search(status.to_string().as_bytes()) != 0)
    }

    pub fn add_parts(parts: i32, new_parts: &str) -> i32 {
        parts | parts_in(new_parts)
    }

    pub fn remove_parts(parts: i32, new_parts: &str) -> i32 {
        parts & !parts_in(new_parts)
    }

    pub fn set_ctl_audit_engine_active(&mut self) {
        self.ctl_audit_engine_active = true;
    }

    /// `merge`: the values set in `from` override this configuration, then
    /// the writer is re-initialised.
    pub fn merge(&mut self, from: &AuditLog) -> Result<(), String> {
        // AL_MERGE_STRING_CONF
        fn merge_string(from: &str, to: &mut String) {
            if !from.is_empty() {
                *to = from.to_string();
            }
        }
        merge_string(&from.path1, &mut self.path1);
        merge_string(&from.path2, &mut self.path2);
        merge_string(&from.storage_dir, &mut self.storage_dir);
        if let Some(r) = &from.relevant {
            self.relevant = RelevantStatus::new(&r.pattern);
        }
        merge_string(&from.prefix, &mut self.prefix);

        if from.file_permission != -1 {
            self.file_permission = from.file_permission;
        }

        if from.directory_permission != -1 {
            self.directory_permission = from.directory_permission;
        }

        if from.audit_type != AuditLogType::NotSetAuditLogType {
            self.audit_type = from.audit_type;
        }

        if from.status != AuditLogStatus::NotSetLogStatus {
            self.status = from.status;
        }

        if from.parts != -1 {
            self.parts = from.parts;
        }

        if from.format != AuditLogFormat::NotSetAuditLogFormat {
            self.format = from.format;
        }

        if from.ctl_audit_engine_active {
            self.ctl_audit_engine_active = from.ctl_audit_engine_active;
        }

        self.init()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modsecurity::ModSecurity;
    use crate::rule_message::RuleMessage;
    use crate::rule_with_actions::{RuleWithActions, RuleWithActionsKind};
    use crate::rules_set::RulesSet;
    use crate::rules_set_properties::RuleEngine;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    const ABFHZ: i32 = AuditLog::A_AUDIT_LOG_PART
        | AuditLog::B_AUDIT_LOG_PART
        | AuditLog::F_AUDIT_LOG_PART
        | AuditLog::H_AUDIT_LOG_PART
        | AuditLog::Z_AUDIT_LOG_PART;

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("msrs-auditlog-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn p(d: &Path, f: &str) -> String {
        d.join(f).to_str().unwrap().to_string()
    }

    /// The transaction of the C++ comparison harness.
    fn run(rules: &RulesSet, id: &str, f: impl FnOnce(&mut Transaction<'_>)) {
        let ms = ModSecurity::new();
        let mut t = Transaction::with_id(&ms, rules, id, None);
        t.process_connection("1.2.3.4", 1234, "5.6.7.8", 80);
        t.process_uri(b"/a?x=1", b"POST", b"1.1");
        t.add_request_header(b"Host", b"example.com");
        t.add_request_header(b"User-Agent", b"UA");
        t.process_request_headers();
        t.add_response_header(b"Content-Type", b"text/plain");
        t.process_response_headers(200, "HTTP 1.1");
        f(&mut t);
        t.process_logging();
    }

    fn rules_with(configure: impl FnOnce(&mut AuditLog)) -> RulesSet {
        let mut rules = RulesSet::new();
        rules.properties.sec_rule_engine = Some(RuleEngine::Enabled);
        let mut from = AuditLog::new();
        from.set_status(AuditLogStatus::OnAuditLogStatus);
        from.set_parts("ABFHZ");
        configure(&mut from);
        rules.properties.audit_log.merge(&from).unwrap();
        rules
    }

    /// Replaces the boundary and the date so that entries can be compared.
    fn normalize_native(log: &str) -> String {
        log.lines()
            .map(|l| {
                if l.starts_with("---") && l.ends_with("--") && l.len() == 17 {
                    format!("---BOUNDARY---{}", &l[14..])
                } else if l.starts_with('[') {
                    format!("[DATE]{}", &l[l.find(']').unwrap() + 1..])
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    const NATIVE_ENTRY: &str = "---BOUNDARY---A--\n\
        [DATE] ID 1.2.3.4 1234 5.6.7.8 80\n\
        ---BOUNDARY---B--\n\
        POST /a?x=1 HTTP/1.1\n\
        Host: example.com\n\
        User-Agent: UA\n\
        \n\
        ---BOUNDARY---F--\n\
        HTTP/1.1 200\n\
        Content-Type: text/plain\n\
        \n\
        ---BOUNDARY---H--\n\
        \n\
        ---BOUNDARY---Z--\n\n";

    #[test]
    fn parts_parsing() {
        let mut a = AuditLog::new();
        assert_eq!(a.get_parts(), ABFHZ | AuditLog::C_AUDIT_LOG_PART);
        a.set_parts("abfhz");
        assert_eq!(a.get_parts(), ABFHZ);
        a.set_parts("");
        assert_eq!(a.get_parts(), 0);
        // Every letter anywhere in the string counts, other bytes are ignored.
        a.set_parts("x-K+jIgEdCa");
        assert_eq!(a.get_parts(), 2 | 8 | 16 | 32 | 128 | 512 | 1024 | 2048);
        assert_eq!(AuditLog::add_parts(ABFHZ, "+E"), ABFHZ | AuditLog::E_AUDIT_LOG_PART);
        assert_eq!(AuditLog::add_parts(0, "kz"), AuditLog::K_AUDIT_LOG_PART | AuditLog::Z_AUDIT_LOG_PART);
        assert_eq!(AuditLog::remove_parts(ABFHZ, "-b"), ABFHZ & !AuditLog::B_AUDIT_LOG_PART);
        assert_eq!(AuditLog::remove_parts(ABFHZ, "E"), ABFHZ);
    }

    #[test]
    fn permissions_and_merge() {
        let mut a = AuditLog::new();
        assert_eq!(a.get_file_permission(), 0o640);
        assert_eq!(a.get_directory_permission(), 0o750);

        let mut from = AuditLog::new();
        from.set_file_path1("p1");
        from.set_prefix("pre");
        from.set_file_mode(0o600);
        from.set_relevant_status("^5");
        from.set_format(AuditLogFormat::JSONAuditLogFormat);
        // Status not set: the merge succeeds without creating a writer.
        a.set_file_path2("keep");
        a.set_parts("AZ");
        a.merge(&from).unwrap();
        assert_eq!(a.path1, "p1");
        assert_eq!(a.path2, "keep");
        assert_eq!(a.prefix, "pre");
        assert_eq!(a.get_file_permission(), 0o600);
        assert_eq!(a.get_directory_permission(), 0o750);
        assert_eq!(a.get_parts(), AuditLog::A_AUDIT_LOG_PART | AuditLog::Z_AUDIT_LOG_PART);
        assert_eq!(a.format, AuditLogFormat::JSONAuditLogFormat);
        assert!(a.writer.is_none());
        assert!(a.is_relevant(500));
        assert!(!a.is_relevant(404));

        // Empty strings / unset values do not override.
        a.merge(&AuditLog::new()).unwrap();
        assert_eq!(a.path1, "p1");
        assert_eq!(a.get_parts(), AuditLog::A_AUDIT_LOG_PART | AuditLog::Z_AUDIT_LOG_PART);

        // A serial writer needs a file it can open.
        let mut from = AuditLog::new();
        from.set_status(AuditLogStatus::OnAuditLogStatus);
        from.set_file_path1("/nonexistent-dir/x/audit.log");
        assert_eq!(a.merge(&from).unwrap_err(), "Failed to open file: /nonexistent-dir/x/audit.log");
        assert!(a.writer.is_none());

        // ctl:auditEngine alone enables the writer.
        let d = temp_dir("ctl");
        let mut a = AuditLog::new();
        let mut from = AuditLog::new();
        from.set_ctl_audit_engine_active();
        from.set_file_path1(&p(&d, "a.log"));
        a.merge(&from).unwrap();
        assert!(a.writer.is_some());
    }

    #[test]
    fn relevance() {
        let mut a = AuditLog::new();
        assert!(!a.is_relevant(500), "no SecAuditLogRelevantStatus");
        a.set_relevant_status("^(?:5|4(?!04))");
        assert!(a.is_relevant(500));
        assert!(a.is_relevant(403));
        assert!(!a.is_relevant(404));
        assert!(!a.is_relevant(200));

        let d = temp_dir("relevant");
        let log = p(&d, "serial.log");
        let rules = rules_with(|a| {
            a.set_status(AuditLogStatus::RelevantOnlyAuditLogStatus);
            a.set_relevant_status("^5");
            a.set_file_path1(&log);
        });
        // 200: not relevant, nothing written.
        run(&rules, "not-relevant", |_| {});
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "");
        // A rule message without noauditlog forces the entry.
        let rule: &'static RuleWithActions =
            Box::leak(Box::new(RuleWithActions::new(None, None, "file", 1, RuleWithActionsKind::Unconditional)));
        run(&rules, "forced", |t| t.rules_messages.push(RuleMessage::new(rule)));
        assert!(std::fs::read_to_string(&log).unwrap().contains(" forced 1.2.3.4 "));
        // ... unless it is marked noauditlog.
        run(&rules, "noaudit", |t| {
            let mut m = RuleMessage::new(rule);
            m.no_audit_log = true;
            t.rules_messages.push(m);
        });
        assert!(!std::fs::read_to_string(&log).unwrap().contains("noaudit"));
        // A relevant status code.
        run(&rules, "status500", |t| t.http_code_returned = 500);
        assert!(std::fs::read_to_string(&log).unwrap().contains(" status500 "));
        // ctl:auditEngine=Off wins over the configuration.
        run(&rules, "ctl-off", |t| {
            t.http_code_returned = 500;
            t.ctl_audit_engine = AuditLogStatus::OffAuditLogStatus;
        });
        assert!(!std::fs::read_to_string(&log).unwrap().contains("ctl-off"));
        // ctl:auditEngine=On saves a non relevant transaction.
        run(&rules, "ctl-on", |t| t.ctl_audit_engine = AuditLogStatus::OnAuditLogStatus);
        assert!(std::fs::read_to_string(&log).unwrap().contains(" ctl-on "));
    }

    #[test]
    fn serial_writer() {
        let d = temp_dir("serial");
        let native = p(&d, "serial.log");
        let json = p(&d, "serial.json");
        let rules = rules_with(|a| {
            a.set_type(AuditLogType::SerialAuditLogType);
            a.set_file_path1(&native);
        });
        run(&rules, "id-serial", |_| {});
        let out = std::fs::read_to_string(&native).unwrap();
        assert_eq!(normalize_native(&out) + "\n", NATIVE_ENTRY.replace("ID", "id-serial"));
        // Appends.
        run(&rules, "id-serial2", |_| {});
        assert!(std::fs::read_to_string(&native).unwrap().starts_with(&out));

        let rules = rules_with(|a| {
            a.set_format(AuditLogFormat::JSONAuditLogFormat);
            a.set_file_path1(&json);
        });
        run(&rules, "id-json", |_| {});
        let out = std::fs::read_to_string(&json).unwrap();
        let date_start = out.find("\"time_stamp\":\"").unwrap() + 14;
        let date_end = date_start + out[date_start..].find('"').unwrap();
        let out = format!("{}DATE{}", &out[..date_start], &out[date_end..]);
        assert_eq!(
            out,
            format!(
                "{{\"transaction\":{{\"client_ip\":\"1.2.3.4\",\"time_stamp\":\"DATE\",\"server_id\":\"{}\",\
                 \"client_port\":1234,\"host_ip\":\"5.6.7.8\",\"host_port\":80,\"unique_id\":\"id-json\",\
                 \"is_interrupted\":false,\"request\":{{\"method\":\"POST\",\"http_version\":\"1.1\",\
                 \"hostname\":\"5.6.7.8\",\"uri\":\"/a?x=1\",\"headers\":{{\"Host\":\"example.com\",\
                 \"User-Agent\":\"UA\"}}}},\"response\":{{\"http_code\":200,\"headers\":{{\"Content-Type\":\
                 \"text/plain\"}}}},\"producer\":{{\"modsecurity\":\"ModSecurity v3.0.17 (Linux)\",\
                 \"connector\":\"\",\"secrules_engine\":\"Enabled\",\"components\":[]}},\"messages\":[]}}}}\n",
                crate::unique_id::UniqueId::unique_id()
            )
        );
    }

    /// Checks the entry file of a parallel writer and returns its path.
    fn check_parallel_entry(storage: &Path, id: &str, t: i64, mode: u32) -> String {
        let day = crate::utils::system::strftime_local(t, "%Y%m%d");
        let minute = crate::utils::system::strftime_local(t, "%Y%m%d-%H%M");
        let second = crate::utils::system::strftime_local(t, "%Y%m%d-%H%M%S");
        let file = storage.join(&day).join(&minute).join(format!("{}-{}", second, id));
        let meta = std::fs::metadata(&file).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, mode);
        file.to_str().unwrap().to_string()
    }

    fn check_index(index: &str, id: &str, file: &str) {
        let content = std::fs::read_to_string(file).unwrap();
        let md5 = crate::utils::string::string_to_hex(&<md5::Md5 as md5::Digest>::digest(content.as_bytes()));
        let line = std::fs::read_to_string(index).unwrap();
        let after_date = &line[line.find(']').unwrap() + 1..];
        assert!(line.starts_with("example.com 1.2.3.4 - ["), "{}", line);
        assert_eq!(
            after_date,
            format!(
                " \"POST /a?x=1 HTTP/1.1\" 200 0 - \"UA\" {} - {} 0 {}.000000 md5:{}\n",
                id,
                file,
                content.len(),
                md5
            )
        );
    }

    #[test]
    fn parallel_writer() {
        // The directories are created with mkdir (umask applies).
        // SAFETY: umask has no preconditions.
        let umask = unsafe {
            let m = libc::umask(0o022);
            libc::umask(m);
            m
        } as u32;
        let d = temp_dir("parallel");
        let storage = d.join("par");
        let before = crate::utils::system::now();

        // SecAuditLog only: index into path1, custom modes.
        let rules = rules_with(|a| {
            a.set_type(AuditLogType::ParallelAuditLogType);
            a.set_storage_dir(storage.to_str().unwrap());
            a.set_file_path1(&p(&d, "index1.log"));
            a.set_file_mode(0o600);
            a.set_storage_dir_mode(0o700);
        });
        let ms = ModSecurity::new();
        let t = Transaction::with_id(&ms, &rules, "id-par1", None);
        let ts = t.time_stamp;
        assert!(ts >= before);
        drop(t);
        run(&rules, "id-par1", |t| t.time_stamp = ts);
        assert_eq!(std::fs::metadata(&storage).unwrap().permissions().mode() & 0o777, 0o700 & !umask);
        let file = check_parallel_entry(&storage, "id-par1", ts, 0o600 & !umask);
        assert_eq!(
            normalize_native(&std::fs::read_to_string(&file).unwrap()) + "\n",
            NATIVE_ENTRY.replace("ID", "id-par1")
        );
        check_index(&p(&d, "index1.log"), "id-par1", &file);

        // SecAuditLog and SecAuditLog2: index into path2 only.
        let rules = rules_with(|a| {
            a.set_type(AuditLogType::ParallelAuditLogType);
            a.set_storage_dir(storage.to_str().unwrap());
            a.set_file_path1(&p(&d, "index1b.log"));
            a.set_file_path2(&p(&d, "index2.log"));
        });
        run(&rules, "id-par2", |t| t.time_stamp = ts);
        let file = check_parallel_entry(&storage, "id-par2", ts, 0o640 & !umask);
        assert_eq!(std::fs::read_to_string(p(&d, "index1b.log")).unwrap(), "");
        check_index(&p(&d, "index2.log"), "id-par2", &file);

        // SecAuditLog2 only.
        let rules = rules_with(|a| {
            a.set_type(AuditLogType::ParallelAuditLogType);
            a.set_storage_dir(storage.to_str().unwrap());
            a.set_file_path2(&p(&d, "index2b.log"));
        });
        run(&rules, "id-par3", |t| t.time_stamp = ts);
        let file = check_parallel_entry(&storage, "id-par3", ts, 0o640 & !umask);
        check_index(&p(&d, "index2b.log"), "id-par3", &file);

        // JSON, no index; default directory mode.
        let storage_json = d.join("parjson");
        let rules = rules_with(|a| {
            a.set_type(AuditLogType::ParallelAuditLogType);
            a.set_format(AuditLogFormat::JSONAuditLogFormat);
            a.set_storage_dir(storage_json.to_str().unwrap());
        });
        run(&rules, "id-par4", |t| t.time_stamp = ts);
        let day = storage_json.join(crate::utils::system::strftime_local(ts, "%Y%m%d"));
        assert_eq!(std::fs::metadata(&day).unwrap().permissions().mode() & 0o777, 0o750 & !umask);
        let file = check_parallel_entry(&storage_json, "id-par4", ts, 0o640 & !umask);
        assert!(std::fs::read_to_string(file).unwrap().contains("\"unique_id\":\"id-par4\""));
    }

    #[test]
    fn parallel_writer_errors() {
        // No storage directory.
        let ms = ModSecurity::new();
        let rules = rules_with(|a| {
            a.set_type(AuditLogType::ParallelAuditLogType);
        });
        let t = Transaction::with_id(&ms, &rules, "x", None);
        let w = Writer::Parallel;
        assert_eq!(w.write(&rules.properties.audit_log, &t, ABFHZ).unwrap_err(), "Log path is not valid.");
        // Not able to create the storage directory.
        let mut a = AuditLog::new();
        a.set_status(AuditLogStatus::OnAuditLogStatus);
        a.set_type(AuditLogType::ParallelAuditLogType);
        a.set_storage_dir("/nonexistent-dir/x");
        let e = a.init().unwrap_err();
        assert!(e.starts_with("Not able to create directory: /nonexistent-dir/x: "), "{}", e);
    }

    #[test]
    fn writer_reference_counting() {
        let d = temp_dir("refcount");
        let log = p(&d, "a.log");
        let mut a = AuditLog::new();
        a.set_status(AuditLogStatus::OnAuditLogStatus);
        a.set_file_path1(&log);
        a.init().unwrap();
        // Re-initialising keeps the file open (new writer opened first).
        a.init().unwrap();
        let files = crate::utils::shared_files::SharedFiles::get_instance();
        assert!(files.write(&log, b"x").is_ok());
        drop(a);
        assert!(files.write(&log, b"x").is_err());
    }
}
