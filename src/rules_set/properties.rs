//! The configuration of a rule set: the values set by the SecLang
//! directives.
//!
//! The configuration state shared by the parser `Driver` and `RulesSet`
//! (both derive from `RulesSetProperties` in C++; both embed it here).

use std::collections::BTreeSet;
use std::sync::Arc;

use modsecurity_compat::cnum::strtoll;

use crate::actions::rule_action::RuleAction;
use crate::audit_log::{AuditLog, SetupError};
use crate::debug_log::{DebugLog, DefaultDebugLog};
use crate::phases::NUMBER_OF_PHASES;
use crate::rules_set::exceptions::RulesExceptions;
use modsecurity_operators::geo_lookup::GeoDb;

/// Numeric configuration values (`ConfigInt`, `ConfigUnsignedInt`,
/// `ConfigUnsignedLong` in C++), with the range of the C++ specialisation.
/// A value that no directive set is `None` in [`RulesSetProperties`].
pub trait ConfigNumber: Copy + Default {
    const SIGNED: bool;
    fn min_value() -> i128;
    fn max_value() -> i128;
    fn from_i128(v: i128) -> Self;
}

macro_rules! config_number {
    ($t:ty, $signed:expr, $min:expr) => {
        impl ConfigNumber for $t {
            const SIGNED: bool = $signed;
            fn min_value() -> i128 {
                $min
            }
            fn max_value() -> i128 {
                <$t>::MAX as i128
            }
            fn from_i128(v: i128) -> Self {
                v as $t
            }
        }
    };
}

// ConfigInt uses the full int32 range; the unsigned variants have a minimum
// of 0.
config_number!(i32, true, i32::MIN as i128);
config_number!(u32, false, 0);
config_number!(u64, false, 0);

/// Parses a numeric directive value: `std::stoll` / `std::stoull` plus the
/// range checks of the C++ type, with its error messages.
pub fn parse_config_number<T: ConfigNumber>(a: &str) -> Result<T, String> {
    let val: i128 = match parse_cxx_integer(a, T::SIGNED) {
        CxxInt::Invalid => return Err("Invalid number format (not numeric)".to_string()),
        CxxInt::OutOfRange => return Err("Number out of range".to_string()),
        CxxInt::Value(v) => v,
    };
    if val > T::max_value() {
        return Err("Value is too big.".to_string());
    }
    if val < T::min_value() {
        return Err("Value is too small.".to_string());
    }
    Ok(T::from_i128(val))
}

enum CxxInt {
    Invalid,
    OutOfRange,
    Value(i128),
}

/// `std::stoll` / `std::stoull` semantics: leading white space, optional
/// sign, decimal digits, trailing garbage ignored. `stoull` accepts a minus
/// sign and negates modulo 2^64.
fn parse_cxx_integer(a: &str, signed: bool) -> CxxInt {
    let s = a.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, rest) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return CxxInt::Invalid;
    }
    let Ok(mag) = digits.parse::<u128>() else {
        return CxxInt::OutOfRange;
    };
    if signed {
        let v: i128 = if neg { -(mag as i128) } else { mag as i128 };
        if v > i64::MAX as i128 || v < i64::MIN as i128 {
            return CxxInt::OutOfRange;
        }
        CxxInt::Value(v)
    } else {
        if mag > u64::MAX as u128 {
            return CxxInt::OutOfRange;
        }
        let v = if neg { (mag as u64).wrapping_neg() } else { mag as u64 };
        CxxInt::Value(v as i128)
    }
}

/// Parses a file mode (`SecUploadFileMode`) in octal: "0640" is 0640.
pub fn parse_octal_mode(a: &str) -> Result<u32, String> {
    if a.is_empty() || a.bytes().any(|c| !(b'0'..=b'7').contains(&c)) {
        return Err("Invalid octal number".to_string());
    }
    let first = a.find(|c| c != '0').unwrap_or(a.len());
    let start = first.min(a.len() - 1);
    let digits = &a[start..];
    if digits.len() > 11 {
        return Err("Value is too big.".to_string());
    }
    let v = u64::from_str_radix(digits, 8).unwrap_or(0);
    parse_config_number(&v.to_string())
}

/// A set of strings configured by directives (`SecResponseBodyMimeType`);
/// `clear` records `SecResponseBodyMimeTypesClear`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigSet {
    pub set: bool,
    pub clear: bool,
    pub value: BTreeSet<String>,
}

/// The map of `SecUnicodeMapFile` (used by `t:urlDecodeUni`).
pub use modsecurity_transformations::UnicodeMap as UnicodeMapHolder;

/// `SecUnicodeMapFile`: the code page and its map, when set.
#[derive(Debug, Clone, Default)]
pub struct ConfigUnicodeMap {
    pub set: bool,
    pub unicode_code_page: u32,
    pub unicode_map_table: Option<Arc<UnicodeMapHolder>>,
}

const CODEPAGE_SEPARATORS: &[u8] = b" \t\n\r";

impl ConfigUnicodeMap {
    pub fn merge(&mut self, from: &ConfigUnicodeMap) {
        if !from.set {
            return;
        }
        self.set = true;
        self.unicode_code_page = from.unicode_code_page;
        self.unicode_map_table = from.unicode_map_table.clone();
    }

    /// Loads the mapping for `code_page` from a `unicode.mapping` file
    /// into `driver`.
    pub fn load_config(f: &str, config_code_page: u32, driver: &mut RulesSetProperties) -> Result<(), String> {
        driver.unicode_map_table.set = true;
        driver.unicode_map_table.unicode_code_page = config_code_page;
        let mut table = UnicodeMapHolder::default();
        // http://tools.ietf.org/html/rfc3490#section-3.1
        table.change(0x3002, 0x2e);
        table.change(0xff61, 0x2e);
        table.change(0xff0e, 0x2e);
        table.change(0x002e, 0x2e);
        let fail = || format!("Failed to open the unicode map file from: {} ", f);
        let buf = match std::fs::read(f) {
            Ok(b) => b,
            Err(_) => {
                driver.unicode_map_table.unicode_map_table = Some(Arc::new(table));
                return Err(fail());
            }
        };
        if buf.is_empty() {
            driver.unicode_map_table.unicode_map_table = Some(Arc::new(table));
            return Err(fail());
        }
        let mut found = false;
        let mut processing = false;
        // The C++ code reads the file as a C string: it ends at a NUL byte.
        let buf = modsecurity_compat::chars::c_str(&buf);
        for p in buf.split(|c| CODEPAGE_SEPARATORS.contains(c)).filter(|t| !t.is_empty()) {
            let codepage = crate::utils::string::atoi(p) as u32;
            if codepage == config_code_page {
                found = true;
            }
            let has_colon = p.contains(&b':');
            if found && has_colon {
                processing = true;
                // `strtok_r(mapping, ":", &hmap)`: the code is what follows
                // the leading colons, up to the next one; the map is the
                // rest. Both are `(int) strtol(.., 16)`.
                let start = p.iter().position(|&c| c != b':').unwrap_or(p.len());
                let end = p[start..].iter().position(|&c| c == b':').map_or(p.len(), |n| start + n);
                let (ucode, hmap) = (&p[start..end], p.get(end + 1..).unwrap_or_default());
                // Only colons: C++ passes a null pointer to strtol here.
                if !ucode.is_empty() {
                    let code = strtoll(ucode, 16).value as i32;
                    let map = strtoll(hmap, 16).value as i32;
                    if (0..=65535).contains(&code) {
                        table.change(code as usize, map);
                    }
                }
            }
            if processing && !has_colon {
                break;
            }
        }
        driver.unicode_map_table.unicode_map_table = Some(Arc::new(table));
        Ok(())
    }
}

/// `SecParseXmlIntoArgs`: whether the XML body is also parsed into
/// `ARGS` (the C++ `ConfigXMLParseXmlIntoArgs` without its not-set state,
/// which is `None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseXmlIntoArgs {
    On,
    Off,
    OnlyArgs,
}

/// The state of the rule engine (`SecRuleEngine`, `ctl:ruleEngine`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEngine {
    /// Rules won't be evaluated if Rule Engine is set to Disabled
    Disabled,
    /// Rules will be evaluated and disturb actions will take place if needed.
    Enabled,
    /// Rules will be evaluated but it won't generate any disruptive action.
    DetectionOnly,
}

/// Defines what actions should be taken in case the body (response or
/// request) is bigger than the expected size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLimitAction {
    /// Process partial
    ProcessPartial,
    /// Reject the request
    Reject,
}

/// Defines what actions should be taken in case the remote rules failed to
/// be downloaded (independent of the circumstances). When not configured
/// the failure is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFailedRemoteRulesAction {
    Abort,
    Warn,
}

/// The name of a rule engine state as the logs print it (`None` is the
/// C++ not-set state).
pub fn rule_engine_state_string(i: Option<RuleEngine>) -> &'static str {
    match i {
        Some(RuleEngine::Disabled) => "Disabled",
        Some(RuleEngine::Enabled) => "Enabled",
        Some(RuleEngine::DetectionOnly) => "DetectionOnly",
        None => "PropertyNotSet/DetectionOnly",
    }
}

/// The value of the C++ `ConfigBoolean` enumerator (`True`, `False`,
/// `NotSet`), which some debug messages print as a number.
pub fn config_boolean_code(i: Option<bool>) -> i32 {
    match i {
        Some(true) => 0,
        Some(false) => 1,
        None => 2,
    }
}

pub fn config_xml_parse_xml_into_args_string(i: Option<ParseXmlIntoArgs>) -> &'static str {
    match i {
        Some(ParseXmlIntoArgs::On) => "True",
        Some(ParseXmlIntoArgs::Off) => "False",
        Some(ParseXmlIntoArgs::OnlyArgs) => "OnlyArgs",
        None => "Not set",
    }
}

/// Default actions (`SecDefaultAction`) per phase; shared between the
/// driver and every rule set they are merged into.
pub type DefaultActions = [Vec<Arc<RuleAction>>; NUMBER_OF_PHASES];

/// Declares [`Settings`]: its fields and, from the same list, the merge of
/// two of them, so that a setting cannot be added without being merged.
macro_rules! settings {
    ($($(#[$doc:meta])* $name:ident: $ty:ty,)*) => {
        /// The settings a configuration gives a single value to. Each is
        /// `None` until its directive sets it; when configurations are
        /// merged, the value already set wins ([`Settings::merge_unset`]).
        #[derive(Default)]
        pub struct Settings {
            $($(#[$doc])* pub $name: Option<$ty>,)*
        }

        impl Settings {
            /// Takes from `from` the settings that are not set here.
            pub fn merge_unset(&mut self, from: &Settings) {
                $(if self.$name.is_none() {
                    self.$name.clone_from(&from.$name);
                })*
            }
        }
    };
}

settings! {
    /// `SecRuleEngine`.
    sec_rule_engine: RuleEngine,
    /// `SecRequestBodyAccess`.
    sec_request_body_access: bool,
    /// `SecResponseBodyAccess`.
    sec_response_body_access: bool,
    /// `SecXmlExternalEntity`.
    sec_xml_external_entity: bool,
    /// `SecParseXmlIntoArgs`.
    sec_xml_parse_xml_into_args: ParseXmlIntoArgs,
    /// `SecUploadKeepFiles`.
    upload_keep_files: bool,
    /// `SecTmpSaveUploadedFiles`.
    tmp_save_uploaded_files: bool,
    /// `SecArgumentsLimit`.
    arguments_limit: u32,
    /// `SecRequestBodyJsonDepthLimit`.
    request_body_json_depth_limit: u32,
    /// `SecRequestBodyLimit`.
    request_body_limit: u64,
    /// `SecRequestBodyNoFilesLimit`.
    request_body_no_files_limit: u64,
    /// `SecResponseBodyLimit`.
    response_body_limit: u64,
    /// `SecRequestBodyLimitAction`.
    request_body_limit_action: BodyLimitAction,
    /// `SecResponseBodyLimitAction`.
    response_body_limit_action: BodyLimitAction,
    /// `SecPcreMatchLimit`.
    pcre_match_limit: u32,
    /// `SecUploadFileLimit`.
    upload_file_limit: u32,
    /// `SecUploadFileMode` (octal).
    upload_file_mode: u32,
    /// `SecUploadDir`.
    upload_directory: String,
    /// `SecTmpDir`.
    upload_tmp_directory: String,
    /// `SecArgumentSeparator`.
    sec_argument_separator: String,
    /// `SecWebAppId`.
    sec_web_app_id: String,
    /// `SecHttpBlKey`.
    httpbl_key: String,
    /// `SecGeoLookupDb`: shared with the rule sets this one is merged into.
    geo_db: Arc<GeoDb>,
}

pub struct RulesSetProperties {
    /// The single valued settings.
    pub settings: Settings,
    pub audit_log: AuditLog,
    pub debug_log: Box<dyn DebugLog>,
    pub remote_rules_action_on_failed: Option<OnFailedRemoteRulesAction>,
    pub exceptions: RulesExceptions,
    pub components: Vec<String>,
    pub parser_error: String,
    pub response_body_type_to_be_inspected: ConfigSet,
    pub default_actions: DefaultActions,
    pub unicode_map_table: ConfigUnicodeMap,
}

impl Default for RulesSetProperties {
    fn default() -> Self {
        Self::with_debug_log(Box::new(DefaultDebugLog::new()))
    }
}

impl RulesSetProperties {
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty properties that write the debug log to `debug_log`.
    pub fn with_debug_log(debug_log: Box<dyn DebugLog>) -> Self {
        RulesSetProperties {
            settings: Settings::default(),
            audit_log: AuditLog::new(),
            debug_log,
            remote_rules_action_on_failed: None,
            exceptions: RulesExceptions::new(),
            components: Vec::new(),
            parser_error: String::new(),
            response_body_type_to_be_inspected: ConfigSet::default(),
            default_actions: Default::default(),
            unicode_map_table: ConfigUnicodeMap::default(),
        }
    }

    /// `SecWebAppId` (empty when not set).
    pub fn web_app_id(&self) -> &[u8] {
        self.settings.sec_web_app_id.as_deref().unwrap_or_default().as_bytes()
    }

    /// Merges `from` into `to`: values set in `to` win, lists (exceptions,
    /// default actions, ...) are appended. A failure (audit log or debug log
    /// file) stops the merge of the remaining logging properties.
    pub fn merge_properties(from: &mut RulesSetProperties, to: &mut RulesSetProperties) -> Result<(), String> {
        to.settings.merge_unset(&from.settings);
        to.unicode_map_table.merge(&from.unicode_map_table);
        to.exceptions.merge(&from.exceptions);
        to.components.extend(from.components.iter().cloned());

        if from.response_body_type_to_be_inspected.set {
            if from.response_body_type_to_be_inspected.clear {
                to.response_body_type_to_be_inspected.value.clear();
                from.response_body_type_to_be_inspected.value.clear();
            } else {
                for v in from.response_body_type_to_be_inspected.value.iter() {
                    to.response_body_type_to_be_inspected.value.insert(v.clone());
                }
            }
            to.response_body_type_to_be_inspected.set = true;
        }

        for (to, from) in to.default_actions.iter_mut().zip(&from.default_actions) {
            to.extend(from.iter().cloned());
        }

        // A failure C++ does not report leaves the configuration accepted.
        if let Err(SetupError::Reported(e)) = to.audit_log.merge(&from.audit_log) {
            return Err(e);
        }

        if let (Some(file), None) = (from.debug_log.file(), to.debug_log.file()) {
            to.debug_log.set_file(file)?;
        }

        if let (Some(level), None) = (from.debug_log.level(), to.debug_log.level()) {
            to.debug_log.set_level(level);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_value_parse() {
        assert_eq!(parse_config_number::<u32>("10"), Ok(10));
        assert_eq!(parse_config_number::<u32>("99999999999").unwrap_err(), "Value is too big.");
        assert_eq!(parse_config_number::<u32>("x").unwrap_err(), "Invalid number format (not numeric)");
        assert_eq!(parse_config_number::<u64>("99999999999999999999999").unwrap_err(), "Number out of range");
        // std::stoull negates modulo 2^64.
        assert_eq!(parse_config_number::<u64>(" -1"), Ok(u64::MAX));
        assert_eq!(parse_octal_mode("0640"), Ok(0o640));
        assert_eq!(parse_octal_mode("08").unwrap_err(), "Invalid octal number");
    }

    /// The entries of a unicode map are read as C++ reads them:
    /// `strtok_r(.., ":")` and `(int) strtol(.., 16)` (each case below was
    /// compared with the C++ library).
    #[test]
    fn unicode_map_entries() {
        let dir = std::env::temp_dir().join(format!("msrs-unicode-map-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("map.txt");
        let table = |entries: &str| {
            std::fs::write(&file, format!("9999 (test)\n{entries}\n\n")).unwrap();
            let mut properties = RulesSetProperties::new();
            ConfigUnicodeMap::load_config(file.to_str().unwrap(), 9999, &mut properties).unwrap();
            properties.unicode_map_table.unicode_map_table.unwrap()
        };
        let at = |entries: &str, code: usize| table(entries).at(code);

        assert_eq!(at("0041:42", 0x41), 0x42);
        assert_eq!(at("0x41:0x42 +43:44", 0x41), 0x42);
        assert_eq!(at("0x41:0x42 +43:44", 0x43), 0x44);
        // A negative or overflowing code is out of range: no entry (they
        // used to be read as code 0).
        assert_eq!(at("-41:42", 0), -1);
        assert_eq!(at("fffffffffffffffff:43", 0), -1);
        // A negative map is stored as it is; an overflowing one is
        // `(int) LONG_MAX`, -1, which reads as "not mapped" (both used to
        // be 0).
        assert_eq!(at("0041:-42", 0x41), -0x42);
        assert_eq!(at("0041:fffffffffffffffff", 0x41), -1);
        // Leading colons are skipped: `:42` is the code 0x42 without a map
        // (it used to be code 0 mapped to 0x42).
        assert_eq!(at(":42", 0x42), 0);
        assert_eq!(at(":42", 0), -1);
        // Text that is not a number is 0, as before.
        assert_eq!(at("zz:42", 0), 0x42);
        assert_eq!(at("41:", 0x41), 0);
        // Only colons (C++ crashes): ignored.
        assert_eq!(at("::: 0041:42", 0x41), 0x42);
        // The file ends at a NUL byte, as a C string.
        assert_eq!(at("0041:42\0 0043:44", 0x43), -1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn merge_keeps_values_set_in_to() {
        let mut from = RulesSetProperties::new();
        let mut to = RulesSetProperties::new();
        from.settings.sec_rule_engine = Some(RuleEngine::Enabled);
        from.settings.request_body_limit = Some(10);
        from.settings.sec_web_app_id = Some("a".into());
        to.settings.request_body_limit = Some(20);
        RulesSetProperties::merge_properties(&mut from, &mut to).unwrap();
        assert_eq!(to.settings.sec_rule_engine, Some(RuleEngine::Enabled));
        assert_eq!(to.settings.request_body_limit, Some(20));
        assert_eq!(to.web_app_id(), b"a");
        assert_eq!(RulesSetProperties::new().web_app_id(), b"");

        // Every setting is merged (they are declared once, with the merge).
        let mut all = Settings::default();
        all.merge_unset(&from.settings);
        assert_eq!(all.sec_rule_engine, Some(RuleEngine::Enabled));
        assert_eq!(all.request_body_limit, Some(10));
        // `SecRemoteRulesFailAction` is not one of them: it is not merged,
        // as in C++.
        let mut from = RulesSetProperties::new();
        from.remote_rules_action_on_failed = Some(OnFailedRemoteRulesAction::Warn);
        let mut to = RulesSetProperties::new();
        RulesSetProperties::merge_properties(&mut from, &mut to).unwrap();
        assert!(to.remote_rules_action_on_failed.is_none());
    }

    #[test]
    fn c_display_values() {
        // The C++ enumerator values and texts printed in the logs.
        assert_eq!([Some(true), Some(false), None].map(config_boolean_code), [0, 1, 2]);
        assert_eq!(rule_engine_state_string(None), "PropertyNotSet/DetectionOnly");
        assert_eq!(config_xml_parse_xml_into_args_string(Some(ParseXmlIntoArgs::On)), "True");
    }
}
