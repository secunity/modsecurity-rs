//! Port of `headers/modsecurity/rules_set_properties.h` and
//! `src/rules_set_properties.cc`.
//!
//! The configuration state shared by the parser `Driver` and `RulesSet`
//! (both derive from `RulesSetProperties` in C++; both embed it here).

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::actions::action::Action;
use crate::audit_log::audit_log::AuditLog;
use crate::debug_log::debug_log::{DebugLog, DefaultDebugLog};
use crate::modsecurity::NUMBER_OF_PHASES;
use crate::rules_exceptions::RulesExceptions;

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

/// `ConfigValue::parse`: `std::stoll` / `std::stoull` plus the range checks
/// of the C++ type, with its error messages.
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

/// `ConfigOctalInt::parse`: a file mode (`SecUploadFileMode`), "0640" is
/// 0640.
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

/// The C++ `merge` of the optional configuration values: a value set in
/// `to` wins over the one of `from`.
fn merge_value<T: Clone>(to: &mut Option<T>, from: &Option<T>) {
    if to.is_none() {
        to.clone_from(from);
    }
}

/// `ConfigSet`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigSet {
    pub set: bool,
    pub clear: bool,
    pub value: BTreeSet<String>,
}

/// `UnicodeMapHolder`: code point -> mapped byte (-1 when unmapped).
#[derive(Debug, Clone)]
pub struct UnicodeMapHolder {
    pub data: Vec<i32>,
}

impl Default for UnicodeMapHolder {
    fn default() -> Self {
        UnicodeMapHolder { data: vec![-1; 65536] }
    }
}

impl UnicodeMapHolder {
    pub fn at(&self, index: usize) -> i32 {
        self.data[index]
    }

    pub fn change(&mut self, i: usize, a: i32) {
        self.data[i] = a;
    }
}

/// `ConfigUnicodeMap`
#[derive(Debug, Clone, Default)]
pub struct ConfigUnicodeMap {
    pub set: bool,
    pub unicode_code_page: f64,
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

    /// `ConfigUnicodeMap::loadConfig`: loads the mapping for `code_page` from
    /// a `unicode.mapping` file into `driver`.
    pub fn load_config(f: &str, config_code_page: f64, driver: &mut RulesSetProperties) -> Result<(), String> {
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
        for p in buf.split(|c| CODEPAGE_SEPARATORS.contains(c)).filter(|t| !t.is_empty()) {
            let codepage = crate::utils::string::atoi(p) as u32;
            if codepage as f64 == config_code_page {
                found = true;
            }
            let has_colon = p.contains(&b':');
            if found && has_colon {
                processing = true;
                let mut it = p.splitn(2, |&c| c == b':');
                let ucode = it.next().unwrap_or_default();
                let hmap = it.next().unwrap_or_default();
                let code = strtol16(ucode);
                let map = strtol16(hmap);
                if (0..=65535).contains(&code) {
                    table.change(code as usize, map as i32);
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

/// `strtol(s, nullptr, 16)`
fn strtol16(s: &[u8]) -> i64 {
    let s = std::str::from_utf8(s).unwrap_or("");
    let s = s.trim_start();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    let digits: String = s.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    i64::from_str_radix(&digits, 16).unwrap_or(0)
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

/// `RulesSetProperties::ruleEngineStateString` (`None` is the C++ not-set
/// state).
pub fn rule_engine_state_string(i: Option<RuleEngine>) -> &'static str {
    match i {
        Some(RuleEngine::Disabled) => "Disabled",
        Some(RuleEngine::Enabled) => "Enabled",
        Some(RuleEngine::DetectionOnly) => "DetectionOnly",
        None => "PropertyNotSet/DetectionOnly",
    }
}

/// `RulesSetProperties::configBooleanString`
pub fn config_boolean_string(i: Option<bool>) -> &'static str {
    match i {
        Some(true) => "True",
        Some(false) => "False",
        None => "Not set",
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
pub type DefaultActions = [Vec<Arc<dyn Action>>; NUMBER_OF_PHASES];

pub struct RulesSetProperties {
    pub audit_log: AuditLog,
    pub request_body_limit_action: Option<BodyLimitAction>,
    pub response_body_limit_action: Option<BodyLimitAction>,
    pub sec_request_body_access: Option<bool>,
    pub sec_response_body_access: Option<bool>,
    pub sec_xml_external_entity: Option<bool>,
    pub sec_xml_parse_xml_into_args: Option<ParseXmlIntoArgs>,
    pub tmp_save_uploaded_files: Option<bool>,
    pub upload_keep_files: Option<bool>,
    pub arguments_limit: Option<u32>,
    pub request_body_json_depth_limit: Option<u32>,
    pub request_body_limit: Option<u64>,
    pub request_body_no_files_limit: Option<u64>,
    pub response_body_limit: Option<u64>,
    pub pcre_match_limit: Option<u32>,
    pub upload_file_limit: Option<u32>,
    /// `SecUploadFileMode` (octal).
    pub upload_file_mode: Option<u32>,
    pub debug_log: Box<dyn DebugLog>,
    pub remote_rules_action_on_failed: Option<OnFailedRemoteRulesAction>,
    pub sec_rule_engine: Option<RuleEngine>,
    pub exceptions: RulesExceptions,
    pub components: Vec<String>,
    pub parser_error: String,
    pub response_body_type_to_be_inspected: ConfigSet,
    pub httpbl_key: Option<String>,
    pub upload_directory: Option<String>,
    pub upload_tmp_directory: Option<String>,
    pub sec_argument_separator: Option<String>,
    pub sec_web_app_id: Option<String>,
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

    /// `RulesSetProperties(DebugLog *debugLog)`
    pub fn with_debug_log(debug_log: Box<dyn DebugLog>) -> Self {
        RulesSetProperties {
            audit_log: AuditLog::new(),
            request_body_limit_action: None,
            response_body_limit_action: None,
            sec_request_body_access: None,
            sec_response_body_access: None,
            sec_xml_external_entity: None,
            sec_xml_parse_xml_into_args: None,
            tmp_save_uploaded_files: None,
            upload_keep_files: None,
            arguments_limit: None,
            request_body_json_depth_limit: None,
            request_body_limit: None,
            request_body_no_files_limit: None,
            response_body_limit: None,
            pcre_match_limit: None,
            upload_file_limit: None,
            upload_file_mode: None,
            debug_log,
            remote_rules_action_on_failed: None,
            sec_rule_engine: None,
            exceptions: RulesExceptions::new(),
            components: Vec::new(),
            parser_error: String::new(),
            response_body_type_to_be_inspected: ConfigSet::default(),
            httpbl_key: None,
            upload_directory: None,
            upload_tmp_directory: None,
            sec_argument_separator: None,
            sec_web_app_id: None,
            default_actions: Default::default(),
            unicode_map_table: ConfigUnicodeMap::default(),
        }
    }

    /// `SecWebAppId` (empty when not set).
    pub fn web_app_id(&self) -> &[u8] {
        self.sec_web_app_id.as_deref().unwrap_or_default().as_bytes()
    }

    /// `mergeProperties(from, to, err)`. A failure (audit log or debug log
    /// file) stops the merge of the remaining logging properties.
    pub fn merge_properties(from: &mut RulesSetProperties, to: &mut RulesSetProperties) -> Result<(), String> {
        merge_value(&mut to.sec_rule_engine, &from.sec_rule_engine);
        merge_value(&mut to.sec_request_body_access, &from.sec_request_body_access);
        merge_value(&mut to.sec_response_body_access, &from.sec_response_body_access);
        merge_value(&mut to.sec_xml_external_entity, &from.sec_xml_external_entity);
        merge_value(&mut to.sec_xml_parse_xml_into_args, &from.sec_xml_parse_xml_into_args);
        merge_value(&mut to.upload_keep_files, &from.upload_keep_files);
        merge_value(&mut to.tmp_save_uploaded_files, &from.tmp_save_uploaded_files);
        merge_value(&mut to.arguments_limit, &from.arguments_limit);
        merge_value(&mut to.request_body_json_depth_limit, &from.request_body_json_depth_limit);
        merge_value(&mut to.request_body_limit, &from.request_body_limit);
        merge_value(&mut to.request_body_no_files_limit, &from.request_body_no_files_limit);
        merge_value(&mut to.response_body_limit, &from.response_body_limit);
        merge_value(&mut to.request_body_limit_action, &from.request_body_limit_action);
        merge_value(&mut to.response_body_limit_action, &from.response_body_limit_action);
        merge_value(&mut to.pcre_match_limit, &from.pcre_match_limit);
        merge_value(&mut to.upload_file_limit, &from.upload_file_limit);
        merge_value(&mut to.upload_file_mode, &from.upload_file_mode);
        merge_value(&mut to.upload_directory, &from.upload_directory);
        merge_value(&mut to.upload_tmp_directory, &from.upload_tmp_directory);
        merge_value(&mut to.sec_argument_separator, &from.sec_argument_separator);
        merge_value(&mut to.sec_web_app_id, &from.sec_web_app_id);
        to.unicode_map_table.merge(&from.unicode_map_table);
        merge_value(&mut to.httpbl_key, &from.httpbl_key);
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

        if let Err(e) = to.audit_log.merge(&from.audit_log)
            && !e.is_empty()
        {
            return Err(e);
        }

        if from.debug_log.is_log_file_set() && !to.debug_log.is_log_file_set() {
            let f = from.debug_log.get_debug_log_file().to_string();
            to.debug_log.set_debug_log_file(&f)?;
        }

        if from.debug_log.is_log_level_set() && !to.debug_log.is_log_level_set() {
            to.debug_log.set_debug_log_level(from.debug_log.get_debug_log_level());
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

    #[test]
    fn merge_keeps_values_set_in_to() {
        let mut from = RulesSetProperties::new();
        let mut to = RulesSetProperties::new();
        from.sec_rule_engine = Some(RuleEngine::Enabled);
        from.request_body_limit = Some(10);
        from.sec_web_app_id = Some("a".into());
        to.request_body_limit = Some(20);
        RulesSetProperties::merge_properties(&mut from, &mut to).unwrap();
        assert_eq!(to.sec_rule_engine, Some(RuleEngine::Enabled));
        assert_eq!(to.request_body_limit, Some(20));
        assert_eq!(to.web_app_id(), b"a");
        assert_eq!(RulesSetProperties::new().web_app_id(), b"");
    }

    #[test]
    fn c_display_values() {
        // The C++ enumerator values and texts printed in the logs.
        assert_eq!([Some(true), Some(false), None].map(config_boolean_code), [0, 1, 2]);
        assert_eq!([Some(true), Some(false), None].map(config_boolean_string), ["True", "False", "Not set"]);
        assert_eq!(rule_engine_state_string(None), "PropertyNotSet/DetectionOnly");
        assert_eq!(config_xml_parse_xml_into_args_string(Some(ParseXmlIntoArgs::On)), "True");
    }
}
