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

/// `ConfigValue<T>`: an optional numeric configuration value with range
/// checking (`ConfigInt`, `ConfigUnsignedInt`, `ConfigUnsignedLong`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConfigValue<T> {
    pub set: bool,
    pub value: T,
}

/// Numeric types usable in [`ConfigValue`], with the range of the C++
/// specialisation.
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

impl<T: ConfigNumber> ConfigValue<T> {
    pub fn merge(&mut self, from: &ConfigValue<T>) {
        if self.set || !from.set {
            return;
        }
        self.set = true;
        self.value = from.value;
    }

    /// The default parser (`std::stoll`/`std::stoull` plus range checks).
    pub fn parse(&mut self, a: &str) -> Result<(), String> {
        let parsed = parse_cxx_integer(a, T::SIGNED);
        let val: i128 = match parsed {
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
        self.value = T::from_i128(val);
        self.set = true;
        Ok(())
    }
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

pub type ConfigInt = ConfigValue<i32>;
pub type ConfigUnsignedInt = ConfigValue<u32>;
pub type ConfigUnsignedLong = ConfigValue<u64>;

/// `ConfigOctalInt`: file modes (`SecUploadFileMode`): "0640" is 0640.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConfigOctalInt(pub ConfigUnsignedInt);

impl ConfigOctalInt {
    pub fn parse(&mut self, a: &str) -> Result<(), String> {
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
        self.0.parse(&v.to_string())
    }

    pub fn merge(&mut self, from: &ConfigOctalInt) {
        self.0.merge(&from.0);
    }

    pub fn set(&self) -> bool {
        self.0.set
    }

    pub fn value(&self) -> u32 {
        self.0.value
    }
}

/// `ConfigString`
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigString {
    pub set: bool,
    pub value: String,
}

impl ConfigString {
    pub fn merge(&mut self, from: &ConfigString) {
        if self.set || !from.set {
            return;
        }
        self.set = true;
        self.value = from.value.clone();
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

/// The ConfigBoolean enumerator defines the states for configuration boolean
/// values. The default value is `PropertyNotSetConfigBoolean`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigBoolean {
    TrueConfigBoolean,
    FalseConfigBoolean,
    PropertyNotSetConfigBoolean,
}

/// States for `SecParseXmlIntoArgs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigXMLParseXmlIntoArgs {
    TrueConfigXMLParseXmlIntoArgs,
    FalseConfigXMLParseXmlIntoArgs,
    OnlyArgsConfigXMLParseXmlIntoArgs,
    PropertyNotSetConfigXMLParseXmlIntoArgs,
}

/// The RuleEngine enumerator consists in mapping the different states of the
/// rule engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEngine {
    /// Rules won't be evaluated if Rule Engine is set to DisabledRuleEngine
    DisabledRuleEngine,
    /// Rules will be evaluated and disturb actions will take place if needed.
    EnabledRuleEngine,
    /// Rules will be evaluated but it won't generate any disruptive action.
    DetectionOnlyRuleEngine,
    PropertyNotSetRuleEngine,
}

/// Defines what actions should be taken in case the body (response or
/// request) is bigger than the expected size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLimitAction {
    /// Process partial
    ProcessPartialBodyLimitAction,
    /// Reject the request
    RejectBodyLimitAction,
    PropertyNotSetBodyLimitAction,
}

/// Defines what actions should be taken in case the remote rules failed to
/// be downloaded (independent of the circumstances).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFailedRemoteRulesAction {
    AbortOnFailedRemoteRulesAction,
    WarnOnFailedRemoteRulesAction,
    PropertyNotSetRemoteRulesAction,
}

pub fn rule_engine_state_string(i: RuleEngine) -> &'static str {
    match i {
        RuleEngine::DisabledRuleEngine => "Disabled",
        RuleEngine::EnabledRuleEngine => "Enabled",
        RuleEngine::DetectionOnlyRuleEngine => "DetectionOnly",
        RuleEngine::PropertyNotSetRuleEngine => "PropertyNotSet/DetectionOnly",
    }
}

pub fn config_boolean_string(i: ConfigBoolean) -> &'static str {
    match i {
        ConfigBoolean::TrueConfigBoolean => "True",
        ConfigBoolean::FalseConfigBoolean => "False",
        ConfigBoolean::PropertyNotSetConfigBoolean => "Not set",
    }
}

pub fn config_xml_parse_xml_into_args_string(i: ConfigXMLParseXmlIntoArgs) -> &'static str {
    match i {
        ConfigXMLParseXmlIntoArgs::TrueConfigXMLParseXmlIntoArgs => "True",
        ConfigXMLParseXmlIntoArgs::FalseConfigXMLParseXmlIntoArgs => "False",
        ConfigXMLParseXmlIntoArgs::OnlyArgsConfigXMLParseXmlIntoArgs => "OnlyArgs",
        ConfigXMLParseXmlIntoArgs::PropertyNotSetConfigXMLParseXmlIntoArgs => "Not set",
    }
}

/// Default actions (`SecDefaultAction`) per phase; shared between the
/// driver and every rule set they are merged into.
pub type DefaultActions = [Vec<Arc<dyn Action>>; NUMBER_OF_PHASES];

pub struct RulesSetProperties {
    pub audit_log: AuditLog,
    pub request_body_limit_action: BodyLimitAction,
    pub response_body_limit_action: BodyLimitAction,
    pub sec_request_body_access: ConfigBoolean,
    pub sec_response_body_access: ConfigBoolean,
    pub sec_xml_external_entity: ConfigBoolean,
    pub sec_xml_parse_xml_into_args: ConfigXMLParseXmlIntoArgs,
    pub tmp_save_uploaded_files: ConfigBoolean,
    pub upload_keep_files: ConfigBoolean,
    pub arguments_limit: ConfigUnsignedInt,
    pub request_body_json_depth_limit: ConfigUnsignedInt,
    pub request_body_limit: ConfigUnsignedLong,
    pub request_body_no_files_limit: ConfigUnsignedLong,
    pub response_body_limit: ConfigUnsignedLong,
    pub pcre_match_limit: ConfigUnsignedInt,
    pub upload_file_limit: ConfigUnsignedInt,
    pub upload_file_mode: ConfigOctalInt,
    pub debug_log: Box<dyn DebugLog>,
    pub remote_rules_action_on_failed: OnFailedRemoteRulesAction,
    pub sec_rule_engine: RuleEngine,
    pub exceptions: RulesExceptions,
    pub components: Vec<String>,
    pub parser_error: String,
    pub response_body_type_to_be_inspected: ConfigSet,
    pub httpbl_key: ConfigString,
    pub upload_directory: ConfigString,
    pub upload_tmp_directory: ConfigString,
    pub sec_argument_separator: ConfigString,
    pub sec_web_app_id: ConfigString,
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
            request_body_limit_action: BodyLimitAction::PropertyNotSetBodyLimitAction,
            response_body_limit_action: BodyLimitAction::PropertyNotSetBodyLimitAction,
            sec_request_body_access: ConfigBoolean::PropertyNotSetConfigBoolean,
            sec_response_body_access: ConfigBoolean::PropertyNotSetConfigBoolean,
            sec_xml_external_entity: ConfigBoolean::PropertyNotSetConfigBoolean,
            sec_xml_parse_xml_into_args: ConfigXMLParseXmlIntoArgs::PropertyNotSetConfigXMLParseXmlIntoArgs,
            tmp_save_uploaded_files: ConfigBoolean::PropertyNotSetConfigBoolean,
            upload_keep_files: ConfigBoolean::PropertyNotSetConfigBoolean,
            arguments_limit: ConfigUnsignedInt::default(),
            request_body_json_depth_limit: ConfigUnsignedInt::default(),
            request_body_limit: ConfigUnsignedLong::default(),
            request_body_no_files_limit: ConfigUnsignedLong::default(),
            response_body_limit: ConfigUnsignedLong::default(),
            pcre_match_limit: ConfigUnsignedInt::default(),
            upload_file_limit: ConfigUnsignedInt::default(),
            upload_file_mode: ConfigOctalInt::default(),
            debug_log,
            remote_rules_action_on_failed: OnFailedRemoteRulesAction::PropertyNotSetRemoteRulesAction,
            sec_rule_engine: RuleEngine::PropertyNotSetRuleEngine,
            exceptions: RulesExceptions::new(),
            components: Vec::new(),
            parser_error: String::new(),
            response_body_type_to_be_inspected: ConfigSet::default(),
            httpbl_key: ConfigString::default(),
            upload_directory: ConfigString::default(),
            upload_tmp_directory: ConfigString::default(),
            sec_argument_separator: ConfigString::default(),
            sec_web_app_id: ConfigString::default(),
            default_actions: Default::default(),
            unicode_map_table: ConfigUnicodeMap::default(),
        }
    }

    /// `mergeProperties(from, to, err)`
    pub fn merge_properties(from: &mut RulesSetProperties, to: &mut RulesSetProperties, err: &mut String) -> i32 {
        fn merge_enum<T: PartialEq + Copy>(to: &mut T, from: T, not_set: T) {
            if *to == not_set && from != not_set {
                *to = from;
            }
        }
        merge_enum(&mut to.sec_rule_engine, from.sec_rule_engine, RuleEngine::PropertyNotSetRuleEngine);
        merge_enum(
            &mut to.sec_request_body_access,
            from.sec_request_body_access,
            ConfigBoolean::PropertyNotSetConfigBoolean,
        );
        merge_enum(
            &mut to.sec_response_body_access,
            from.sec_response_body_access,
            ConfigBoolean::PropertyNotSetConfigBoolean,
        );
        merge_enum(
            &mut to.sec_xml_external_entity,
            from.sec_xml_external_entity,
            ConfigBoolean::PropertyNotSetConfigBoolean,
        );
        merge_enum(
            &mut to.sec_xml_parse_xml_into_args,
            from.sec_xml_parse_xml_into_args,
            ConfigXMLParseXmlIntoArgs::PropertyNotSetConfigXMLParseXmlIntoArgs,
        );
        merge_enum(&mut to.upload_keep_files, from.upload_keep_files, ConfigBoolean::PropertyNotSetConfigBoolean);
        merge_enum(
            &mut to.tmp_save_uploaded_files,
            from.tmp_save_uploaded_files,
            ConfigBoolean::PropertyNotSetConfigBoolean,
        );
        to.arguments_limit.merge(&from.arguments_limit);
        to.request_body_json_depth_limit.merge(&from.request_body_json_depth_limit);
        to.request_body_limit.merge(&from.request_body_limit);
        to.request_body_no_files_limit.merge(&from.request_body_no_files_limit);
        to.response_body_limit.merge(&from.response_body_limit);
        merge_enum(
            &mut to.request_body_limit_action,
            from.request_body_limit_action,
            BodyLimitAction::PropertyNotSetBodyLimitAction,
        );
        merge_enum(
            &mut to.response_body_limit_action,
            from.response_body_limit_action,
            BodyLimitAction::PropertyNotSetBodyLimitAction,
        );
        to.pcre_match_limit.merge(&from.pcre_match_limit);
        to.upload_file_limit.merge(&from.upload_file_limit);
        to.upload_file_mode.merge(&from.upload_file_mode);
        to.upload_directory.merge(&from.upload_directory);
        to.upload_tmp_directory.merge(&from.upload_tmp_directory);
        to.sec_argument_separator.merge(&from.sec_argument_separator);
        to.sec_web_app_id.merge(&from.sec_web_app_id);
        to.unicode_map_table.merge(&from.unicode_map_table);
        to.httpbl_key.merge(&from.httpbl_key);
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

        for i in 0..NUMBER_OF_PHASES {
            for a in from.default_actions[i].iter() {
                to.default_actions[i].push(a.clone());
            }
        }

        if let Err(e) = to.audit_log.merge(&from.audit_log)
            && !e.is_empty()
        {
            err.push_str(&e);
            return -1;
        }

        if from.debug_log.is_log_file_set() && !to.debug_log.is_log_file_set() {
            let mut error = String::new();
            let f = from.debug_log.get_debug_log_file().to_string();
            to.debug_log.set_debug_log_file(&f, &mut error);
            if !error.is_empty() {
                err.push_str(&error);
                return -1;
            }
        }

        if from.debug_log.is_log_level_set() && !to.debug_log.is_log_level_set() {
            to.debug_log.set_debug_log_level(from.debug_log.get_debug_log_level());
        }

        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_value_parse() {
        let mut v = ConfigUnsignedInt::default();
        assert!(v.parse("10").is_ok());
        assert_eq!(v.value, 10);
        assert_eq!(v.parse("99999999999").unwrap_err(), "Value is too big.");
        assert_eq!(v.parse("x").unwrap_err(), "Invalid number format (not numeric)");
        let mut l = ConfigUnsignedLong::default();
        assert_eq!(l.parse("99999999999999999999999").unwrap_err(), "Number out of range");
        let mut o = ConfigOctalInt::default();
        assert!(o.parse("0640").is_ok());
        assert_eq!(o.value(), 0o640);
        assert_eq!(o.parse("08").unwrap_err(), "Invalid octal number");
    }
}
