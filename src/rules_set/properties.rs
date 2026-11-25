//! The configuration of a rule set: the values set by the SecLang
//! directives.
//!
//! The parser's `Driver` and the [`RulesSet`](super::RulesSet) each hold a
//! [`RulesSetProperties`]; [`RulesSetProperties::merge_properties`] merges
//! one into the other.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::actions::rule_action::RuleAction;
use crate::audit_log::{AuditLog, SetupError};
use crate::debug_log::{DebugLog, DefaultDebugLog};
use crate::phases::NUMBER_OF_PHASES;
use crate::rules_set::exceptions::RulesExceptions;
use modsecurity_operators::geo_lookup::GeoDb;

/// The number of a numeric directive (`SecRequestBodyLimit 131072`):
/// decimal digits that fit `T`.
pub fn parse_config_number<T: std::str::FromStr>(a: &str) -> Result<T, String> {
    if a.is_empty() || !a.bytes().all(|c| c.is_ascii_digit()) {
        return Err("Invalid number format (not numeric)".to_string());
    }
    a.parse().map_err(|_| "Value is too big.".to_string())
}

/// A file mode (`SecUploadFileMode 0640`): octal digits that fit a `u32`.
pub fn parse_octal_mode(a: &str) -> Result<u32, String> {
    if a.is_empty() || a.bytes().any(|c| !(b'0'..=b'7').contains(&c)) {
        return Err("Invalid octal number".to_string());
    }
    u32::from_str_radix(a, 8).map_err(|_| "Value is too big.".to_string())
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

    /// Loads the map of the code page `config_code_page` from the file `f`
    /// (`unicode.mapping`) into `driver`. A file that cannot be read or is
    /// empty is an error, and leaves a map with only the full stops of RFC
    /// 3490.
    pub fn load_config(f: &str, config_code_page: u32, driver: &mut RulesSetProperties) -> Result<(), String> {
        driver.unicode_map_table.set = true;
        driver.unicode_map_table.unicode_code_page = config_code_page;
        let mut table = UnicodeMapHolder::default();
        // http://tools.ietf.org/html/rfc3490#section-3.1
        table.set(0x3002, 0x2e);
        table.set(0xff61, 0x2e);
        table.set(0xff0e, 0x2e);
        table.set(0x002e, 0x2e);
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
        // The file is a list of code pages: a line with the number of the
        // page and its name, then its entries, `code:byte` in hexadecimal
        // (`00a0:20`), until the next page. An entry that is not two such
        // numbers is ignored.
        let hex16 = |text: &[u8]| std::str::from_utf8(text).ok().and_then(|t| u16::from_str_radix(t, 16).ok());
        let hex8 = |text: &[u8]| std::str::from_utf8(text).ok().and_then(|t| u8::from_str_radix(t, 16).ok());
        let mut in_page = false;
        let mut entries = false;
        for token in buf.split(|c| CODEPAGE_SEPARATORS.contains(c)).filter(|t| !t.is_empty()) {
            match token.iter().position(|&c| c == b':') {
                // The next page begins.
                None if entries => break,
                None => {
                    let number = std::str::from_utf8(token).ok().and_then(crate::utils::string::parse_digits::<u32>);
                    in_page |= number == Some(config_code_page);
                }
                Some(colon) if in_page => {
                    entries = true;
                    if let (Some(code), Some(byte)) = (hex16(&token[..colon]), hex8(&token[colon + 1..])) {
                        table.set(code, byte);
                    }
                }
                Some(_) => {}
            }
        }
        driver.unicode_map_table.unicode_map_table = Some(Arc::new(table));
        Ok(())
    }
}

/// `SecParseXmlIntoArgs`: whether the XML body is also parsed into
/// `ARGS`. A configuration that does not set it holds `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseXmlIntoArgs {
    On,
    Off,
    OnlyArgs,
}

/// The state of the rule engine (`SecRuleEngine`, `ctl:ruleEngine`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEngine {
    /// `Off`: rules are not evaluated.
    Disabled,
    /// `On`: rules are evaluated and their disruptive actions take effect.
    Enabled,
    /// `DetectionOnly`: rules are evaluated, but no disruptive action takes
    /// effect.
    DetectionOnly,
}

/// What to do with a request or response body over its limit
/// (`SecRequestBodyLimitAction`, `SecResponseBodyLimitAction`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLimitAction {
    /// Keep and inspect the body up to the limit.
    ProcessPartial,
    /// Interrupt the transaction with a 403 when the rule engine is `On`.
    Reject,
}

/// What to do when `SecRemoteRules` cannot download its rules
/// (`SecRemoteRulesFailAction`): `Abort` refuses the configuration; `Warn`,
/// like no setting, goes on without those rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFailedRemoteRulesAction {
    Abort,
    Warn,
}

/// The name of a rule engine state as the logs print it (`None`: no
/// directive set it).
pub fn rule_engine_state_string(i: Option<RuleEngine>) -> &'static str {
    match i {
        Some(RuleEngine::Disabled) => "Disabled",
        Some(RuleEngine::Enabled) => "Enabled",
        Some(RuleEngine::DetectionOnly) => "DetectionOnly",
        None => "PropertyNotSet/DetectionOnly",
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
    /// components, ...) are appended. The default actions of a phase come
    /// from one configuration: `to`'s when it has some for that phase,
    /// `from`'s otherwise. A failure (audit log or debug log file) stops the
    /// merge of the remaining logging properties.
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

        // A phase's SecDefaultAction is one list with one disruptive action:
        // two lists put together would run both, and the disruptive action
        // of `from` would be the one `block` uses.
        for (to, from) in to.default_actions.iter_mut().zip(&from.default_actions) {
            if to.is_empty() {
                to.clone_from(from);
            }
        }

        // A `SetupError::Unreported` failure leaves the configuration accepted.
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
        assert_eq!(parse_config_number::<u64>("99999999999999999999999").unwrap_err(), "Value is too big.");
        for not_digits in ["", " 1", "-1", "+1", "1x"] {
            assert!(parse_config_number::<u64>(not_digits).is_err(), "{not_digits:?}");
        }
        assert_eq!(parse_octal_mode("0640"), Ok(0o640));
        assert_eq!(parse_octal_mode("000000000640"), Ok(0o640));
        assert_eq!(parse_octal_mode("08").unwrap_err(), "Invalid octal number");
        assert_eq!(parse_octal_mode("777777777777").unwrap_err(), "Value is too big.");
    }

    /// The entries of the configured code page are read, and only
    /// well-formed ones.
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
        let at = |entries: &str, code: u16| table(entries).get(code);

        assert_eq!(at("0041:42", 0x41), Some(0x42));
        assert_eq!(at("41:42 0043:44", 0x43), Some(0x44));
        assert_eq!(at("0041:42", 0x43), None);
        // The entries of another page are not this page's.
        assert_eq!(at("0041:42\n\n8888 (other)\n0043:44", 0x43), None);
        // An entry that is not `code:byte` in hexadecimal is ignored. (C
        // read each number as far as it could: a sign, a `0x` prefix and
        // trailing text were accepted, and a map above ff was kept.)
        for entry in
            ["-41:42", "0x41:0x42", "0041:-42", "0041:142", "10041:42", "zz:42", "41:", ":42", ":::", "0041:42\0"]
        {
            let table = table(&format!("{entry} 0050:51"));
            assert_eq!((table.get(0x41), table.get(0x42), table.get(0)), (None, None, None), "{entry}");
            assert_eq!(table.get(0x50), Some(0x51), "{entry}");
        }
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
        // and the value of `to` stays.
        let mut from = RulesSetProperties::new();
        from.remote_rules_action_on_failed = Some(OnFailedRemoteRulesAction::Warn);
        let mut to = RulesSetProperties::new();
        RulesSetProperties::merge_properties(&mut from, &mut to).unwrap();
        assert!(to.remote_rules_action_on_failed.is_none());
    }

    #[test]
    fn c_display_values() {
        // The texts printed in the logs.
        assert_eq!(rule_engine_state_string(None), "PropertyNotSet/DetectionOnly");
        assert_eq!(config_xml_parse_xml_into_args_string(Some(ParseXmlIntoArgs::On)), "True");
    }
}
