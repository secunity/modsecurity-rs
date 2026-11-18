//! The setting directives: every directive that is a keyword and a value
//! (`SecRuleEngine On`, `SecAuditLog /var/log/audit.log`, `Include
//! rules/*.conf`).
//!
//! [`directive`] has one entry per directive: how its value is written
//! (the patterns of the `modsecurity-seclang` crate's `value` module, or a
//! choice of words) and what it does.

use crate::audit_log::{AuditLogFormat, AuditLogStatus, AuditLogType};
use crate::parser::build::{Builder, Failed, Res, load};
use crate::parser::syntax;
use crate::parser::syntax::value::{
    self, Class::*, Extract, Extract::*, Pattern, Pattern::*, Refused, remove_brackets_if_needed,
};
use crate::rules_set::properties::{
    BodyLimitAction, ConfigUnicodeMap, OnFailedRemoteRulesAction, ParseXmlIntoArgs, RuleEngine, parse_config_number,
    parse_octal_mode,
};
use crate::utils::https_client::HttpsClient;
use crate::utils::string::{atoi, ssplit, strtol_int};
use crate::utils::system::{expand_env, find_resource};

/// The value of a setting directive, as its effect gets it.
struct Given<'a> {
    /// The value as the C++ scanner hands it over; for a choice of words,
    /// the word chosen.
    bytes: Vec<u8>,
    /// `bytes` as text.
    text: String,
    /// The text after the keyword that the value was read from.
    token: &'a [u8],
    /// Which of the directive's patterns the value was written as.
    pattern: usize,
}

impl Given<'_> {
    /// Whether the word chosen is `word`.
    fn is(&self, word: &str) -> bool {
        self.text.eq_ignore_ascii_case(word)
    }
}

/// How the value of a directive is written.
enum Form {
    /// In one of these ways (in the order of the C++ scanner rules, which
    /// breaks ties).
    Value(&'static [(Pattern, Extract)]),
    /// One of these words (case-insensitive); none for a directive without
    /// a value.
    Word(&'static [&'static str]),
}

type Apply = fn(&mut Builder<'_, '_>, &Given<'_>) -> Res<()>;

/// What a directive does with its value.
enum Effect {
    Apply(Apply),
    /// Accepted and ignored (`SecTmpDir`, `SecDataDir`, ...).
    Ignored,
    /// Rejected with this message (once its value is well formed).
    Unsupported(&'static str),
}

struct Directive {
    form: Form,
    effect: Effect,
}

const ON_OFF: &[&str] = &["On", "Off"];
const PATH: &[(Pattern, Extract)] = &[(Sep(Path), SanFindSep), (SepQuoted(Path), SanFindSep)];
const NUMBER: &[(Pattern, Extract)] = &[(Sep(Number), FindSep)];
const FREE_TEXT_LINE: &[(Pattern, Extract)] = &[(Sep(FreeTextNewLine), FindSep)];
const FREE_TEXT_LINE_SAN: &[(Pattern, Extract)] =
    &[(Sep(FreeTextNewLine), SanFindSep), (SepQuoted(FreeTextNewLine), SanFindSep)];
/// Text right after the keyword.
const DIRECT: &[(Pattern, Extract)] = &[(Direct(FreeTextNewLine), FindSep)];
const QUOTED_TEXT: &[(Pattern, Extract)] = &[(SepQuoted(FreeText), Strchr2)];
/// A directive that takes no value.
const NOTHING: Form = Form::Word(&[]);

/// A directive with a value.
fn value(patterns: &'static [(Pattern, Extract)], apply: Apply) -> Option<Directive> {
    Some(Directive { form: Form::Value(patterns), effect: Effect::Apply(apply) })
}

/// A directive with a choice of words.
fn word(words: &'static [&'static str], apply: Apply) -> Option<Directive> {
    Some(Directive { form: Form::Word(words), effect: Effect::Apply(apply) })
}

fn ignored(patterns: &'static [(Pattern, Extract)]) -> Option<Directive> {
    Some(Directive { form: Form::Value(patterns), effect: Effect::Ignored })
}

fn unsupported(form: Form, message: &'static str) -> Option<Directive> {
    Some(Directive { form, effect: Effect::Unsupported(message) })
}

/// A switch that can only be off: `On` is rejected with `message`.
fn only_off(b: &mut Builder<'_, '_>, v: &Given<'_>, message: &str) -> Res<()> {
    if v.is("on") { b.fail(message) } else { Ok(()) }
}

fn body_limit_action(v: &Given<'_>) -> BodyLimitAction {
    if v.is("processpartial") { BodyLimitAction::ProcessPartial } else { BodyLimitAction::Reject }
}

/// The directive `keyword` (in any case).
fn directive(keyword: &str) -> Option<Directive> {
    match keyword.to_ascii_lowercase().as_str() {
        // --- Audit log ---------------------------------------------------
        "secauditengine" => word(&["RelevantOnly", "Off", "On"], |b, v| {
            b.driver.properties.audit_log.set_status(if v.is("relevantonly") {
                AuditLogStatus::RelevantOnly
            } else if v.is("off") {
                AuditLogStatus::Off
            } else {
                AuditLogStatus::On
            });
            Ok(())
        }),
        "secauditlog" => value(&[(Sep(Path), FindSep), (SepQuoted(Path), SanFindSep)], |b, v| {
            b.driver.properties.audit_log.set_file_path1(&v.text);
            Ok(())
        }),
        "secauditlog2" => value(&[(Sep(Path), FindSep)], |b, v| {
            b.driver.properties.audit_log.set_file_path2(&v.text);
            Ok(())
        }),
        "secauditlogdirmode" => value(&[(Sep(Number), SanFindSep), (SepQuoted(Number), SanFindSep)], |b, v| {
            b.driver.properties.audit_log.set_storage_dir_mode(strtol_int(&v.text, 8) as u32);
            Ok(())
        }),
        "secauditlogfilemode" => value(NUMBER, |b, v| {
            b.driver.properties.audit_log.set_file_mode(strtol_int(&v.text, 8) as u32);
            Ok(())
        }),
        "secauditlogformat" => word(&["JSON", "Native"], |b, v| {
            let format = if v.is("json") { AuditLogFormat::Json } else { AuditLogFormat::Native };
            b.driver.properties.audit_log.set_format(format);
            Ok(())
        }),
        "secauditlogparts" => value(&[(Sep(AuditParts), SanFindSep), (SepQuoted(AuditParts), SanFindSep)], |b, v| {
            b.driver.properties.audit_log.set_parts(&v.text);
            Ok(())
        }),
        "secauditlogprefix" => value(FREE_TEXT_LINE_SAN, |b, v| {
            b.driver.properties.audit_log.set_prefix(&v.text);
            Ok(())
        }),
        "secauditlogrelevantstatus" => {
            value(&[(Sep(FreeTextNewLine), SanFindSep), (SepQuoted(Word), SanFindSep)], |b, v| {
                b.driver.properties.audit_log.set_relevant_status(&v.text);
                Ok(())
            })
        }
        "secauditlogstoragedir" => value(PATH, |b, v| {
            b.driver.properties.audit_log.set_storage_dir(&v.text);
            Ok(())
        }),
        "secauditlogtype" => word(&["Serial", "Parallel", "Concurrent", "https"], |b, v| {
            b.driver.properties.audit_log.set_type(if v.is("serial") {
                AuditLogType::Serial
            } else if v.is("https") {
                AuditLogType::Https
            } else {
                AuditLogType::Parallel
            });
            Ok(())
        }),

        // --- Debug log ---------------------------------------------------
        "secdebuglog" => value(&[(Sep(Path), FindSep), (SepQuoted(Path), SanFindSep)], |b, v| {
            match b.driver.properties.debug_log.set_file(&v.text) {
                Ok(()) => Ok(()),
                Err(error) => b.fail(&format!("Failed to start DebugLog: {}", error)),
            }
        }),
        "secdebugloglevel" => value(NUMBER, |b, v| {
            b.driver.properties.debug_log.set_level(atoi(&v.bytes));
            Ok(())
        }),

        // --- The engine and what it inspects -------------------------------
        "secruleengine" => word(&["Off", "On", "DetectionOnly"], |b, v| {
            b.driver.properties.settings.sec_rule_engine = Some(if v.is("off") {
                RuleEngine::Disabled
            } else if v.is("on") {
                RuleEngine::Enabled
            } else {
                RuleEngine::DetectionOnly
            });
            Ok(())
        }),
        "secrequestbodyaccess" => word(ON_OFF, |b, v| {
            b.driver.properties.settings.sec_request_body_access = Some(v.is("on"));
            Ok(())
        }),
        "secresponsebodyaccess" => word(ON_OFF, |b, v| {
            b.driver.properties.settings.sec_response_body_access = Some(v.is("on"));
            Ok(())
        }),
        "secresponsebodymimetype" => value(FREE_TEXT_LINE, |b, v| {
            let tokens: std::collections::BTreeSet<&str> = v.text.split_ascii_whitespace().collect();
            let t = &mut b.driver.properties.response_body_type_to_be_inspected;
            t.set = true;
            for it in tokens {
                t.value.insert(it.to_ascii_lowercase());
            }
            Ok(())
        }),
        "secresponsebodymimetypesclear" => word(&[], |b, _| {
            let t = &mut b.driver.properties.response_body_type_to_be_inspected;
            t.set = true;
            t.clear = true;
            t.value.clear();
            Ok(())
        }),
        "secxmlexternalentity" => word(ON_OFF, |b, v| {
            b.driver.properties.settings.sec_xml_external_entity = Some(v.is("on"));
            Ok(())
        }),
        "secparsexmlintoargs" => word(&["OnlyArgs", "Off", "On"], |b, v| {
            b.driver.properties.settings.sec_xml_parse_xml_into_args = Some(if v.is("onlyargs") {
                ParseXmlIntoArgs::OnlyArgs
            } else if v.is("off") {
                ParseXmlIntoArgs::Off
            } else {
                ParseXmlIntoArgs::On
            });
            Ok(())
        }),
        // `[ \t]+FREE_TEXT_NEW_LINE` (`CONGIG_DIR_SEC_ARG_SEP`, an ignored
        // directive of the C++ scanner) wins when it is longer: with a
        // space after the separator.
        "secargumentseparator" => {
            value(&[(SepQuoted(Word), SanFindSep), (Sep(Word), SanFindSep), (Sep(FreeTextNewLine), FindSep)], |b, v| {
                if v.pattern == 2 {
                    return Ok(());
                }
                if v.bytes.len() != 1 {
                    return b.fail("Argument separator should be set to a single character.");
                }
                b.driver.properties.settings.sec_argument_separator = Some(v.text.clone());
                Ok(())
            })
        }
        "seccookieformat" => {
            value(
                NUMBER,
                |b, v| {
                    if atoi(&v.bytes) == 1 { b.fail("SecCookieFormat 1 is not yet supported.") } else { Ok(()) }
                },
            )
        }
        "secunicodemapfile" => value(&[(UnicodeMap, FindSep)], |b, v| b.unicode_map_file(&v.text)),
        "secgeolookupdb" => value(FREE_TEXT_LINE, |b, v| b.geo_lookup_db(&v.text)),
        "sechttpblkey" => value(FREE_TEXT_LINE, |b, v| {
            b.driver.properties.settings.httpbl_key = Some(v.text.clone());
            Ok(())
        }),
        "secwebappid" => value(&[(SepQuoted(FreeText), SanStrchr2), (Sep(FreeTextNewLine), SanFindSep)], |b, v| {
            b.driver.properties.settings.sec_web_app_id = Some(v.text.clone());
            Ok(())
        }),
        "seccomponentsignature" => value(QUOTED_TEXT, |b, v| {
            b.driver.properties.components.push(v.text.clone());
            Ok(())
        }),

        // --- Limits ------------------------------------------------------
        "secargumentslimit" => value(NUMBER, |b, v| {
            b.driver.properties.settings.arguments_limit = Some(atoi(&v.bytes) as u32);
            Ok(())
        }),
        "secrequestbodyjsondepthlimit" => value(NUMBER, |b, v| {
            b.driver.properties.settings.request_body_json_depth_limit = Some(atoi(&v.bytes) as u32);
            Ok(())
        }),
        "secrequestbodylimit" => value(NUMBER, |b, v| match parse_config_number(&v.text) {
            Ok(n) => {
                b.driver.properties.settings.request_body_limit = Some(n);
                Ok(())
            }
            Err(e) => b.fail(&format!("Failed to parse SecRequestBodyLimit: {}", e)),
        }),
        "secrequestbodynofileslimit" => value(NUMBER, |b, v| match parse_config_number(&v.text) {
            Ok(n) => {
                b.driver.properties.settings.request_body_no_files_limit = Some(n);
                Ok(())
            }
            Err(e) => b.fail(&format!("Failed to parse SecRequestsBodyNoFilesLimit: {}", e)),
        }),
        "secresponsebodylimit" => value(NUMBER, |b, v| match parse_config_number(&v.text) {
            Ok(n) => {
                b.driver.properties.settings.response_body_limit = Some(n);
                Ok(())
            }
            Err(e) => b.fail(&format!("Failed to parse SecResponseBodyLimit: {}", e)),
        }),
        "secpcrematchlimit" => value(NUMBER, |b, v| match parse_config_number(&v.text) {
            Ok(n) => {
                b.driver.properties.settings.pcre_match_limit = Some(n);
                Ok(())
            }
            Err(e) => b.fail(&format!("Failed to parse SecPcreMatchLimit: {}", e)),
        }),
        "secrequestbodylimitaction" => word(&["ProcessPartial", "Reject"], |b, v| {
            b.driver.properties.settings.request_body_limit_action = Some(body_limit_action(v));
            Ok(())
        }),
        "secresponsebodylimitaction" => word(&["ProcessPartial", "Reject"], |b, v| {
            b.driver.properties.settings.response_body_limit_action = Some(body_limit_action(v));
            Ok(())
        }),

        // --- Uploads -----------------------------------------------------
        "secuploaddir" => value(PATH, |b, v| {
            b.driver.properties.settings.upload_directory = Some(v.text.clone());
            Ok(())
        }),
        "secuploadfilelimit" => value(NUMBER, |b, v| match parse_config_number(&v.text) {
            Ok(n) => {
                b.driver.properties.settings.upload_file_limit = Some(n);
                Ok(())
            }
            Err(e) => b.fail(&format!("Failed to parse SecUploadFileLimit: {}", e)),
        }),
        "secuploadfilemode" => value(NUMBER, |b, v| match parse_octal_mode(&v.text) {
            Ok(n) => {
                b.driver.properties.settings.upload_file_mode = Some(n);
                Ok(())
            }
            Err(e) => b.fail(&format!("Failed to parse SecUploadFileMode: {}", e)),
        }),
        "secuploadkeepfiles" => word(&["On", "Off", "RelevantOnly"], |b, v| {
            if v.is("relevantonly") {
                return b
                    .fail("SecUploadKeepFiles RelevantOnly is not currently supported. Accepted values are On or Off");
            }
            b.driver.properties.settings.upload_keep_files = Some(v.is("on"));
            Ok(())
        }),
        "sectmpsaveuploadedfiles" => word(ON_OFF, |b, v| {
            b.driver.properties.settings.tmp_save_uploaded_files = Some(v.is("on"));
            Ok(())
        }),

        // --- Rules -------------------------------------------------------
        "secmarker" => value(&[(SepQuoted(Word), FindSep), (Sep(Word), FindSep)], |b, v| {
            let marker = remove_brackets_if_needed(v.text.clone());
            let file = b.file_name();
            b.driver.add_sec_marker(&marker, &file, b.line as i32);
            Ok(())
        }),
        "secruleremovebyid" => {
            value(&[(Sep(FreeTextNewLine), SanFindSep)], |b, v| match b.driver.properties.exceptions.load(&v.text) {
                Ok(()) => Ok(()),
                Err(error) => b.fail(&format!("SecRuleRemoveById: failed to load:{}. {}", v.text, error)),
            })
        }
        "secruleremovebymsg" => value(FREE_TEXT_LINE_SAN, |b, v| {
            b.driver.properties.exceptions.load_remove_rule_by_msg(&v.text);
            Ok(())
        }),
        "secruleremovebytag" => value(FREE_TEXT_LINE_SAN, |b, v| {
            b.driver.properties.exceptions.load_remove_rule_by_tag(&v.text);
            Ok(())
        }),
        "include" => value(&[(Sep(Path), FindSep), (SepQuoted(Path), FindSep)], |b, v| b.include(v.token)),
        "secremoterules" => value(&[(Remote, FindSep)], |b, v| b.remote_rules(&v.text)),
        "secremoterulesfailaction" => word(&["Abort", "Warn"], |b, v| {
            b.driver.properties.remote_rules_action_on_failed =
                Some(if v.is("abort") { OnFailedRemoteRulesAction::Abort } else { OnFailedRemoteRulesAction::Warn });
            Ok(())
        }),

        // --- Accepted without effect -------------------------------------
        // (`SecPcreMatchLimitRecursion` so that modsecurity.conf-recommended
        // loads.)
        "secpcrematchlimitrecursion" | "seccollectiontimeout" => ignored(NUMBER),
        "sectmpdir" | "secdatadir" => ignored(PATH),
        "secstatusengine" => ignored(FREE_TEXT_LINE),

        // --- Switches that can only be off -------------------------------
        "secconnengine" => word(ON_OFF, |b, v| only_off(b, v, "SecConnEngine is not yet supported.")),
        "seccontentinjection" => word(ON_OFF, |b, v| only_off(b, v, "SecContentInjection is not yet supported.")),
        "secdisablebackendcompression" => {
            word(ON_OFF, |b, v| only_off(b, v, "SecDisableBackendCompression is not supported."))
        }
        "sechashengine" => word(ON_OFF, |b, v| only_off(b, v, "SecHashEngine is not yet supported.")),
        "secinterceptonerror" => word(ON_OFF, |b, v| only_off(b, v, "SecInterceptOnError is not yet supported.")),
        "secruleinheritance" => word(ON_OFF, |b, v| only_off(b, v, "SecRuleInheritance is not yet supported.")),

        // --- Not supported -----------------------------------------------
        "seccachetransformations" => unsupported(Form::Value(DIRECT), "SecCacheTransformations is not supported."),
        "secchrootdir" => unsupported(Form::Value(PATH), "SecChrootDir is not supported."),
        "secconnreadstatelimit" => unsupported(Form::Value(DIRECT), "SecConnReadStateLimit is not yet supported."),
        "secconnwritestatelimit" => unsupported(Form::Value(DIRECT), "SecConnWriteStateLimit is not yet supported."),
        "seccookiev0separator" => unsupported(
            Form::Value(&[(SepQuoted(Word), SanFindSep), (Sep(Word), SanFindSep)]),
            "SecCookieV0Separator is not yet supported.",
        ),
        "secgsblookupdb" => unsupported(Form::Value(PATH), "SecGsbLookupDb is not supported."),
        "secguardianlog" => unsupported(NOTHING, "SecGuardianLog is not supported."),
        "sechashkey" => unsupported(NOTHING, "SecHashKey is not yet supported."),
        "sechashmethodpm" => unsupported(NOTHING, "SecHashMethodPm is not yet supported."),
        "sechashmethodrx" => unsupported(NOTHING, "SecHashMethodRx is not yet supported."),
        "sechashparam" => unsupported(NOTHING, "SecHashParam is not yet supported."),
        "secrequestbodyinmemorylimit" => unsupported(
            Form::Value(NUMBER),
            "As of ModSecurity version 3.0, SecRequestBodyInMemoryLimit is no longer supported. Instead, you can use your web server configurations to control those values. ModSecurity will follow the web server decision.",
        ),
        "secruleperftime" => unsupported(Form::Value(NUMBER), "SecRulePerfTime is not yet supported."),
        "secsensorid" => unsupported(Form::Value(DIRECT), "SecSensorId is not yet supported."),
        "secserversignature" => unsupported(Form::Value(QUOTED_TEXT), "SecServerSignature is not supported."),
        "secstreaminbodyinspection" => unsupported(NOTHING, "SecStreamInBodyInspection is not supported."),
        "secstreamoutbodyinspection" => unsupported(NOTHING, "SecStreamOutBodyInspection is not supported."),
        _ => None,
    }
}

impl Builder<'_, '_> {
    /// Applies the directive `keyword`, whose value is in the `rest` of
    /// its line.
    pub(super) fn setting(&mut self, keyword: &str, rest: &str) -> Res<()> {
        let rest = syntax::bytes(rest);
        let lossy = String::from_utf8_lossy;
        let Some(d) = directive(keyword) else {
            return self.fail(&format!("Invalid input: {}{}", keyword, lossy(&rest)));
        };
        let given = match d.form {
            Form::Value(patterns) => value::read(keyword, &rest, patterns).map(|v| Given {
                text: lossy(&v.bytes).into_owned(),
                bytes: v.bytes,
                token: v.token,
                pattern: v.pattern,
            }),
            Form::Word(words) => value::word(&rest, words).map(|w| Given {
                text: w.to_string(),
                bytes: w.as_bytes().to_vec(),
                token: &rest,
                pattern: 0,
            }),
        };
        let given = match given {
            Ok(given) => given,
            Err(Refused::NotAValue(text)) => {
                return self.fail(&format!("Invalid value for {}: {}", keyword, lossy(text)));
            }
            Err(Refused::Trailing(text)) => return self.fail(&format!("Invalid input: {}", lossy(text))),
        };
        match d.effect {
            Effect::Apply(apply) => apply(self, &given),
            Effect::Ignored => Ok(()),
            Effect::Unsupported(message) => self.fail(message),
        }
    }

    /// `SecGeoLookupDb <file>`
    fn geo_lookup_db(&mut self, v: &str) -> Res<()> {
        if !cfg!(feature = "maxmind") {
            return self.fail("This version of ModSecurity was not compiled with GeoIP or MaxMind support.");
        }
        let lookup = find_resource(v, &self.file_name());
        let Some(file) = lookup.path else {
            return self.fail(&format!("Failed to load locate the GeoDB file from: {} {}", v, lookup.looked_at));
        };
        match modsecurity_operators::geo_lookup::GeoDb::open(&file) {
            Ok(db) => self.driver.properties.settings.geo_db = Some(std::sync::Arc::new(db)),
            // A database opened before stays in use, as in C++.
            Err(_) if self.driver.properties.settings.geo_db.is_some() => {}
            Err(err) => return self.fail(&format!("Failed to load the GeoDB from: {}. {}", file, err)),
        }
        Ok(())
    }

    /// `SecUnicodeMapFile <file> <code page>`
    fn unicode_map_file(&mut self, v: &str) -> Res<()> {
        let mut param: Vec<String> =
            ssplit(v.as_bytes(), b' ').into_iter().map(|p| String::from_utf8_lossy(&p).into_owned()).collect();
        if param.len() <= 1 {
            return self.fail(&format!("Failed to process unicode map, missing parameter: {} ", v));
        }
        let last = param.pop().unwrap_or_default();
        let Some(num) = last.parse::<u32>().ok().filter(|_| last.bytes().all(|c| c.is_ascii_digit())) else {
            return self
                .fail(&format!("Failed to process unicode map, last parameter is expected to be a number: {} ", last));
        };
        let f = param.join(" ");
        let lookup = find_resource(&f, &self.file_name());
        let Some(file) = lookup.path else {
            return self.fail(&format!("Failed to locate the unicode map file from: {} {}", f, lookup.looked_at));
        };
        if let Err(error) = ConfigUnicodeMap::load_config(&file, num, &mut self.driver.properties) {
            return self.fail(&error);
        }
        Ok(())
    }

    /// `Include <path>`: loads each file the (glob) path names, in place.
    fn include(&mut self, token: &[u8]) -> Res<()> {
        let token = String::from_utf8_lossy(token);
        let after_whitespace = token.trim_start_matches([' ', '\t']);
        let quoted = after_whitespace.starts_with('"');
        let file = if quoted {
            after_whitespace.get(1..after_whitespace.len().saturating_sub(1)).unwrap_or("")
        } else {
            after_whitespace
        };
        let current = self.file_name();
        let lookup = find_resource(file, &current);
        let Some(fi) = lookup.path else {
            let at = self.lines.location(self.file, self.at);
            self.driver.error(at, "", &format!("{}: Not able to open file. {}", file, lookup.looked_at));
            return Err(Failed);
        };
        for s in expand_env(&fi, 0) {
            let lookup = find_resource(&s, &current);
            let f = lookup.path.unwrap_or_default();
            let Ok(data) = std::fs::read(&f) else {
                let at = self.lines.location(self.file, self.at);
                self.driver.error(at, "", &format!("{}: Not able to open file. {}", s, lookup.looked_at));
                return Err(Failed);
            };
            let idx = self.driver.add_filename(f);
            load(self.driver, &data, idx)?;
        }
        Ok(())
    }

    /// `SecRemoteRules <key> <url>`: downloads the rules and loads them.
    fn remote_rules(&mut self, v: &str) -> Res<()> {
        let Some((key, url)) = v.split_once(' ') else {
            return self.fail("SecRemoteRules demands a key and a URI");
        };
        let mut c = HttpsClient::new();
        c.set_key(key);
        if !c.download(url) {
            match self.driver.properties.remote_rules_action_on_failed {
                Some(OnFailedRemoteRulesAction::Abort) => {
                    return self.fail(&format!("{} - Failed to download: {}", url, c.error));
                }
                // TODO (C++): Implement the server logging mechanism.
                _ => return Ok(()),
            }
        }
        let idx = self.driver.add_filename(url.to_string());
        load(self.driver, &c.content, idx)
    }
}

/// `SecUnicodeMapFile`: the code page is a decimal integer.
#[cfg(test)]
mod unicode_map_tests {
    use crate::rules_set::RulesSet;

    #[test]
    fn code_page() {
        let load = |code_page: &str| {
            let mut rules = RulesSet::new();
            let file = concat!(env!("CARGO_MANIFEST_DIR"), "/unicode.mapping");
            rules
                .load(&format!("SecUnicodeMapFile {file} {code_page}\n"))
                .map(|_| rules.properties.unicode_map_table.unicode_code_page)
        };
        assert_eq!(load("20127").ok(), Some(20127));
        // C++ reads the longest floating point prefix of each of these.
        for code_page in ["20127x", "20127.0", "2.0127e4", "+20127", "-1", "0x4e9f", "4294967296"] {
            assert!(load(code_page).is_err(), "{code_page}");
        }
    }
}

/// `SecGeoLookupDb`: which rule set has which database.
#[cfg(all(test, feature = "maxmind"))]
mod geo_lookup_db_tests {
    use crate::instance::ModSecurity;
    use crate::rules_set::RulesSet;
    use crate::transaction::Transaction;

    fn db() -> String {
        format!("{}/test/test-cases/data/GeoIP2-City-Test.mmdb", env!("CARGO_MANIFEST_DIR"))
    }

    /// `REMOTE_ADDR` 200.249.12.31 (Brazil in the test database) matched
    /// against `@geoLookup`.
    const RULE: &str = "SecRuleEngine On\nSecRule REMOTE_ADDR \"@geoLookup\" \"id:1,phase:1,deny,status:403\"\n";

    fn denied(rules: &RulesSet) -> bool {
        let ms = ModSecurity::new();
        let mut t = Transaction::new(&ms, rules, None);
        t.process_connection("200.249.12.31", 12345, "127.0.0.1", 80);
        t.process_uri(b"/", b"GET", b"1.1");
        t.process_request_headers();
        t.intervention().is_some_and(|it| it.status == 403)
    }

    #[test]
    fn each_rule_set_has_its_own_database() {
        let mut with_db = RulesSet::new();
        with_db.load(&format!("SecGeoLookupDb {}\n{}", db(), RULE)).unwrap();
        assert!(with_db.properties.settings.geo_db.is_some());
        assert!(denied(&with_db));

        // C++ would use the database another rule set loaded.
        let mut without_db = RulesSet::new();
        without_db.load(RULE).unwrap();
        assert!(without_db.properties.settings.geo_db.is_none());
        assert!(!denied(&without_db));

        // Merged rule sets inherit it (nginx locations from their parents).
        let mut parent = RulesSet::new();
        parent.load(&format!("SecGeoLookupDb {}\n", db())).unwrap();
        let mut child = RulesSet::new();
        child.load(RULE).unwrap();
        child.merge(&mut parent).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            child.properties.settings.geo_db.as_ref().unwrap(),
            parent.properties.settings.geo_db.as_ref().unwrap()
        ));
        assert!(denied(&child));
    }

    #[test]
    fn a_failed_database_after_one_that_opened() {
        // A file that is not a database.
        let bad = format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"));
        // The database that opened stays in use, as in C++.
        let mut rules = RulesSet::new();
        let conf = format!("SecGeoLookupDb {}\nSecGeoLookupDb {}\n{}", db(), bad, RULE);
        rules.load(&conf).unwrap();
        assert!(denied(&rules));

        // Alone, it is an error.
        let mut rules = RulesSet::new();
        let err = rules.load(&format!("SecGeoLookupDb {}\n", bad)).unwrap_err();
        assert!(err.message().contains(&format!("Failed to load the GeoDB from: {}. Can't open: ", bad)), "{err}");
    }
}
