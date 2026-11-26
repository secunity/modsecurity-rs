//! The setting directives: every directive that is a keyword and a value
//! (`SecRuleEngine On`, `SecAuditLog /var/log/audit.log`, `Include
//! rules/*.conf`).
//!
//! [`directive`] has one entry per directive: how its value is written
//! (the forms of the `modsecurity-seclang` crate's `value` module, or a
//! choice of words) and what it does.

use crate::audit_log::{AuditLogFormat, AuditLogStatus, AuditLogType};
use crate::parser::build::{Builder, Failed, Res, load};
use crate::parser::syntax;
use crate::parser::syntax::value::{self, Class::*, Pattern, Pattern::*, Quotes, Quotes::*, Refused};
use crate::rules_set::properties::{
    BodyLimitAction, ConfigUnicodeMap, OnFailedRemoteRulesAction, ParseXmlIntoArgs, RuleEngine, RulesSetProperties,
    parse_config_number, parse_octal_mode,
};
use crate::utils::https_client::HttpsClient;
use crate::utils::string::{parse_digits, ssplit};
use crate::utils::system::{expand_env, find_resource};

/// The value of a setting directive, as its effect gets it.
struct Given {
    /// The value; for a choice of words, the word chosen.
    text: String,
    /// Which of the directive's forms the value was written in.
    form: usize,
}

impl Given {
    /// Whether the word chosen is `word`.
    fn is(&self, word: &str) -> bool {
        self.text.eq_ignore_ascii_case(word)
    }
}

/// How the value of a directive is written.
enum Form {
    /// In one of these forms (their order breaks ties).
    Value(&'static [(Pattern, Quotes)]),
    /// One of these words (case-insensitive); none for a directive without
    /// a value.
    Word(Vec<&'static str>),
}

type Apply = Box<dyn Fn(&mut Builder<'_, '_>, &Given) -> Res<()>>;

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
const PATH: &[(Pattern, Quotes)] = &[(Sep(Path), Double), (SepQuoted(Path), Double)];
const NUMBER: &[(Pattern, Quotes)] = &[(Sep(Number), Double)];
const FREE_TEXT_LINE: &[(Pattern, Quotes)] = &[(Sep(FreeTextNewLine), Double)];
const FREE_TEXT_LINE_UNQUOTED: &[(Pattern, Quotes)] =
    &[(Sep(FreeTextNewLine), DoubleAndSingle), (SepQuoted(FreeTextNewLine), DoubleAndSingle)];
/// Text right after the keyword.
const DIRECT: &[(Pattern, Quotes)] = &[(Direct(FreeTextNewLine), Double)];
const QUOTED_TEXT: &[(Pattern, Quotes)] = &[(SepQuoted(FreeText), DoubleAndSingle)];
/// A directive that takes no value.
const NOTHING: Form = Form::Word(Vec::new());

/// A directive with a value.
fn value(
    forms: &'static [(Pattern, Quotes)],
    apply: impl Fn(&mut Builder<'_, '_>, &Given) -> Res<()> + 'static,
) -> Option<Directive> {
    Some(Directive { form: Form::Value(forms), effect: Effect::Apply(Box::new(apply)) })
}

/// A directive with a choice of words.
fn word(
    words: &'static [&'static str],
    apply: impl Fn(&mut Builder<'_, '_>, &Given) -> Res<()> + 'static,
) -> Option<Directive> {
    Some(Directive { form: Form::Word(words.to_vec()), effect: Effect::Apply(Box::new(apply)) })
}

/// A choice of words, each with the value it stands for: `set` stores the
/// value of the word given.
fn choice<T: Copy + 'static>(
    choices: &'static [(&'static str, T)],
    set: fn(&mut RulesSetProperties, T),
) -> Option<Directive> {
    let apply = move |b: &mut Builder<'_, '_>, v: &Given| {
        let (_, value) = choices.iter().find(|(w, _)| v.is(w)).expect("the word given is one of the choices");
        set(&mut b.driver.rules.properties, *value);
        Ok(())
    };
    Some(Directive {
        form: Form::Word(choices.iter().map(|&(w, _)| w).collect()),
        effect: Effect::Apply(Box::new(apply)),
    })
}

/// `On` or `Off`.
fn on_off(set: fn(&mut RulesSetProperties, bool)) -> Option<Directive> {
    choice(&[("On", true), ("Off", false)], set)
}

/// A switch that can only be off: `On` is refused with `message`.
fn only_off(message: &'static str) -> Option<Directive> {
    word(ON_OFF, move |b, v| if v.is("on") { b.fail(message) } else { Ok(()) })
}

/// A value whose text `set` stores.
fn text(forms: &'static [(Pattern, Quotes)], set: fn(&mut RulesSetProperties, String)) -> Option<Directive> {
    value(forms, move |b, v| {
        set(&mut b.driver.rules.properties, v.text.clone());
        Ok(())
    })
}

/// A number, at most the largest `T`; `name` is the directive's name in the
/// error message.
fn limit<T: std::str::FromStr + 'static>(name: &'static str, set: fn(&mut RulesSetProperties, T)) -> Option<Directive> {
    value(NUMBER, move |b, v| match parse_config_number(&v.text) {
        Ok(n) => {
            set(&mut b.driver.rules.properties, n);
            Ok(())
        }
        Err(e) => b.fail(&format!("Failed to parse {}: {}", name, e)),
    })
}

/// An octal file mode; `name` is the directive's name in the error message.
fn mode(
    forms: &'static [(Pattern, Quotes)],
    name: &'static str,
    set: fn(&mut RulesSetProperties, u32),
) -> Option<Directive> {
    value(forms, move |b, v| match parse_octal_mode(&v.text) {
        Ok(mode) => {
            set(&mut b.driver.rules.properties, mode);
            Ok(())
        }
        Err(e) => b.fail(&format!("Failed to parse {}: {}", name, e)),
    })
}

fn ignored(forms: &'static [(Pattern, Quotes)]) -> Option<Directive> {
    Some(Directive { form: Form::Value(forms), effect: Effect::Ignored })
}

fn unsupported(form: Form, message: &'static str) -> Option<Directive> {
    Some(Directive { form, effect: Effect::Unsupported(message) })
}

const BODY_LIMIT_ACTIONS: &[(&str, BodyLimitAction)] =
    &[("ProcessPartial", BodyLimitAction::ProcessPartial), ("Reject", BodyLimitAction::Reject)];

/// The directive `keyword` (in any case).
fn directive(keyword: &str) -> Option<Directive> {
    match keyword.to_ascii_lowercase().as_str() {
        // --- Audit log ---------------------------------------------------
        "secauditengine" => choice(
            &[("RelevantOnly", AuditLogStatus::RelevantOnly), ("Off", AuditLogStatus::Off), ("On", AuditLogStatus::On)],
            |p, s| p.audit_log.set_status(s),
        ),
        "secauditlog" => text(PATH, |p, path| p.audit_log.set_file_path1(&path)),
        "secauditlog2" => text(&[(Sep(Path), Double)], |p, path| p.audit_log.set_file_path2(&path)),
        "secauditlogdirmode" => {
            mode(&[(Sep(Number), Double), (SepQuoted(Number), Double)], "SecAuditLogDirMode", |p, m| {
                p.audit_log.set_storage_dir_mode(m)
            })
        }
        "secauditlogfilemode" => mode(NUMBER, "SecAuditLogFileMode", |p, m| p.audit_log.set_file_mode(m)),
        "secauditlogformat" => choice(&[("JSON", AuditLogFormat::Json), ("Native", AuditLogFormat::Native)], |p, f| {
            p.audit_log.set_format(f)
        }),
        "secauditlogparts" => text(&[(Sep(AuditParts), Double), (SepQuoted(AuditParts), Double)], |p, parts| {
            p.audit_log.set_parts(&parts)
        }),
        "secauditlogprefix" => text(FREE_TEXT_LINE_UNQUOTED, |p, prefix| p.audit_log.set_prefix(&prefix)),
        "secauditlogrelevantstatus" => {
            value(&[(Sep(FreeTextNewLine), DoubleAndSingle), (SepQuoted(Word), DoubleAndSingle)], |b, v| {
                let set = b.driver.rules.properties.audit_log.set_relevant_status(&v.text);
                set.or_else(|error| b.fail(&error))
            })
        }
        "secauditlogstoragedir" => text(PATH, |p, dir| p.audit_log.set_storage_dir(&dir)),
        "secauditlogtype" => choice(
            &[
                ("Serial", AuditLogType::Serial),
                ("Parallel", AuditLogType::Parallel),
                ("Concurrent", AuditLogType::Parallel),
                ("https", AuditLogType::Https),
            ],
            |p, t| p.audit_log.set_type(t),
        ),

        // --- Debug log ---------------------------------------------------
        "secdebuglog" => value(&[(Sep(Path), Double), (SepQuoted(Path), Double)], |b, v| {
            match b.driver.rules.properties.debug_log.set_file(&v.text) {
                Ok(()) => Ok(()),
                Err(error) => b.fail(&format!("Failed to start DebugLog: {}", error)),
            }
        }),
        "secdebugloglevel" => value(NUMBER, |b, v| {
            // A number too large for a level asks for everything.
            b.driver.rules.properties.debug_log.set_level(parse_digits(&v.text).unwrap_or(u8::MAX));
            Ok(())
        }),

        // --- The engine and what it inspects -------------------------------
        "secruleengine" => choice(
            &[("Off", RuleEngine::Disabled), ("On", RuleEngine::Enabled), ("DetectionOnly", RuleEngine::DetectionOnly)],
            |p, e| p.settings.sec_rule_engine = Some(e),
        ),
        "secrequestbodyaccess" => on_off(|p, on| p.settings.sec_request_body_access = Some(on)),
        "secresponsebodyaccess" => on_off(|p, on| p.settings.sec_response_body_access = Some(on)),
        "secresponsebodymimetype" => value(FREE_TEXT_LINE, |b, v| {
            let tokens: std::collections::BTreeSet<&str> = v.text.split_ascii_whitespace().collect();
            let t = &mut b.driver.rules.properties.response_body_type_to_be_inspected;
            t.set = true;
            for it in tokens {
                t.value.insert(it.to_ascii_lowercase());
            }
            Ok(())
        }),
        "secresponsebodymimetypesclear" => word(&[], |b, _| {
            let t = &mut b.driver.rules.properties.response_body_type_to_be_inspected;
            t.set = true;
            t.clear = true;
            t.value.clear();
            Ok(())
        }),
        "secxmlexternalentity" => on_off(|p, on| p.settings.sec_xml_external_entity = Some(on)),
        "secparsexmlintoargs" => choice(
            &[("OnlyArgs", ParseXmlIntoArgs::OnlyArgs), ("Off", ParseXmlIntoArgs::Off), ("On", ParseXmlIntoArgs::On)],
            |p, x| p.settings.sec_xml_parse_xml_into_args = Some(x),
        ),
        // The third form (free text up to the end of the line), which is
        // accepted and ignored, wins when it is longer: with more text
        // after the separator (`& ;`).
        "secargumentseparator" => value(
            &[(SepQuoted(Word), DoubleAndSingle), (Sep(Word), DoubleAndSingle), (Sep(FreeTextNewLine), Double)],
            |b, v| {
                if v.form == 2 {
                    return Ok(());
                }
                if v.text.len() != 1 {
                    return b.fail("Argument separator should be set to a single character.");
                }
                b.driver.rules.properties.settings.sec_argument_separator = Some(v.text.clone());
                Ok(())
            },
        ),
        "seccookieformat" => value(NUMBER, |b, v| {
            if parse_digits(&v.text) == Some(1u32) { b.fail("SecCookieFormat 1 is not yet supported.") } else { Ok(()) }
        }),
        "secunicodemapfile" => value(&[(UnicodeMap, Double)], |b, v| b.unicode_map_file(&v.text)),
        "secgeolookupdb" => value(FREE_TEXT_LINE, |b, v| b.geo_lookup_db(&v.text)),
        "sechttpblkey" => text(FREE_TEXT_LINE, |p, key| p.settings.httpbl_key = Some(key)),
        "secwebappid" => {
            text(&[(SepQuoted(FreeText), DoubleAndSingle), (Sep(FreeTextNewLine), DoubleAndSingle)], |p, id| {
                p.settings.sec_web_app_id = Some(id)
            })
        }
        "seccomponentsignature" => text(QUOTED_TEXT, |p, signature| p.components.push(signature)),

        // --- Limits ------------------------------------------------------
        "secargumentslimit" => limit("SecArgumentsLimit", |p, n| p.settings.arguments_limit = Some(n)),
        "secrequestbodyjsondepthlimit" => {
            limit("SecRequestBodyJsonDepthLimit", |p, n| p.settings.request_body_json_depth_limit = Some(n))
        }
        "secrequestbodylimit" => limit("SecRequestBodyLimit", |p, n| p.settings.request_body_limit = Some(n)),
        "secrequestbodynofileslimit" => {
            limit("SecRequestBodyNoFilesLimit", |p, n| p.settings.request_body_no_files_limit = Some(n))
        }
        "secresponsebodylimit" => limit("SecResponseBodyLimit", |p, n| p.settings.response_body_limit = Some(n)),
        "secpcrematchlimit" => limit("SecPcreMatchLimit", |p, n| p.settings.pcre_match_limit = Some(n)),
        "secrequestbodylimitaction" => {
            choice(BODY_LIMIT_ACTIONS, |p, a| p.settings.request_body_limit_action = Some(a))
        }
        "secresponsebodylimitaction" => {
            choice(BODY_LIMIT_ACTIONS, |p, a| p.settings.response_body_limit_action = Some(a))
        }

        // --- Uploads -----------------------------------------------------
        "secuploaddir" => text(PATH, |p, dir| p.settings.upload_directory = Some(dir)),
        "secuploadfilelimit" => limit("SecUploadFileLimit", |p, n| p.settings.upload_file_limit = Some(n)),
        "secuploadfilemode" => mode(NUMBER, "SecUploadFileMode", |p, m| p.settings.upload_file_mode = Some(m)),
        "secuploadkeepfiles" => word(&["On", "Off", "RelevantOnly"], |b, v| {
            if v.is("relevantonly") {
                return b
                    .fail("SecUploadKeepFiles RelevantOnly is not currently supported. Accepted values are On or Off");
            }
            b.driver.rules.properties.settings.upload_keep_files = Some(v.is("on"));
            Ok(())
        }),
        "sectmpsaveuploadedfiles" => on_off(|p, on| p.settings.tmp_save_uploaded_files = Some(on)),

        // --- Rules -------------------------------------------------------
        "secmarker" => value(&[(SepQuoted(Word), DoubleAndSingle), (Sep(Word), DoubleAndSingle)], |b, v| {
            let file = b.file_name();
            b.driver.add_sec_marker(&v.text, &file, b.line);
            Ok(())
        }),
        "secruleremovebyid" => value(&[(Sep(FreeTextNewLine), DoubleAndSingle)], |b, v| {
            match b.driver.rules.properties.exceptions.load(&v.text) {
                Ok(()) => Ok(()),
                Err(error) => b.fail(&format!("SecRuleRemoveById: failed to load:{}. {}", v.text, error)),
            }
        }),
        "secruleremovebymsg" => text(FREE_TEXT_LINE_UNQUOTED, |p, msg| p.exceptions.load_remove_rule_by_msg(&msg)),
        "secruleremovebytag" => text(FREE_TEXT_LINE_UNQUOTED, |p, tag| p.exceptions.load_remove_rule_by_tag(&tag)),
        "include" => value(&[(Sep(Path), Double), (SepQuoted(Path), Double)], |b, v| b.include(&v.text)),
        "secremoterules" => value(&[(Remote, Double)], |b, v| b.remote_rules(&v.text)),
        "secremoterulesfailaction" => {
            choice(&[("Abort", OnFailedRemoteRulesAction::Abort), ("Warn", OnFailedRemoteRulesAction::Warn)], |p, a| {
                p.remote_rules_action_on_failed = Some(a)
            })
        }

        // --- Accepted without effect -------------------------------------
        // (`SecPcreMatchLimitRecursion` so that modsecurity.conf-recommended
        // loads.)
        "secpcrematchlimitrecursion" | "seccollectiontimeout" => ignored(NUMBER),
        "sectmpdir" | "secdatadir" => ignored(PATH),
        "secstatusengine" => ignored(FREE_TEXT_LINE),

        // --- Switches that can only be off -------------------------------
        "secconnengine" => only_off("SecConnEngine is not yet supported."),
        "seccontentinjection" => only_off("SecContentInjection is not yet supported."),
        "secdisablebackendcompression" => only_off("SecDisableBackendCompression is not supported."),
        "sechashengine" => only_off("SecHashEngine is not yet supported."),
        "secinterceptonerror" => only_off("SecInterceptOnError is not yet supported."),
        "secruleinheritance" => only_off("SecRuleInheritance is not yet supported."),

        // --- Not supported -----------------------------------------------
        "seccachetransformations" => unsupported(Form::Value(DIRECT), "SecCacheTransformations is not supported."),
        "secchrootdir" => unsupported(Form::Value(PATH), "SecChrootDir is not supported."),
        "secconnreadstatelimit" => unsupported(Form::Value(DIRECT), "SecConnReadStateLimit is not yet supported."),
        "secconnwritestatelimit" => unsupported(Form::Value(DIRECT), "SecConnWriteStateLimit is not yet supported."),
        "seccookiev0separator" => unsupported(
            Form::Value(&[(SepQuoted(Word), DoubleAndSingle), (Sep(Word), DoubleAndSingle)]),
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
            Form::Value(forms) => {
                value::read(&rest, forms).map(|v| Given { text: lossy(v.text).into_owned(), form: v.form })
            }
            Form::Word(words) => value::word(&rest, &words).map(|w| Given { text: w.to_string(), form: 0 }),
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
            Ok(db) => self.driver.rules.properties.settings.geo_db = Some(std::sync::Arc::new(db)),
            // A database opened before stays in use.
            Err(_) if self.driver.rules.properties.settings.geo_db.is_some() => {}
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
        if let Err(error) = ConfigUnicodeMap::load_config(&file, num, &mut self.driver.rules.properties) {
            return self.fail(&error);
        }
        Ok(())
    }

    /// `Include <path>`: loads each file the (glob) path names, in place.
    fn include(&mut self, file: &str) -> Res<()> {
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
            match self.driver.rules.properties.remote_rules_action_on_failed {
                Some(OnFailedRemoteRulesAction::Abort) => {
                    return self.fail(&format!("{} - Failed to download: {}", url, c.error));
                }
                // Known limitation: the failed download is not reported in
                // the server log.
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
        // The database that opened stays in use.
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
