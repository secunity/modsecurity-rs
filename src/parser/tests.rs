//! Tests of the SecLang front end.
//!
//! What a configuration builds is compared through the `Debug` text of the
//! rules of every phase and the configuration properties. The configurations
//! are OWASP CRS (`CRS_DIR`, skipped when not set),
//! `modsecurity.conf-recommended`, the rules of every regression test and
//! the `.conf` files of `test/test-cases/data`. (Commit 4a83876 compared
//! them, and a million mutations, with the flex/bison style parser that
//! this front end replaced.)

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::parser::driver::Driver;

/// What a parser built from a configuration.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Accepted(String),
    Rejected(String),
}

fn dump(d: &Driver) -> String {
    let p = &d.rules.properties;
    let mut s = String::new();
    let _ = writeln!(s, "rules: {:#?}", d.rules.rules_set_phases);
    let _ = writeln!(s, "audit_log: {:#?}", p.audit_log);
    let _ = writeln!(
        s,
        "limits: {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        p.settings.request_body_limit_action,
        p.settings.response_body_limit_action,
        p.settings.arguments_limit,
        p.settings.request_body_json_depth_limit,
        p.settings.request_body_limit,
        p.settings.request_body_no_files_limit,
        p.settings.response_body_limit,
        p.settings.pcre_match_limit,
        p.settings.upload_file_limit,
        p.settings.upload_file_mode
    );
    let _ = writeln!(
        s,
        "switches: {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        p.settings.sec_request_body_access,
        p.settings.sec_response_body_access,
        p.settings.sec_xml_external_entity,
        p.settings.sec_xml_parse_xml_into_args,
        p.settings.tmp_save_uploaded_files,
        p.settings.upload_keep_files,
        p.remote_rules_action_on_failed,
        p.settings.sec_rule_engine,
        p.debug_log.level()
    );
    let _ = writeln!(s, "debug_log file: {:?}", p.debug_log.file());
    let _ = writeln!(s, "exceptions: {:#?}", p.exceptions);
    let _ = writeln!(s, "components: {:?}", p.components);
    let _ = writeln!(s, "mime: {:?}", p.response_body_type_to_be_inspected);
    let _ = writeln!(
        s,
        "strings: {:?} {:?} {:?} {:?} {:?}",
        p.settings.httpbl_key,
        p.settings.upload_directory,
        p.settings.upload_tmp_directory,
        p.settings.sec_argument_separator,
        p.settings.sec_web_app_id
    );
    let _ = writeln!(s, "default actions: {:#?}", p.default_actions);
    let _ = writeln!(
        s,
        "unicode map: {} {} {}",
        p.unicode_map_table.set,
        p.unicode_map_table.unicode_code_page,
        p.unicode_map_table.unicode_map_table.is_some()
    );
    s
}

/// Removes what differs between two loads of the same rules: addresses
/// (`0x...`) printed by native handles.
fn without_addresses(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("0x") {
        out.push_str(&rest[..i + 2]);
        rest = rest[i + 2..].trim_start_matches(|c: char| c.is_ascii_hexdigit());
    }
    out.push_str(rest);
    out
}

fn run(data: &[u8], reference: &str, whole_file: bool) -> Outcome {
    let mut d = Driver::new();
    let ok = if whole_file { d.parse_bytes(data, reference) } else { d.parse_bytes_incremental(data, reference) };
    if ok {
        Outcome::Accepted(without_addresses(&dump(&d)))
    } else {
        Outcome::Rejected(d.rules.properties.parser_error.clone())
    }
}

/// A configuration to compare: its text and the reference it is loaded
/// with (relative paths in it are resolved from there).
struct Config {
    name: String,
    data: Vec<u8>,
    reference: String,
}

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// `CRS_DIR`: an OWASP CRS checkout (its configurations are compared when
/// it is set).
fn crs_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("CRS_DIR")?);
    dir.join("rules").is_dir().then_some(dir)
}

fn sorted_files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|r| {
            r.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|e| e == ext)).collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// The rules of each test of the regression JSON files.
fn regression_configs() -> Vec<Config> {
    use modsecurity_compat::json::JsonValue;
    let dir = repo().join("test/test-cases/regression");
    let mut out = Vec::new();
    for f in sorted_files(&dir, "json") {
        let Ok(bytes) = std::fs::read(&f) else { continue };
        let Ok(v) = modsecurity_compat::json::parse_tree(&bytes) else {
            continue;
        };
        let tests = match v {
            JsonValue::Array(a) => a,
            other => vec![other],
        };
        for (i, t) in tests.iter().enumerate() {
            let Some(JsonValue::Array(lines)) = t.get("rules") else { continue };
            let mut rules = Vec::new();
            for l in lines {
                rules.extend_from_slice(l.as_str().unwrap_or_default());
                rules.push(b'\n');
            }
            // The regression runner loads them from `test/` with the file
            // name as reference.
            let reference = repo().join("test").join(f.file_name().unwrap()).to_string_lossy().into_owned();
            out.push(Config {
                name: format!("{}#{}", f.file_name().unwrap().to_string_lossy(), i),
                data: rules,
                reference,
            });
        }
    }
    out
}

fn real_configs() -> Vec<Config> {
    let mut out = Vec::new();
    let file = |p: &Path| Config {
        name: p.to_string_lossy().into_owned(),
        data: std::fs::read(p).unwrap_or_default(),
        reference: p.to_string_lossy().into_owned(),
    };
    out.push(file(&repo().join("modsecurity.conf-recommended")));
    // What the `SecRemoteRules` regression tests download.
    out.push(file(&repo().join("test/modsecurity-regression-rules.txt")));
    if let Some(crs) = crs_dir() {
        let setup = crs.join("crs-setup.conf.example");
        if setup.is_file() {
            out.push(file(&setup));
        }
        for f in sorted_files(&crs.join("rules"), "conf") {
            out.push(file(&f));
        }
        // The whole CRS, as it is deployed.
        let text = format!(
            "Include {}\nInclude {}/rules/*.conf\n",
            crs.join("crs-setup.conf.example").display(),
            crs.display()
        );
        out.push(Config { name: "CRS (Include)".into(), data: text.into_bytes(), reference: "crs".into() });
    }
    for f in sorted_files(&repo().join("test/test-cases/data"), "conf") {
        out.push(file(&f));
    }
    out.extend(regression_configs());
    // No downloads: `SecRemoteRules` and the operators that read a list
    // from a URL (`@ipMatchFromFile https://...`) are left out.
    out.retain(|c| !downloads(&c.data));
    out
}

/// Whether loading `data` downloads something.
fn downloads(data: &[u8]) -> bool {
    let lower = data.to_ascii_lowercase();
    let has = |s: &[u8]| lower.windows(s.len()).any(|w| w == s);
    has(b"secremoterules") || has(b"fromfile http") || has(b"@ipmatchf http") || has(b"@pmf http")
}

fn first_difference(a: &str, b: &str) -> String {
    for (i, (x, y)) in a.lines().zip(b.lines()).enumerate() {
        if x != y {
            return format!("line {}:\n  {}\n  {}", i + 1, x.trim(), y.trim());
        }
    }
    format!("length {} vs {}", a.lines().count(), b.lines().count())
}

fn describe(a: &Outcome, b: &Outcome) -> String {
    match (a, b) {
        (Outcome::Accepted(x), Outcome::Accepted(y)) => format!("built differently: {}", first_difference(x, y)),
        (Outcome::Accepted(_), Outcome::Rejected(e)) | (Outcome::Rejected(e), Outcome::Accepted(_)) => {
            format!("accepted one way only: {}", e.trim())
        }
        (Outcome::Rejected(x), Outcome::Rejected(y)) => format!("different errors: {} / {}", x.trim(), y.trim()),
    }
}

/// The two ways the front end reads a file (at once, or statement by
/// statement after a syntax error) build the same.
#[test]
fn whole_file_and_statement_reads_are_identical() {
    let mut failures = Vec::new();
    let configs = real_configs();
    for c in &configs {
        let mut d = Driver::new();
        let ok = d.parse_bytes_incremental(&c.data, &c.reference);
        let incremental = if ok {
            Outcome::Accepted(without_addresses(&dump(&d)))
        } else {
            Outcome::Rejected(d.rules.properties.parser_error.clone())
        };
        let whole = run(&c.data, &c.reference, true);
        if incremental != whole {
            failures.push(format!("{}: {}", c.name, describe(&incremental, &whole)));
        }
    }
    assert!(failures.is_empty(), "{} of {} differ:\n{}", failures.len(), configs.len(), failures.join("\n\n"));
}

/// A configuration with CRLF line ends builds what it builds with LF ones:
/// the carriage return is part of the line end.
#[test]
fn crlf_line_ends() {
    let conf = concat!(
        "# A comment\n",
        "SecRuleEngine On\n",
        "SecRequestBodyLimit 1000\n",
        "SecRuleRemoveById 1 2\n",
        "SecRuleRemoveByTag a\n",
        "SecRuleRemoveByMsg 'b c'\n",
        "SecResponseBodyMimeType text/plain text/html\n",
        "SecHttpBlKey key\n",
        "SecWebAppId app\n",
        "SecArgumentSeparator ;\n",
        "SecMarker END\n",
        "SecAuditLogParts ABIJDEFHZ\n",
        "SecDefaultAction \"phase:2,log,pass\"\n",
        "SecAction \"id:10,phase:1,pass,msg:'x',setvar:tx.a=1\"\n",
        "SecRule ARGS \"@rx a\" \"id:12,phase:2,deny,\\\n",
        "    t:none,tag:t\"\n",
        "SecRule ARGS:b \"@streq b\" \\\n",
        "    \"id:13,phase:2,pass\"\n",
        "SecRule ARGS @detectSQLi\n",
        "  \"id:14,phase:2,pass\"\n",
        "SecRule REQUEST_HEADERS:User-Agent abc \"id:15,phase:1,pass\"\n",
        "SecRule ARGS \"@rx x\" \"id:16,chain\"\n",
        "SecRule ARGS:y \"@eq 1\"\n",
        "SecRuleUpdateTargetById 12 !ARGS:x\n",
        "SecRuleUpdateTargetByTag t ARGS:z\n",
        "SecRuleUpdateActionById 13 \"t:lowercase\"\n",
        // A commented out rule, continued on the next line.
        "#SecRule ARGS \"@rx a\" \"id:98,\\\n",
        "    phase:2\"\n",
    );
    let lf = run(conf.as_bytes(), "t", true);
    assert!(matches!(lf, Outcome::Accepted(_)), "{lf:?}");
    let crlf = conf.replace('\n', "\r\n");
    for whole in [true, false] {
        assert_eq!(run(crlf.as_bytes(), "t", whole), lf, "whole file: {whole}");
    }
    // Without a line feed after the last line.
    let last = "SecRuleRemoveByTag a\r";
    assert_eq!(run(last.as_bytes(), "t", true), run(b"SecRuleRemoveByTag a", "t", true));

    // A line break inside quotes is part of the quoted text, CR included
    // (the regression test request-body-parser-multipart-crlf.json matches
    // `"@streq 22\r\n2"`).
    for quoted in ["SecRule ARGS \"@streq a\nb\" \"id:20,phase:2,pass\"\n", "SecAction \"id:20,msg:'one\ntwo'\"\n"] {
        let lf = run(quoted.as_bytes(), "t", true);
        let crlf = run(quoted.replace('\n', "\r\n").as_bytes(), "t", true);
        let Outcome::Accepted(dump) = &crlf else { panic!("{crlf:?}") };
        assert!(dump.contains("13,"), "{dump}");
        assert_ne!(crlf, lf);
    }
}

/// What directives get as their values: the white space and the quotes
/// around a value are not part of it.
#[test]
fn values_without_what_surrounds_them() {
    use crate::phases::Phases;
    let conf = concat!(
        "SecMarker END\n",
        "SecMarker \"QUOTED\"\n",
        "SecMarker 'SINGLE' # comment\n",
        "SecMarker\t\"'BOTH'\"\n",
        "SecMarker \t SPACED \n",
        "SecRuleRemoveById 1 2  4-5\n",
        "SecRuleRemoveById  '7 8'  \n",
        "SecRuleRemoveByTag  'a b' \n",
        "SecRuleRemoveByMsg \" m \"\n",
        "SecWebAppId \"my app\"\n",
        "SecComponentSignature \"sig/1\"\n",
        "SecUploadDir  \"/tmp/a b\" \n",
        "SecRule ARGS \"@rx a\" \"id:10,phase:1,pass,tag:t\"\n",
        "SecRuleUpdateTargetByTag  \"' t '\" ARGS:x\n",
        "SecRuleUpdateTargetById '10' ARGS:y\n",
        "SecRuleUpdateTargetByMsg \t'm' ARGS:z\n",
        "SecDebugLogLevel  3\n",
    );
    let mut d = Driver::new();
    assert!(d.parse(conf, "t"), "{}", d.rules.properties.parser_error);
    let markers: Vec<&str> = d
        .rules
        .rules_set_phases
        .for_phase(Phases::RequestHeaders)
        .iter()
        .filter_map(|e| e.as_marker().map(|m| m.name.as_str()))
        .collect();
    assert_eq!(markers, ["END", "QUOTED", "SINGLE", "BOTH", "SPACED"]);
    let p = &d.rules.properties;
    let removed: Vec<u64> = (0..10).filter(|&id| p.exceptions.contains(id)).collect();
    assert_eq!(removed, [1, 2, 4, 5, 7, 8]);
    assert_eq!(p.exceptions.remove_rule_by_tag, ["a b"]);
    assert_eq!(p.exceptions.remove_rule_by_msg, [" m "]);
    assert_eq!(p.settings.sec_web_app_id.as_deref(), Some("my app"));
    assert_eq!(p.components, ["sig/1"]);
    assert_eq!(p.settings.upload_directory.as_deref(), Some("/tmp/a b"));
    let by_tag: Vec<&str> = p.exceptions.variable_update_target_by_tag.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(by_tag, [" t "]);
    let by_msg: Vec<&str> = p.exceptions.variable_update_target_by_msg.iter().map(|(m, _)| m.as_str()).collect();
    assert_eq!(by_msg, ["m"]);
    assert_eq!(p.debug_log.level(), Some(3));
    assert_eq!(p.exceptions.variable_update_target_by_id.for_rule(10).len(), 1);

    // A double quote ends the list of `SecRuleRemoveById`.
    let (n, err) = load("SecRuleRemoveById \"1 2  4-5\"\n", "t");
    assert_eq!(n, -1);
    assert!(err.contains("Invalid value for SecRuleRemoveById: \"1 2  4-5\""), "{err}");
}

/// The C API view of a load: the number of rules or -1, and the errors.
fn load(rules: &str, reference: &str) -> (i32, String) {
    let mut r = crate::rules_set::RulesSet::new();
    let n = r.load_with_ref(rules, reference).map_or(-1, |n| n as i32);
    (n, r.parser_error())
}

/// The modes of the audit log files are octal numbers. (C read them as
/// far as the octal digits go: `0789` was mode 7.)
#[test]
fn file_modes() {
    let mut d = Driver::new();
    assert!(d.parse("SecAuditLogFileMode 0640\nSecAuditLogDirMode 0750\n", "t"), "{}", d.rules.properties.parser_error);
    let dump = format!("{:?}", d.rules.properties.audit_log);
    assert!(dump.contains(&format!("file_permission: Some({})", 0o640)), "{dump}");
    assert!(dump.contains(&format!("directory_permission: Some({})", 0o750)), "{dump}");
    let mut d = Driver::new();
    assert!(!d.parse("SecAuditLogFileMode 0789\n", "t"));
    let expected = "Failed to parse SecAuditLogFileMode: Invalid octal number";
    assert!(d.rules.properties.parser_error.contains(expected), "{}", d.rules.properties.parser_error);
}

#[test]
fn empty_and_comments() {
    assert_eq!(load("", "x").0, 0);
    assert_eq!(load("# just a comment\n", "x").0, 0);
    assert_eq!(load("\n\n", "x").0, 0);
}

#[test]
fn chains_and_duplicates() {
    use crate::phases::Phases;
    let rules = "SecRule ARGS \"@rx a\" \"id:1,phase:2,chain,deny\"\nSecRule ARGS \"@rx b\" \"chain\"\nSecRule ARGS \"@rx c\" \"t:none\"\nSecRule ARGS \"@rx d\" \"id:2,phase:2,pass\"\n";
    let mut d = Driver::new();
    assert!(d.parse(rules, "t"), "{}", d.rules.properties.parser_error);
    let phase = d.rules.rules_set_phases.for_phase(Phases::RequestBody);
    assert_eq!(phase.len(), 2);
    let r = phase[0].as_rule().unwrap();
    let child = r.chain.next.as_ref().unwrap();
    assert!(child.chain.is_continuation);
    assert!(child.chain.next.is_some());
    assert_eq!(child.phase(), Phases::RequestBody);
    let (n, err) = load("SecRule ARGS \"@rx a\" \"id:40\"\nSecRule ARGS \"@rx a\" \"id:40\"\n", "t");
    assert_eq!(n, -1);
    assert_eq!(err, "Rule id: 40 is duplicated\n");
}

/// The line numbers of the rules of `rules` (sorted by id).
fn rule_lines(rules: &str) -> Vec<(u64, usize)> {
    let mut d = Driver::new();
    assert!(d.parse(rules, "t"), "{}", d.rules.properties.parser_error);
    let mut out: Vec<(u64, usize)> = crate::phases::Phases::ALL
        .iter()
        .flat_map(|&p| d.rules.rules_set_phases.for_phase(p).iter())
        .filter_map(|r| r.as_rule().map(|r| (r.logged_id(), r.line_number)))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Rules are on the line of their keyword. (The C++ scanner did not count
/// the line feeds inside quoted texts, between a rule's variables and its
/// operator, between `SecAction` and its actions, after
/// `SecRuleUpdateTargetBy*`, a blank line after a rule without actions,
/// and the blank lines after a commented out `SecRule`.)
#[test]
fn line_numbers() {
    let rules = [
        r#"SecRule ARGS "@rx a" \"#,                         // 1
        r#"    "id:1,phase:2,pass,msg:'one \"#,              // 2
        r#"    two'""#,                                      // 3
        r#"SecRule ARGS \"#,                                 // 4
        r#"    "@rx b" "id:2,phase:2,pass""#,                // 5
        r#"SecAction \"#,                                    // 6
        r#"    "id:3,phase:2,pass""#,                        // 7
        r#"SecRuleUpdateTargetById 1 !ARGS:x"#,              // 8
        "",                                                  // 9
        "",                                                  // 10
        r#"SecRule ARGS "@rx c" "id:6,phase:2,pass,chain""#, // 11
        r#"    SecRule ARGS "@rx c2""#,                      // 12
        "",                                                  // 13
        r#"SecRule ARGS "@rx d"#,                            // 14
        r#"e" "id:4,phase:2,pass""#,                         // 15
        r#"#SecRule ARGS "@rx e" \"#,                        // 16
        "",                                                  // 17
        "",                                                  // 18
        r#"#  "id:9""#,                                      // 19
        r#"SecAction "id:5,phase:2,pass""#,                  // 20
    ]
    .join("\n");
    assert_eq!(rule_lines(&rules), vec![(1, 1), (2, 4), (3, 6), (4, 14), (5, 20), (6, 11)]);
}

/// A rule without actions may be followed by a directive or a comment on
/// the next line (C++: "Expecting an action"); actions on the next line
/// are still its actions.
#[test]
fn directive_after_rule_without_actions() {
    let chain = "SecRule ARGS \"@rx a\" \"id:1,phase:2,pass,chain\"\n    SecRule ARGS \"@rx b\"\n";
    assert_eq!(rule_lines(&format!("{chain}SecAction \"id:2,phase:2,pass\"\n")), vec![(1, 1), (2, 3)]);
    assert_eq!(rule_lines(&format!("{chain}# a comment\nSecAction \"id:2,phase:2,pass\"\n")), vec![(1, 1), (2, 4)]);
    assert_eq!(rule_lines(&format!("{chain}Include /dev/null\n")), vec![(1, 1)]);
    assert_eq!(rule_lines("SecRule ARGS \"@rx a\"\n    \"id:1,phase:2,pass\"\n"), vec![(1, 1)]);
    assert_eq!(rule_lines("SecRule ARGS \"@rx a\"\nid:1\n"), vec![(1, 1)]);
}

/// A whole collection is a variable like any other: `SecRule TX "foo"` is
/// a regular expression on `TX`, and `%{tx}x` is `TX` followed by `x` (the
/// C++ grammar read what follows as the collection's key).
#[test]
fn whole_collection_followed_by_text() {
    let mut d = Driver::new();
    let rules = "SecRule TX \"foo\" \"id:1,phase:2,pass,msg:'%{tx}x'\"\n";
    assert!(d.parse(rules, "t"), "{}", d.rules.properties.parser_error);
    let dump = format!("{:#?}", d.rules.rules_set_phases);
    assert!(dump.contains("Rx {"), "{dump}");
    assert!(!dump.contains("dynamic"), "{dump}");
    assert_eq!(dump.matches("full_name: \"TX\"").count(), 2, "{dump}");
}

/// A `%` that does not start a macro is text: C++ rejected it between
/// single quotes and in an unquoted operator, and elsewhere took the next
/// character with it (`"@contains 5%"` did not end at its quote).
#[test]
fn percent_is_text() {
    let mut d = Driver::new();
    let rules = "SecRule ARGS \"@contains 5%\" \"id:1,phase:2,pass,msg:'100%',tag:a%,setvar:tx.a=5%\"\n\
                 SecRule ARGS @contains b% \"id:2,phase:2,pass,msg:'%{tx.a}%'\"\n";
    assert!(d.parse(rules, "t"), "{}", d.rules.properties.parser_error);
    // Literals are printed as byte lists.
    let dump = format!("{:?}", d.rules.rules_set_phases);
    let bytes = |s: &str| format!("{:?}", s.as_bytes().to_vec());
    for literal in ["5%", "100%", "a%", "b%"] {
        assert!(dump.contains(&bytes(literal)), "{literal} in {dump}");
    }
    // `%{VAR}%` stays the variable.
    assert!(!dump.contains(&bytes("%")), "{dump}");
}

/// In a double-quoted operator parameter, `\"` is a quote (C++ kept the
/// backslash: upstream issue 3750 / PR 3753). `\\` stays two backslashes.
#[test]
fn escaped_quote_in_operator() {
    let mut d = Driver::new();
    let rules = r#"SecRule ARGS "@contains test()\"quote\"" "id:1,phase:2,pass"
SecRule ARGS "@streq a\\\"b" "id:2,phase:2,pass"
SecRule ARGS "@streq c\\d" "id:3,phase:2,pass"
SecRule ARGS @streq e\"f "id:4,phase:2,pass"
"#;
    assert!(d.parse(rules, "t"), "{}", d.rules.properties.parser_error);
    let dump = format!("{:?}", d.rules.rules_set_phases);
    let bytes = |s: &str| format!("{:?}", s.as_bytes().to_vec());
    for param in [r#"test()"quote""#, r#"a\\"b"#, r#"c\\d"#, r#"e\"f"#] {
        assert!(dump.contains(&bytes(param)), "{param} in {dump}");
    }
}

/// An action list must end with its quote (C++ accepted a list ending at
/// the end of the line).
#[test]
fn action_list_needs_its_closing_quote() {
    assert_eq!(load("SecRule ARGS \"@rx a\" \"id:1,phase:2,pass\n", "t").0, -1);
    assert_eq!(load("SecAction \"id:1,phase:2,pass\n", "t").0, -1);
    assert_eq!(load("SecRule ARGS \"@rx a\" \"id:1,phase:2,pass\"\n", "t").0, 1);
}

/// `@name` must be a known operator (C++ read an unknown one, and a
/// parameter given to an operator that takes none, as a regular expression
/// of the whole text).
#[test]
fn unknown_operators() {
    for op in ["@foo bar", "@containz x", "@lt3", "@lt' 3", "@detectSQLi x", "@unconditionalMatch x"] {
        let rules = format!("SecRule ARGS \"{op}\" \"id:1,phase:2,pass\"\n");
        assert_eq!(load(&rules, "t").0, -1, "{op}");
    }
    // Still regular expressions, and spaces before the closing quote of an
    // operator without a parameter.
    for op in ["@", "@1", "foo", "@detectSQLi  ", "!@rx a"] {
        let rules = format!("SecRule ARGS \"{op}\" \"id:1,phase:2,pass\"\n");
        assert_eq!(load(&rules, "t").0, 1, "{op}");
    }
}

/// `phase:'request'` is the phase (C++ built an `allow` action from it: the
/// scanner's `allow` rule also matches `phase:'request'` and comes first).
#[test]
fn quoted_phase_name() {
    use crate::phases::Phases;
    let mut d = Driver::new();
    assert!(d.parse("SecAction \"id:1,phase:'request',pass\"\n", "t"), "{}", d.rules.properties.parser_error);
    let rule = d.rules.rules_set_phases.for_phase(Phases::RequestBody)[0].as_rule().unwrap();
    assert_eq!(rule.phase(), Phases::RequestBody);
    assert!(!format!("{rule:?}").contains("Allow"), "{rule:?}");
    assert_eq!(load("SecAction \"id:1,phase:'phase',pass\"\n", "t").0, -1);
}

/// A number too large for its action or directive is an error. (C++ reads
/// some with `std::stoi`, which throws, so the directive is an error, and
/// some with `atoi`, which saturates. They used to wrap around here, so
/// `skip:18446744073709551617` was `skip:1` and
/// `SecArgumentsLimit 18446744073709551617` a limit of one argument.)
#[test]
fn numbers_beyond_the_int_range() {
    const TWO_64_PLUS_1: &str = "18446744073709551617";
    let rejected = [
        (
            format!("SecAction \"id:1,phase:1,pass,skip:{TWO_64_PLUS_1}\""),
            "Skip: The input \"18446744073709551617\" is not a number.",
        ),
        (format!("SecAction \"id:1,phase:1,pass,accuracy:{TWO_64_PLUS_1}\""), "Accuracy: The input"),
        (format!("SecAction \"id:1,phase:1,pass,maturity:{TWO_64_PLUS_1}\""), "Maturity: The input"),
        (format!("SecAction \"id:1,phase:1,pass,severity:{TWO_64_PLUS_1}\""), "Severity: The input"),
        (format!("SecAction \"id:1,phase:1,deny,status:{TWO_64_PLUS_1}\""), "Not a valid number: 18446744073709551617"),
        (
            format!("SecAction \"id:1,phase:1,pass,ctl:ruleRemoveById={TWO_64_PLUS_1}\""),
            "Not a number or range: 18446744073709551617",
        ),
        (
            format!("SecAction \"id:1,phase:1,pass,ctl:ruleRemoveTargetById={TWO_64_PLUS_1};ARGS\""),
            "Not able to convert '18446744073709551617' into a number",
        ),
        (format!("SecRuleRemoveById {TWO_64_PLUS_1}"), "Not a number or range: 18446744073709551617"),
        (format!("SecAction \"id:1,phase:{TWO_64_PLUS_1},pass\""), "Unknown phase: 18446744073709551617"),
        // An id is decimal digits, wherever one is written.
        ("SecRuleUpdateTargetById 1e0 !ARGS".to_string(), "does not seems to be a valid rule id"),
        ("SecRuleUpdateActionById 1abc \"pass\"".to_string(), "does not seems to be a valid rule id"),
        ("SecAction \"id:1,phase:1,pass,ctl:ruleRemoveById=12abc\"".to_string(), "Not a number or range: 12abc"),
        ("SecAction \"id:1,phase:1,pass,ctl:ruleRemoveTargetById=1.0;ARGS\"".to_string(), "Not able to convert '1.0'"),
    ];
    for (rule, error) in rejected {
        let mut d = Driver::new();
        assert!(!d.parse(&format!("{rule}\n"), "t"), "accepted: {rule}");
        assert!(d.rules.properties.parser_error.contains(error), "{rule}: {}", d.rules.properties.parser_error);
    }

    // Beyond `int` but within 64 bits: an id like another for
    // `SecRuleRemoveById`.
    let mut d = Driver::new();
    assert!(d.parse("SecRuleRemoveById 3000000000 1-3000000000\n", "t"), "{}", d.rules.properties.parser_error);

    // A limit too large for its directive is an error, as for every
    // numeric directive. (These two used to read it as the largest limit.)
    for directive in [
        "SecArgumentsLimit",
        "SecRequestBodyJsonDepthLimit",
        "SecUploadFileLimit",
        "SecPcreMatchLimit",
        "SecRequestBodyLimit",
    ] {
        let mut d = Driver::new();
        assert!(!d.parse(&format!("{directive} {TWO_64_PLUS_1}\n"), "t"), "{directive}");
        let expected = format!("Failed to parse {directive}: Value is too big.");
        assert!(d.rules.properties.parser_error.contains(&expected), "{}", d.rules.properties.parser_error);
    }
}

/// One-line configurations around every setting directive and every
/// action name: values of each shape, well and badly formed. No line opens
/// a file outside `tmp` or downloads anything.
fn generated_lines(tmp: &str) -> Vec<String> {
    const SETTINGS: &[&str] = &[
        "SecAuditLogDirMode",
        "SecAuditLogStorageDir",
        "SecAuditEngine",
        "SecAuditLogFileMode",
        "SecAuditLog2",
        "SecAuditLogParts",
        "SecAuditLog",
        "SecAuditLogFormat",
        "SecAuditLogRelevantStatus",
        "SecAuditLogPrefix",
        "SecAuditLogType",
        "SecUploadKeepFiles",
        "SecUploadFileLimit",
        "SecUploadFileMode",
        "SecUploadDir",
        "SecTmpSaveUploadedFiles",
        "SecMarker",
        "SecRuleEngine",
        "SecRequestBodyAccess",
        "SecResponseBodyAccess",
        "SecArgumentSeparator",
        "SecComponentSignature",
        "SecConnEngine",
        "SecWebAppId",
        "SecServerSignature",
        "SecCacheTransformations",
        "SecDisableBackendCompression",
        "SecContentInjection",
        "SecChrootDir",
        "SecHashEngine",
        "SecHashKey",
        "SecHashParam",
        "SecHashMethodRx",
        "SecHashMethodPm",
        "SecGsbLookupDb",
        "SecGuardianLog",
        "SecInterceptOnError",
        "SecConnReadStateLimit",
        "SecConnWriteStateLimit",
        "SecSensorId",
        "SecRuleInheritance",
        "SecRulePerfTime",
        "SecStreamInBodyInspection",
        "SecStreamOutBodyInspection",
        "SecRuleRemoveById",
        "SecRuleRemoveByMsg",
        "SecRuleRemoveByTag",
        "SecDebugLog",
        "SecDebugLogLevel",
        "SecGeoLookupDb",
        "SecArgumentsLimit",
        "SecRequestBodyJsonDepthLimit",
        "SecRequestBodyLimit",
        "SecRequestBodyNoFilesLimit",
        "SecRequestBodyInMemoryLimit",
        "SecResponseBodyLimit",
        "SecRequestBodyLimitAction",
        "SecResponseBodyLimitAction",
        "SecRemoteRulesFailAction",
        "SecPcreMatchLimitRecursion",
        "SecPcreMatchLimit",
        "SecResponseBodyMimeType",
        "SecResponseBodyMimeTypesClear",
        "SecXmlExternalEntity",
        "SecParseXmlIntoArgs",
        "SecTmpDir",
        "SecDataDir",
        "SecStatusEngine",
        "SecCookieFormat",
        "SecCookieV0Separator",
        "SecUnicodeMapFile",
        "SecCollectionTimeout",
        "SecHttpBlKey",
        "Include",
        "SecRemoteRules",
        "SecNoSuchDirective",
        "secruleengine",
        "SECAUDITLOGPARTS",
    ];
    // The directives that open the file their value names: they only get
    // names in `tmp`.
    const OPENS: &[&str] = &["SecDebugLog", "SecAuditLog", "SecAuditLog2", "SecAuditLogStorageDir", "SecUploadDir"];
    const VALUES: &[&str] = &[
        "",
        " ",
        "x",
        " On",
        " on",
        " OFF",
        "  Off",
        "\tOn",
        " On # comment",
        " On x",
        " On\r",
        " RelevantOnly",
        " DetectionOnly",
        " JSON",
        " Native",
        " Serial",
        " Parallel",
        " Concurrent",
        " https",
        " ProcessPartial",
        " Reject",
        " Abort",
        " Warn",
        " OnlyArgs",
        " 0",
        " 1",
        " 12",
        "  12",
        "\t12",
        " \"12\"",
        " \"12",
        " 12\"",
        " 1x",
        " -1",
        " 0777",
        " 1 2",
        " 99999999999999999999",
        " abc",
        "  abc",
        " \"abc\"",
        " \"a b\"",
        " a b",
        " a,b",
        " a|b",
        " 'a'",
        " \"\"",
        " \"a\\\"b\"",
        " \"a\\\\\"b\"",
        " ABCZ",
        " \"ABIJ\"",
        " abiz",
        " ABX",
        " +E",
        " x\ty",
        " 20000 x",
        " \\",
        " &",
        " \"&\"",
        " & ",
        " text/html text/xml",
        " 1-5 7",
        " \"1 2 3\"",
        " tag-one",
        " ^5\\d\\d$",
        " \"^(?:5|4(?!04))\"",
        " abc # comment",
        " \"abc\" # comment",
        " \"abc\" x",
        "   ",
        " \t",
        " \tabc",
        "  \t \"abc\"",
        "  \"a b\"  ",
        " 'a b' ",
        " \"'a'\"",
        " \"' a '\"",
        " ' a '",
        " a\r",
        " 'a",
    ];
    let mut lines = Vec::new();
    for setting in SETTINGS {
        if OPENS.contains(setting) {
            for v in [
                "".to_string(),
                format!(" {tmp}/a.log"),
                format!("  {tmp}/a.log"),
                format!("\t{tmp}/a.log"),
                format!(" \"{tmp}/a.log\""),
                format!(" \"{tmp}/a.log"),
                format!(" {tmp}/a.log # comment"),
                format!(" {tmp}/a b.log"),
                format!(" {tmp}/a.log x,y"),
                format!(" {tmp}/a%.log"),
            ] {
                lines.push(format!("{setting}{v}"));
            }
            continue;
        }
        if setting.eq_ignore_ascii_case("SecRemoteRules") {
            // Only what is refused before anything is downloaded.
            for v in ["", " key", " key ", "  key url", "\tkey url"] {
                lines.push(format!("{setting}{v}"));
            }
            continue;
        }
        for v in VALUES {
            lines.push(format!("{setting}{v}"));
        }
        for v in [
            format!(" {tmp}/none.conf"),
            format!(" \"{tmp}/none.conf\""),
            format!(" {tmp}/*.none"),
            format!(" {tmp}/none 20127"),
        ] {
            lines.push(format!("{setting}{v}"));
        }
    }

    const ACTIONS: &[&str] = &[
        "append",
        "deprecatevar",
        "pause",
        "prepend",
        "proxy",
        "sanitiseArg",
        "sanitiseMatched",
        "sanitiseMatchedBytes",
        "sanitiseRequestHeader",
        "sanitiseResponseHeader",
        "auditlog",
        "block",
        "capture",
        "chain",
        "deny",
        "drop",
        "log",
        "multiMatch",
        "noauditlog",
        "nolog",
        "pass",
        "allow",
        "accuracy",
        "maturity",
        "exec",
        "id",
        "phase",
        "rev",
        "severity",
        "skipAfter",
        "skip",
        "status",
        "ver",
        "xmlns",
        "t",
        "ctl",
        "msg",
        "logdata",
        "tag",
        "setenv",
        "setrsc",
        "setsid",
        "setuid",
        "expirevar",
        "redirect",
        "initcol",
        "setvar",
        "nosuchaction",
        "LOG",
        "Deny",
        "T",
    ];
    const ACTION_VALUES: &[&str] = &[
        "",
        ":",
        ":1",
        ":'1'",
        ":12",
        ":abc",
        ":'abc'",
        ":''",
        ":'a,b'",
        ":request",
        ":phase",
        ":REQUEST",
        ":2",
        ":'2'",
        ":logging",
        ":'response'",
        ":CRITICAL",
        ":'critical'",
        ":0",
        ":99999999999999999999",
        ":lowercase",
        ":none",
        ":urlDecodeUni",
        ":bogus",
        ":x'y",
        ":'x",
        ":/no/such/script.lua",
        ":'/no/such/script.lua'",
        ":403",
        ":'403'",
        ":%{tx.a}",
        ":'%{tx.a}'",
        ":soap=http://example.com/",
        ":'soap=http://example.com/'",
        ":ip=1",
        ":tx.a=1",
        ":a=b",
        ":1.5",
        ":-1",
        ":END_MARKER",
        ":https://example.com/",
        ":OWASP_CRS/3.0",
    ];
    for action in ACTIONS {
        for v in ACTION_VALUES {
            lines.push(format!("SecAction \"id:7,phase:1,{action}{v}\""));
            lines.push(format!("SecRule ARGS \"@streq a\" \"id:7,phase:2,pass,{action}{v},t:trim\""));
        }
    }
    const CTL: &[&str] = &[
        "auditEngine",
        "auditLogParts",
        "requestBodyProcessor",
        "forceRequestBodyVariable",
        "parseXmlIntoArgs",
        "requestBodyAccess",
        "ruleEngine",
        "ruleRemoveById",
        "ruleRemoveByTag",
        "ruleRemoveTargetById",
        "ruleRemoveTargetByTag",
        "responseBodyAccess",
        "nosuch",
        "RULEENGINE",
    ];
    const CTL_VALUES: &[&str] = &[
        "",
        "=",
        "=On",
        "=on",
        "=Off",
        "=RelevantOnly",
        "=DetectionOnly",
        "=OnlyArgs",
        "=JSON",
        "=xml",
        "=URLENCODED",
        "=+E",
        "=-FH",
        "=|A",
        "=+X",
        "=E",
        "=+",
        "=1",
        "=1-5",
        "=tag/one",
        "=1;ARGS:x",
        "=tag;ARGS:x",
        "=1;",
        "=a b",
        "='1'",
        "=x,y",
        "=99999999999999999999",
        "=1-99999999999999999999",
    ];
    for name in CTL {
        for v in CTL_VALUES {
            lines.push(format!("SecAction \"id:7,phase:1,pass,ctl:{name}{v}\""));
        }
    }
    // The values of the directives with a grammar of their own.
    const SELECTORS: &[&str] = &[
        " 7",
        "  7",
        "\t7",
        " \t7",
        "\t \t7",
        " \"7\"",
        "  \"7\"",
        " \t\"7\"",
        " '7'",
        " \"'7'\"",
        " ''",
        " \"\"",
        " '",
        " \"'\"",
        " \" 7 \"",
        " \"' 7 '\"",
        " 7-9",
        " 'a'b'",
        " a",
        " \"a b\"",
        " 'a",
    ];
    const RULE: &str = "SecRule ARGS \"@rx a\" \"id:7,phase:1,pass,tag:'a b',msg:'a b'\"\n";
    for v in SELECTORS {
        for by in ["Id", "Tag", "Msg"] {
            lines.push(format!("{RULE}SecRuleUpdateTargetBy{by}{v} ARGS:x"));
        }
        lines.push(format!("{RULE}SecRuleUpdateActionById{v} \"t:lowercase\""));
        lines.push(format!("SecRuleScript{v} \"id:8\""));
    }
    lines
}

/// Writes what every configuration (the real ones and the generated lines)
/// builds to the file `DUMP_TO`, to compare the parser before and after a
/// change to it:
///
/// ```text
/// DUMP_TO=$PWD/target/before.txt cargo test --lib parser::tests::dump_outcomes -- --ignored
/// ```
#[test]
#[ignore]
fn dump_outcomes() {
    let Some(to) = std::env::var_os("DUMP_TO") else { return };
    let tmp = repo().join("target/tmp/parser-dump");
    std::fs::create_dir_all(&tmp).expect("temporary directory");
    let tmp_name = tmp.to_string_lossy().into_owned();
    let mut out = String::new();
    for c in real_configs() {
        for whole in [true, false] {
            // These dumps are large (the whole CRS): a hash of each is
            // enough to see a change.
            let outcome = match run(&c.data, &c.reference, whole) {
                Outcome::Accepted(dump) => {
                    use std::hash::{Hash, Hasher};
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    dump.hash(&mut h);
                    format!("accepted, {} bytes, hash {:016x}", dump.len(), h.finish())
                }
                Outcome::Rejected(error) => format!("rejected: {error}"),
            };
            let _ = writeln!(out, "### {} (whole file: {whole})\n{outcome}", c.name);
        }
    }
    let lines = generated_lines(&tmp_name);
    for line in &lines {
        let outcome = match run(line.as_bytes(), "generated.conf", true) {
            Outcome::Accepted(dump) => format!("accepted\n{dump}"),
            Outcome::Rejected(error) => format!("rejected: {error}"),
        };
        let _ = writeln!(out, "### {line:?}\n{}", outcome.replace(&tmp_name, "<tmp>"));
    }
    std::fs::write(&to, out).expect("writing the dump");
    let _ = std::fs::remove_dir_all(&tmp);
    println!("{} generated lines", lines.len());
}

/// The properties of a rule (`id`, `phase`, `rev`, `ver`, `accuracy`,
/// `maturity`, `chain`): `SecRuleUpdateActionById` cannot change them, and
/// `SecDefaultAction` takes only `phase`. The messages name them as written.
#[test]
fn rule_properties_outside_of_a_rule() {
    let properties = ["ID:2", "phase:2", "Rev:'1'", "ver:'v'", "accuracy:3", "maturity:4", "chain"];
    for p in properties {
        let name = p.split(':').next().unwrap();
        let (n, err) = load(&format!("SecAction \"id:1,phase:1,pass\"\nSecRuleUpdateActionById 1 \"{p}\"\n"), "t");
        assert_eq!(n, -1, "{p}");
        assert!(
            err.contains(&format!("SecRuleUpdateActionById: the action `{name}' of a rule cannot be updated.")),
            "{err}"
        );
    }
    for p in properties.iter().filter(|p| !p.starts_with("phase")) {
        let name = p.split(':').next().unwrap();
        let (n, err) = load(&format!("SecDefaultAction \"phase:2,log,deny,status:403,{p}\"\n"), "t");
        assert_eq!(n, -1, "{p}");
        assert!(
            err.contains(&format!("The action '{name}' is not suitable to be part of the SecDefaultActions")),
            "{err}"
        );
    }
    // `phase` says which phase the default actions are for.
    let mut d = Driver::new();
    assert!(d.parse("SecDefaultAction \"phase:3,log,deny,status:403\"\n", "t"), "{}", d.rules.properties.parser_error);
    assert_eq!(d.rules.properties.default_actions[crate::phases::Phases::ResponseHeaders.index()].len(), 3);
}

/// The settings declared with a choice of words, `On`/`Off`, a limit or a
/// switch that can only be off.
#[test]
fn setting_helpers() {
    use crate::audit_log::AuditLogType;
    use crate::rules_set::properties::RuleEngine;
    let parsed = |text: &str| {
        let mut d = Driver::new();
        let ok = d.parse(text, "t");
        (ok, d)
    };
    // A word in any case gives its value; two words can give the same one.
    let (ok, d) = parsed("SecRuleEngine detectiononly\nSecRequestBodyAccess ON\n");
    assert!(ok, "{}", d.rules.properties.parser_error);
    assert_eq!(d.rules.properties.settings.sec_rule_engine, Some(RuleEngine::DetectionOnly));
    assert_eq!(d.rules.properties.settings.sec_request_body_access, Some(true));
    for (word, expected) in [("Serial", AuditLogType::Serial), ("Concurrent", AuditLogType::Parallel)] {
        let (ok, d) = parsed(&format!("SecAuditLogType {word}\n"));
        assert!(ok);
        assert!(format!("{:?}", d.rules.properties.audit_log).contains(&format!("audit_type: Some({expected:?})")));
    }
    // A word that is not a choice is refused.
    let (ok, d) = parsed("SecRuleEngine Maybe\n");
    assert!(!ok);
    assert!(
        d.rules.properties.parser_error.contains("Invalid value for SecRuleEngine: Maybe"),
        "{}",
        d.rules.properties.parser_error
    );
    // A limit names its directive in its error.
    let (ok, d) = parsed("SecArgumentsLimit 99999999999999999999\n");
    assert!(!ok);
    assert!(d.rules.properties.parser_error.contains("Failed to parse SecArgumentsLimit: "));
    // A switch that can only be off.
    assert!(parsed("SecHashEngine Off\n").0);
    let (ok, d) = parsed("SecHashEngine On\n");
    assert!(!ok);
    assert!(d.rules.properties.parser_error.contains("SecHashEngine is not yet supported."));
}
