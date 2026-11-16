//! Tests of the SecLang front end.
//!
//! What a configuration builds is compared through the `Debug` text of the
//! rules of every phase and the configuration properties. The configurations
//! are OWASP CRS (`CRS_DIR`, skipped when not set),
//! `modsecurity.conf-recommended`, the rules of every regression test and
//! the `.conf` files of `test/test-cases/data`. (Commit 4a83876 compared
//! them, and a million mutations, with the port of the C++ flex/bison
//! parser, removed since.)

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
    let p = &d.properties;
    let mut s = String::new();
    let _ = writeln!(s, "rules: {:#?}", d.rules_set_phases);
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
        Outcome::Rejected(d.properties.parser_error.clone())
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
    use crate::utils::json::JsonValue;
    let dir = repo().join("test/test-cases/regression");
    let mut out = Vec::new();
    for f in sorted_files(&dir, "json") {
        let Ok(bytes) = std::fs::read(&f) else { continue };
        let Ok(v) = crate::utils::json::parse_tree(&bytes) else {
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

/// The two ways the new front end reads a file (at once, or statement by
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
            Outcome::Rejected(d.properties.parser_error.clone())
        };
        let whole = run(&c.data, &c.reference, true);
        if incremental != whole {
            failures.push(format!("{}: {}", c.name, describe(&incremental, &whole)));
        }
    }
    assert!(failures.is_empty(), "{} of {} differ:\n{}", failures.len(), configs.len(), failures.join("\n\n"));
}

/// The C API view of a load: the number of rules or -1, and the errors.
fn load(rules: &str, reference: &str) -> (i32, String) {
    let mut r = crate::rules_set::RulesSet::new();
    let n = r.load_with_ref(rules, reference).map_or(-1, |n| n as i32);
    (n, r.parser_error())
}

#[test]
fn c_conversions() {
    use crate::utils::string::{stod, strtol_int};
    assert_eq!(strtol_int(" 0750", 8), 0o750);
    assert_eq!(strtol_int("\"0750\"", 8), 0);
    assert_eq!(stod("12"), Some(12.0));
    assert_eq!(stod(" 1.5e3x"), Some(1500.0));
    assert_eq!(stod("abc"), None);
    assert_eq!(stod("1e999"), None);
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
    assert!(d.parse(rules, "t"), "{}", d.properties.parser_error);
    let phase = d.rules_set_phases.for_phase(Phases::RequestBody);
    assert_eq!(phase.len(), 2);
    let r = phase[0].as_rule().unwrap();
    let child = r.chained_rule_child.as_ref().unwrap();
    assert!(child.chained_rule_parent);
    assert!(child.chained_rule_child.is_some());
    assert_eq!(child.phase(), Some(Phases::RequestBody));
    let (n, err) = load("SecRule ARGS \"@rx a\" \"id:40\"\nSecRule ARGS \"@rx a\" \"id:40\"\n", "t");
    assert_eq!(n, -1);
    assert_eq!(err, "Rule id: 40 is duplicated\n");
}

/// The line numbers of the rules of `rules` (sorted by id).
fn rule_lines(rules: &str) -> Vec<(i64, i32)> {
    let mut d = Driver::new();
    assert!(d.parse(rules, "t"), "{}", d.properties.parser_error);
    let mut out: Vec<(i64, i32)> = crate::phases::Phases::ALL
        .iter()
        .flat_map(|&p| d.rules_set_phases.for_phase(p).iter())
        .filter_map(|r| r.as_rule().map(|r| (r.rule_id, r.line_number)))
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
    assert!(d.parse(rules, "t"), "{}", d.properties.parser_error);
    let dump = format!("{:#?}", d.rules_set_phases);
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
    assert!(d.parse(rules, "t"), "{}", d.properties.parser_error);
    // Literals are printed as byte lists.
    let dump = format!("{:?}", d.rules_set_phases);
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
    assert!(d.parse(rules, "t"), "{}", d.properties.parser_error);
    let dump = format!("{:?}", d.rules_set_phases);
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
    assert!(d.parse("SecAction \"id:1,phase:'request',pass\"\n", "t"), "{}", d.properties.parser_error);
    let rule = d.rules_set_phases.for_phase(Phases::RequestBody)[0].as_rule().unwrap();
    assert_eq!(rule.phase(), Some(Phases::RequestBody));
    assert!(!format!("{rule:?}").contains("Allow"), "{rule:?}");
    assert_eq!(load("SecAction \"id:1,phase:'phase',pass\"\n", "t").0, -1);
}
