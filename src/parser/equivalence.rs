//! Compares the `pest` front end (`syntax.rs`, `build.rs`) with the port of
//! the C++ flex/bison parser on real configurations and on mutations of
//! them.
//!
//! For each configuration both parsers load it into a fresh `Driver`, and
//! what they built (rules of every phase, configuration properties) is
//! compared through its `Debug` text. A syntax error is compared as
//! accepted/rejected only: the wording and position of syntax errors are
//! not part of the compatibility contract.
//!
//! * `real_configurations_are_identical`: OWASP CRS (`CRS_DIR`, skipped when
//!   missing), `modsecurity.conf-recommended`, the rules of every regression
//!   test and the `.conf` files of `test/test-cases/data`. Must be identical.
//! * `mutations_report` (ignored, run on demand): single-character mutations
//!   of the lines of those configurations; prints the differences by
//!   category.

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
        p.request_body_limit_action,
        p.response_body_limit_action,
        p.arguments_limit,
        p.request_body_json_depth_limit,
        p.request_body_limit,
        p.request_body_no_files_limit,
        p.response_body_limit,
        p.pcre_match_limit,
        p.upload_file_limit,
        p.upload_file_mode
    );
    let _ = writeln!(
        s,
        "switches: {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
        p.sec_request_body_access,
        p.sec_response_body_access,
        p.sec_xml_external_entity,
        p.sec_xml_parse_xml_into_args,
        p.tmp_save_uploaded_files,
        p.upload_keep_files,
        p.remote_rules_action_on_failed,
        p.sec_rule_engine,
        p.debug_log.level()
    );
    let _ = writeln!(s, "debug_log file: {:?}", p.debug_log.file());
    let _ = writeln!(s, "exceptions: {:#?}", p.exceptions);
    let _ = writeln!(s, "components: {:?}", p.components);
    let _ = writeln!(s, "mime: {:?}", p.response_body_type_to_be_inspected);
    let _ = writeln!(
        s,
        "strings: {:?} {:?} {:?} {:?} {:?}",
        p.httpbl_key, p.upload_directory, p.upload_tmp_directory, p.sec_argument_separator, p.sec_web_app_id
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

fn run(data: &[u8], reference: &str, pest: bool) -> Outcome {
    let mut d = Driver::new();
    let ok = if pest { d.parse_bytes_pest(data, reference) } else { d.parse_bytes_flex(data, reference) };
    if ok {
        Outcome::Accepted(without_addresses(&dump(&d)))
    } else {
        Outcome::Rejected(d.properties.parser_error.clone())
    }
}

/// The two outcomes, when they differ.
fn compare(data: &[u8], reference: &str) -> Option<(Outcome, Outcome)> {
    let old = run(data, reference, false);
    let new = run(data, reference, true);
    match (&old, &new) {
        (Outcome::Rejected(_), Outcome::Rejected(_)) => None,
        _ if old == new => None,
        _ => Some((old, new)),
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
            return format!("line {}:\n  flex: {}\n  pest: {}", i + 1, x.trim(), y.trim());
        }
    }
    format!("length {} vs {}", a.lines().count(), b.lines().count())
}

fn describe(old: &Outcome, new: &Outcome) -> String {
    match (old, new) {
        (Outcome::Accepted(a), Outcome::Accepted(b)) => format!("built differently: {}", first_difference(a, b)),
        (Outcome::Accepted(_), Outcome::Rejected(e)) => format!("rejected by pest only: {}", e.trim()),
        (Outcome::Rejected(e), Outcome::Accepted(_)) => format!("accepted by pest only (flex: {})", e.trim()),
        (Outcome::Rejected(_), Outcome::Rejected(_)) => unreachable!(),
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
        let ok = d.parse_bytes_pest_incremental(&c.data, &c.reference);
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

#[test]
fn real_configurations_are_identical() {
    let configs = real_configs();
    assert!(configs.len() > 100, "the regression tests were not found");
    let mut failures = Vec::new();
    for c in &configs {
        if let Some((old, new)) = compare(&c.data, &c.reference) {
            failures.push(format!("{}: {}", c.name, describe(&old, &new)));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} configurations differ:\n{}",
        failures.len(),
        configs.len(),
        failures.join("\n\n")
    );
}

/// The category of a difference, for the report.
fn category(old: &Outcome, new: &Outcome) -> &'static str {
    match (old, new) {
        (Outcome::Accepted(_), Outcome::Accepted(_)) => "built differently",
        (Outcome::Accepted(_), Outcome::Rejected(_)) => "rejected by pest only",
        (Outcome::Rejected(_), Outcome::Accepted(_)) => "accepted by pest only",
        _ => unreachable!(),
    }
}

/// Mutations of `line`, with a description: each position gets one
/// character deleted, or one of a few significant characters inserted.
fn mutations(line: &[u8]) -> Vec<(Vec<u8>, String)> {
    let mut out = Vec::new();
    let context = |i: usize| {
        let a = i.saturating_sub(8);
        let b = (i + 8).min(line.len());
        format!("{}^{}", String::from_utf8_lossy(&line[a..i]), String::from_utf8_lossy(&line[i..b]))
    };
    for i in 0..line.len() {
        let mut m = line.to_vec();
        let c = m.remove(i);
        out.push((m, format!("delete {:?} at {}", c as char, context(i))));
        for &c in b"\"' \\,|:=!%{}#\t" {
            let mut m = line.to_vec();
            m.insert(i, c);
            out.push((m, format!("insert {:?} at {}", c as char, context(i))));
        }
    }
    out
}

/// Single-character mutations of the directive lines of the regression
/// rules and of CRS. Prints the differences by category; run with
/// `cargo test --features pest-parser mutations_report -- --ignored --nocapture`.
#[test]
#[ignore]
fn mutations_report() {
    let mut lines: Vec<(Vec<u8>, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for c in real_configs() {
        for l in c.data.split(|&b| b == b'\n') {
            let t = l.trim_ascii();
            // (Mutating an `Include` path loads whole rule sets.)
            let include = t.len() > 7 && t[..7].eq_ignore_ascii_case(b"include");
            if t.is_empty()
                || t.starts_with(b"#")
                || t.len() > 400
                || include
                || downloads(t)
                || !seen.insert(t.to_vec())
            {
                continue;
            }
            lines.push((t.to_vec(), c.reference.clone()));
        }
    }
    let limit: usize = std::env::var("MUTATION_LINES").ok().and_then(|v| v.parse().ok()).unwrap_or(400);
    // A deterministic spread over the lines.
    let step = (lines.len() / limit.max(1)).max(1);
    let mut by_category: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
    let mut total = 0;
    let chosen: Vec<&(Vec<u8>, String)> = lines.iter().step_by(step).take(limit).collect();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let results: Vec<(usize, Vec<(&str, String)>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = chosen
            .chunks(chosen.len().div_ceil(threads).max(1))
            .map(|chunk| {
                scope.spawn(move || {
                    let mut total = 0;
                    let mut found = Vec::new();
                    let trace = std::env::var_os("MUTATION_TRACE").is_some();
                    for (line, reference) in chunk {
                        if trace {
                            eprintln!("line: {}", String::from_utf8_lossy(line));
                        }
                        for (m, what) in mutations(line) {
                            if trace {
                                eprintln!("  {}", what);
                            }
                            total += 1;
                            if let Some((old, new)) = compare(&m, reference) {
                                found.push((
                                    category(&old, &new),
                                    format!(
                                        "{}\n    mutation: {}\n    {}",
                                        String::from_utf8_lossy(&m),
                                        what,
                                        describe(&old, &new)
                                    ),
                                ));
                            }
                        }
                    }
                    (total, found)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("a mutation thread")).collect()
    });
    for (n, found) in results {
        total += n;
        for (cat, item) in found {
            by_category.entry(cat).or_default().push(item);
        }
    }
    // The flex scanner echoes what it cannot match to stdout: the report
    // goes to stderr and to `target/parser-mutations.txt`.
    let mut report = format!("{} mutations of {} lines\n", total, lines.len().min(limit));
    for (cat, items) in &by_category {
        let _ = writeln!(report, "\n== {}: {} ==", cat, items.len());
        for i in items {
            let _ = writeln!(report, "  {}", i);
        }
    }
    let _ = std::fs::write(repo().join("target/parser-mutations.txt"), &report);
    for l in report.lines().filter(|l| !l.starts_with("  ")) {
        eprintln!("{}", l);
    }
}

/// Prints the line numbers both parsers give the rules of `LINE_PROBE`.
#[test]
#[ignore]
fn line_probe() {
    let Some(path) = std::env::var_os("LINE_PROBE") else { return };
    let data = std::fs::read(&path).unwrap();
    for pest in [false, true] {
        let mut d = Driver::new();
        let ok = if pest { d.parse_bytes_pest(&data, "probe") } else { d.parse_bytes_flex(&data, "probe") };
        let mut lines = Vec::new();
        for phase in crate::modsecurity::Phases::ALL {
            for r in d.rules_set_phases.for_phase(phase) {
                if let Some(r) = r.as_rule_with_actions() {
                    lines.push((r.line_number, r.rule_id));
                }
            }
        }
        lines.sort();
        lines.dedup();
        println!("{} ok={} {:?}", if pest { "pest" } else { "flex" }, ok, lines);
    }
}
