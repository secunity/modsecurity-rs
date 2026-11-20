//! Runs the operator and transformation test cases of
//! `secrules-language-tests`.
//!
//! Usage (from the `test/` directory, with the command line of the original
//! `unit_tests` utility):
//! `unit_tests [path ...]`; without arguments the operators and
//! transformations suites are run. Exit status: number of failures.

#[path = "../common/mod.rs"]
mod common;

use common::*;
use modsecurity::internal::{
    Capture, InjectionResult, JsonValue, Rule, RuleAction, RuleKind, Transformation,
    clear_libinjection_overrides_for_testing, evaluate_operator, instantiate_operator, new_rule_message,
    set_libinjection_sqli_override_for_testing, set_libinjection_xss_override_for_testing, to_hex_if_needed, tx_value,
};
use modsecurity::{ModSecurity, RulesSet, Transaction};

const DEFAULT_TEST_PATH: &str = "test-cases/secrules-language-tests/operators";

struct UnitTest {
    filename: String,
    name: String,
    ty: String,
    param: String,
    input: Vec<u8>,
    resource: String,
    ret: i64,
    capture: i64,
    libinjection_override: String,
    output: Vec<u8>,
}

impl UnitTest {
    fn from_json(filename: &str, v: &JsonValue) -> Self {
        let mut input = json_string(v.get("input"));
        json2bin(&mut input);
        let mut output = json_string(v.get("output"));
        json2bin(&mut output);
        UnitTest {
            filename: filename.to_string(),
            name: lossy(&json_string(v.get("name"))),
            ty: lossy(&json_string(v.get("type"))),
            param: lossy(&json_string(v.get("param"))),
            input,
            resource: lossy(&json_string(v.get("resource"))),
            ret: json_int(v.get("ret")),
            capture: json_int(v.get("capture")),
            libinjection_override: lossy(&json_string(v.get("libinjection_override"))),
            output,
        }
    }
}

fn sqli_force_error(_: &[u8], _: &mut Vec<u8>) -> InjectionResult {
    InjectionResult::Error
}

fn xss_force_error(_: &[u8]) -> InjectionResult {
    InjectionResult::Error
}

fn configure_libinjection_override(t: &UnitTest) {
    clear_libinjection_overrides_for_testing();
    if t.libinjection_override != "error" {
        return;
    }
    match t.name.to_ascii_lowercase().as_str() {
        "detectsqli" => set_libinjection_sqli_override_for_testing(sqli_force_error),
        "detectxss" => set_libinjection_xss_override_for_testing(xss_force_error),
        _ => {}
    }
}

/// Returns (ret, output).
fn eval_operator(t: &UnitTest, transaction: &mut Transaction<'_>) -> (i64, Vec<u8>) {
    let mut op = instantiate_operator(&t.name, &t.param).expect("operator exists");
    let _ = op.init(&t.filename);
    configure_libinjection_override(t);
    let actions = if t.capture != 0 { Some(vec![RuleAction::Capture(Capture::new("capture"))]) } else { None };
    let rule = Rule::new(actions, None, "dummy.conf", 0, RuleKind::SecAction);
    let mut rm = new_rule_message(&rule);
    let matched = evaluate_operator(&op, transaction, &rule, &t.input, &mut rm);
    let mut output = Vec::new();
    if t.capture != 0
        && let Some(tx0) = tx_value(transaction, b"0")
    {
        output = tx0.to_vec();
    }
    clear_libinjection_overrides_for_testing();
    (matched as i64, output)
}

fn eval_transformation(t: &UnitTest, transaction: &Transaction<'_>) -> (i64, Vec<u8>) {
    let tfn = Transformation::from_name(&format!("t:{}", t.name));
    let mut ret = t.input.clone();
    tfn.transform(&mut ret, Some(transaction));
    (1, ret)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();
    let resources = resources();
    let mut paths = args.clone();
    if paths.is_empty() {
        paths.push(DEFAULT_TEST_PATH.to_string());
        paths.push("test-cases/secrules-language-tests/transformations".to_string());
    }

    let ms = ModSecurity::new();
    let rules = RulesSet::new();
    let mut total = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let mut report = String::new();

    for path in &paths {
        let mut files = load_tests(path);
        files.sort_by(|a, b| a.0.cmp(&b.0));
        for (filename, tests) in files {
            let mut file_failed = 0;
            let mut file_skipped = 0;
            for v in &tests {
                total += 1;
                let t = UnitTest::from_json(&filename, v);
                if !t.resource.is_empty() && !resources.contains(&t.resource.as_str()) {
                    file_skipped += 1;
                    continue;
                }
                let mut transaction = Transaction::new(&ms, &rules, None);
                let (ret, output, failed_now) = match t.ty.as_str() {
                    "op" => {
                        let (ret, output) = eval_operator(&t, &mut transaction);
                        let f = if ret != t.ret {
                            true
                        } else if t.capture != 0 || !t.output.is_empty() {
                            output != t.output
                        } else {
                            false
                        };
                        (ret, output, f)
                    }
                    "tfn" => {
                        let (ret, output) = eval_transformation(&t, &transaction);
                        (ret, output.clone(), output != t.output)
                    }
                    other => {
                        eprintln!("Failed. Test type is unknown: << {}", other);
                        continue;
                    }
                };
                if failed_now {
                    file_failed += 1;
                    report.push_str(&format!(
                        "{}Test failed.{} From: {}\nname: {} param: {:?}\ninput: \"{}\"\n",
                        KRED,
                        RESET,
                        filename,
                        t.name,
                        t.param,
                        to_hex_if_needed(&t.input, false)
                    ));
                    if ret != t.ret {
                        report.push_str(&format!("Expecting: \"{}\" - returned: \"{}\"\n", t.ret, ret));
                    }
                    if output != t.output {
                        report.push_str(&format!(
                            "Expecting: \"{}\" - returned: \"{}\"\n",
                            to_hex_if_needed(&t.output, false),
                            to_hex_if_needed(&output, false)
                        ));
                    }
                    report.push('\n');
                }
            }
            failed += file_failed;
            skipped += file_skipped;
            print!("  {}...\t", filename);
            if file_failed == 0 {
                print!("{}0 tests failed.", KGRN);
            } else {
                print!("{}{} tests failed.", KRED, file_failed);
            }
            print!("{}", RESET);
            if file_skipped > 0 {
                print!(" {} skipped.", file_skipped);
            }
            println!();
        }
    }
    println!("Total >> {}", total);
    print!("{}", report);
    println!();
    print!("Ran a total of: {} unit tests - ", total);
    if failed == 0 {
        println!("{}All tests passed.{}", KGRN, RESET);
    } else {
        println!("{}{} failed.{}", KRED, failed, RESET);
    }
    println!(" {} skipped.", skipped);
    std::process::exit(failed.min(255));
}
