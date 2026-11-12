//! Port of `tools/rules-check/rules-check.cc` (`modsec-rules-check`).
//!
//! Loads every argument (a file name, or SecLang directives given on the
//! command line) into one rules set and reports how many rules each one
//! added, or the parser error.

use modsecurity::rules_set::RulesSet;

fn print_help(name: &str) {
    println!("Use: {} [<filename>|SecLangCommand]", name);
    println!();
}

fn main() {
    let args: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    let mut rules = RulesSet::new();
    let mut ret = 0;

    if args.len() < 2 {
        print_help(args.first().map(String::as_str).unwrap_or("modsec-rules-check"));
        return;
    }

    for arg in &args[1..] {
        // strip arg from leading and trailing '"' chars
        let arg = arg.trim_end_matches('"').trim_start_matches('"');

        if arg.is_empty() {
            continue;
        }

        print!(" : {}  --  ", arg);
        let r = if std::fs::metadata(arg).is_ok() { rules.load_from_uri(arg) } else { rules.load(arg) };

        let mut err = String::new();
        let loaded = match r {
            Ok(n) => n as i64,
            Err(_) => {
                // The errors are reported (and forgotten) per argument.
                err = std::mem::take(&mut rules.properties.parser_error);
                ret = -1;
                -1
            }
        };
        println!("Loaded {} rules.", loaded);
        if !err.is_empty() {
            eprintln!("    {}", err);
        }
    }

    if ret < 0 {
        println!("Test failed.");
    } else {
        println!("Test ok.");
    }

    std::process::exit(ret);
}
