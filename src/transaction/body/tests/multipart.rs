/// Helpers shared by the request body processor tests: a transaction set up
/// as the regression test harness does, with a debug log kept in memory.
pub(crate) mod test_support {
    pub use crate::debug_log::test_support::CaptureLog;
    use crate::instance::ModSecurity;
    use crate::rules_set::RulesSet;
    use crate::rules_set::properties::RulesSetProperties;
    use crate::transaction::{RequestBodyType, Transaction};

    /// A rule set with an in-memory debug log at level 9.
    pub fn new_rules() -> RulesSet {
        let mut rules = RulesSet::new();
        rules.properties = RulesSetProperties::with_debug_log(Box::new(CaptureLog::default()));
        rules
    }

    /// The messages logged so far.
    pub fn log(rules: &RulesSet) -> Vec<String> {
        CaptureLog::lines_of(rules.properties.debug_log.as_ref())
    }

    /// Runs a request with `headers` and `body` up to (and including) the
    /// request body phase; `processor` mimics `ctl:requestBodyProcessor`.
    pub fn run<'a>(
        ms: &'a ModSecurity,
        rules: &'a RulesSet,
        headers: &[(&[u8], &[u8])],
        body: &[u8],
        processor: Option<RequestBodyType>,
    ) -> Transaction<'a> {
        let mut t = Transaction::new(ms, rules, None);
        t.process_connection("200.249.12.31", 123, "200.249.12.31", 80);
        t.process_uri(b"/", b"POST", b"1.1");
        for (k, v) in headers {
            t.add_request_header(k, v);
        }
        t.process_request_headers();
        if let Some(p) = processor {
            t.body.request_body_processor = p;
        }
        t.append_request_body(body);
        t.process_request_body();
        t
    }
}

mod tests {
    use super::test_support::{log, new_rules, run};
    use crate::instance::ModSecurity;
    use modsecurity_body::multipart::*;

    fn ct(boundary: &str) -> Vec<u8> {
        format!("multipart/form-data; boundary={}", boundary).into_bytes()
    }

    const NORMAL: &[u8] = b"--0000\r\n\
Content-Disposition: form-data; name=\"name\"\r\n\
\r\n\
Brian Rectanus\r\n\
--0000\r\n\
Content-Disposition: form-data; name=\"email\"\r\n\
\r\n\
brian.rectanus@breach.com\r\n\
--0000\r\n\
Content-Disposition: form-data; name=\"image\"; filename=\"image.jpg\"\r\n\
Content-Type: image/jpeg\r\n\
\r\n\
BINARYDATA\r\n\
--0000--\r\n";

    #[test]
    fn normal_request() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], NORMAL, None);
        assert_eq!(t.vars.args.resolve_first(b"name").unwrap(), b"Brian Rectanus");
        assert_eq!(t.vars.args_post.resolve_first(b"email").unwrap(), b"brian.rectanus@breach.com");
        assert_eq!(t.vars.files.resolve_first(b"image").unwrap(), b"image.jpg");
        assert_eq!(t.vars.files_sizes.resolve_first(b"image").unwrap(), b"10");
        assert_eq!(t.vars.files_names.resolve_first(b"image").unwrap(), b"image");
        assert_eq!(t.vars.multipart_strict_error.value, b"0");
        // 2: boundaries were seen and the final one matched
        assert_eq!(t.vars.multipart_unmatched_boundary.value, b"2");
        assert_eq!(t.vars.reqbody_error.value, b"0");
        let l = log(&rules);
        assert!(l.iter().any(|m| m
            == "Multipart: Added file part to the list: name \"image\" file name \"image.jpg\" (offset 258, length 10)"));
        assert!(l.iter().any(|m| m == "Multipart: Cleanup started (keep files set to Not set)"));
    }

    #[test]
    fn final_boundary_missing() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let body = b"--0000\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        assert_eq!(t.vars.reqbody_error.value, b"1");
        assert_eq!(t.vars.reqbody_error_msg.value, b"Multipart parsing error: Multipart: Final boundary missing.");
    }

    #[test]
    fn invalid_boundaries() {
        let cases: &[(&[u8], &str)] = &[
            (b"multipart/form-data", "Multipart: Boundary not found in C-T."),
            (b"multipart/form-data; BOUNDARY=a", "Multipart: Invalid boundary in C-T (case sensitivity)."),
            (b"multipart/form-data; boundary=a; boundary=b", "Multipart: Multiple boundary parameters in C-T."),
            (b"multipart/form-data; boundary=\"a", "Multipart: Invalid boundary in C-T (quote)."),
            (b"multipart/form-data; boundary=a\"", "Multipart: Invalid boundary in C-T (quote)."),
            (b"multipart/form-data, boundary=a", "Multipart: Invalid boundary in C-T (malformed)."),
            (b"multipart/form-data; boundaryx=a", "Multipart: Invalid boundary in C-T (parameter name)."),
            (b"multipart/form-data; boundary=a\x01", "Multipart: Invalid boundary in C-T (characters)."),
        ];
        for (header, err) in cases {
            let ms = ModSecurity::new();
            let rules = new_rules();
            let t = run(&ms, &rules, &[(b"Content-Type", header)], b"--a\r\n", None);
            assert_eq!(
                String::from_utf8_lossy(&t.vars.reqbody_error_msg.value),
                format!("Multipart parsing error: {}", err),
                "{}",
                String::from_utf8_lossy(header)
            );
        }
    }

    #[test]
    fn tolerated_parameter_after_boundary_and_flags() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let header = b"multipart/form-data boundary = \"0000\"; charset=utf-8";
        // the value ` "0000"; charset=utf-8` is not quoted; cut at the `;` it
        // still has invalid characters
        let t = run(&ms, &rules, &[(b"Content-Type", header)], NORMAL, None);
        assert_eq!(
            t.vars.reqbody_error_msg.value,
            b"Multipart parsing error: Multipart: Invalid boundary in C-T (characters)."
        );

        let ms = ModSecurity::new();
        let rules = new_rules();
        let header = b"multipart/form-data boundary =0000;charset=utf-8";
        let t = run(&ms, &rules, &[(b"Content-Type", header)], NORMAL, None);
        assert_eq!(t.vars.reqbody_error.value, b"0");
        assert_eq!(t.vars.multipart_missing_semicolon.value, b"1");
        assert_eq!(t.vars.multipart_boundary_white_space.value, b"1");
        assert_eq!(t.vars.multipart_strict_error.value, b"1");
        assert!(log(&rules).iter().any(|m| m == "Multipart: Invalid parameter after boundary in C-T (tolerated)."));
    }

    #[test]
    fn content_disposition_parsing() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let body = b"--0000\r\n\
Content-Disposition: form-data; name='a'; filename*=utf-8'en'na%20me.txt\r\n\
\r\n\
x\r\n\
--0000\r\n\
Content-Disposition: form-data;\r\n\
\x20name=\"b\\\"c\"\r\n\
\r\n\
y\r\n\
--0000--\r\n";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        assert_eq!(t.vars.reqbody_error.value, b"0", "{:?}", log(&rules));
        assert_eq!(t.vars.files.resolve_first(b"a").unwrap(), b"na me.txt");
        assert_eq!(t.vars.multipart_file_name_charset.resolve_first(b"a").unwrap(), b"utf-8");
        assert_eq!(t.vars.multipart_file_name_language.resolve_first(b"a").unwrap(), b"en");
        assert_eq!(t.vars.multipart_invalid_quoting.value, b"1");
        assert_eq!(t.vars.multipart_header_folding.value, b"1");
        assert_eq!(t.vars.args.resolve_first(b"b\"c").unwrap(), b"y");
        // the part headers, recorded per part name
        let mut l = Vec::new();
        t.vars.multipart_part_headers.resolve(&mut l);
        let headers: Vec<_> = l.iter().map(|v| String::from_utf8_lossy(v.value()).into_owned()).collect();
        assert!(headers.contains(&"Content-Disposition: form-data; name=\"b\\\"c\"".to_string()), "{:?}", headers);
    }

    #[test]
    fn header_errors_do_not_stop_parsing() {
        // An error in a part header is not fatal: it is recorded and
        // the parser goes on.
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let body = b"--0000\r\nContent-Type: text/plain\r\n\r\nx\r\n--0000--\r\n";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        let l = log(&rules);
        assert!(l.iter().any(|m| m == "Multipart: Part missing Content-Disposition header."));
        // the part stays in the header state: "x" is a header line without
        // colon, and the final boundary, where data should begin, too
        assert!(l.iter().any(|m| m == "Multipart: Invalid part header (colon missing): x\r\n"));
        assert!(l.iter().any(|m| m == "Multipart: Invalid part (data contains boundary)"));
        assert_eq!(t.vars.reqbody_error_msg.value, b"Multipart parsing error: Multipart: Final boundary missing.");
        assert_eq!(t.vars.multipart_invalid_part.value, b"1");
    }

    #[test]
    fn data_before_and_after() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let body = b"junk\r\n--0000\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nb\r\n--0000--\r\nafter";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        assert_eq!(t.vars.multipart_data_before.value, b"1");
        assert_eq!(t.vars.multipart_data_after.value, b"1");
        assert_eq!(t.vars.args.resolve_first(b"a").unwrap(), b"b");
        let l = log(&rules);
        assert!(l.iter().any(|m| m == "Multipart: Ignoring data after last boundary (5bytes left)"));
    }

    #[test]
    fn lf_line_endings_and_unmatched_boundary() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let ct = ct("0000");
        let body = b"--0000\nContent-Disposition: form-data; name=\"a\"\n\nb --0000x\n--0000--\n";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        assert_eq!(t.vars.multipart_lf_line.value, b"1");
        assert_eq!(t.vars.multipart_crlf_lf_lines.value, b"0");
        assert_eq!(t.vars.multipart_unmatched_boundary.value, b"2");
        assert_eq!(t.vars.args.resolve_first(b"a").unwrap(), b"b --0000x");
    }

    #[test]
    fn upload_files_are_saved_and_deleted() {
        let dir = std::env::temp_dir().join(format!("msrs-multipart-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.settings.tmp_save_uploaded_files = Some(true);
        rules.properties.settings.upload_directory = Some(dir.to_string_lossy().into_owned());
        rules.properties.settings.upload_file_mode = Some(0o600);
        let ct = ct("0000");
        let name;
        {
            let t = run(&ms, &rules, &[(b"Content-Type", &ct)], NORMAL, None);
            name = String::from_utf8(t.vars.files_tmp_names.iter().next().unwrap().0.to_vec()).unwrap();
            assert!(name.starts_with(rules.properties.settings.upload_directory.as_deref().unwrap()), "{}", name);
            assert!(name.contains("-file-"));
            assert_eq!(std::fs::read(&name).unwrap(), b"BINARYDATA");
            assert_eq!(t.vars.files_tmp_content.resolve_first(b"image").unwrap(), b"BINARYDATA");
            assert_eq!(t.vars.files_combined_size.value, b"10");
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&name).unwrap().permissions().mode() & 0o777, 0o600);
            let l = log(&rules);
            assert!(l.iter().any(|m| m.starts_with("Multipart: Created temporary file 1 (mode 0600): ")), "{:?}", l);
            assert!(l.iter().any(|m| m.starts_with("Multipart: Marking temporary file for deletion: ")));
        }
        // gone with the transaction
        assert!(!std::path::Path::new(&name).exists());

        // SecUploadKeepFiles On keeps them
        rules.properties.settings.upload_keep_files = Some(true);
        let name;
        {
            let t = run(&ms, &rules, &[(b"Content-Type", &ct)], NORMAL, None);
            name = String::from_utf8(t.vars.files_tmp_names.iter().next().unwrap().0.to_vec()).unwrap();
        }
        assert!(std::path::Path::new(&name).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn upload_file_limit() {
        let dir = std::env::temp_dir().join(format!("msrs-multipart-limit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.settings.tmp_save_uploaded_files = Some(true);
        rules.properties.settings.upload_directory = Some(dir.to_string_lossy().into_owned());
        rules.properties.settings.upload_file_limit = Some(1);
        let ct = ct("0000");
        let body = b"--0000\r\n\
Content-Disposition: form-data; name=\"f1\"; filename=\"1.txt\"\r\n\r\none\r\n\
--0000\r\n\
Content-Disposition: form-data; name=\"f2\"; filename=\"2.txt\"\r\n\r\ntwo!\r\n\
--0000--\r\n";
        let t = run(&ms, &rules, &[(b"Content-Type", &ct)], body, None);
        assert_eq!(
            t.vars.reqbody_error_msg.value,
            b"Multipart parsing error: Multipart: Upload file limit exceeded 1. Use SecUploadFileLimit to change the limit."
        );
        assert_eq!(t.vars.files_sizes.resolve_first(b"f2").unwrap(), b"4");
        assert_eq!(t.vars.files_tmp_names.len(), 1);
        assert_eq!(t.vars.multipart_strict_error.value, b"1");
        drop(t);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn helpers() {
        assert_eq!(Multipart::count_boundary_params(b"a; BOUNDARY=1; boundary"), 1);
        assert_eq!(Multipart::count_boundary_params(b"boundary=1 boundary=2"), 2);
        assert!(Multipart::boundary_characters_valid(b"a b"));
        assert!(!Multipart::boundary_characters_valid(b"a "));
        assert!(!Multipart::boundary_characters_valid(b"a;b"));
        assert!(Multipart::is_token_char(b'a'));
        assert!(!Multipart::is_token_char(b'='));
    }
}

/// Differential harness: runs the requests of regression test files through
/// the request body processors and prints the related debug log messages,
/// for comparison with the C++ implementation. Run with
/// `BODYPROC_REGRESSION=<file.json>[,...] cargo test --lib regression_dump -- --ignored --nocapture`.
mod regression_dump {
    use super::test_support::{CaptureLog, log};
    use crate::instance::ModSecurity;
    use crate::rules_set::RulesSet;
    use crate::rules_set::properties::{ParseXmlIntoArgs, RulesSetProperties, parse_config_number, parse_octal_mode};
    use crate::transaction::{RequestBodyType, Transaction};
    use modsecurity_compat::json::{JsonValue, parse_tree};

    const PREFIXES: &[&str] = &[
        "Multipart",
        "Adding request argument",
        "Skipping request argument",
        "XML",
        "JSON",
        "Request body excluding files",
        "Registered XML",
        "Failed to register",
    ];

    fn s(v: Option<&JsonValue>) -> Vec<u8> {
        match v {
            Some(JsonValue::String(s)) => s.clone(),
            Some(JsonValue::Number(n)) => n.clone(),
            _ => Vec::new(),
        }
    }

    fn configure(rules: &mut RulesSet, lines: &[String]) -> (Option<RequestBodyType>, Option<ParseXmlIntoArgs>) {
        let p = &mut rules.properties;
        let mut processor = None;
        let mut ctl_args = None;
        for l in lines {
            let mut it = l.splitn(2, ' ');
            let d = it.next().unwrap_or("").to_ascii_lowercase();
            let v = it.next().unwrap_or("").trim().trim_matches('"').to_string();
            let b = |v: &str| {
                if v.eq_ignore_ascii_case("on") { Some(true) } else { Some(false) }
            };
            match d.as_str() {
                "secrequestbodyjsondepthlimit" => {
                    p.settings.request_body_json_depth_limit = Some(parse_config_number(&v).unwrap())
                }
                "secargumentslimit" => p.settings.arguments_limit = Some(parse_config_number(&v).unwrap()),
                "secrequestbodynofileslimit" => {
                    p.settings.request_body_no_files_limit = Some(parse_config_number(&v).unwrap())
                }
                "secrequestbodylimit" => p.settings.request_body_limit = Some(parse_config_number(&v).unwrap()),
                "secuploadfilelimit" => p.settings.upload_file_limit = Some(parse_config_number(&v).unwrap()),
                "secuploadfilemode" => p.settings.upload_file_mode = Some(parse_octal_mode(&v).unwrap()),
                "secuploaddir" => p.settings.upload_directory = Some(v.clone()),
                "secuploadkeepfiles" => p.settings.upload_keep_files = b(&v),
                "sectmpsaveuploadedfiles" => p.settings.tmp_save_uploaded_files = b(&v),
                "secxmlexternalentity" => p.settings.sec_xml_external_entity = b(&v),
                "secparsexmlintoargs" => {
                    p.settings.sec_xml_parse_xml_into_args = match v.to_ascii_lowercase().as_str() {
                        "on" => Some(ParseXmlIntoArgs::On),
                        "onlyargs" => Some(ParseXmlIntoArgs::OnlyArgs),
                        _ => Some(ParseXmlIntoArgs::Off),
                    }
                }
                "secrule" => {
                    if l.contains("ctl:requestBodyProcessor=XML") {
                        processor = Some(RequestBodyType::XMLRequestBody);
                    } else if l.contains("ctl:requestBodyProcessor=JSON") {
                        processor = Some(RequestBodyType::JSONRequestBody);
                    }
                    if l.contains("ctl:parseXmlIntoArgs=OnlyArgs") {
                        ctl_args = Some(ParseXmlIntoArgs::OnlyArgs);
                    } else if l.contains("ctl:parseXmlIntoArgs=On") {
                        ctl_args = Some(ParseXmlIntoArgs::On);
                    } else if l.contains("ctl:parseXmlIntoArgs=Off") {
                        ctl_args = Some(ParseXmlIntoArgs::Off);
                    }
                }
                _ => {}
            }
        }
        (processor, ctl_args)
    }

    /// Emulates the `SecRule XML...` rules of a test: XPath targets (with
    /// the rule's `xmlns` actions) and the validation operators.
    #[cfg(feature = "libxml2")]
    fn xml_rules(t: &mut Transaction<'_>, lines: &[String]) {
        use crate::actions::xmlns::XmlNS;
        use crate::operators::operator::Operator;
        use crate::rule::{Rule, RuleKind};

        for l in lines {
            let Some(rest) = l.strip_prefix("SecRule XML") else {
                continue;
            };
            let target = format!("XML{}", rest.split(' ').next().unwrap_or(""));
            let quoted: Vec<&str> = l.split('"').collect();
            let op = quoted.get(1).copied().unwrap_or("");
            let actions = quoted.get(3).copied().unwrap_or("");
            let mut acts: Vec<crate::actions::rule_action::RuleAction> = Vec::new();
            for a in actions.split(',') {
                if a.starts_with("xmlns:") {
                    let (name, payload) = crate::actions::action::name_and_payload(a);
                    let x = XmlNS::new(name, payload).unwrap();
                    acts.push(crate::actions::rule_action::RuleAction::from(x));
                }
            }
            let rule = Rule::new(Some(acts), None, "x", 1, RuleKind::SecAction);
            if target != "XML" {
                let v = crate::variables::new_variable(
                    "XML",
                    crate::variables::VariableSelector::DictElement(
                        target.strip_prefix("XML:").unwrap_or(&target).to_string(),
                    ),
                )
                .unwrap();
                let mut values = Vec::new();
                v.evaluate(t, Some(&rule), &mut values);
                for x in values {
                    println!("XMLVAR {}={}", String::from_utf8_lossy(x.key()), String::from_utf8_lossy(x.value()));
                }
            }
            let (name, param) = op.split_once(' ').unwrap_or((op, ""));
            let mut o: Operator = match name {
                "@validateDTD" | "@validateSchema" => {
                    crate::operators::operator::instantiate(&name[1..], param).unwrap()
                }
                _ => continue,
            };
            o.init("x.json").unwrap();
            let mut rm = crate::rule::message::RuleMessage::new(&rule);
            println!(
                "OP {} -> {}",
                name,
                o.evaluate(&mut crate::operators::operator::MatchContext::new(t, &rule, &mut rm), b"")
            );
        }
    }

    #[test]
    #[ignore]
    fn regression_dump() {
        let Ok(files) = std::env::var("BODYPROC_REGRESSION") else {
            return;
        };
        // resources are relative to the test directory
        if let Ok(dir) = std::env::var("BODYPROC_CWD") {
            std::env::set_current_dir(dir).unwrap();
        }
        for f in files.split(',') {
            let data = std::fs::read(f).unwrap();
            let JsonValue::Array(tests) = parse_tree(&data).unwrap() else { panic!("not an array") };
            for (i, test) in tests.iter().enumerate() {
                println!("=== {} {}", i, String::from_utf8_lossy(&s(test.get("title"))));
                let lines: Vec<String> = match test.get("rules") {
                    Some(JsonValue::Array(a)) => {
                        a.iter().map(|r| String::from_utf8_lossy(&s(Some(r))).into_owned()).collect()
                    }
                    _ => Vec::new(),
                };
                let mut rules = RulesSet::new();
                rules.properties = RulesSetProperties::with_debug_log(Box::new(CaptureLog::default()));
                let (processor, ctl_args) = configure(&mut rules, &lines);
                let ms = ModSecurity::new();
                {
                    let req = test.get("request").unwrap();
                    let mut t = Transaction::new(&ms, &rules, None);
                    t.process_connection("200.249.12.31", 123, "200.249.12.31", 80);
                    t.process_uri(&s(req.get("uri")), &s(req.get("method")), b"1.1");
                    if let Some(JsonValue::Object(h)) = req.get("headers") {
                        for (k, v) in h {
                            t.add_request_header(k, &s(Some(v)));
                        }
                    }
                    t.process_request_headers();
                    if let Some(p) = processor {
                        t.body.request_body_processor = p;
                    }
                    if let Some(a) = ctl_args {
                        t.ctl.parse_xml_into_args = Some(a);
                    }
                    let mut body = Vec::new();
                    if let Some(JsonValue::Array(b)) = req.get("body") {
                        for l in b {
                            body.extend_from_slice(&s(Some(l)));
                        }
                    }
                    t.append_request_body(&body);
                    t.process_request_body();
                    #[cfg(feature = "libxml2")]
                    xml_rules(&mut t, &lines);
                    let mut vars = Vec::new();
                    t.vars.args.resolve(&mut vars);
                    for v in vars.iter().rev() {
                        println!("ARG {}={}", String::from_utf8_lossy(v.key()), String::from_utf8_lossy(v.value()));
                    }
                    println!("REQBODY_ERROR_MSG {}", String::from_utf8_lossy(&t.vars.reqbody_error_msg.value));
                }
                for m in log(&rules) {
                    if PREFIXES.iter().any(|p| m.starts_with(p)) {
                        println!("{}", m);
                    }
                }
            }
        }
    }
}
