mod tests {
    use crate::instance::ModSecurity;
    use crate::rules_set::properties::parse_config_number;
    use crate::transaction::RequestBodyProcessor;
    use crate::transaction::body::tests::multipart::test_support::{log, new_rules, run};

    fn args(body: &[u8], depth: Option<&str>, limit: Option<&str>) -> (Vec<(String, String)>, String) {
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        if let Some(d) = depth {
            rules.properties.settings.request_body_json_depth_limit = Some(parse_config_number(d).unwrap());
        }
        if let Some(l) = limit {
            rules.properties.settings.arguments_limit = Some(parse_config_number(l).unwrap());
        }
        let t = run(&ms, &rules, &[(b"Content-Type", b"application/json")], body, Some(RequestBodyProcessor::Json));
        let mut l = Vec::new();
        t.vars.args.resolve(&mut l);
        let mut v: Vec<(String, String)> = l
            .iter()
            .map(|v| (String::from_utf8_lossy(v.key()).into_owned(), String::from_utf8_lossy(v.value()).into_owned()))
            .collect();
        v.sort();
        let _ = log(&rules);
        (v, String::from_utf8_lossy(t.vars.reqbody_error_msg.value()).into_owned())
    }

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = p.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        v.sort();
        v
    }

    #[test]
    fn names_follow_the_document_structure() {
        let (a, err) = args(br#"{"a":[1,[2,3],{"b":null}],"c":true,"":"e","d":{},"f":-1.5e3}"#, None, None);
        assert_eq!(err, "");
        assert_eq!(
            a,
            pairs(&[
                ("json.a.array_0", "1"),
                ("json.a.array_1.array_0", "2"),
                ("json.a.array_1.array_1", "3"),
                ("json.a.array_2.b", ""),
                ("json.c", "true"),
                ("json.empty-key", "e"),
                ("json.f", "-1.5e3"),
            ])
        );
        let (a, _) = args(b"123", None, None);
        assert_eq!(a, pairs(&[("json", "123")]));
        let (a, _) = args(br#"[1,{"x":[]},[[["deep"]]]]"#, None, None);
        assert_eq!(a, pairs(&[("json.array_0", "1"), ("json.array_2.array_0.array_0.array_0", "deep")]));
    }

    #[test]
    fn errors() {
        let (_, err) = args(b"a", None, None);
        assert_eq!(err, "JSON parsing error: lexical error: invalid char in json text.\n");
        let (a, err) = args(br#"{"a":[1,2"#, None, None);
        assert_eq!(err, "JSON parsing error: parse error: premature EOF\n");
        assert_eq!(a.len(), 2);
        let (_, err) = args(br#"{"a":1} x"#, None, None);
        assert_eq!(err, "JSON parsing error: parse error: trailing garbage\n");
    }

    #[test]
    fn limits() {
        let body = br#"{"key1":{"key2":{"key3":{"key4":{"key5":"thevalue"}}}}}"#;
        let (a, err) = args(body, Some("5"), None);
        assert_eq!(err, "");
        assert_eq!(a, pairs(&[("json.key1.key2.key3.key4.key5", "thevalue")]));
        let (a, err) = args(body, Some("4"), None);
        assert_eq!(
            err,
            "JSON parsing error: parse error: client cancelled parse via callback return value\n. Parsing depth limit exceeded"
        );
        assert!(a.is_empty());

        let (a, err) = args(br#"{"a":1,"b":2,"c":3}"#, None, Some("2"));
        assert_eq!(err, "JSON parsing error: parse error: client cancelled parse via callback return value\n");
        assert_eq!(a, pairs(&[("json.a", "1"), ("json.b", "2")]));
    }

    /// A long key repeated in the name of every value below it: the names
    /// stop at their allowance (64 times the body, and 1 MiB) with a
    /// request body processor error.
    #[test]
    fn argument_names_too_long() {
        let values = vec!["1"; 10_000].join(",");
        let body = format!("{{\"{}\":[{values}]}}", "k".repeat(64 << 10));
        let ms = ModSecurity::new();
        let rules = new_rules();
        let t = run(
            &ms,
            &rules,
            &[(b"Content-Type", b"application/json")],
            body.as_bytes(),
            Some(RequestBodyProcessor::Json),
        );
        assert_eq!(t.vars.reqbody_error.value(), b"1");
        assert_eq!(t.vars.reqbody_processor_error.value(), b"1");
        assert_eq!(
            t.vars.reqbody_processor_error_msg.value(),
            b"JSON parsing error: parse error: client cancelled parse via callback return value\n. Argument names too long"
        );
        assert!(t.vars.args.len() < 10_000);
    }

    #[test]
    fn repeated_processing_retains_partial_paths_and_error_messages() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let mut t = run(&ms, &rules, &[], br#"{"a":[1,2"#, Some(RequestBodyProcessor::Json));
        let error = t.vars.reqbody_error_msg.value().to_vec();
        assert_eq!(error, b"JSON parsing error: parse error: premature EOF\n");
        t.http.request_body = b"[3]".to_vec();
        t.process_request_body();
        assert_eq!(t.vars.args.resolve_first(b"json.a.array_2.array_0").unwrap(), b"3");
        assert_eq!(t.vars.reqbody_error.value(), b"0");
        // Successful processing clears the flags, but retains earlier text.
        assert_eq!(t.vars.reqbody_error_msg.value(), error);
        assert_eq!(t.http.request_body, b"[3]");
        assert_eq!(t.vars.request_body.value(), b"[3]");
    }

    #[test]
    fn empty_bodies_and_depth_errors_keep_their_existing_state() {
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.settings.request_body_json_depth_limit = Some(0);
        let mut t = run(&ms, &rules, &[], b"[]", Some(RequestBodyProcessor::Json));
        assert_eq!(t.vars.reqbody_error.value(), b"1");
        t.http.request_body = b"x".to_vec();
        t.process_request_body();
        let error = b"JSON parsing error: lexical error: invalid char in json text.\n. Parsing depth limit exceeded";
        assert_eq!(t.vars.reqbody_error_msg.value(), error);
        t.http.request_body.clear();
        t.process_request_body();
        assert_eq!(t.vars.reqbody_error.value(), b"0");
        assert_eq!(t.vars.reqbody_error_msg.value(), error);
    }
}
