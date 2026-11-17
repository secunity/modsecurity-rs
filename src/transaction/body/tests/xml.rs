#[cfg(feature = "libxml2")]
mod tests {
    use crate::actions::rule_action::RuleAction;
    use crate::actions::xmlns::XmlNS;
    use crate::instance::ModSecurity;
    use crate::operators::operator::Operator;
    use crate::rule::{Rule, RuleKind};
    use crate::rules_set::properties::ParseXmlIntoArgs;
    use crate::transaction::body::tests::multipart::test_support::{log, new_rules, run};
    use crate::transaction::{RequestBodyType, Transaction};
    use crate::variables::variable_value::VariableValue;
    use crate::variables::{VariableSelector, new_variable};

    const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/test-cases/data/");

    fn xml<'a>(ms: &'a ModSecurity, rules: &'a crate::rules_set::RulesSet, body: &[u8]) -> Transaction<'a> {
        run(ms, rules, &[(b"Content-Type", b"text/xml")], body, Some(RequestBodyType::XMLRequestBody))
    }

    fn xpath(t: &Transaction<'_>, expr: &str, ns: Option<(&str, &str)>) -> Vec<String> {
        let mut acts: Vec<RuleAction> = Vec::new();
        if let Some((scope, href)) = ns {
            let x = XmlNS::new(&format!("xmlns:{}={}", scope, href)).unwrap();
            acts.push(RuleAction::from(x));
        }
        let rule = Rule::new(Some(acts), None, "f", 1, RuleKind::SecAction);
        let v = new_variable("XML", VariableSelector::DictElement(expr.to_string())).unwrap();
        let mut l: Vec<VariableValue> = Vec::new();
        v.evaluate(t, Some(&rule), &mut l);
        l.iter()
            .map(|v| {
                assert_eq!(v.key(), format!("XML:{}", expr).as_bytes());
                String::from_utf8_lossy(v.value()).into_owned()
            })
            .collect()
    }

    #[test]
    fn document_and_xpath() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let t = xml(&ms, &rules, br#"<a xmlns:p="http://x/ns"><p:b>1</p:b><p:b>2</p:b><c>3</c></a>"#);
        assert_eq!(t.vars.reqbody_error.value, b"0");
        assert_eq!(xpath(&t, "/a/p:b", Some(("p", "http://x/ns"))), ["1", "2"]);
        assert_eq!(xpath(&t, "/a/c", None), ["3"]);
        assert!(xpath(&t, "count(/a/c)", None).is_empty());
        assert!(xpath(&t, "/a/q:b", None).is_empty());
        let l = log(&rules);
        assert!(l.iter().any(|m| m == "XML: Parsing complete (well_formed 1)."));
        assert!(l.iter().any(|m| m == "Registered XML namespace href \"http://x/ns\" prefix \"p\""));
        assert!(l.iter().any(|m| m == "XML: Unable to evaluate xpath expression."));
        assert!(!l.iter().any(|m| m.starts_with("XML: SecParseXmlIntoArgs")));

        // XML (no element) is the whole tree, keyed by its empty name.
        let mut l = Vec::new();
        new_variable("XML", VariableSelector::None).unwrap().evaluate(&t, None, &mut l);
        assert_eq!(l[0].key(), b"");
        assert_eq!(l[0].value(), b"[XML document tree]");
    }

    #[test]
    fn malformed_document() {
        let ms = ModSecurity::new();
        let rules = new_rules();
        let t = xml(&ms, &rules, b"<a><b></a>");
        assert_eq!(t.vars.reqbody_error_msg.value, b"XML parsing error: XML: Failed to parse document.");
        assert_eq!(t.vars.reqbody_processor_error.value, b"1");
        // the (partial) document is kept, as in C++
        assert!(t.body.xml.as_ref().unwrap().has_doc());
        assert_eq!(t.body.xml.as_ref().unwrap().well_formed(), 0);
    }

    #[test]
    fn parse_into_args() {
        let body = br#"<a x="1"><b>t1</b><c><d>t2</d><d>&amp;</d></c>tail<e/></a>"#;
        for mode in [Some(ParseXmlIntoArgs::On), Some(ParseXmlIntoArgs::OnlyArgs)] {
            let ms = ModSecurity::new();
            let mut rules = new_rules();
            rules.properties.settings.sec_xml_parse_xml_into_args = mode;
            let t = xml(&ms, &rules, body);
            let mut l = Vec::new();
            t.vars.args.resolve(&mut l);
            let mut a: Vec<(String, String)> = l
                .iter()
                .map(|v| {
                    (String::from_utf8_lossy(v.key()).into_owned(), String::from_utf8_lossy(v.value()).into_owned())
                })
                .collect();
            a.sort();
            assert_eq!(
                a,
                [
                    ("xml.a.b".to_string(), "t1".to_string()),
                    ("xml.a.c.d".to_string(), "&".to_string()),
                    ("xml.a.c.d".to_string(), "t2".to_string()),
                    ("xml.a.e".to_string(), "".to_string()),
                ]
            );
            assert_eq!(t.vars.reqbody_error.value, b"0");
            // OnlyArgs: no document
            assert_eq!(t.body.xml.as_ref().unwrap().has_doc(), mode == Some(ParseXmlIntoArgs::On));
        }

        // SecArgumentsLimit stops the SAX parser
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.settings.sec_xml_parse_xml_into_args = Some(ParseXmlIntoArgs::On);
        rules.properties.settings.arguments_limit = Some(2);
        let t = xml(&ms, &rules, b"<a><b>1</b><b>2</b><b>3</b><b>4</b></a>");
        assert_eq!(t.vars.args.len(), 2);
        assert_eq!(t.vars.reqbody_error_msg.value, b"XML parsing error: XML: Failed to parse document for ARGS.");
    }

    /// The documents libxml2 builds and leaves in a parser context are
    /// freed: the one holding a DTD's entities while parsing into ARGS (C++
    /// leaked it), and the one of a parse abandoned before the end of the
    /// body. (A leak is seen under the sanitizer: replay
    /// `fuzz/regressions/body/` with the `body` fuzz target.)
    #[test]
    fn documents_left_in_contexts() {
        let body = br#"<?xml version="1.0"?><!DOCTYPE a [<!ENTITY js "Jo">]><a><b>&js;</b></a>"#;
        for mode in [Some(ParseXmlIntoArgs::On), Some(ParseXmlIntoArgs::OnlyArgs)] {
            let ms = ModSecurity::new();
            let mut rules = new_rules();
            rules.properties.settings.sec_xml_parse_xml_into_args = mode;
            // (The SAX handler that parses into ARGS has no entity
            // callbacks, so the document fails there, as in C++.)
            let t = xml(&ms, &rules, body);
            assert_eq!(t.vars.reqbody_error_msg.value, b"XML parsing error: XML: Failed to parse document for ARGS.");
        }
        // Abandoned: the transaction ends before the body is complete.
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.settings.sec_xml_parse_xml_into_args = Some(ParseXmlIntoArgs::On);
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_connection("200.249.12.31", 123, "200.249.12.31", 80);
        t.process_uri(b"/", b"POST", b"1.1");
        t.add_request_header(b"Content-Type", b"text/xml");
        t.process_request_headers();
        t.body.request_body_type = RequestBodyType::XMLRequestBody;
        t.append_request_body(&body[..60]);
        drop(t);
    }

    fn validate(op: &Operator, t: &mut Transaction<'_>) -> bool {
        crate::operators::operator::test_support::eval_in(op, t, b"")
    }

    /// `@validateDTD file`, as the engine builds it.
    fn dtd_op(file: &str) -> Operator {
        crate::operators::operator::instantiate("validateDTD", file).unwrap()
    }

    /// `@validateSchema file`, as the engine builds it.
    fn schema_op(file: &str) -> Operator {
        crate::operators::operator::instantiate("validateSchema", file).unwrap()
    }

    #[test]
    fn validate_dtd_and_schema() {
        let envelope = br#"<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE Envelope SYSTEM "SoapEnvelope.dtd">
<Envelope><Body><getInput><id type="string">12123</id></getInput></Body></Envelope>"#;
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.settings.sec_xml_external_entity = Some(true);
        let dtd_path = format!("{}SoapEnvelope.dtd", DATA);
        let mut dtd = dtd_op(&dtd_path);
        dtd.init("x.conf").unwrap();
        let mut bad_dtd = dtd_op(&format!("{}SoapEnvelope-bad.dtd", DATA));
        bad_dtd.init("x.conf").unwrap();
        let mut missing = dtd_op("missing.dtd");
        assert!(missing.init("x.conf").unwrap_err().starts_with("XML: File not found: missing.dtd. Looking at:"));

        let mut t = xml(&ms, &rules, envelope);
        assert!(!validate(&dtd, &mut t));
        assert!(validate(&bad_dtd, &mut t));
        let l = log(&rules);
        assert!(l.contains(&format!("XML: Successfully validated payload against DTD: {}", dtd_path)));
        assert!(l.iter().any(|m| m.starts_with("XML: Failed to load DTD: ")));

        let invalid = String::from_utf8_lossy(envelope).replace("Body>", "xBody>");
        let mut t = xml(&ms, &rules, invalid.as_bytes());
        assert!(validate(&dtd, &mut t));
        let l = log(&rules);
        assert!(l.contains(&"XML Error: No declaration for element xBody\n".to_string()), "{:?}", l);
        assert!(l.contains(&"XML: DTD validation failed.".to_string()));

        // Schema
        let soap = br#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><x/></soap:Body></soap:Envelope>"#;
        let xsd_path = format!("{}SoapEnvelope.xsd", DATA);
        let mut xsd = schema_op(&xsd_path);
        xsd.init("x.conf").unwrap();
        let mut t = xml(&ms, &rules, soap);
        assert!(!validate(&xsd, &mut t), "{:?}", log(&rules));
        assert!(log(&rules).contains(&format!("XML: Successfully validated payload against Schema: {}", xsd_path)));
        let mut t = xml(&ms, &rules, String::from_utf8_lossy(soap).replace("Body>", "xBody>").as_bytes());
        assert!(validate(&xsd, &mut t));
        assert!(log(&rules).iter().any(|m| m.starts_with(
            "XML Error: Element '{http://schemas.xmlsoap.org/soap/envelope/}xBody': This element is not expected."
        )));

        let bad_xsd_path = format!("{}SoapEnvelope-bad.xsd", DATA);
        let mut bad_xsd = schema_op(&bad_xsd_path);
        bad_xsd.init("x.conf").unwrap();
        let mut t = xml(&ms, &rules, soap);
        assert!(validate(&bad_xsd, &mut t));
        assert!(log(&rules).contains(&format!(
            "XML: Failed to load Schema: {0}. XML Error: Failed to parse the XML resource '{0}'.\n",
            bad_xsd_path
        )));

        // not well formed / no document
        let mut t = xml(&ms, &rules, b"<a>");
        assert!(validate(&xsd, &mut t));
        assert!(validate(&dtd, &mut t));
        let l = log(&rules);
        assert!(l.contains(&"XML: Schema validation failed because content is not well formed.".to_string()));
        assert!(l.contains(&"XML: DTD validation failed because content is not well formed.".to_string()));
        let mut t = Transaction::new(&ms, &rules, None);
        assert!(validate(&xsd, &mut t));
        assert!(log(&rules).contains(&"XML document tree could not be found for schema validation.".to_string()));
    }

    #[test]
    fn external_entities() {
        let body = br#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE author [<!ELEMENT book ANY><!ENTITY js SYSTEM "/etc/hostname">]><bookstore><book>&js;</book></bookstore>"#;
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.settings.sec_xml_external_entity = Some(false);
        let mut dtd = dtd_op(&format!("{}SoapEnvelope.dtd", DATA));
        dtd.init("x.conf").unwrap();
        let mut t = xml(&ms, &rules, body);
        // the DTD cannot be loaded either: the loader is libxml2-wide
        assert!(validate(&dtd, &mut t));
        assert!(log(&rules).iter().any(|m| m.starts_with("XML: Failed to load DTD: ")));
    }
}

/// A transaction (and so its XML parsers and document) can move to another
/// thread, as before libxml2 was put behind `utils::libxml2`.
#[test]
fn transaction_is_send() {
    fn send<T: Send>() {}
    send::<crate::transaction::Transaction<'static>>();
    fn shared<T: Send + Sync>() {}
    shared::<crate::instance::ModSecurity>();
    shared::<crate::rules_set::RulesSet>();
}
