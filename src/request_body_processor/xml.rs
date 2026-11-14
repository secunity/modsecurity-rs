//! The XML request body processor (feature `libxml2`, the C++
//! `WITH_LIBXML2`). The body is parsed with libxml2's push parser into a
//! document, which the `XML` variable (XPath) and the `@validateDTD` /
//! `@validateSchema` operators work on. With `SecParseXmlIntoArgs` set to
//! `On` or `OnlyArgs` a second, SAX based, parser turns the leaf elements of
//! the document into `ARGS` named after their path (`xml.root.child`).
//!
//! libxml2 itself is behind the safe API of `utils::libxml2`.

/// Initialises libxml2 (`xmlInitParser()`), done once by the `ModSecurity`
/// constructor.
pub fn init_parser() {
    #[cfg(feature = "libxml2")]
    crate::utils::libxml2::init_parser();
}

#[cfg(feature = "libxml2")]
pub use with_libxml2::Xml;

#[cfg(feature = "libxml2")]
mod with_libxml2 {
    use crate::rules_set_properties::{ParseXmlIntoArgs, config_xml_parse_xml_into_args_string};
    use crate::transaction::Transaction;
    use crate::utils::libxml2::{self, Document, PushParser, SaxHandler, SaxParser};

    /// An open element while parsing XML into args.
    #[derive(Debug, Default)]
    struct NodeData {
        has_child: bool,
    }

    /// The state of the SAX parser that turns the XML into
    /// `ARGS`.
    #[derive(Debug)]
    struct XmlNodes {
        nodes: Vec<NodeData>,
        node_depth: u64,
        currpath: Vec<u8>,
        currval: Vec<u8>,
        currval_is_set: bool,
    }

    impl XmlNodes {
        fn new() -> Self {
            XmlNodes {
                nodes: Vec::new(),
                node_depth: 0,
                // the XML will contain at least one node, which is the pseudo
                // root node 'xml'
                currpath: b"xml.".to_vec(),
                currval: Vec::new(),
                currval_is_set: false,
            }
        }

        /// Opens the element `name`: appends it to the current path and
        /// clears the current value.
        fn on_start_element(&mut self, name: &[u8]) {
            self.nodes.push(NodeData::default());
            self.node_depth += 1;
            // FIXME - later if we want to check the depth of XML tree
            // if it's not the first (root) item, then append a '.'
            // note, the condition should always be true because there is
            // always a pseudo root element: 'xml'
            let n = self.nodes.len();
            if n > 1 {
                self.currpath.push(b'.');
                self.nodes[n - 2].has_child = true;
            }
            self.currpath.extend_from_slice(name);
            // set the current value empty
            // this is necessary because if there is any text between the
            // tags (new line, etc) it will be added to the current value
            self.currval.clear();
            self.currval_is_set = false;
        }

        /// Closes the element `name`; a leaf element becomes an argument.
        /// Returns `false` when parsing has to stop because the number of
        /// arguments reached the limit.
        fn on_end_element(&mut self, t: &mut Transaction<'_>, name: &[u8]) -> bool {
            let mut keep_parsing = true;
            if self.nodes.last().is_some_and(|nd| !nd.has_child) {
                keep_parsing = t.add_argument("XML", &self.currpath, &self.currval, 0);
            }
            if !self.currpath.is_empty() {
                // set an offset to store whether this is the first item, in
                // order to know whether to remove the '.'
                let offset = if self.nodes.len() > 1 { 1 } else { 0 };
                let new_len = self.currpath.len().saturating_sub(name.len() + offset);
                self.currpath.truncate(new_len);
            }
            self.nodes.pop();
            self.node_depth = self.node_depth.wrapping_sub(1);
            self.currval.clear();
            self.currval_is_set = false;
            keep_parsing
        }

        /// Appends text to the value of the current element.
        fn on_characters(&mut self, content: &[u8]) {
            // libxml2 SAX parser will call this function multiple times
            // during the parsing of a single node, if the value has
            // multibyte characters, so we need to concatenate the values
            if !self.currval_is_set {
                self.currval = content.to_vec();
                self.currval_is_set = true;
            } else {
                self.currval.extend_from_slice(content);
            }
        }
    }

    /// The SAX handler of the parser into ARGS: the parser state and the
    /// transaction the arguments go to.
    struct ArgsHandler<'a, 't> {
        nodes: &'a mut XmlNodes,
        t: &'a mut Transaction<'t>,
    }

    impl SaxHandler for ArgsHandler<'_, '_> {
        /// An element starts.
        fn start_element(&mut self, name: &[u8]) {
            self.nodes.on_start_element(name);
        }

        /// An element ends; `false` stops the parser.
        fn end_element(&mut self, name: &[u8]) -> bool {
            self.nodes.on_end_element(self.t, name)
        }

        /// Text of the current element.
        fn characters(&mut self, text: &[u8]) {
            self.nodes.on_characters(text);
        }
    }

    /// The XML body processor of a transaction: the parsers and the
    /// resulting document.
    #[derive(Debug, Default)]
    pub struct Xml {
        parsing_ctx: Option<PushParser>,
        /// additional parser for arguments
        parsing_ctx_arg: Option<SaxParser>,
        doc: Option<Document>,
        /// parser state for SAX parser
        xml_parser_state: Option<XmlNodes>,

        well_formed: u32,
    }

    impl Xml {
        pub fn new() -> Self {
            Self::default()
        }

        /// Whether the parsed document is available.
        #[cfg(test)]
        pub fn has_doc(&self) -> bool {
            self.doc.is_some()
        }

        /// The parsed document.
        pub(crate) fn document(&self) -> Option<&Document> {
            self.doc.as_ref()
        }

        /// Whether the document is well formed: 1 if it is, 0 otherwise (or
        /// before parsing completed).
        pub fn well_formed(&self) -> u32 {
            self.well_formed
        }

        fn parse_into_args(t: &Transaction<'_>) -> bool {
            matches!(t.sec_xml_parse_xml_into_args, Some(ParseXmlIntoArgs::On) | Some(ParseXmlIntoArgs::OnlyArgs))
        }

        fn only_args(t: &Transaction<'_>) -> bool {
            t.sec_xml_parse_xml_into_args == Some(ParseXmlIntoArgs::OnlyArgs)
        }

        /// Prepares the processor for a body: sets the external entity
        /// policy and, when parsing into `ARGS`, the SAX parser state.
        pub fn init(&mut self, t: &mut Transaction<'_>) -> bool {
            libxml2::allow_external_entities(t.rules.properties.sec_xml_external_entity == Some(true));

            if Self::parse_into_args(t) {
                crate::ms_dbg_a!(
                    t,
                    9,
                    "XML: SecParseXmlIntoArgs is set to {}",
                    config_xml_parse_xml_into_args_string(t.sec_xml_parse_xml_into_args)
                );
                // set the parser state struct
                self.xml_parser_state = Some(XmlNodes::new());
            }

            true
        }

        /// Runs `f` with the SAX handler for the parser state and `t`.
        fn with_handler<R>(
            nodes: &mut Option<XmlNodes>,
            t: &mut Transaction<'_>,
            f: impl FnOnce(&mut dyn SaxHandler) -> R,
        ) -> R {
            /// The handler without a parser state (not reached: the parser
            /// into ARGS only exists with one).
            struct Ignore;
            impl SaxHandler for Ignore {
                fn start_element(&mut self, _: &[u8]) {}
                fn end_element(&mut self, _: &[u8]) -> bool {
                    true
                }
                fn characters(&mut self, _: &[u8]) {}
            }
            match nodes {
                Some(nodes) => f(&mut ArgsHandler { nodes, t }),
                None => f(&mut Ignore),
            }
        }

        /// Feeds a chunk of the body to the parsers (the first chunk creates
        /// them).
        pub fn process_chunk(&mut self, t: &mut Transaction<'_>, buf: &[u8]) -> Result<(), String> {
            // We want to initialise our parsing context here, to enable us
            // to pass it the first chunk of data so that it can attempt to
            // auto-detect the encoding.
            if self.parsing_ctx.is_none() && self.parsing_ctx_arg.is_none() {
                // First invocation.

                crate::ms_dbg_a!(t, 4, "XML: Initialising parser.");

                // NOTE When Sax interface is used libxml will not create the
                // document object, but we need it.

                if !Self::only_args(t) {
                    let Some(parser) = PushParser::new(buf) else {
                        crate::ms_dbg_a!(t, 4, "XML: Failed to create parsing context.");
                        return Err("XML: Failed to create parsing context.".to_string());
                    };
                    self.parsing_ctx = Some(parser);
                }

                if Self::parse_into_args(t) {
                    let Some(parser) = SaxParser::new(buf) else {
                        return Err("XML: Failed to create parsing context for ARGS.".to_string());
                    };
                    self.parsing_ctx_arg = Some(parser);
                }

                return Ok(());
            }

            // Not a first invocation.
            if let Some(parser) = &self.parsing_ctx
                && !Self::only_args(t)
            {
                parser.parse_chunk(buf);
                if parser.well_formed() != 1 {
                    crate::ms_dbg_a!(t, 4, "XML: Failed to parse document.");
                    return Err("XML: Failed to parse document.".to_string());
                }
            }

            if let Some(parser) = &self.parsing_ctx_arg
                && Self::parse_into_args(t)
            {
                Self::with_handler(&mut self.xml_parser_state, t, |h| parser.parse_chunk(buf, h));
                if parser.well_formed() != 1 {
                    crate::ms_dbg_a!(t, 4, "XML: Failed to parse document for ARGS.");
                    return Err("XML: Failed to parse document for ARGS.".to_string());
                }
            }

            Ok(())
        }

        /// Ends the body: finishes the parsers and keeps the document.
        pub fn complete(&mut self, t: &mut Transaction<'_>) -> Result<(), String> {
            // Only if we have a context, meaning we've done some work.
            if self.parsing_ctx.is_none() && self.parsing_ctx_arg.is_none() {
                return Ok(());
            }
            if self.parsing_ctx.is_some()
                && !Self::only_args(t)
                && let Some(parser) = self.parsing_ctx.take()
            {
                // This is how we signal the end of parsing to libxml; the
                // document is owned by `self` from now on.
                let (well_formed, doc) = parser.finish();
                self.well_formed = well_formed as u32;
                self.doc = doc;
                crate::ms_dbg_a!(t, 4, "XML: Parsing complete (well_formed {}).", self.well_formed);

                if self.well_formed != 1 {
                    crate::ms_dbg_a!(t, 4, "XML: Failed to parse document.");
                    return Err("XML: Failed to parse document.".to_string());
                }
            }
            if self.parsing_ctx_arg.is_some()
                && Self::parse_into_args(t)
                && let Some(parser) = self.parsing_ctx_arg.take()
            {
                // This is how we signal the end of parsing to libxml.
                let rc = Self::with_handler(&mut self.xml_parser_state, t, |h| parser.finish(h));
                if rc != 0 {
                    return Err("XML: Failed to parse document for ARGS.".to_string());
                }
            }

            Ok(())
        }
    }
}

#[cfg(all(test, feature = "libxml2"))]
mod tests {
    use crate::actions::xmlns::XmlNS;
    use crate::modsecurity::ModSecurity;
    use crate::operators::operator::Operator;
    use crate::operators::validate_dtd::ValidateDTD;
    use crate::operators::validate_schema::ValidateSchema;
    use crate::request_body_processor::multipart::test_support::{log, new_rules, run};
    use crate::rule_with_actions::{RuleAction, RuleWithActions, RuleWithActionsKind};
    use crate::rules_set_properties::ParseXmlIntoArgs;
    use crate::run_time_string::RunTimeString;
    use crate::transaction::{RequestBodyType, Transaction};
    use crate::variable_value::VariableValue;
    use crate::variables::{VariableSelector, new_variable};

    const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/test-cases/data/");

    fn xml<'a>(ms: &'a ModSecurity, rules: &'a crate::rules_set::RulesSet, body: &[u8]) -> Transaction<'a> {
        run(ms, rules, &[(b"Content-Type", b"text/xml")], body, Some(RequestBodyType::XMLRequestBody))
    }

    fn xpath(t: &Transaction<'_>, expr: &str, ns: Option<(&str, &str)>) -> Vec<String> {
        let mut acts: Vec<RuleAction> = Vec::new();
        if let Some((scope, href)) = ns {
            let x = XmlNS::new(&format!("xmlns:{}={}", scope, href)).unwrap();
            acts.push(RuleAction::Other(Box::new(x)));
        }
        let rule = RuleWithActions::new(Some(acts), None, "f", 1, RuleWithActionsKind::Unconditional);
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
        assert!(t.xml.as_ref().unwrap().has_doc());
        assert_eq!(t.xml.as_ref().unwrap().well_formed(), 0);
    }

    #[test]
    fn parse_into_args() {
        let body = br#"<a x="1"><b>t1</b><c><d>t2</d><d>&amp;</d></c>tail<e/></a>"#;
        for mode in [Some(ParseXmlIntoArgs::On), Some(ParseXmlIntoArgs::OnlyArgs)] {
            let ms = ModSecurity::new();
            let mut rules = new_rules();
            rules.properties.sec_xml_parse_xml_into_args = mode;
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
            assert_eq!(t.xml.as_ref().unwrap().has_doc(), mode == Some(ParseXmlIntoArgs::On));
        }

        // SecArgumentsLimit stops the SAX parser
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.sec_xml_parse_xml_into_args = Some(ParseXmlIntoArgs::On);
        rules.properties.arguments_limit = Some(2);
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
            rules.properties.sec_xml_parse_xml_into_args = mode;
            // (The SAX handler that parses into ARGS has no entity
            // callbacks, so the document fails there, as in C++.)
            let t = xml(&ms, &rules, body);
            assert_eq!(t.vars.reqbody_error_msg.value, b"XML parsing error: XML: Failed to parse document for ARGS.");
        }
        // Abandoned: the transaction ends before the body is complete.
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.sec_xml_parse_xml_into_args = Some(ParseXmlIntoArgs::On);
        let mut t = Transaction::new(&ms, &rules, None);
        t.process_connection("200.249.12.31", 123, "200.249.12.31", 80);
        t.process_uri(b"/", b"POST", b"1.1");
        t.add_request_header(b"Content-Type", b"text/xml");
        t.process_request_headers();
        t.request_body_type = RequestBodyType::XMLRequestBody;
        t.append_request_body(&body[..60]);
        drop(t);
    }

    fn validate(op: &dyn Operator, t: &mut Transaction<'_>) -> bool {
        crate::operators::operator::test_support::eval_in(op, t, b"")
    }

    #[test]
    fn validate_dtd_and_schema() {
        let envelope = br#"<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE Envelope SYSTEM "SoapEnvelope.dtd">
<Envelope><Body><getInput><id type="string">12123</id></getInput></Body></Envelope>"#;
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.sec_xml_external_entity = Some(true);
        let dtd_path = format!("{}SoapEnvelope.dtd", DATA);
        let mut dtd = ValidateDTD::new(RunTimeString::from_text(&dtd_path));
        dtd.init("x.conf").unwrap();
        let mut bad_dtd = ValidateDTD::new(RunTimeString::from_text(&format!("{}SoapEnvelope-bad.dtd", DATA)));
        bad_dtd.init("x.conf").unwrap();
        let mut missing = ValidateDTD::new(RunTimeString::from_text("missing.dtd"));
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
        let mut xsd = ValidateSchema::new(RunTimeString::from_text(&xsd_path));
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
        let mut bad_xsd = ValidateSchema::new(RunTimeString::from_text(&bad_xsd_path));
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
        rules.properties.sec_xml_external_entity = Some(false);
        let mut dtd = ValidateDTD::new(RunTimeString::from_text(&format!("{}SoapEnvelope.dtd", DATA)));
        dtd.init("x.conf").unwrap();
        let mut t = xml(&ms, &rules, body);
        // the DTD cannot be loaded either: the loader is libxml2-wide
        assert!(validate(&dtd, &mut t));
        assert!(log(&rules).iter().any(|m| m.starts_with("XML: Failed to load DTD: ")));
    }
}

/// A transaction (and so its XML parsers and document) can move to another
/// thread, as before libxml2 was put behind `utils::libxml2`.
#[cfg(test)]
#[test]
fn transaction_is_send() {
    fn send<T: Send>() {}
    send::<crate::transaction::Transaction<'static>>();
    fn shared<T: Send + Sync>() {}
    shared::<crate::modsecurity::ModSecurity>();
    shared::<crate::rules_set::RulesSet>();
}
