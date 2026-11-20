//! The XML request body processor (feature `libxml2`).
//! The body is parsed with libxml2's push parser into a
//! document, which the `XML` variable (XPath) and the `@validateDTD` /
//! `@validateSchema` operators work on. With `SecParseXmlIntoArgs` set to
//! `On` or `OnlyArgs` a second, SAX based, parser turns the leaf elements of
//! the document into `ARGS` named after their path (`xml.root.child`).
//!
//! libxml2 itself is behind the safe API of `modsecurity_native::libxml2`.

/// Initialises libxml2 (`xmlInitParser()`), done once by the `ModSecurity`
/// constructor.
pub fn init_parser() {
    #[cfg(feature = "libxml2")]
    modsecurity_native::libxml2::init_parser();
}

#[cfg(feature = "libxml2")]
pub use with_libxml2::{Context, IntoArgs, Xml};

#[cfg(feature = "libxml2")]
mod with_libxml2 {
    /// `SecParseXmlIntoArgs`: whether the leaf elements become arguments,
    /// and whether the document is still built.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IntoArgs {
        Off,
        On,
        OnlyArgs,
    }

    impl IntoArgs {
        /// The setting as the debug log shows it.
        fn as_str(self) -> &'static str {
            match self {
                IntoArgs::On => "True",
                IntoArgs::Off => "False",
                IntoArgs::OnlyArgs => "OnlyArgs",
            }
        }
    }

    /// What the XML processor needs from the transaction it parses for.
    pub trait Context: DebugSink {
        /// `SecXmlExternalEntity`: whether external entities are loaded.
        fn external_entities(&self) -> bool;

        /// `SecParseXmlIntoArgs` for this transaction.
        fn args_mode(&self) -> IntoArgs;

        /// Adds the argument `name` = `value` (a leaf element); `false`
        /// when the arguments limit was reached and parsing has to stop.
        fn add_argument(&mut self, name: &[u8], value: &[u8]) -> bool;
    }

    use modsecurity_native::libxml2::{self, Document, PushParser, SaxHandler, SaxParser};
    use modsecurity_types::{DebugSink, ms_dbg};

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
            // Known limitation: the depth is counted but not limited.
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
        fn on_end_element(&mut self, cx: &mut dyn Context, name: &[u8]) -> bool {
            let mut keep_parsing = true;
            if self.nodes.last().is_some_and(|nd| !nd.has_child) {
                keep_parsing = cx.add_argument(&self.currpath, &self.currval);
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
    struct ArgsHandler<'a> {
        nodes: &'a mut XmlNodes,
        cx: &'a mut dyn Context,
    }

    impl SaxHandler for ArgsHandler<'_> {
        /// An element starts.
        fn start_element(&mut self, name: &[u8]) {
            self.nodes.on_start_element(name);
        }

        /// An element ends; `false` stops the parser.
        fn end_element(&mut self, name: &[u8]) -> bool {
            self.nodes.on_end_element(self.cx, name)
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
        pub fn has_doc(&self) -> bool {
            self.doc.is_some()
        }

        /// The parsed document.
        pub fn document(&self) -> Option<&Document> {
            self.doc.as_ref()
        }

        /// Whether the document is well formed: 1 if it is, 0 otherwise (or
        /// before parsing completed).
        pub fn well_formed(&self) -> u32 {
            self.well_formed
        }

        fn parse_into_args(cx: &dyn Context) -> bool {
            matches!(cx.args_mode(), IntoArgs::On | IntoArgs::OnlyArgs)
        }

        fn only_args(cx: &dyn Context) -> bool {
            cx.args_mode() == IntoArgs::OnlyArgs
        }

        /// Prepares the processor for a body: sets the external entity
        /// policy and, when parsing into `ARGS`, the SAX parser state.
        pub fn init(&mut self, cx: &mut dyn Context) -> bool {
            libxml2::allow_external_entities(cx.external_entities());

            if Self::parse_into_args(cx) {
                ms_dbg!(cx, 9, "XML: SecParseXmlIntoArgs is set to {}", cx.args_mode().as_str());
                // set the parser state struct
                self.xml_parser_state = Some(XmlNodes::new());
            }

            true
        }

        /// Runs `f` with the SAX handler for the parser state and `t`.
        fn with_handler<R>(
            nodes: &mut Option<XmlNodes>,
            cx: &mut dyn Context,
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
                Some(nodes) => f(&mut ArgsHandler { nodes, cx }),
                None => f(&mut Ignore),
            }
        }

        /// Feeds a chunk of the body to the parsers (the first chunk creates
        /// them).
        pub fn process_chunk(&mut self, cx: &mut dyn Context, buf: &[u8]) -> Result<(), String> {
            // We want to initialise our parsing context here, to enable us
            // to pass it the first chunk of data so that it can attempt to
            // auto-detect the encoding.
            if self.parsing_ctx.is_none() && self.parsing_ctx_arg.is_none() {
                // First invocation.

                ms_dbg!(cx, 4, "XML: Initialising parser.");

                // NOTE When Sax interface is used libxml will not create the
                // document object, but we need it.

                if !Self::only_args(cx) {
                    let Some(parser) = PushParser::new(buf) else {
                        ms_dbg!(cx, 4, "XML: Failed to create parsing context.");
                        return Err("XML: Failed to create parsing context.".to_string());
                    };
                    self.parsing_ctx = Some(parser);
                }

                if Self::parse_into_args(cx) {
                    let Some(parser) = SaxParser::new(buf) else {
                        return Err("XML: Failed to create parsing context for ARGS.".to_string());
                    };
                    self.parsing_ctx_arg = Some(parser);
                }

                return Ok(());
            }

            // Not a first invocation.
            if let Some(parser) = &self.parsing_ctx
                && !Self::only_args(cx)
            {
                parser.parse_chunk(buf);
                if parser.well_formed() != 1 {
                    ms_dbg!(cx, 4, "XML: Failed to parse document.");
                    return Err("XML: Failed to parse document.".to_string());
                }
            }

            if let Some(parser) = &self.parsing_ctx_arg
                && Self::parse_into_args(cx)
            {
                Self::with_handler(&mut self.xml_parser_state, cx, |h| parser.parse_chunk(buf, h));
                if parser.well_formed() != 1 {
                    ms_dbg!(cx, 4, "XML: Failed to parse document for ARGS.");
                    return Err("XML: Failed to parse document for ARGS.".to_string());
                }
            }

            Ok(())
        }

        /// Ends the body: finishes the parsers and keeps the document.
        pub fn complete(&mut self, cx: &mut dyn Context) -> Result<(), String> {
            // Only if we have a context, meaning we've done some work.
            if self.parsing_ctx.is_none() && self.parsing_ctx_arg.is_none() {
                return Ok(());
            }
            if self.parsing_ctx.is_some()
                && !Self::only_args(cx)
                && let Some(parser) = self.parsing_ctx.take()
            {
                // This is how we signal the end of parsing to libxml; the
                // document is owned by `self` from now on.
                let (well_formed, doc) = parser.finish();
                self.well_formed = well_formed as u32;
                self.doc = doc;
                ms_dbg!(cx, 4, "XML: Parsing complete (well_formed {}).", self.well_formed);

                if self.well_formed != 1 {
                    ms_dbg!(cx, 4, "XML: Failed to parse document.");
                    return Err("XML: Failed to parse document.".to_string());
                }
            }
            if self.parsing_ctx_arg.is_some()
                && Self::parse_into_args(cx)
                && let Some(parser) = self.parsing_ctx_arg.take()
            {
                // This is how we signal the end of parsing to libxml.
                let rc = Self::with_handler(&mut self.xml_parser_state, cx, |h| parser.finish(h));
                if rc != 0 {
                    return Err("XML: Failed to parse document for ARGS.".to_string());
                }
            }

            Ok(())
        }
    }
}
