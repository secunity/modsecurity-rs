//! The XML request body processor (feature `libxml2`).
//! The body is parsed with libxml2's push parser into a
//! document, which the `XML` variable (XPath) and the `@validateDTD` /
//! `@validateSchema` operators work on. With `SecParseXmlIntoArgs` set to
//! `On` or `OnlyArgs` a second, SAX based, parser turns the leaf elements of
//! the document into `ARGS` named after their path (`xml.root.child`).
//!
//! libxml2 itself is behind the safe API of `modsecurity_native::libxml2`.

/// Initialises libxml2, once per process (see
/// `modsecurity_native::libxml2::init_parser`); the `ModSecurity`
/// constructor calls it.
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

    use crate::names::NameBudget;

    /// The error of a body whose argument names exceed their allowance
    /// (`crate::names`).
    const NAMES_TOO_LONG: &str = "XML: Argument names too long.";

    /// An open element while parsing XML into args.
    #[derive(Debug, Default)]
    struct NodeData {
        has_child: bool,
    }

    /// The state of the SAX parser that turns the XML into
    /// `ARGS`.
    #[derive(Debug)]
    struct XmlNodes {
        /// The open elements (libxml2 limits how deep they go).
        nodes: Vec<NodeData>,
        /// `xml.` and the names of the open elements, joined by dots.
        currpath: Vec<u8>,
        /// The text of the current element.
        currval: Vec<u8>,
        /// What is left of the allowance of argument names (it grows with
        /// every chunk of the body).
        names: NameBudget,
        /// Parsing stopped because the names exceeded their allowance.
        names_too_long: bool,
    }

    impl XmlNodes {
        fn new() -> Self {
            XmlNodes {
                nodes: Vec::new(),
                // The names start with the pseudo root 'xml'.
                currpath: b"xml.".to_vec(),
                currval: Vec::new(),
                names: NameBudget::new(),
                names_too_long: false,
            }
        }

        /// Opens the element `name`: appends it to the current path and
        /// clears the current value.
        fn on_start_element(&mut self, name: &[u8]) {
            self.nodes.push(NodeData::default());
            // The root element follows the dot of `xml.`; any other one
            // needs a dot of its own.
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
        }

        /// Closes the element `name`; a leaf element becomes an argument.
        /// Returns `false` when parsing has to stop because the number of
        /// arguments reached the limit, or their names their allowance.
        fn on_end_element(&mut self, cx: &mut dyn Context, name: &[u8]) -> bool {
            let mut keep_parsing = true;
            if self.nodes.last().is_some_and(|nd| !nd.has_child) {
                if self.names.take(self.currpath.len()) {
                    keep_parsing = cx.add_argument(&self.currpath, &self.currval);
                } else {
                    self.names_too_long = true;
                    keep_parsing = false;
                }
            }
            // The name goes, with its dot unless it is the root element.
            let dot = usize::from(self.nodes.len() > 1);
            let new_len = self.currpath.len().saturating_sub(name.len() + dot);
            self.currpath.truncate(new_len);
            self.nodes.pop();
            self.currval.clear();
            keep_parsing
        }

        /// Appends text to the value of the current element.
        fn on_characters(&mut self, content: &[u8]) {
            // libxml2 SAX parser will call this function multiple times
            // during the parsing of a single node, if the value has
            // multibyte characters, so we need to concatenate the values
            self.currval.extend_from_slice(content);
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

        well_formed: bool,
    }

    impl Xml {
        pub fn new() -> Self {
            Self::default()
        }

        /// The parsed document.
        pub fn document(&self) -> Option<&Document> {
            self.doc.as_ref()
        }

        /// Whether the document is well formed (`false` before parsing
        /// completed).
        pub fn well_formed(&self) -> bool {
            self.well_formed
        }

        fn parse_into_args(cx: &dyn Context) -> bool {
            matches!(cx.args_mode(), IntoArgs::On | IntoArgs::OnlyArgs)
        }

        fn only_args(cx: &dyn Context) -> bool {
            cx.args_mode() == IntoArgs::OnlyArgs
        }

        /// The error of the parser into ARGS when the argument names
        /// exceeded their allowance and stopped it.
        fn names_error(&self, cx: &dyn Context) -> Option<String> {
            if !self.xml_parser_state.as_ref().is_some_and(|s| s.names_too_long) {
                return None;
            }
            ms_dbg!(cx, 4, "{}", NAMES_TOO_LONG);
            Some(NAMES_TOO_LONG.to_string())
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

        /// Runs `f` with the SAX handler for the parser state and `cx`. (The
        /// state exists: `init` makes it before the parser into ARGS is
        /// made, and nothing removes it.)
        fn with_handler<R>(
            nodes: &mut Option<XmlNodes>,
            cx: &mut dyn Context,
            f: impl FnOnce(&mut dyn SaxHandler) -> R,
        ) -> R {
            f(&mut ArgsHandler { nodes: nodes.get_or_insert_with(XmlNodes::new), cx })
        }

        /// Feeds a chunk of the body to the parsers (the first chunk creates
        /// them).
        pub fn process_chunk(&mut self, cx: &mut dyn Context, buf: &[u8]) -> Result<(), String> {
            if let Some(state) = &mut self.xml_parser_state {
                state.names.add_body(buf.len());
            }

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
                if !parser.well_formed() {
                    ms_dbg!(cx, 4, "XML: Failed to parse document.");
                    return Err("XML: Failed to parse document.".to_string());
                }
            }

            if let Some(parser) = &self.parsing_ctx_arg
                && Self::parse_into_args(cx)
            {
                Self::with_handler(&mut self.xml_parser_state, cx, |h| parser.parse_chunk(buf, h));
                if let Some(error) = self.names_error(cx) {
                    return Err(error);
                }
                if !parser.well_formed() {
                    ms_dbg!(cx, 4, "XML: Failed to parse document for ARGS.");
                    return Err("XML: Failed to parse document for ARGS.".to_string());
                }
            }

            Ok(())
        }

        /// Ends the body: finishes the parsers and keeps the document.
        pub fn complete(&mut self, cx: &mut dyn Context) -> Result<(), String> {
            // Only the parsers that were made, meaning some work was done.
            if !Self::only_args(cx)
                && let Some(parser) = self.parsing_ctx.take()
            {
                // This is how we signal the end of parsing to libxml; the
                // document is owned by `self` from now on.
                let (well_formed, doc) = parser.finish();
                self.well_formed = well_formed;
                self.doc = doc;
                ms_dbg!(cx, 4, "XML: Parsing complete (well_formed {}).", u8::from(self.well_formed));

                if !self.well_formed {
                    ms_dbg!(cx, 4, "XML: Failed to parse document.");
                    return Err("XML: Failed to parse document.".to_string());
                }
            }
            if Self::parse_into_args(cx)
                && let Some(parser) = self.parsing_ctx_arg.take()
            {
                // This is how we signal the end of parsing to libxml.
                let rc = Self::with_handler(&mut self.xml_parser_state, cx, |h| parser.finish(h));
                if let Some(error) = self.names_error(cx) {
                    return Err(error);
                }
                if rc != 0 {
                    return Err("XML: Failed to parse document for ARGS.".to_string());
                }
            }

            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::names::{NAMES_BASE, NAMES_PER_BODY_BYTE};

        /// Counts the arguments and the size of their names.
        struct Count {
            mode: IntoArgs,
            count: usize,
            total: usize,
        }

        impl DebugSink for Count {
            fn debug_enabled(&self, _level: u8) -> bool {
                false
            }
            fn debug(&self, _level: u8, _message: &str) {}
        }

        impl Context for Count {
            fn external_entities(&self) -> bool {
                false
            }
            fn args_mode(&self) -> IntoArgs {
                self.mode
            }
            fn add_argument(&mut self, name: &[u8], _value: &[u8]) -> bool {
                self.count += 1;
                self.total += name.len();
                true
            }
        }

        /// Parses `body` (given whole) into ARGS: the number of arguments,
        /// the total size of their names, and the result.
        fn names(mode: IntoArgs, body: &[u8]) -> (usize, usize, Result<(), String>) {
            super::super::init_parser();
            let mut cx = Count { mode, count: 0, total: 0 };
            let mut xml = Xml::new();
            assert!(xml.init(&mut cx));
            let result = xml.process_chunk(&mut cx, body).and(xml.complete(&mut cx));
            (cx.count, cx.total, result)
        }

        /// `values` empty elements `<v/>` inside the elements `path`.
        fn document(path: &[String], values: usize) -> Vec<u8> {
            let open: String = path.iter().map(|name| format!("<{name}>")).collect();
            let close: String = path.iter().rev().map(|name| format!("</{name}>")).collect();
            format!("{open}{}{close}", "<v/>".repeat(values)).into_bytes()
        }

        /// Long element names over many values are repeated in the name of
        /// each: the names stop at their allowance, with an error. A body
        /// that only gives some of its arguments always reports an error.
        #[test]
        fn total_size_of_names_is_bounded() {
            for mode in [IntoArgs::On, IntoArgs::OnlyArgs] {
                let body = document(&["a".repeat(40_000), "b".repeat(40_000)], 10_000);
                let (count, total, result) = names(mode, &body);
                assert_eq!(result.unwrap_err(), NAMES_TOO_LONG);
                assert!(total <= NAMES_BASE + NAMES_PER_BODY_BYTE * body.len(), "{total}");
                assert!(count < 10_000, "{count}");

                let path: Vec<String> = ["root", "level", "items", "item"].map(String::from).to_vec();
                let body = document(&path, 100_000);
                let (count, total, result) = names(mode, &body);
                assert_eq!(result, Ok(()));
                assert_eq!(count, 100_000);
                assert!(total > NAMES_BASE, "{total}");
            }
        }
    }
}
