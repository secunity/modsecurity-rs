//! Port of `src/request_body_processor/xml.cc`, `src/request_body_processor/xml.h`.
//!
//! The XML request body processor, built on libxml2 (feature `libxml2`, the
//! C++ `WITH_LIBXML2`). The body is parsed with libxml2's push parser into a
//! document tree, which the `XML` variable (XPath) and the `@validateDTD` /
//! `@validateSchema` operators work on. With `SecParseXmlIntoArgs` set to
//! `On` or `OnlyArgs` a second, SAX based, parser turns the leaf elements of
//! the document into `ARGS` named after their path (`xml.root.child`).
//!
//! libxml2 is bound through the minimal hand written FFI in [`ffi`]; all the
//! `unsafe` code of the XML support (here, in `variables::xml` and in the
//! validation operators) goes through it.

/// `xmlInitParser()`, done once by the `ModSecurity` constructor.
pub fn init_parser() {
    #[cfg(feature = "libxml2")]
    // SAFETY: xmlInitParser takes no arguments and may be called any number
    // of times (and from any thread).
    unsafe {
        ffi::xmlInitParser();
    }
}

#[cfg(feature = "libxml2")]
pub use with_libxml2::Xml;

/// The subset of the libxml2 C API used by ModSecurity.
///
/// Only the leading members of the libxml2 structures whose fields are read
/// directly are declared; those members have kept their position since
/// libxml2 2.0 (the structures are only ever accessed through pointers
/// handed out by libxml2).
#[cfg(feature = "libxml2")]
#[allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
pub(crate) mod ffi {
    use std::ffi::{c_char, c_int, c_uint, c_void};

    /// `xmlDoc` (opaque).
    #[repr(C)]
    pub struct xmlDoc {
        _private: [u8; 0],
    }

    /// `xmlValidCtxt` (opaque).
    #[repr(C)]
    pub struct xmlValidCtxt {
        _private: [u8; 0],
    }

    /// `xmlDtd` (opaque).
    #[repr(C)]
    pub struct xmlDtd {
        _private: [u8; 0],
    }

    /// `xmlNode` (opaque).
    #[repr(C)]
    pub struct xmlNode {
        _private: [u8; 0],
    }

    /// `xmlParserInputBuffer` (opaque).
    #[repr(C)]
    pub struct xmlParserInputBuffer {
        _private: [u8; 0],
    }

    /// `xmlXPathContext` (opaque).
    #[repr(C)]
    pub struct xmlXPathContext {
        _private: [u8; 0],
    }

    /// `xmlSchemaParserCtxt` (opaque).
    #[repr(C)]
    pub struct xmlSchemaParserCtxt {
        _private: [u8; 0],
    }

    /// `xmlSchema` (opaque).
    #[repr(C)]
    pub struct xmlSchema {
        _private: [u8; 0],
    }

    /// `xmlSchemaValidCtxt` (opaque).
    #[repr(C)]
    pub struct xmlSchemaValidCtxt {
        _private: [u8; 0],
    }

    /// The leading members of `struct _xmlParserCtxt`.
    #[repr(C)]
    pub struct xmlParserCtxt {
        pub sax: *mut xmlSAXHandler,
        pub userData: *mut c_void,
        /// the document being built
        pub myDoc: *mut xmlDoc,
        /// is the document well formed?
        pub wellFormed: c_int,
    }

    /// The leading members of `struct _xmlNodeSet`.
    #[repr(C)]
    pub struct xmlNodeSet {
        pub nodeNr: c_int,
        pub nodeMax: c_int,
        pub nodeTab: *mut *mut xmlNode,
    }

    /// The leading members of `struct _xmlXPathObject`.
    #[repr(C)]
    pub struct xmlXPathObject {
        pub type_: c_int,
        pub nodesetval: *mut xmlNodeSet,
    }

    /// The leading members of `struct _xmlError`.
    #[repr(C)]
    pub struct xmlError {
        pub domain: c_int,
        pub code: c_int,
        pub message: *mut c_char,
        pub level: c_int,
    }

    /// `XML_ERR_WARNING` (`xmlErrorLevel`)
    pub const XML_ERR_WARNING: c_int = 1;

    /// `XML_FROM_SCHEMASP` / `XML_FROM_SCHEMASV` (`xmlErrorDomain`)
    pub const XML_FROM_SCHEMASP: c_int = 16;
    pub const XML_FROM_SCHEMASV: c_int = 17;

    pub const XML_PARSE_NOERROR: c_int = 1 << 5;
    pub const XML_PARSE_NOWARNING: c_int = 1 << 6;

    pub const XML_SAX2_MAGIC: c_uint = 0xDEED_BEAF;

    pub type charactersSAXFunc = unsafe extern "C" fn(ctx: *mut c_void, ch: *const u8, len: c_int);
    pub type startElementNsSAX2Func = unsafe extern "C" fn(
        ctx: *mut c_void,
        localname: *const u8,
        prefix: *const u8,
        URI: *const u8,
        nb_namespaces: c_int,
        namespaces: *mut *const u8,
        nb_attributes: c_int,
        nb_defaulted: c_int,
        attributes: *mut *const u8,
    );
    pub type endElementNsSAX2Func =
        unsafe extern "C" fn(ctx: *mut c_void, localname: *const u8, prefix: *const u8, URI: *const u8);
    pub type xmlStructuredErrorFunc = unsafe extern "C" fn(userData: *mut c_void, error: *const xmlError);
    pub type xmlParserInputBufferCreateFilenameFunc =
        unsafe extern "C" fn(URI: *const c_char, enc: c_int) -> *mut xmlParserInputBuffer;
    pub type xmlFreeFunc = unsafe extern "C" fn(mem: *mut c_void);

    /// `struct _xmlSAXHandler` (complete: libxml2 reads all of it).
    #[repr(C)]
    #[derive(Debug)]
    pub struct xmlSAXHandler {
        /// `internalSubset` .. `reference`, unused.
        pub sax1_head: [*const c_void; 17],
        pub characters: Option<charactersSAXFunc>,
        /// `ignorableWhitespace` .. `externalSubset`, unused.
        pub sax1_tail: [*const c_void; 9],
        pub initialized: c_uint,
        pub _private: *mut c_void,
        pub startElementNs: Option<startElementNsSAX2Func>,
        pub endElementNs: Option<endElementNsSAX2Func>,
        pub serror: Option<xmlStructuredErrorFunc>,
    }

    impl xmlSAXHandler {
        /// A handler with every callback unset (the C++ `memset(.., 0, ..)`).
        pub fn zeroed() -> Self {
            xmlSAXHandler {
                sax1_head: [std::ptr::null(); 17],
                characters: None,
                sax1_tail: [std::ptr::null(); 9],
                initialized: 0,
                _private: std::ptr::null_mut(),
                startElementNs: None,
                endElementNs: None,
                serror: None,
            }
        }
    }

    #[link(name = "xml2")]
    unsafe extern "C" {
        pub static xmlFree: Option<xmlFreeFunc>;

        pub fn xmlInitParser();

        // Push parser
        pub fn xmlCreatePushParserCtxt(
            sax: *mut xmlSAXHandler,
            user_data: *mut c_void,
            chunk: *const c_char,
            size: c_int,
            filename: *const c_char,
        ) -> *mut xmlParserCtxt;
        pub fn xmlParseChunk(ctxt: *mut xmlParserCtxt, chunk: *const c_char, size: c_int, terminate: c_int) -> c_int;
        pub fn xmlStopParser(ctxt: *mut xmlParserCtxt);
        pub fn xmlFreeParserCtxt(ctxt: *mut xmlParserCtxt);
        pub fn xmlCtxtGetOptions(ctxt: *mut xmlParserCtxt) -> c_int;
        pub fn xmlCtxtSetOptions(ctxt: *mut xmlParserCtxt, options: c_int) -> c_int;
        pub fn xmlFreeDoc(doc: *mut xmlDoc);

        // External entities
        pub fn xmlParserInputBufferCreateFilenameDefault(
            func: Option<xmlParserInputBufferCreateFilenameFunc>,
        ) -> Option<xmlParserInputBufferCreateFilenameFunc>;
        pub fn __xmlParserInputBufferCreateFilename(URI: *const c_char, enc: c_int) -> *mut xmlParserInputBuffer;

        // Tree / XPath
        pub fn xmlNodeGetContent(node: *const xmlNode) -> *mut u8;
        pub fn xmlXPathNewContext(doc: *mut xmlDoc) -> *mut xmlXPathContext;
        pub fn xmlXPathFreeContext(ctxt: *mut xmlXPathContext);
        pub fn xmlXPathRegisterNs(ctxt: *mut xmlXPathContext, prefix: *const u8, ns_uri: *const u8) -> c_int;
        pub fn xmlXPathEvalExpression(str: *const u8, ctxt: *mut xmlXPathContext) -> *mut xmlXPathObject;
        pub fn xmlXPathFreeObject(obj: *mut xmlXPathObject);

        // DTD validation
        pub fn xmlParseDTD(ExternalID: *const u8, SystemID: *const u8) -> *mut xmlDtd;
        pub fn xmlFreeDtd(dtd: *mut xmlDtd);
        pub fn xmlNewValidCtxt() -> *mut xmlValidCtxt;
        pub fn xmlFreeValidCtxt(ctxt: *mut xmlValidCtxt);
        pub fn xmlValidateDtd(ctxt: *mut xmlValidCtxt, doc: *mut xmlDoc, dtd: *mut xmlDtd) -> c_int;

        // Error reporting (the structured handler is thread local)
        pub fn xmlSetStructuredErrorFunc(ctx: *mut c_void, handler: Option<xmlStructuredErrorFunc>);
        pub fn __xmlStructuredError() -> *mut Option<xmlStructuredErrorFunc>;
        pub fn __xmlStructuredErrorContext() -> *mut *mut c_void;

        // Schema validation
        pub fn xmlSchemaNewParserCtxt(URL: *const c_char) -> *mut xmlSchemaParserCtxt;
        pub fn xmlSchemaSetParserStructuredErrors(
            ctxt: *mut xmlSchemaParserCtxt,
            serror: Option<xmlStructuredErrorFunc>,
            ctx: *mut c_void,
        );
        pub fn xmlSchemaParse(ctxt: *mut xmlSchemaParserCtxt) -> *mut xmlSchema;
        pub fn xmlSchemaFreeParserCtxt(ctxt: *mut xmlSchemaParserCtxt);
        pub fn xmlSchemaFree(schema: *mut xmlSchema);
        pub fn xmlSchemaNewValidCtxt(schema: *mut xmlSchema) -> *mut xmlSchemaValidCtxt;
        pub fn xmlSchemaFreeValidCtxt(ctxt: *mut xmlSchemaValidCtxt);
        pub fn xmlSchemaSetValidStructuredErrors(
            ctxt: *mut xmlSchemaValidCtxt,
            serror: Option<xmlStructuredErrorFunc>,
            ctx: *mut c_void,
        );
        pub fn xmlSchemaValidateDoc(ctxt: *mut xmlSchemaValidCtxt, doc: *mut xmlDoc) -> c_int;
    }

    /// Frees memory handed out by libxml2 (`xmlFree`).
    ///
    /// # Safety
    /// `p` must be null or memory allocated by libxml2 and not freed yet.
    pub unsafe fn xml_free(p: *mut c_void) {
        // SAFETY: xmlFree is initialised by libxml2 before any allocation it
        // hands out; the caller guarantees `p` is such an allocation.
        unsafe {
            if let Some(f) = xmlFree {
                f(p);
            }
        }
    }

    /// The bytes of a NUL terminated libxml2 string.
    ///
    /// # Safety
    /// `p` must be null or point to a NUL terminated string that outlives
    /// the returned slice.
    pub unsafe fn c_bytes<'s>(p: *const u8) -> &'s [u8] {
        if p.is_null() {
            return &[];
        }
        // SAFETY: guaranteed by the caller.
        unsafe { std::ffi::CStr::from_ptr(p as *const c_char).to_bytes() }
    }

    /// `s.c_str()`: a NUL terminated copy of `s`, cut at its first NUL byte
    /// (as the C string view of a `std::string` would be).
    pub fn c_string(s: &[u8]) -> std::ffi::CString {
        let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
        std::ffi::CString::new(&s[..end]).expect("no NUL byte")
    }
}

#[cfg(feature = "libxml2")]
mod with_libxml2 {
    use std::ffi::{c_char, c_int, c_void};
    use std::ptr;

    use super::ffi;
    use crate::rules_set_properties::{
        ConfigBoolean, ConfigXMLParseXmlIntoArgs, config_xml_parse_xml_into_args_string,
    };
    use crate::transaction::Transaction;

    /// `NodeData` for parsing XML into args.
    #[derive(Debug, Default)]
    struct NodeData {
        has_child: bool,
    }

    /// `XMLNodes`: the state of the SAX parser that turns the XML into
    /// `ARGS`.
    #[derive(Debug)]
    struct XmlNodes {
        nodes: Vec<NodeData>,
        node_depth: u64,
        currpath: Vec<u8>,
        currval: Vec<u8>,
        currval_is_set: bool,
        /// The transaction the arguments go to, set only for the duration
        /// of the libxml2 calls made by `process_chunk` / `complete`.
        transaction: *mut Transaction<'static>,
        // need to store context - this is the same as in xml_data
        // need to stop parsing if the number of arguments reached the limit
        parsing_ctx_arg: *mut ffi::xmlParserCtxt,
    }

    impl XmlNodes {
        fn new() -> Self {
            XmlNodes {
                nodes: Vec::new(),
                node_depth: 0,
                currpath: Vec::new(),
                currval: Vec::new(),
                currval_is_set: false,
                transaction: ptr::null_mut(),
                parsing_ctx_arg: ptr::null_mut(),
            }
        }

        /// `MSCSAXHandler::onStartElement`
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

        /// `MSCSAXHandler::onEndElement`
        fn on_end_element(&mut self, t: &mut Transaction<'_>, name: &[u8]) {
            if self.nodes.last().is_some_and(|nd| !nd.has_child) {
                // check the return value
                // if false, then stop parsing
                // this means the number of arguments reached the limit
                if !t.add_argument("XML", &self.currpath, &self.currval, 0) && !self.parsing_ctx_arg.is_null() {
                    // SAFETY: parsing_ctx_arg is the live context that is
                    // running this callback.
                    unsafe { ffi::xmlStopParser(self.parsing_ctx_arg) };
                }
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
        }

        /// `MSCSAXHandler::onCharacters`
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

    /// `MSC_startElement`
    unsafe extern "C" fn msc_start_element(
        user_data: *mut c_void,
        name: *const u8,
        _prefix: *const u8,
        _uri: *const u8,
        _nb_namespaces: c_int,
        _namespaces: *mut *const u8,
        _nb_attributes: c_int,
        _nb_defaulted: c_int,
        _attributes: *mut *const u8,
    ) {
        // SAFETY: user_data is the `XmlNodes` registered with the parsing
        // context (boxed, so its address is stable, and alive while the
        // context is); name is a NUL terminated string owned by libxml2.
        unsafe {
            let state = &mut *(user_data as *mut XmlNodes);
            state.on_start_element(ffi::c_bytes(name));
        }
    }

    /// `MSC_endElement`
    unsafe extern "C" fn msc_end_element(user_data: *mut c_void, name: *const u8, _prefix: *const u8, _uri: *const u8) {
        // SAFETY: as in `msc_start_element`; `transaction` is set by the
        // `Xml` methods around every libxml2 call that can reach this
        // callback and points to the transaction they were given.
        unsafe {
            let state = &mut *(user_data as *mut XmlNodes);
            if state.transaction.is_null() {
                return;
            }
            let t = &mut *state.transaction;
            state.on_end_element(t, ffi::c_bytes(name));
        }
    }

    /// `MSC_xmlcharacters`
    unsafe extern "C" fn msc_xmlcharacters(user_data: *mut c_void, ch: *const u8, len: c_int) {
        // SAFETY: as in `msc_start_element`; libxml2 passes `len` valid
        // bytes at `ch`.
        unsafe {
            let state = &mut *(user_data as *mut XmlNodes);
            let content = if ch.is_null() || len <= 0 { &[][..] } else { std::slice::from_raw_parts(ch, len as usize) };
            state.on_characters(content);
        }
    }

    /// `XML::unloadExternalEntity`: the external entity loader used when
    /// `SecXMLExternalEntity` is off; loads nothing.
    unsafe extern "C" fn unload_external_entity(_uri: *const c_char, _enc: c_int) -> *mut ffi::xmlParserInputBuffer {
        ptr::null_mut()
    }

    /// The parser contexts of the libxml2 calls are given the body with a
    /// C `int` size.
    fn c_len(buf: &[u8]) -> c_int {
        c_int::try_from(buf.len()).unwrap_or(c_int::MAX)
    }

    /// `XML` (with its `xml_data` member): owns the libxml2 parsing contexts
    /// and the resulting document, freed on drop.
    #[derive(Debug)]
    pub struct Xml {
        sax_handler: Option<Box<ffi::xmlSAXHandler>>,
        parsing_ctx: *mut ffi::xmlParserCtxt,
        doc: *mut ffi::xmlDoc,

        well_formed: u32,

        /// error reporting and XML array flag
        xml_error: String,

        /// additional parser context for arguments
        parsing_ctx_arg: *mut ffi::xmlParserCtxt,

        /// parser state for SAX parser
        xml_parser_state: Option<Box<XmlNodes>>,
    }

    // SAFETY: the libxml2 objects referenced by an `Xml` are owned by it
    // alone and are only used through `&mut self` (or, for the document,
    // through `&self` by the code evaluating the transaction that owns the
    // `Xml`); libxml2 objects are not tied to the thread that created them.
    unsafe impl Send for Xml {}

    impl Default for Xml {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Xml {
        pub fn new() -> Self {
            Xml {
                sax_handler: None,
                parsing_ctx: ptr::null_mut(),
                doc: ptr::null_mut(),
                well_formed: 0,
                xml_error: String::new(),
                parsing_ctx_arg: ptr::null_mut(),
                xml_parser_state: None,
            }
        }

        /// The parsed document (`m_data.doc`), null when there is none.
        pub(crate) fn doc(&self) -> *mut ffi::xmlDoc {
            self.doc
        }

        /// `m_data.well_formed`
        pub fn well_formed(&self) -> u32 {
            self.well_formed
        }

        /// Whether the parsed document is available.
        pub fn has_doc(&self) -> bool {
            !self.doc.is_null()
        }

        fn parse_into_args(t: &Transaction<'_>) -> bool {
            matches!(
                t.sec_xml_parse_xml_into_args,
                ConfigXMLParseXmlIntoArgs::TrueConfigXMLParseXmlIntoArgs
                    | ConfigXMLParseXmlIntoArgs::OnlyArgsConfigXMLParseXmlIntoArgs
            )
        }

        fn only_args(t: &Transaction<'_>) -> bool {
            t.sec_xml_parse_xml_into_args == ConfigXMLParseXmlIntoArgs::OnlyArgsConfigXMLParseXmlIntoArgs
        }

        /// Makes `t` available to the SAX callbacks.
        fn attach(&mut self, t: &mut Transaction<'_>) {
            if let Some(s) = self.xml_parser_state.as_mut() {
                s.transaction = (t as *mut Transaction<'_>).cast::<Transaction<'static>>();
            }
        }

        fn detach(&mut self) {
            if let Some(s) = self.xml_parser_state.as_mut() {
                s.transaction = ptr::null_mut();
            }
        }

        /// Disables parser errors being printed to stderr.
        fn quiet(ctxt: *mut ffi::xmlParserCtxt) {
            // SAFETY: ctxt is a live parser context.
            unsafe {
                let options = ffi::xmlCtxtGetOptions(ctxt);
                ffi::xmlCtxtSetOptions(ctxt, options | ffi::XML_PARSE_NOWARNING | ffi::XML_PARSE_NOERROR);
            }
        }

        /// `init`
        pub fn init(&mut self, t: &mut Transaction<'_>) -> bool {
            let loader: ffi::xmlParserInputBufferCreateFilenameFunc =
                if t.rules.properties.sec_xml_external_entity == ConfigBoolean::TrueConfigBoolean {
                    ffi::__xmlParserInputBufferCreateFilename
                } else {
                    unload_external_entity
                };
            // SAFETY: sets libxml2's (thread local) external entity loader
            // to a function with the expected signature.
            unsafe {
                ffi::xmlParserInputBufferCreateFilenameDefault(Some(loader));
            }

            if Self::parse_into_args(t) {
                crate::ms_dbg_a!(
                    t,
                    9,
                    "XML: SecParseXmlIntoArgs is set to {}",
                    config_xml_parse_xml_into_args_string(t.sec_xml_parse_xml_into_args)
                );
                let mut sax = Box::new(ffi::xmlSAXHandler::zeroed());
                sax.initialized = ffi::XML_SAX2_MAGIC;
                sax.startElementNs = Some(msc_start_element);
                sax.endElementNs = Some(msc_end_element);
                sax.characters = Some(msc_xmlcharacters);
                self.sax_handler = Some(sax);

                // set the parser state struct
                let mut state = Box::new(XmlNodes::new());
                state.node_depth = 0;
                state.currval.clear();
                // the XML will contain at least one node, which is the pseudo
                // root node 'xml'
                state.currpath = b"xml.".to_vec();
                self.xml_parser_state = Some(state);
            }

            true
        }

        /// `processChunk`
        pub fn process_chunk(&mut self, t: &mut Transaction<'_>, buf: &[u8], error: &mut String) -> bool {
            self.attach(t);
            let ret = self.process_chunk_inner(t, buf, error);
            self.detach();
            ret
        }

        fn process_chunk_inner(&mut self, t: &mut Transaction<'_>, buf: &[u8], error: &mut String) -> bool {
            let chunk = buf.as_ptr() as *const c_char;
            let size = c_len(buf);

            // We want to initialise our parsing context here, to enable us
            // to pass it the first chunk of data so that it can attempt to
            // auto-detect the encoding.
            if self.parsing_ctx.is_null() && self.parsing_ctx_arg.is_null() {
                // First invocation.

                crate::ms_dbg_a!(t, 4, "XML: Initialising parser.");

                // NOTE When Sax interface is used libxml will not create the
                // document object, but we need it.

                if !Self::only_args(t) {
                    // SAFETY: chunk/size describe `buf`; the filename is a
                    // NUL terminated literal.
                    self.parsing_ctx = unsafe {
                        ffi::xmlCreatePushParserCtxt(
                            ptr::null_mut(),
                            ptr::null_mut(),
                            chunk,
                            size,
                            c"body.xml".as_ptr(),
                        )
                    };

                    if self.parsing_ctx.is_null() {
                        crate::ms_dbg_a!(t, 4, "XML: Failed to create parsing context.");
                        *error = "XML: Failed to create parsing context.".to_string();
                        return false;
                    }
                    // disable parser errors being printed to stderr
                    Self::quiet(self.parsing_ctx);
                }

                if Self::parse_into_args(t) {
                    let sax: *mut ffi::xmlSAXHandler =
                        self.sax_handler.as_deref_mut().map_or(ptr::null_mut(), |s| s as *mut _);
                    let state: *mut c_void = self
                        .xml_parser_state
                        .as_deref_mut()
                        .map_or(ptr::null_mut(), |s| s as *mut XmlNodes as *mut c_void);
                    // SAFETY: the SAX handler and the parser state are boxed
                    // and owned by `self`, which also owns (and frees first)
                    // the context they are registered with; chunk/size
                    // describe `buf`.
                    self.parsing_ctx_arg =
                        unsafe { ffi::xmlCreatePushParserCtxt(sax, state, chunk, size, ptr::null()) };
                    if self.parsing_ctx_arg.is_null() {
                        *error = "XML: Failed to create parsing context for ARGS.".to_string();
                        return false;
                    }
                    // disable parser errors being printed to stderr
                    Self::quiet(self.parsing_ctx_arg);
                    // the SAX callback (onEndElement) stops parsing through
                    // this context when SecArgumentsLimit is hit; it must be
                    // set here, not only in the multi-chunk branch below.
                    if let Some(s) = self.xml_parser_state.as_mut() {
                        s.parsing_ctx_arg = self.parsing_ctx_arg;
                    }
                }

                return true;
            }

            // Not a first invocation.
            if !self.parsing_ctx.is_null() && !Self::only_args(t) {
                // SAFETY: parsing_ctx is live; chunk/size describe `buf`.
                unsafe {
                    ffi::xmlParseChunk(self.parsing_ctx, chunk, size, 0);
                }
                // (The C++ code dereferenced the parser state here even when
                // it did not exist.)
                if let Some(s) = self.xml_parser_state.as_mut() {
                    s.parsing_ctx_arg = self.parsing_ctx_arg;
                }
                // SAFETY: parsing_ctx is live.
                if unsafe { (*self.parsing_ctx).wellFormed } != 1 {
                    *error = "XML: Failed to parse document.".to_string();
                    crate::ms_dbg_a!(t, 4, "XML: Failed to parse document.");
                    return false;
                }
            }

            if !self.parsing_ctx_arg.is_null() && Self::parse_into_args(t) {
                // SAFETY: parsing_ctx_arg is live; chunk/size describe `buf`.
                unsafe {
                    ffi::xmlParseChunk(self.parsing_ctx_arg, chunk, size, 0);
                }
                // SAFETY: parsing_ctx_arg is live.
                if unsafe { (*self.parsing_ctx_arg).wellFormed } != 1 {
                    *error = "XML: Failed to parse document for ARGS.".to_string();
                    crate::ms_dbg_a!(t, 4, "XML: Failed to parse document for ARGS.");
                    return false;
                }
            }

            true
        }

        /// `complete`
        pub fn complete(&mut self, t: &mut Transaction<'_>, error: &mut String) -> bool {
            self.attach(t);
            let ret = self.complete_inner(t, error);
            self.detach();
            ret
        }

        fn complete_inner(&mut self, t: &mut Transaction<'_>, error: &mut String) -> bool {
            // Only if we have a context, meaning we've done some work.
            if self.parsing_ctx.is_null() && self.parsing_ctx_arg.is_null() {
                return true;
            }
            if !self.parsing_ctx.is_null() && !Self::only_args(t) {
                // SAFETY: parsing_ctx is live; it is freed (once) right
                // after its results are taken. The document it built is
                // not freed with it and is owned by `self` from now on.
                unsafe {
                    // This is how we signal the end of parsing to libxml.
                    ffi::xmlParseChunk(self.parsing_ctx, ptr::null(), 0, 1);

                    // Preserve the results for our reference.
                    self.well_formed = (*self.parsing_ctx).wellFormed as u32;
                    self.doc = (*self.parsing_ctx).myDoc;

                    // Clean up everything else.
                    ffi::xmlFreeParserCtxt(self.parsing_ctx);
                }
                self.parsing_ctx = ptr::null_mut();
                crate::ms_dbg_a!(t, 4, "XML: Parsing complete (well_formed {}).", self.well_formed);

                if self.well_formed != 1 {
                    *error = "XML: Failed to parse document.".to_string();
                    crate::ms_dbg_a!(t, 4, "XML: Failed to parse document.");
                    return false;
                }
            }
            if !self.parsing_ctx_arg.is_null() && Self::parse_into_args(t) {
                // SAFETY: parsing_ctx_arg is live and freed exactly once.
                unsafe {
                    // This is how we signal the end of parsing to libxml.
                    let rc = ffi::xmlParseChunk(self.parsing_ctx_arg, ptr::null(), 0, 1);
                    ffi::xmlFreeParserCtxt(self.parsing_ctx_arg);
                    self.parsing_ctx_arg = ptr::null_mut();
                    if let Some(s) = self.xml_parser_state.as_mut() {
                        s.parsing_ctx_arg = ptr::null_mut();
                    }
                    if rc != 0 {
                        if !self.xml_error.is_empty() {
                            *error = self.xml_error.clone();
                        } else {
                            *error = "XML: Failed to parse document for ARGS.".to_string();
                        }
                        return false;
                    }
                }
            }

            true
        }
    }

    impl Drop for Xml {
        fn drop(&mut self) {
            // SAFETY: the contexts and the document are owned by `self` and
            // freed exactly once (their pointers are nulled when freed
            // earlier). The parser contexts go first, as they reference the
            // SAX handler and parser state boxes dropped afterwards.
            unsafe {
                if !self.parsing_ctx.is_null() {
                    ffi::xmlFreeParserCtxt(self.parsing_ctx);
                    self.parsing_ctx = ptr::null_mut();
                }
                if !self.parsing_ctx_arg.is_null() {
                    // (Not freed by the C++ destructor: a leak when
                    // `complete` was never called.)
                    ffi::xmlFreeParserCtxt(self.parsing_ctx_arg);
                    self.parsing_ctx_arg = ptr::null_mut();
                }
                if !self.doc.is_null() {
                    ffi::xmlFreeDoc(self.doc);
                    self.doc = ptr::null_mut();
                }
            }
        }
    }
}

#[cfg(all(test, feature = "libxml2"))]
mod tests {
    use crate::actions::action::Action;
    use crate::actions::xmlns::XmlNS;
    use crate::modsecurity::ModSecurity;
    use crate::operators::operator::Operator;
    use crate::operators::validate_dtd::ValidateDTD;
    use crate::operators::validate_schema::ValidateSchema;
    use crate::request_body_processor::multipart::test_support::{log, new_rules, run};
    use crate::rule_with_actions::{RuleWithActions, RuleWithActionsKind};
    use crate::rules_set_properties::{ConfigBoolean, ConfigXMLParseXmlIntoArgs};
    use crate::run_time_string::RunTimeString;
    use crate::transaction::{RequestBodyType, Transaction};
    use crate::variable_value::VariableValue;
    use crate::variables::variable::Variable;

    const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/test-cases/data/");

    fn xml<'a>(ms: &'a ModSecurity, rules: &'a crate::rules_set::RulesSet, body: &[u8]) -> Transaction<'a> {
        run(ms, rules, &[(b"Content-Type", b"text/xml")], body, Some(RequestBodyType::XMLRequestBody))
    }

    fn xpath(t: &Transaction<'_>, expr: &str, ns: Option<(&str, &str)>) -> Vec<String> {
        let mut acts: Vec<Box<dyn Action>> = Vec::new();
        if let Some((scope, href)) = ns {
            let mut x = XmlNS::new("xmlns");
            x.scope = scope.to_string();
            x.href = href.to_string();
            acts.push(Box::new(x));
        }
        let rule = RuleWithActions::new(Some(acts), None, "f", 1, RuleWithActionsKind::Unconditional);
        let v = crate::variables::xml::Xml::new(&format!("XML:{}", expr));
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
        crate::variables::xml::XmlNoDictElement::new().evaluate(&t, None, &mut l);
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
        for mode in [
            ConfigXMLParseXmlIntoArgs::TrueConfigXMLParseXmlIntoArgs,
            ConfigXMLParseXmlIntoArgs::OnlyArgsConfigXMLParseXmlIntoArgs,
        ] {
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
            assert_eq!(
                t.xml.as_ref().unwrap().has_doc(),
                mode == ConfigXMLParseXmlIntoArgs::TrueConfigXMLParseXmlIntoArgs
            );
        }

        // SecArgumentsLimit stops the SAX parser
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.sec_xml_parse_xml_into_args = ConfigXMLParseXmlIntoArgs::TrueConfigXMLParseXmlIntoArgs;
        rules.properties.arguments_limit.parse("2").unwrap();
        let t = xml(&ms, &rules, b"<a><b>1</b><b>2</b><b>3</b><b>4</b></a>");
        assert_eq!(t.vars.args.len(), 2);
        assert_eq!(t.vars.reqbody_error_msg.value, b"XML parsing error: XML: Failed to parse document for ARGS.");
    }

    fn validate(op: &dyn Operator, t: &mut Transaction<'_>) -> bool {
        op.evaluate(Some(t), None, b"", None)
    }

    #[test]
    fn validate_dtd_and_schema() {
        let envelope = br#"<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE Envelope SYSTEM "SoapEnvelope.dtd">
<Envelope><Body><getInput><id type="string">12123</id></getInput></Body></Envelope>"#;
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        rules.properties.sec_xml_external_entity = ConfigBoolean::TrueConfigBoolean;
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
        rules.properties.sec_xml_external_entity = ConfigBoolean::FalseConfigBoolean;
        let mut dtd = ValidateDTD::new(RunTimeString::from_text(&format!("{}SoapEnvelope.dtd", DATA)));
        dtd.init("x.conf").unwrap();
        let mut t = xml(&ms, &rules, body);
        // the DTD cannot be loaded either: the loader is libxml2-wide
        assert!(validate(&dtd, &mut t));
        assert!(log(&rules).iter().any(|m| m.starts_with("XML: Failed to load DTD: ")));
    }
}
