//! libxml2: the C library under the XML support (feature `libxml2`).
//!
//! The FFI declarations (the private `ffi` module) and a safe API over
//! them: the parsers of the XML request body processor ([`PushParser`],
//! building a [`Document`], and [`SaxParser`], reporting elements to a
//! [`SaxHandler`]), and what the rules do with a document (XPath, DTD and
//! schema validation). All the `unsafe` code of the XML support is here.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr::{self, NonNull};

/// The subset of the libxml2 C API used by ModSecurity.
///
/// Only the leading members of the libxml2 structures whose fields are read
/// directly are declared; those members have kept their position since
/// libxml2 2.0 (the structures are only ever accessed through pointers
/// handed out by libxml2).
#[allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code)]
mod ffi {
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
        /// A handler with every callback unset (what `memset(.., 0, ..)` gives in C).
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
}

// ---------------------------------------------------------------------------
// Safe API
// ---------------------------------------------------------------------------

/// `xmlInitParser()`: done once by the `ModSecurity` constructor.
pub fn init_parser() {
    // SAFETY: xmlInitParser takes no arguments and may be called any number
    // of times (and from any thread).
    unsafe { ffi::xmlInitParser() }
}

/// Whether the parsers of this thread may load external entities (the
/// libxml2 default loader) or load none (`SecXMLExternalEntity Off`).
pub fn allow_external_entities(allowed: bool) {
    /// An external entity loader that loads nothing.
    unsafe extern "C" fn load_nothing(_uri: *const c_char, _enc: c_int) -> *mut ffi::xmlParserInputBuffer {
        ptr::null_mut()
    }
    let loader: ffi::xmlParserInputBufferCreateFilenameFunc =
        if allowed { ffi::__xmlParserInputBufferCreateFilename } else { load_nothing };
    // SAFETY: sets libxml2's (thread local) external entity loader to a
    // function with the expected signature.
    unsafe {
        ffi::xmlParserInputBufferCreateFilenameDefault(Some(loader));
    }
}

/// A message libxml2 reports while validating.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    /// The message text (as libxml2 formats it).
    pub text: &'a [u8],
    /// A warning (not an error).
    pub warning: bool,
    /// Raised by the schema code (`XML_FROM_SCHEMASP`/`XML_FROM_SCHEMASV`),
    /// not by the parser reading the schema document.
    pub from_schema: bool,
}

/// Where libxml2's structured error callbacks deliver the messages.
type Sink<'a> = &'a mut dyn FnMut(Message<'_>);

/// The structured error callback: `ctx` is a `*mut Sink`.
unsafe extern "C" fn deliver(ctx: *mut c_void, error: *const ffi::xmlError) {
    if ctx.is_null() || error.is_null() {
        return;
    }
    // SAFETY: libxml2 passes the context given with this callback (a live
    // `*mut Sink`, see the callers) and a live error whose message is null
    // or NUL terminated.
    unsafe {
        let sink = &mut *ctx.cast::<Sink<'_>>();
        let e = &*error;
        sink(Message {
            text: ffi::c_bytes(e.message as *const u8),
            warning: e.level == ffi::XML_ERR_WARNING,
            from_schema: matches!(e.domain, ffi::XML_FROM_SCHEMASP | ffi::XML_FROM_SCHEMASV),
        });
    }
}

/// An owned libxml2 parser context, freed (with the document it may hold)
/// on drop.
#[derive(Debug)]
struct ParserCtxt(NonNull<ffi::xmlParserCtxt>);

impl ParserCtxt {
    /// `xmlCreatePushParserCtxt` with the first chunk of the input (from
    /// which libxml2 detects the encoding); parser errors are not printed.
    fn new(sax: *mut ffi::xmlSAXHandler, first: &[u8], filename: Option<&CStr>) -> Option<Self> {
        let filename = filename.map_or(ptr::null(), CStr::as_ptr);
        // SAFETY: chunk/size describe `first`; `sax` is null or a handler
        // that outlives the context (see `SaxParser`); the filename is null
        // or NUL terminated.
        let p = unsafe {
            ffi::xmlCreatePushParserCtxt(sax, ptr::null_mut(), first.as_ptr().cast(), c_len(first), filename)
        };
        let ctxt = ParserCtxt(NonNull::new(p)?);
        // SAFETY: the context is live.
        unsafe {
            let options = ffi::xmlCtxtGetOptions(ctxt.as_ptr());
            ffi::xmlCtxtSetOptions(ctxt.as_ptr(), options | ffi::XML_PARSE_NOWARNING | ffi::XML_PARSE_NOERROR);
        }
        Some(ctxt)
    }

    fn as_ptr(&self) -> *mut ffi::xmlParserCtxt {
        self.0.as_ptr()
    }

    fn well_formed(&self) -> c_int {
        // SAFETY: the context is live while `self` exists.
        unsafe { (*self.as_ptr()).wellFormed }
    }

    /// `xmlParseChunk` (`terminate` signals the end of the input).
    fn parse_chunk(&self, buf: &[u8], terminate: bool) -> c_int {
        let (chunk, size) = if terminate { (ptr::null(), 0) } else { (buf.as_ptr().cast(), c_len(buf)) };
        // SAFETY: the context is live; chunk/size describe `buf` (or are
        // null/0 for the final call).
        unsafe { ffi::xmlParseChunk(self.as_ptr(), chunk, size, c_int::from(terminate)) }
    }

    /// Takes the document the context built (`myDoc`), if any; the context
    /// no longer refers to it.
    fn take_doc(&self) -> Option<Document> {
        // SAFETY: the context is live; `myDoc` is null or a document the
        // context built, which nothing else frees: it becomes owned by the
        // returned `Document` once the context forgets it.
        unsafe {
            let doc = NonNull::new((*self.as_ptr()).myDoc).map(Document);
            (*self.as_ptr()).myDoc = ptr::null_mut();
            doc
        }
    }
}

impl Drop for ParserCtxt {
    fn drop(&mut self) {
        // A document left in the context (not taken by `take_doc`): one the
        // parse was abandoned in, or the one libxml2 builds for the entities
        // of a DTD while parsing with SAX callbacks.
        drop(self.take_doc());
        // SAFETY: the context is owned by `self` and freed only here.
        // `xmlFreeParserCtxt` does not free `myDoc`.
        unsafe { ffi::xmlFreeParserCtxt(self.as_ptr()) }
    }
}

// SAFETY: a parser context (and the document it builds) is owned by one
// `ParserCtxt` and only used through it; libxml2 objects are not tied to
// the thread that created them.
unsafe impl Send for ParserCtxt {}

/// The parser contexts are given chunks with a C `int` size.
fn c_len(buf: &[u8]) -> c_int {
    c_int::try_from(buf.len()).unwrap_or(c_int::MAX)
}

/// A push parser building a document.
#[derive(Debug)]
pub struct PushParser(ParserCtxt);

impl PushParser {
    /// Starts parsing with the first chunk (`None` when libxml2 could not
    /// create the parser).
    pub fn new(first: &[u8]) -> Option<Self> {
        ParserCtxt::new(ptr::null_mut(), first, Some(c"body.xml")).map(PushParser)
    }

    pub fn parse_chunk(&self, buf: &[u8]) {
        self.0.parse_chunk(buf, false);
    }

    /// Whether the document is well formed so far (libxml2's `wellFormed`).
    pub fn well_formed(&self) -> bool {
        self.0.well_formed() == 1
    }

    /// Ends the input: whether the document is well formed, and the
    /// document.
    pub fn finish(self) -> (bool, Option<Document>) {
        self.0.parse_chunk(&[], true);
        (self.0.well_formed() == 1, self.0.take_doc())
    }
}

/// What a [`SaxParser`] reports.
pub trait SaxHandler {
    fn start_element(&mut self, name: &[u8]);
    /// Returns `false` to stop the parser.
    fn end_element(&mut self, name: &[u8]) -> bool;
    /// Text, possibly in several pieces.
    fn characters(&mut self, text: &[u8]);
}

/// The handler of the running libxml2 call, as the SAX callbacks receive
/// it (`userData`), with the context to stop.
struct SaxCall<'a> {
    handler: &'a mut dyn SaxHandler,
    ctxt: *mut ffi::xmlParserCtxt,
}

/// A push parser reporting elements to a [`SaxHandler`] (no document).
///
/// Fields drop in declaration order: the context goes before the SAX
/// handler table it refers to.
#[derive(Debug)]
pub struct SaxParser {
    ctxt: ParserCtxt,
    _callbacks: Box<ffi::xmlSAXHandler>,
}

// SAFETY: the context and the callback table are owned by the parser and
// only used through it; the table is never changed after creation (its
// pointers are function pointers and nulls), and libxml2 objects are not
// tied to the thread that created them.
unsafe impl Send for SaxParser {}

impl SaxParser {
    /// Starts parsing with the first chunk, which reports nothing (`None`
    /// when libxml2 could not create the parser).
    pub fn new(first: &[u8]) -> Option<Self> {
        unsafe extern "C" fn start(
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
            // SAFETY: `user_data` is null or the `SaxCall` of the running
            // `SaxParser::run`; `name` is a NUL terminated string.
            unsafe {
                if let Some(call) = user_data.cast::<SaxCall<'_>>().as_mut() {
                    call.handler.start_element(ffi::c_bytes(name));
                }
            }
        }
        unsafe extern "C" fn end(user_data: *mut c_void, name: *const u8, _prefix: *const u8, _uri: *const u8) {
            // SAFETY: as in `start`.
            unsafe {
                if let Some(call) = user_data.cast::<SaxCall<'_>>().as_mut()
                    && !call.handler.end_element(ffi::c_bytes(name))
                {
                    ffi::xmlStopParser(call.ctxt);
                }
            }
        }
        unsafe extern "C" fn characters(user_data: *mut c_void, ch: *const u8, len: c_int) {
            // SAFETY: as in `start`; libxml2 passes `len` valid bytes at `ch`.
            unsafe {
                if let Some(call) = user_data.cast::<SaxCall<'_>>().as_mut() {
                    let text =
                        if ch.is_null() || len <= 0 { &[][..] } else { std::slice::from_raw_parts(ch, len as usize) };
                    call.handler.characters(text);
                }
            }
        }
        let mut callbacks = Box::new(ffi::xmlSAXHandler::zeroed());
        callbacks.initialized = ffi::XML_SAX2_MAGIC;
        callbacks.startElementNs = Some(start);
        callbacks.endElementNs = Some(end);
        callbacks.characters = Some(characters);
        let ctxt = ParserCtxt::new(&mut *callbacks, first, None)?;
        // No `SaxCall` outside `run` (libxml2's default `userData` is the
        // context itself, which the default handlers of a document building
        // parser need, but these callbacks do not).
        // SAFETY: the context is live.
        unsafe { (*ctxt.as_ptr()).userData = ptr::null_mut() };
        Some(SaxParser { ctxt, _callbacks: callbacks })
    }

    /// Runs `f` (a libxml2 call on the context) with `handler` installed
    /// as the context's `userData`, and uninstalls it afterwards, so the
    /// callbacks never see a dangling pointer.
    fn run<R>(&self, handler: &mut dyn SaxHandler, f: impl FnOnce(&ParserCtxt) -> R) -> R {
        let ctxt = self.ctxt.as_ptr();
        let mut call = SaxCall { handler, ctxt };
        // SAFETY: the context is live; `call` outlives the call to `f`,
        // after which `userData` is cleared again.
        unsafe { (*ctxt).userData = (&mut call as *mut SaxCall<'_>).cast() };
        let r = f(&self.ctxt);
        // SAFETY: as above.
        unsafe { (*ctxt).userData = ptr::null_mut() };
        r
    }

    pub fn parse_chunk(&self, buf: &[u8], handler: &mut dyn SaxHandler) {
        self.run(handler, |c| c.parse_chunk(buf, false));
    }

    /// Whether the input is well formed so far (libxml2's `wellFormed`).
    pub fn well_formed(&self) -> bool {
        self.ctxt.well_formed() == 1
    }

    /// Ends the input; returns the result of the final `xmlParseChunk` (0
    /// when the input is complete and well formed).
    pub fn finish(self, handler: &mut dyn SaxHandler) -> i32 {
        self.run(handler, |c| c.parse_chunk(&[], true))
    }
}

/// An owned libxml2 document, freed on drop.
#[derive(Debug)]
pub struct Document(NonNull<ffi::xmlDoc>);

impl Drop for Document {
    fn drop(&mut self) {
        // SAFETY: the document is owned by `self` and freed only here.
        unsafe { ffi::xmlFreeDoc(self.0.as_ptr()) }
    }
}

// SAFETY: a document is owned by one `Document`; it is only read through
// `&self` (XPath, validation), which libxml2 allows from any thread.
unsafe impl Send for Document {}

/// Why an XPath expression gave no result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XPathError {
    /// libxml2 could not create an XPath context.
    Context,
    /// The namespace at this index of the list could not be registered.
    Namespace(usize),
    /// The expression could not be evaluated.
    Eval,
}

impl Document {
    fn as_ptr(&self) -> *mut ffi::xmlDoc {
        self.0.as_ptr()
    }

    /// The content of the nodes `expr` selects, with the `(prefix, href)`
    /// namespaces registered.
    pub fn xpath(&self, expr: &[u8], namespaces: &[(&[u8], &[u8])]) -> Result<Vec<Vec<u8>>, XPathError> {
        /// Frees the XPath context on every return path.
        struct Ctx(*mut ffi::xmlXPathContext);
        impl Drop for Ctx {
            fn drop(&mut self) {
                // SAFETY: created by xmlXPathNewContext and freed once.
                unsafe { ffi::xmlXPathFreeContext(self.0) };
            }
        }
        // SAFETY: the document is live.
        let ctx = unsafe { ffi::xmlXPathNewContext(self.as_ptr()) };
        if ctx.is_null() {
            return Err(XPathError::Context);
        }
        let ctx = Ctx(ctx);
        for (i, (prefix, href)) in namespaces.iter().enumerate() {
            let (prefix, href) = (c_string(prefix), c_string(href));
            // SAFETY: the context is live; prefix and URI are NUL
            // terminated (libxml2 copies them).
            let rc = unsafe { ffi::xmlXPathRegisterNs(ctx.0, prefix.as_ptr().cast(), href.as_ptr().cast()) };
            if rc != 0 {
                return Err(XPathError::Namespace(i));
            }
        }
        let expr = c_string(expr);
        // SAFETY: the expression is NUL terminated and the context live.
        let obj = unsafe { ffi::xmlXPathEvalExpression(expr.as_ptr().cast(), ctx.0) };
        if obj.is_null() {
            return Err(XPathError::Eval);
        }
        let mut out = Vec::new();
        // SAFETY: `obj` is a live XPath object; its node set (when it has
        // one) holds `nodeNr` valid node pointers into the document. Node
        // contents are copies freed with xmlFree. The object is freed once,
        // after the last use.
        unsafe {
            let nodes = (*obj).nodesetval;
            if !nodes.is_null() {
                let nr = usize::try_from((*nodes).nodeNr).unwrap_or(0);
                for i in 0..nr {
                    let content = ffi::xmlNodeGetContent(*(*nodes).nodeTab.add(i));
                    if !content.is_null() {
                        out.push(ffi::c_bytes(content).to_vec());
                        ffi::xml_free(content.cast());
                    }
                }
            }
            ffi::xmlXPathFreeObject(obj);
        }
        Ok(out)
    }

    /// Validates the document against `dtd`: `None` when no validation
    /// context could be created, otherwise whether the document is valid.
    /// The validator's messages go to `log`.
    pub fn validate_dtd(&self, dtd: &Dtd, log: &mut dyn FnMut(Message<'_>)) -> Option<bool> {
        // SAFETY: plain constructor; the context starts without callbacks.
        let cvp = unsafe { ffi::xmlNewValidCtxt() };
        if cvp.is_null() {
            return None;
        }
        // With no callbacks in the validation context, libxml2 reports to
        // the thread's structured error handler: pointed at `log` for the
        // duration of the validation, then restored.
        let mut sink: Sink<'_> = log;
        // SAFETY: cvp, the document and the DTD are live; the handler
        // context is `sink`, alive for the whole validation; the previous
        // handler is restored before returning; cvp is freed once.
        let valid = unsafe {
            let prev_handler = *ffi::__xmlStructuredError();
            let prev_ctx = *ffi::__xmlStructuredErrorContext();
            ffi::xmlSetStructuredErrorFunc((&mut sink as *mut Sink<'_>).cast(), Some(deliver));
            let valid = ffi::xmlValidateDtd(cvp, self.as_ptr(), dtd.0.as_ptr());
            ffi::xmlSetStructuredErrorFunc(prev_ctx, prev_handler);
            ffi::xmlFreeValidCtxt(cvp);
            valid
        };
        Some(valid != 0)
    }

    /// Validates the document against the schema in `file`. The messages of
    /// loading the schema go to `load_log`, those of the validation to
    /// `log`.
    pub fn validate_schema(
        &self,
        file: &str,
        load_log: &mut dyn FnMut(Message<'_>),
        log: &mut dyn FnMut(Message<'_>),
    ) -> Result<bool, SchemaError> {
        let file = c_string(file.as_bytes());
        // SAFETY: the file name is NUL terminated.
        let parser = unsafe { ffi::xmlSchemaNewParserCtxt(file.as_ptr()) };
        if parser.is_null() {
            return Err(SchemaError::Load);
        }
        let mut load_sink: Sink<'_> = load_log;
        let mut sink: Sink<'_> = log;
        // SAFETY: `parser` is live; the error contexts are the sinks, alive
        // until the contexts are freed below. The schema, the validation
        // context and the parser context are freed exactly once; the
        // document is live.
        unsafe {
            ffi::xmlSchemaSetParserStructuredErrors(parser, Some(deliver), (&mut load_sink as *mut Sink<'_>).cast());
            let schema = ffi::xmlSchemaParse(parser);
            if schema.is_null() {
                ffi::xmlSchemaFreeParserCtxt(parser);
                return Err(SchemaError::Parse);
            }
            let valid_ctx = ffi::xmlSchemaNewValidCtxt(schema);
            if valid_ctx.is_null() {
                ffi::xmlSchemaFree(schema);
                ffi::xmlSchemaFreeParserCtxt(parser);
                return Err(SchemaError::ValidationContext);
            }
            ffi::xmlSchemaSetValidStructuredErrors(valid_ctx, Some(deliver), (&mut sink as *mut Sink<'_>).cast());
            let rc = ffi::xmlSchemaValidateDoc(valid_ctx, self.as_ptr());
            ffi::xmlSchemaFreeValidCtxt(valid_ctx);
            ffi::xmlSchemaFree(schema);
            ffi::xmlSchemaFreeParserCtxt(parser);
            Ok(rc == 0)
        }
    }
}

/// An owned DTD, freed on drop.
#[derive(Debug)]
pub struct Dtd(NonNull<ffi::xmlDtd>);

impl Dtd {
    /// `xmlParseDTD` of the file (`None` when it cannot be loaded).
    pub fn load(file: &str) -> Option<Self> {
        let file = c_string(file.as_bytes());
        // SAFETY: the system id is NUL terminated; the result is owned by
        // the returned `Dtd`.
        NonNull::new(unsafe { ffi::xmlParseDTD(ptr::null(), file.as_ptr().cast()) }).map(Dtd)
    }
}

impl Drop for Dtd {
    fn drop(&mut self) {
        // SAFETY: returned by xmlParseDTD and freed once.
        unsafe { ffi::xmlFreeDtd(self.0.as_ptr()) };
    }
}

/// Why a schema validation did not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaError {
    /// No schema parser could be created (the file cannot be read).
    Load,
    /// The schema could not be parsed.
    Parse,
    /// No validation context could be created.
    ValidationContext,
}

/// A NUL terminated copy of `s`, cut at its first NUL byte (libxml2 takes
/// C strings, which cannot hold one).
fn c_string(s: &[u8]) -> CString {
    CString::new(crate::c_str(s)).expect("no NUL byte")
}
