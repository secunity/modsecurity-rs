//! The request body of a transaction: which processor parses it
//! (`modsecurity-body` has them) and what is reported about it, and the
//! transaction as the context of those processors (where their variables
//! go, the settings they read).

use std::sync::Arc;

use crate::transaction::arguments::ArgumentWriter;
use crate::transaction::{RequestBodyType, Transaction};
use crate::variables::variable_value::VariableValue;
use modsecurity_body::multipart::{self, Entries, Flag, Multipart, MultipartPartTmpFile, Uploads};

/// How a request body is parsed.
enum Processor {
    #[cfg(feature = "libxml2")]
    Xml,
    Json,
    Multipart,
    UrlEncoded,
    /// A body type that is recognised but has no processor.
    Missing,
    /// Nothing is known about the body: it is not parsed.
    None,
}

impl Transaction<'_> {
    /// The processor of the request body: the one a rule chose with
    /// `ctl:requestBodyProcessor`, or the one of the Content-Type.
    fn request_body_processor(&self) -> Processor {
        let body = &self.body;
        #[cfg(feature = "libxml2")]
        if body.request_body_processor == RequestBodyType::XMLRequestBody {
            return Processor::Xml;
        }
        if body.request_body_processor == RequestBodyType::JSONRequestBody {
            Processor::Json
        } else if body.request_body_type == RequestBodyType::MultiPartRequestBody {
            Processor::Multipart
        } else if body.request_body_type == RequestBodyType::WWWFormUrlEncoded {
            Processor::UrlEncoded
        } else if body.request_body_type != RequestBodyType::UnknownFormat {
            Processor::Missing
        } else {
            Processor::None
        }
    }

    /// Parses the request body with its processor, and sets `REQBODY_ERROR`
    /// and the variables that go with it.
    pub(super) fn parse_request_body(&mut self) {
        // A body over `SecRequestBodyNoFilesLimit` is reported and not
        // parsed (a multipart body is measured without its files, once
        // parsed).
        let over_limit = self.request_body_over_no_files_limit();
        match self.request_body_processor() {
            #[cfg(feature = "libxml2")]
            Processor::Xml if over_limit => {}
            #[cfg(feature = "libxml2")]
            Processor::Xml => {
                let result = self.parse_xml_body();
                self.set_reqbody_result("XML parsing error: ", result);
            }
            Processor::Json if over_limit => {}
            Processor::Json => {
                // An empty body is not an error.
                let result =
                    self.parse_json_body().or_else(|e| if self.http.request_body.is_empty() { Ok(()) } else { Err(e) });
                self.set_reqbody_result("JSON parsing error: ", result);
            }
            Processor::Multipart => self.parse_multipart_body(),
            Processor::UrlEncoded => {
                self.vars.offset += 1;
                if !over_limit {
                    let off = self.vars.offset;
                    ArgumentWriter {
                        vars: &mut self.vars,
                        combined_size: &mut self.http.args_combined_size,
                        rules: self.rules,
                        id: &self.id,
                        uri: &self.http.uri,
                    }
                    .extract("POST", &self.http.request_body, off);
                }
            }
            Processor::Missing => {
                let content_type = self.vars.request_headers.resolve_first(b"Content-Type");
                let content_type = content_type.map(|c| String::from_utf8_lossy(&c).into_owned()).unwrap_or_default();
                self.set_reqbody_result("Unknown request body processor: ", Err(content_type));
            }
            Processor::None => self.set_reqbody_result("", Ok(())),
        }
    }

    /// Whether the body is larger than `SecRequestBodyNoFilesLimit`, for
    /// the bodies without files (URL-encoded, JSON, XML). Reports it.
    fn request_body_over_no_files_limit(&mut self) -> bool {
        let body = &self.body;
        if !(body.request_body_type == RequestBodyType::WWWFormUrlEncoded
            || body.request_body_processor == RequestBodyType::JSONRequestBody
            || body.request_body_processor == RequestBodyType::XMLRequestBody)
        {
            return false;
        }
        match self.rules.properties.settings.request_body_no_files_limit {
            Some(limit) if self.http.request_body.len() as u64 > limit => {
                self.set_reqbody_over_no_files_limit(limit);
                true
            }
            _ => false,
        }
    }

    /// Reports a body (without its files) over `SecRequestBodyNoFilesLimit`.
    fn set_reqbody_over_no_files_limit(&mut self, limit: u64) {
        self.vars.reqbody_error.set(b"1", 0);
        self.vars.reqbody_error_msg.set(b"Request body excluding files is bigger than the maximum expected.", 0);
        let off = self.vars.offset;
        self.vars.inbound_data_error.set(b"1", off);
        crate::ms_dbg!(self, 5, "Request body excluding files is bigger than the maximum expected. Limit: {}", limit);
    }

    /// Sets `REQBODY_ERROR` and `REQBODY_PROCESSOR_ERROR` from the result
    /// of a processor; the error messages are `prefix` and the error.
    fn set_reqbody_result(&mut self, prefix: &str, result: Result<(), String>) {
        let off = self.vars.offset;
        match result {
            Ok(()) => {
                self.vars.reqbody_error.set(b"0", off);
                self.vars.reqbody_processor_error.set(b"0", off);
            }
            Err(error) => {
                let msg = format!("{}{}", prefix, error);
                self.vars.reqbody_error.set(b"1", off);
                self.vars.reqbody_processor_error.set(b"1", off);
                self.vars.reqbody_error_msg.set(msg.as_bytes(), off);
                self.vars.reqbody_processor_error_msg.set(msg.as_bytes(), off);
            }
        }
    }

    #[cfg(feature = "libxml2")]
    fn parse_xml_body(&mut self) -> Result<(), String> {
        use modsecurity_body::xml::Xml;
        // The processor writes to the transaction while it reads the body.
        let body = std::mem::take(&mut self.http.request_body);
        let mut xml = self.body.xml.take().unwrap_or_else(|| Box::new(Xml::new()));
        let mut result = Ok(());
        if xml.init(self) {
            // The error of `complete` replaces that of `process_chunk`.
            result = xml.process_chunk(self, &body);
            result = xml.complete(self).and(result);
        }
        self.body.xml = Some(xml);
        self.http.request_body = body;
        result
    }

    fn parse_json_body(&mut self) -> Result<(), String> {
        if let Some(depth) = self.rules.properties.settings.request_body_json_depth_limit {
            self.body.json.set_max_depth(depth);
        }
        let mut arguments = ArgumentWriter {
            vars: &mut self.vars,
            combined_size: &mut self.http.args_combined_size,
            rules: self.rules,
            id: &self.id,
            uri: &self.http.uri,
        };
        self.body.json.parse(&self.http.request_body, |key, value| arguments.add("JSON", key, value, 0))
    }

    /// Parses a `multipart/form-data` body and reports its result: an
    /// error of the parser, or form data (the body without its files)
    /// over `SecRequestBodyNoFilesLimit`.
    fn parse_multipart_body(&mut self) {
        let mut error = None;
        let mut no_files_length: u64 = 0;
        if let Some(content_type) = self.vars.request_headers.resolve_first(b"Content-Type") {
            // The parser writes to the transaction while it reads the body.
            let body = std::mem::take(&mut self.http.request_body);
            let mut m = Multipart::new(&content_type);
            if m.init(self) {
                let off = self.vars.offset;
                m.process(self, &body, off);
            }
            no_files_length = m.reqbody_no_files_length as u64;
            m.multipart_complete(self);
            error = m.error().map(str::to_owned);
            self.http.request_body = body;
        }
        match (error, self.rules.properties.settings.request_body_no_files_limit) {
            (Some(error), _) => self.set_reqbody_result("Multipart parsing error: ", Err(error)),
            (None, Some(limit)) if no_files_length > limit => self.set_reqbody_over_no_files_limit(limit),
            (None, _) => self.set_reqbody_result("", Ok(())),
        }
    }

    /// Whether the rules are given the request body: `SecRequestBodyAccess`,
    /// unless a rule changed it with `ctl:requestBodyAccess`.
    pub(super) fn request_body_access(&self) -> bool {
        if self.rules.properties.settings.sec_request_body_access == Some(false) {
            if self.ctl.request_body_access != Some(true) {
                crate::ms_dbg!(self, 4, "Request body processing is disabled");
                return false;
            }
            crate::ms_dbg!(
                self,
                4,
                "Request body processing is disabled, but enabled to this transaction due to ctl:requestBodyAccess action"
            );
        } else if self.ctl.request_body_access == Some(false) {
            crate::ms_dbg!(
                self,
                4,
                "Request body processing is enabled, but disabled to this transaction due to ctl:requestBodyAccess action"
            );
            return false;
        }
        true
    }

    /// Sets `FULL_REQUEST`, `REQUEST_BODY` and their lengths.
    pub(super) fn set_request_body_variables(&mut self) {
        let mut full_request: Vec<u8> = Vec::new();
        let mut l: Vec<VariableValue> = Vec::new();
        self.vars.request_headers.resolve(&mut l);
        for h in &l {
            full_request.extend_from_slice(h.key());
            full_request.extend_from_slice(b": ");
            full_request.extend_from_slice(h.value());
            full_request.push(b'\n');
        }
        full_request.extend_from_slice(b"\n\n");
        full_request.extend_from_slice(&self.http.request_body);
        let off = self.vars.offset;
        self.vars.full_request.set(&full_request, off);
        self.vars.full_request_length.set(full_request.len().to_string().as_bytes(), off);

        if !self.http.request_body.is_empty() {
            self.vars.request_body.set(&self.http.request_body, off);
            self.vars.request_body_length.set_with_len(
                self.http.request_body.len().to_string().as_bytes(),
                off,
                self.http.request_body.len(),
            );
        }
    }
}

impl multipart::Context for Transaction<'_> {
    fn offset(&self) -> usize {
        self.vars.offset
    }

    fn set(&mut self, flag: Flag, value: &[u8], offset: usize) {
        self.flag(flag).set(value, offset);
    }

    fn set_with_len(&mut self, flag: Flag, value: &[u8], offset: usize, len: usize) {
        match flag {
            // The combined size comes from every file: each adds its
            // origin.
            Flag::FilesCombinedSize => {
                let origin = crate::variables::variable_origin::VariableOrigin::new(len, offset);
                self.vars.files_combined_size.set_adding_origins(value, [origin]);
            }
            _ => self.flag(flag).set_with_len(value, offset, len),
        }
    }

    fn add(&mut self, entries: Entries, key: &[u8], value: &[u8], offset: usize) {
        self.entries(entries).set(key, value, offset);
    }

    fn add_with_len(&mut self, entries: Entries, key: &[u8], value: &[u8], offset: usize, len: usize) {
        self.entries(entries).set_with_len(key, value, offset, len);
    }

    fn uploads(&self) -> Uploads {
        let props = &self.rules.properties;
        Uploads {
            keep_files: props.settings.upload_keep_files,
            tmp_save_files: props.settings.tmp_save_uploaded_files,
            file_limit: props.settings.upload_file_limit.unwrap_or(0),
            file_mode: props.settings.upload_file_mode.unwrap_or(0),
        }
    }

    fn upload_file_prefix(&self) -> String {
        let time = crate::utils::system::strftime_local(crate::utils::system::now(), "/%Y%m%d-%H%M%S");
        let directory = self.rules.properties.settings.upload_directory.as_deref().unwrap_or_default();
        format!("{}{}-{}", directory, time, self.id)
    }

    fn keep_tmp_file(&mut self, file: Arc<MultipartPartTmpFile>) {
        self.body.multipart_part_tmp_files.push(file);
    }
}

impl Transaction<'_> {
    /// The variable of a multipart [`Flag`].
    fn flag(&mut self, flag: Flag) -> &mut crate::variables::anchored_variable::AnchoredVariable {
        let v = &mut self.vars;
        match flag {
            Flag::MultipartBoundaryQuoted => &mut v.multipart_boundary_quoted,
            Flag::MultipartBoundaryWhiteSpace => &mut v.multipart_boundary_white_space,
            Flag::MultipartCrlfLfLines => &mut v.multipart_crlf_lf_lines,
            Flag::MultipartDataAfter => &mut v.multipart_data_after,
            Flag::MultipartDataBefore => &mut v.multipart_data_before,
            Flag::MultipartDuplicatePartHeader => &mut v.multipart_duplicate_part_header,
            Flag::MultipartHeaderFolding => &mut v.multipart_header_folding,
            Flag::MultipartInvalidHeaderFolding => &mut v.multipart_invalid_header_folding,
            Flag::MultipartInvalidPart => &mut v.multipart_invalid_part,
            Flag::MultipartInvalidQuoting => &mut v.multipart_invalid_quoting,
            Flag::MultipartLfLine => &mut v.multipart_lf_line,
            Flag::MultipartMissingSemicolon => &mut v.multipart_missing_semicolon,
            Flag::MultipartStrictError => &mut v.multipart_strict_error,
            Flag::MultipartUnmatchedBoundary => &mut v.multipart_unmatched_boundary,
            Flag::FilesCombinedSize => &mut v.files_combined_size,
        }
    }

    /// The variable of multipart [`Entries`].
    fn entries(&mut self, entries: Entries) -> &mut crate::variables::anchored_set_variable::AnchoredSetVariable {
        let v = &mut self.vars;
        match entries {
            Entries::Args => &mut v.args,
            Entries::ArgsPost => &mut v.args_post,
            Entries::Files => &mut v.files,
            Entries::FilesNames => &mut v.files_names,
            Entries::FilesSizes => &mut v.files_sizes,
            Entries::FilesTmpContent => &mut v.files_tmp_content,
            Entries::FilesTmpNames => &mut v.files_tmp_names,
            Entries::MultipartFileName => &mut v.multipart_file_name,
            Entries::MultipartFileNameCharset => &mut v.multipart_file_name_charset,
            Entries::MultipartFileNameLanguage => &mut v.multipart_file_name_language,
            Entries::MultipartName => &mut v.multipart_name,
            Entries::MultipartPartHeaders => &mut v.multipart_part_headers,
        }
    }
}

#[cfg(feature = "libxml2")]
impl modsecurity_body::xml::Context for Transaction<'_> {
    fn external_entities(&self) -> bool {
        self.rules.properties.settings.sec_xml_external_entity == Some(true)
    }

    fn args_mode(&self) -> modsecurity_body::xml::IntoArgs {
        use crate::rules_set::properties::ParseXmlIntoArgs;
        use modsecurity_body::xml::IntoArgs;
        match self.ctl.parse_xml_into_args {
            Some(ParseXmlIntoArgs::On) => IntoArgs::On,
            Some(ParseXmlIntoArgs::OnlyArgs) => IntoArgs::OnlyArgs,
            Some(ParseXmlIntoArgs::Off) | None => IntoArgs::Off,
        }
    }

    fn add_argument(&mut self, name: &[u8], value: &[u8]) -> bool {
        Transaction::add_argument(self, "XML", name, value, 0)
    }
}

/// The body processors through a transaction (each is tested alone in the
/// `modsecurity-body` crate).
#[cfg(test)]
pub(crate) mod tests {
    mod json;
    pub(crate) mod multipart;
    mod xml;
}
