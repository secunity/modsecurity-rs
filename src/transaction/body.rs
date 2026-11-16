//! The transaction as the context of the request body processors: where
//! their variables go, and the settings they read.

use std::sync::Arc;

use crate::request_body_processor::multipart::{self, Entries, Flag, MultipartPartTmpFile, Uploads};
use crate::transaction::Transaction;

impl multipart::Context for Transaction<'_> {
    fn debug_enabled(&self, level: i32) -> bool {
        Transaction::debug_enabled(self, level)
    }

    fn debug(&self, level: i32, message: &str) {
        Transaction::debug(self, level, message)
    }

    fn offset(&self) -> usize {
        self.vars.offset
    }

    fn set(&mut self, flag: Flag, value: &[u8], offset: usize) {
        self.flag(flag).set(value, offset);
    }

    fn set_with_len(&mut self, flag: Flag, value: &[u8], offset: usize, len: usize) {
        self.flag(flag).set_with_len(value, offset, len);
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
            keep_files: props.upload_keep_files,
            tmp_save_files: props.tmp_save_uploaded_files,
            file_limit: props.upload_file_limit.unwrap_or(0),
            file_mode: props.upload_file_mode.unwrap_or(0),
        }
    }

    fn upload_file_prefix(&self) -> String {
        let time = crate::utils::system::strftime_local(crate::utils::system::now(), "/%Y%m%d-%H%M%S");
        let directory = self.rules.properties.upload_directory.as_deref().unwrap_or_default();
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
impl crate::request_body_processor::xml::Context for Transaction<'_> {
    fn debug_enabled(&self, level: i32) -> bool {
        Transaction::debug_enabled(self, level)
    }

    fn debug(&self, level: i32, message: &str) {
        Transaction::debug(self, level, message)
    }

    fn external_entities(&self) -> bool {
        self.rules.properties.sec_xml_external_entity == Some(true)
    }

    fn args_mode(&self) -> crate::request_body_processor::xml::IntoArgs {
        use crate::request_body_processor::xml::IntoArgs;
        use crate::rules_set::properties::ParseXmlIntoArgs;
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
