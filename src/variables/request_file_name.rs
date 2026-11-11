//! Port of `src/variables/request_file_name.h`.
//!
//! `DEFINE_VARIABLE(RequestFilename, REQUEST_FILENAME, m_variableRequestFilename)`

crate::define_variable!(RequestFilename, "REQUEST_FILENAME", request_filename);
