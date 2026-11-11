//! Port of `src/variables/multipart_invalid_header_folding.h`.
//!
//! `DEFINE_VARIABLE(MultipartInvalidHeaderFolding, MULTIPART_INVALID_HEADER_FOLDING, m_variableMultipartInvalidHeaderFolding)`

crate::define_variable!(
    MultipartInvalidHeaderFolding,
    "MULTIPART_INVALID_HEADER_FOLDING",
    multipart_invalid_header_folding
);
