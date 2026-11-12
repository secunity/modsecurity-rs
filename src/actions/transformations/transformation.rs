//! Port of `src/actions/transformations/transformation.h` /
//! `src/actions/transformations/transformation.cc`.
//!
//! In C++ every transformation is a subclass of `Transformation` (itself an
//! `Action`). Here a transformation is one [`Transformation`] value whose
//! [`TransformationKind`] selects the function applied; the functions live
//! in the modules of `actions::transformations`.

use crate::actions::action::{Action, Kind, name_of};
use crate::actions::transformations::*;
use crate::transaction::Transaction;
use crate::utils::decode::urldecode_nonstrict_inplace;

/// The transformation functions (`t:xxx`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformationKind {
    Base64Decode,
    Base64DecodeExt,
    Base64Encode,
    CmdLine,
    CompressWhitespace,
    CssDecode,
    EscapeSeqDecode,
    HexDecode,
    HexEncode,
    HtmlEntityDecode,
    JsDecode,
    Length,
    LowerCase,
    Md5,
    /// `t:none`: changes nothing, but discards the transformations listed
    /// before it (see `RuleWithActions::execute_transformations`).
    None,
    NormalisePath,
    NormalisePathWin,
    ParityEven7bit,
    ParityOdd7bit,
    ParityZero7bit,
    RemoveComments,
    RemoveCommentsChar,
    RemoveNulls,
    RemoveWhitespace,
    ReplaceComments,
    ReplaceNulls,
    Sha1,
    SqlHexDecode,
    Trim,
    TrimLeft,
    TrimRight,
    UpperCase,
    UrlDecode,
    UrlDecodeUni,
    UrlEncode,
    Utf8ToUnicode,
    /// The plain C++ `Transformation` class (returned for unknown names):
    /// leaves the value as it is.
    Identity,
}

/// A transformation (`t:xxx`): an action of kind
/// `RunTimeBeforeMatchAttemptKind` that rewrites the target value.
#[derive(Debug, Clone)]
pub struct Transformation {
    /// The name as written in the rule (e.g. `t:lowerCase`), which the
    /// debug log and the transformation paths print.
    name: String,
    pub kind: TransformationKind,
}

impl Transformation {
    pub fn new(kind: TransformationKind, action: &str) -> Self {
        Transformation { name: name_of(action), kind }
    }

    /// `Transformation::instantiate`: the transformation named `a`
    /// (`t:<name>`). Names are matched by prefix in the C++ order (so
    /// `t:trimLeftX` is `trimLeft`); unknown names do nothing.
    pub fn from_name(a: &str) -> Self {
        use TransformationKind as K;
        const NAMES: &[(&str, TransformationKind)] = &[
            ("base64DecodeExt", K::Base64DecodeExt),
            ("base64Decode", K::Base64Decode),
            ("base64Encode", K::Base64Encode),
            ("cmd_line", K::CmdLine),
            ("compress_whitespace", K::CompressWhitespace),
            ("cssDecode", K::CssDecode),
            ("escapeSeqDecode", K::EscapeSeqDecode),
            ("hexDecode", K::HexDecode),
            ("hexEncode", K::HexEncode),
            ("htmlEntityDecode", K::HtmlEntityDecode),
            ("jsDecode", K::JsDecode),
            ("length", K::Length),
            ("lowercase", K::LowerCase),
            ("md5", K::Md5),
            ("none", K::None),
            ("normalizePathWin", K::NormalisePathWin),
            ("normalisePathWin", K::NormalisePathWin),
            ("normalizePath", K::NormalisePath),
            ("normalisePath", K::NormalisePath),
            ("parityEven7bit", K::ParityEven7bit),
            ("parityOdd7bit", K::ParityOdd7bit),
            ("parityZero7bit", K::ParityZero7bit),
            ("removeCommentsChar", K::RemoveCommentsChar),
            ("removeComments", K::RemoveComments),
            ("removeNulls", K::RemoveNulls),
            ("removeWhitespace", K::RemoveWhitespace),
            ("compressWhitespace", K::CompressWhitespace),
            ("replaceComments", K::ReplaceComments),
            ("replaceNulls", K::ReplaceNulls),
            ("sha1", K::Sha1),
            ("sqlHexDecode", K::SqlHexDecode),
            ("transformation", K::Identity),
            ("trimLeft", K::TrimLeft),
            ("trimRight", K::TrimRight),
            ("trim", K::Trim),
            ("uppercase", K::UpperCase),
            ("urlDecodeUni", K::UrlDecodeUni),
            ("urlDecode", K::UrlDecode),
            ("urlEncode", K::UrlEncode),
            ("utf8toUnicode", K::Utf8ToUnicode),
        ];
        // `a.compare(2, strlen(name), name) == 0`: the text after the first
        // two characters starts with `name`.
        let rest = a.as_bytes().get(2..).unwrap_or_default();
        let kind = NAMES.iter().find(|(name, _)| rest.starts_with(name.as_bytes())).map_or(K::Identity, |&(_, k)| k);
        Transformation::new(kind, a)
    }

    pub fn is_none(&self) -> bool {
        self.kind == TransformationKind::None
    }

    /// Transforms `value` in place; returns whether it changed. Only
    /// `urlDecodeUni` uses the transaction (for `SecUnicodeMapFile`).
    pub fn transform(&self, value: &mut Vec<u8>, t: Option<&Transaction<'_>>) -> bool {
        use TransformationKind as K;
        match self.kind {
            K::Base64Decode => base64_decode::transform(value),
            K::Base64DecodeExt => base64_decode_ext::transform(value),
            K::Base64Encode => base64_encode::transform(value),
            K::CmdLine => cmd_line::transform(value),
            K::CompressWhitespace => compress_whitespace::transform(value),
            K::CssDecode => css_decode::transform(value),
            K::EscapeSeqDecode => escape_seq_decode::transform(value),
            K::HexDecode => hex_decode::transform(value),
            K::HexEncode => hex_encode::transform(value),
            K::HtmlEntityDecode => html_entity_decode::transform(value),
            K::JsDecode => js_decode::transform(value),
            K::Length => {
                *value = value.len().to_string().into_bytes();
                true
            }
            K::LowerCase => case::lower(value),
            K::UpperCase => case::upper(value),
            K::Md5 => crate::utils::md5::Md5::digest_replace(value),
            K::Sha1 => crate::utils::sha1::Sha1::digest_replace(value),
            K::NormalisePath => normalise_path::normalize_path_inplace(value, false),
            K::NormalisePathWin => normalise_path::normalize_path_inplace(value, true),
            K::ParityEven7bit => parity_7bit::even(value),
            K::ParityOdd7bit => parity_7bit::odd(value),
            K::ParityZero7bit => parity_7bit::zero(value),
            K::RemoveComments => remove_comments::transform(value),
            K::RemoveCommentsChar => remove_comments_char::transform(value),
            K::RemoveNulls => remove_nulls::transform(value),
            K::RemoveWhitespace => remove_whitespace::transform(value),
            K::ReplaceComments => replace_comments::transform(value),
            K::ReplaceNulls => replace_nulls::transform(value),
            K::SqlHexDecode => sql_hex_decode::transform(value),
            K::Trim => trim::trim(value),
            K::TrimLeft => trim::ltrim(value),
            K::TrimRight => trim::rtrim(value),
            K::UrlDecode => urldecode_nonstrict_inplace(value, &mut 0),
            K::UrlDecodeUni => url_decode_uni::transform(value, t),
            K::UrlEncode => url_encode::transform(value),
            K::Utf8ToUnicode => utf8_to_unicode::transform(value),
            K::None | K::Identity => false,
        }
    }
}

impl Action for Transformation {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> Kind {
        Kind::RunTimeBeforeMatchAttempt
    }

    fn as_transformation(&self) -> Option<&Transformation> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(name: &str, input: &[u8]) -> (bool, Vec<u8>) {
        let mut v = input.to_vec();
        let changed = Transformation::from_name(name).transform(&mut v, Option::None);
        (changed, v)
    }

    #[test]
    fn names_match_by_prefix_in_cxx_order() {
        let kind = |n: &str| Transformation::from_name(n).kind;
        assert_eq!(kind("t:base64DecodeExt"), TransformationKind::Base64DecodeExt);
        assert_eq!(kind("t:base64Decode"), TransformationKind::Base64Decode);
        assert_eq!(kind("t:trimLeft"), TransformationKind::TrimLeft);
        assert_eq!(kind("t:trimX"), TransformationKind::Trim);
        assert_eq!(kind("t:normalizePathWin"), TransformationKind::NormalisePathWin);
        assert_eq!(kind("t:LOWERCASE"), TransformationKind::Identity);
        assert_eq!(kind("t:nosuch"), TransformationKind::Identity);
        assert_eq!(Transformation::from_name("t:trimLeft").name(), "t:trimLeft");
        assert!(Transformation::from_name("t:none").is_none());
        assert!(Transformation::from_name("t:none").is_none());
    }

    #[test]
    fn simple_kinds() {
        assert_eq!(apply("t:length", b"abcd"), (true, b"4".to_vec()));
        assert_eq!(apply("t:uppercase", b"aB1"), (true, b"AB1".to_vec()));
        assert_eq!(apply("t:lowercase", b"ab1"), (false, b"ab1".to_vec()));
        assert_eq!(apply("t:trimLeft", b" a "), (true, b"a ".to_vec()));
        assert_eq!(apply("t:trimRight", b" a "), (true, b" a".to_vec()));
        assert_eq!(apply("t:urlDecode", b"a%41+"), (true, b"aA ".to_vec()));
        assert_eq!(apply("t:md5", b"").1.len(), 16);
        assert_eq!(apply("t:sha1", b"").1.len(), 20);
        assert_eq!(apply("t:none", b"x"), (false, b"x".to_vec()));
        assert_eq!(apply("t:nosuch", b"x"), (false, b"x".to_vec()));
        assert_eq!(apply("t:normalizePathWin", b"a\\b"), (true, b"a/b".to_vec()));
    }
}
