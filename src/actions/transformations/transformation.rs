//! Port of `src/actions/transformations/transformation.h` /
//! `src/actions/transformations/transformation.cc`.

use crate::actions::action::{Action, ActionBase, Kind};
use crate::transaction::Transaction;

/// A transformation (`t:xxx`) is an action of kind
/// `RunTimeBeforeMatchAttemptKind` that rewrites the target value.
pub trait Transformation: Action {
    /// Transforms `value` in place; returns whether it changed.
    fn transform(&self, value: &mut Vec<u8>, t: Option<&Transaction<'_>>) -> bool;
}

/// `ActionBase` for a transformation (kind `RunTimeBeforeMatchAttemptKind`).
pub fn transformation_base(action: &str) -> ActionBase {
    ActionBase::with_kind(action, Kind::RunTimeBeforeMatchAttemptKind)
}

/// Declares a transformation struct named `$n` with a `new(action: &str)`
/// constructor and its [`Action`] implementation. The module then only
/// implements [`Transformation`] for it.
#[macro_export]
macro_rules! transformation_struct {
    ($n:ident) => {
        #[derive(Debug, Clone)]
        pub struct $n {
            pub base: $crate::actions::action::ActionBase,
        }

        impl $n {
            pub fn new(action: &str) -> Self {
                $n { base: $crate::actions::transformations::transformation::transformation_base(action) }
            }
        }

        impl $crate::actions::action::Action for $n {
            $crate::action_base_accessors!();
            fn as_transformation(
                &self,
            ) -> Option<&dyn $crate::actions::transformations::transformation::Transformation> {
                Some(self)
            }
        }
    };
}

/// The plain C++ `Transformation` class: returned by
/// [`instantiate`] for unknown names; it never changes the value.
#[derive(Debug, Clone)]
pub struct BaseTransformation {
    pub base: ActionBase,
}

impl BaseTransformation {
    pub fn new(action: &str) -> Self {
        BaseTransformation { base: transformation_base(action) }
    }
}

impl Action for BaseTransformation {
    crate::action_base_accessors!();
    fn as_transformation(&self) -> Option<&dyn Transformation> {
        Some(self)
    }
}

impl Transformation for BaseTransformation {
    fn transform(&self, _value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        false
    }
}

/// `Transformation::instantiate`: the transformation for `t:<name>`.
pub fn instantiate(a: &str) -> Box<dyn Transformation> {
    use crate::actions::transformations::*;
    macro_rules! if_match {
        ($name:literal, $t:expr) => {
            // `a.compare(2, strlen(name), name) == 0`: the text after the
            // first two characters starts with `name`.
            if a.len() >= 2 && a.as_bytes()[2..].starts_with($name.as_bytes()) {
                return Box::new($t);
            }
        };
    }
    if_match!("base64DecodeExt", base64_decode_ext::Base64DecodeExt::new(a));
    if_match!("base64Decode", base64_decode::Base64Decode::new(a));
    if_match!("base64Encode", base64_encode::Base64Encode::new(a));
    if_match!("cmd_line", cmd_line::CmdLine::new(a));
    if_match!("compress_whitespace", compress_whitespace::CompressWhitespace::new(a));
    if_match!("cssDecode", css_decode::CssDecode::new(a));
    if_match!("escapeSeqDecode", escape_seq_decode::EscapeSeqDecode::new(a));
    if_match!("hexDecode", hex_decode::HexDecode::new(a));
    if_match!("hexEncode", hex_encode::HexEncode::new(a));
    if_match!("htmlEntityDecode", html_entity_decode::HtmlEntityDecode::new(a));
    if_match!("jsDecode", js_decode::JsDecode::new(a));
    if_match!("length", length::Length::new(a));
    if_match!("lowercase", lower_case::LowerCase::new(a));
    if_match!("md5", md5::Md5::new(a));
    if_match!("none", none::None::new(a));
    if_match!("normalizePathWin", normalise_path_win::NormalisePathWin::new(a));
    if_match!("normalisePathWin", normalise_path_win::NormalisePathWin::new(a));
    if_match!("normalizePath", normalise_path::NormalisePath::new(a));
    if_match!("normalisePath", normalise_path::NormalisePath::new(a));
    if_match!("parityEven7bit", parity_even_7bit::ParityEven7bit::new(a));
    if_match!("parityOdd7bit", parity_odd_7bit::ParityOdd7bit::new(a));
    if_match!("parityZero7bit", parity_zero_7bit::ParityZero7bit::new(a));
    if_match!("removeCommentsChar", remove_comments_char::RemoveCommentsChar::new(a));
    if_match!("removeComments", remove_comments::RemoveComments::new(a));
    if_match!("removeNulls", remove_nulls::RemoveNulls::new(a));
    if_match!("removeWhitespace", remove_whitespace::RemoveWhitespace::new(a));
    if_match!("compressWhitespace", compress_whitespace::CompressWhitespace::new(a));
    if_match!("replaceComments", replace_comments::ReplaceComments::new(a));
    if_match!("replaceNulls", replace_nulls::ReplaceNulls::new(a));
    if_match!("sha1", sha1::Sha1::new(a));
    if_match!("sqlHexDecode", sql_hex_decode::SqlHexDecode::new(a));
    if_match!("transformation", BaseTransformation::new(a));
    if_match!("trimLeft", trim_left::TrimLeft::new(a));
    if_match!("trimRight", trim_right::TrimRight::new(a));
    if_match!("trim", trim::Trim::new(a));
    if_match!("uppercase", upper_case::UpperCase::new(a));
    if_match!("urlDecodeUni", url_decode_uni::UrlDecodeUni::new(a));
    if_match!("urlDecode", url_decode::UrlDecode::new(a));
    if_match!("urlEncode", url_encode::UrlEncode::new(a));
    if_match!("utf8toUnicode", utf8_to_unicode::Utf8ToUnicode::new(a));
    Box::new(BaseTransformation::new(a))
}
