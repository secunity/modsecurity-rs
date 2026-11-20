//! The SecLang transformations (`t:lowercase`, `t:urlDecodeUni`, ...): pure
//! functions that rewrite a value in place.
//!
//! A [`Transformation`] names one of them; [`Transformation::apply`] runs
//! it. Nothing here knows about rules or transactions: the only outside
//! input is the [`Context`] (the unicode map of `t:urlDecodeUni`).
//!
//! ```
//! use modsecurity_transformations::{Context, Transformation};
//!
//! let t = Transformation::from_name("urlDecode").unwrap();
//! let mut value = b"a%20b".to_vec();
//! t.apply(&mut value, &Context::default());
//! assert_eq!(value, b"a b");
//! ```
//!
//! The decoders the engine also uses elsewhere are public: [`base64`],
//! [`url`] and the byte helpers in [`chars`].

#![forbid(unsafe_code)]

pub mod base64;
pub mod url;

mod base64_decode;
mod base64_decode_ext;
mod base64_encode;
mod case;
mod cmd_line;
mod compress_whitespace;
mod css_decode;
mod escape_seq_decode;
mod hex_decode;
mod hex_encode;
mod html_entity_decode;
mod js_decode;
mod normalise_path;
mod parity_7bit;
mod remove_comments;
mod remove_comments_char;
mod remove_nulls;
mod remove_whitespace;
mod replace_comments;
mod replace_nulls;
mod sql_hex_decode;
mod trim;
mod url_decode_uni;
mod url_encode;
mod utf8_to_unicode;

pub use modsecurity_compat::chars;
use sha1::Digest;

/// A unicode map (`SecUnicodeMapFile`): the byte each of the 65536 code
/// points of `%uHHHH` maps to, or -1.
#[derive(Debug, Clone)]
pub struct UnicodeMap {
    pub data: Vec<i32>,
}

impl Default for UnicodeMap {
    fn default() -> Self {
        UnicodeMap { data: vec![-1; 65536] }
    }
}

impl UnicodeMap {
    pub fn at(&self, index: usize) -> i32 {
        self.data[index]
    }

    pub fn change(&mut self, i: usize, a: i32) {
        self.data[i] = a;
    }
}

/// What a transformation may use besides the value.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context<'a> {
    /// The map of `t:urlDecodeUni`, when one is configured.
    pub unicode_map: Option<&'a UnicodeMap>,
}

/// A transformation function (`t:xxx`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transformation {
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
    /// `t:none`: changes nothing; rules use it to discard the
    /// transformations listed before it.
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
    /// The transformation of an unknown name in
    /// [`Transformation::from_name_prefix`]: leaves the value as it is.
    Identity,
}

use Transformation as T;

/// The names a rule may give after `t:`, in lower case.
const NAMES: &[(&str, Transformation)] = &[
    ("base64decode", T::Base64Decode),
    ("base64decodeext", T::Base64DecodeExt),
    ("base64encode", T::Base64Encode),
    ("cmdline", T::CmdLine),
    ("compresswhitespace", T::CompressWhitespace),
    ("cssdecode", T::CssDecode),
    ("escapeseqdecode", T::EscapeSeqDecode),
    ("hexdecode", T::HexDecode),
    ("hexencode", T::HexEncode),
    ("htmlentitydecode", T::HtmlEntityDecode),
    ("jsdecode", T::JsDecode),
    ("length", T::Length),
    ("lowercase", T::LowerCase),
    ("md5", T::Md5),
    ("none", T::None),
    ("normalisepath", T::NormalisePath),
    ("normalizepath", T::NormalisePath),
    ("normalisepathwin", T::NormalisePathWin),
    ("normalizepathwin", T::NormalisePathWin),
    ("parityeven7bit", T::ParityEven7bit),
    ("parityodd7bit", T::ParityOdd7bit),
    ("parityzero7bit", T::ParityZero7bit),
    ("removecomments", T::RemoveComments),
    ("removecommentschar", T::RemoveCommentsChar),
    ("removenulls", T::RemoveNulls),
    ("removewhitespace", T::RemoveWhitespace),
    ("replacecomments", T::ReplaceComments),
    ("replacenulls", T::ReplaceNulls),
    ("sha1", T::Sha1),
    ("sqlhexdecode", T::SqlHexDecode),
    ("trim", T::Trim),
    ("trimleft", T::TrimLeft),
    ("trimright", T::TrimRight),
    ("uppercase", T::UpperCase),
    ("urldecode", T::UrlDecode),
    ("urldecodeuni", T::UrlDecodeUni),
    ("urlencode", T::UrlEncode),
    ("utf8tounicode", T::Utf8ToUnicode),
];

/// The names of [`Transformation::from_name_prefix`], in the order they
/// are tried (a longer name before its prefixes), with the spellings of
/// that lookup (`cmd_line`, `compress_whitespace`, `transformation`).
const PREFIX_NAMES: &[(&str, Transformation)] = &[
    ("base64DecodeExt", T::Base64DecodeExt),
    ("base64Decode", T::Base64Decode),
    ("base64Encode", T::Base64Encode),
    ("cmd_line", T::CmdLine),
    ("compress_whitespace", T::CompressWhitespace),
    ("cssDecode", T::CssDecode),
    ("escapeSeqDecode", T::EscapeSeqDecode),
    ("hexDecode", T::HexDecode),
    ("hexEncode", T::HexEncode),
    ("htmlEntityDecode", T::HtmlEntityDecode),
    ("jsDecode", T::JsDecode),
    ("length", T::Length),
    ("lowercase", T::LowerCase),
    ("md5", T::Md5),
    ("none", T::None),
    ("normalizePathWin", T::NormalisePathWin),
    ("normalisePathWin", T::NormalisePathWin),
    ("normalizePath", T::NormalisePath),
    ("normalisePath", T::NormalisePath),
    ("parityEven7bit", T::ParityEven7bit),
    ("parityOdd7bit", T::ParityOdd7bit),
    ("parityZero7bit", T::ParityZero7bit),
    ("removeCommentsChar", T::RemoveCommentsChar),
    ("removeComments", T::RemoveComments),
    ("removeNulls", T::RemoveNulls),
    ("removeWhitespace", T::RemoveWhitespace),
    ("compressWhitespace", T::CompressWhitespace),
    ("replaceComments", T::ReplaceComments),
    ("replaceNulls", T::ReplaceNulls),
    ("sha1", T::Sha1),
    ("sqlHexDecode", T::SqlHexDecode),
    ("transformation", T::Identity),
    ("trimLeft", T::TrimLeft),
    ("trimRight", T::TrimRight),
    ("trim", T::Trim),
    ("uppercase", T::UpperCase),
    ("urlDecodeUni", T::UrlDecodeUni),
    ("urlDecode", T::UrlDecode),
    ("urlEncode", T::UrlEncode),
    ("utf8toUnicode", T::Utf8ToUnicode),
];

impl Transformation {
    /// The transformation a rule names after `t:` (`lowercase`,
    /// `urlDecodeUni`, ...), whatever its case; `None` for an unknown
    /// name.
    pub fn from_name(name: &str) -> Option<Transformation> {
        let name = name.to_ascii_lowercase();
        NAMES.iter().find(|(n, _)| *n == name).map(|&(_, t)| t)
    }

    /// The lookup by prefix, which the engine uses
    /// where it is not the SecLang parser that names the transformation
    /// (Lua's `m.getvar`, the unit tests): the first name of its list that
    /// `text` starts with, case sensitively (so `trimLeftX` is `trimLeft`,
    /// and `LOWERCASE` is unknown); [`Transformation::Identity`] for an
    /// unknown name.
    pub fn from_name_prefix(text: &[u8]) -> Transformation {
        PREFIX_NAMES.iter().find(|(name, _)| text.starts_with(name.as_bytes())).map_or(T::Identity, |&(_, t)| t)
    }

    /// Transforms `value` in place.
    pub fn apply(self, value: &mut Vec<u8>, context: &Context<'_>) {
        match self {
            T::Base64Decode => base64_decode::transform(value),
            T::Base64DecodeExt => base64_decode_ext::transform(value),
            T::Base64Encode => base64_encode::transform(value),
            T::CmdLine => cmd_line::transform(value),
            T::CompressWhitespace => compress_whitespace::transform(value),
            T::CssDecode => css_decode::transform(value),
            T::EscapeSeqDecode => escape_seq_decode::transform(value),
            T::HexDecode => hex_decode::transform(value),
            T::HexEncode => hex_encode::transform(value),
            T::HtmlEntityDecode => html_entity_decode::transform(value),
            T::JsDecode => js_decode::transform(value),
            T::Length => *value = value.len().to_string().into_bytes(),
            T::LowerCase => case::lower(value),
            T::UpperCase => case::upper(value),
            T::Md5 => *value = md5::Md5::digest(&*value).to_vec(),
            T::Sha1 => *value = sha1::Sha1::digest(&*value).to_vec(),
            T::NormalisePath => normalise_path::normalize_path_inplace(value, false),
            T::NormalisePathWin => normalise_path::normalize_path_inplace(value, true),
            T::ParityEven7bit => parity_7bit::even(value),
            T::ParityOdd7bit => parity_7bit::odd(value),
            T::ParityZero7bit => parity_7bit::zero(value),
            T::RemoveComments => remove_comments::transform(value),
            T::RemoveCommentsChar => remove_comments_char::transform(value),
            T::RemoveNulls => remove_nulls::transform(value),
            T::RemoveWhitespace => remove_whitespace::transform(value),
            T::ReplaceComments => replace_comments::transform(value),
            T::ReplaceNulls => replace_nulls::transform(value),
            T::SqlHexDecode => sql_hex_decode::transform(value),
            T::Trim => trim::trim(value),
            T::TrimLeft => trim::ltrim(value),
            T::TrimRight => trim::rtrim(value),
            T::UrlDecode => url::urldecode_nonstrict_inplace(value, &mut 0),
            T::UrlDecodeUni => url_decode_uni::transform(value, context.unicode_map),
            T::UrlEncode => url_encode::transform(value),
            T::Utf8ToUnicode => utf8_to_unicode::transform(value),
            T::None | T::Identity => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(name: &str, input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        Transformation::from_name(name).unwrap().apply(&mut v, &Context::default());
        v
    }

    #[test]
    fn names() {
        assert_eq!(Transformation::from_name("LowerCase"), Some(T::LowerCase));
        assert_eq!(Transformation::from_name("normalizePathWin"), Some(T::NormalisePathWin));
        assert_eq!(Transformation::from_name("cmdLine"), Some(T::CmdLine));
        assert_eq!(Transformation::from_name("trimLeftX"), None);
        assert_eq!(Transformation::from_name("transformation"), None);
        // Every transformation but Identity has a name, and names are unique.
        let mut seen = std::collections::HashSet::new();
        assert!(NAMES.iter().all(|(n, _)| seen.insert(*n) && *n == n.to_ascii_lowercase()));
    }

    #[test]
    fn names_by_prefix_in_cxx_order() {
        let kind = |n: &str| Transformation::from_name_prefix(n.as_bytes());
        assert_eq!(kind("base64DecodeExt"), T::Base64DecodeExt);
        assert_eq!(kind("base64Decode"), T::Base64Decode);
        assert_eq!(kind("trimLeft"), T::TrimLeft);
        assert_eq!(kind("trimX"), T::Trim);
        assert_eq!(kind("normalizePathWin"), T::NormalisePathWin);
        assert_eq!(kind("LOWERCASE"), T::Identity);
        assert_eq!(kind("nosuch"), T::Identity);
        assert_eq!(kind("none"), T::None);
    }

    #[test]
    fn simple_kinds() {
        assert_eq!(apply("length", b"abcd"), b"4");
        assert_eq!(apply("uppercase", b"aB1"), b"AB1");
        assert_eq!(apply("lowercase", b"ab1"), b"ab1");
        assert_eq!(apply("trimLeft", b" a "), b"a ");
        assert_eq!(apply("trimRight", b" a "), b" a");
        assert_eq!(apply("urlDecode", b"a%41+"), b"aA ");
        assert_eq!(chars::string_to_hex(&apply("md5", b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(chars::string_to_hex(&apply("sha1", b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(apply("none", b"x"), b"x");
        assert_eq!(apply("normalizePathWin", b"a\\b"), b"a/b");
        let mut v = b"x".to_vec();
        T::Identity.apply(&mut v, &Context::default());
        assert_eq!(v, b"x");
    }
}
