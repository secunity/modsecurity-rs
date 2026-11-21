//! The values of the setting directives (`SecRuleEngine On`,
//! `SecAuditLog /var/log/audit.log`, `SecMarker "END"`).
//!
//! The grammar gives a setting as its keyword and the rest of its line.
//! How that rest is read depends on the directive: each has one or more
//! forms, a [`Pattern`] (how the value is written) and the [`Part`] of
//! what the pattern matches that is the value. The longest match is read
//! (the first form among those of the same length). A caller that knows
//! the directives names the forms of each, and [`read`] or [`word`] gives
//! the value, a piece of the line, or says what is wrong with the text.

/// Whether `c` is the letter of an audit log part.
pub fn is_audit_part(c: u8) -> bool {
    b"ABCDEFGHJKIZ".contains(&c)
}

/// Whether `c` may appear in an unquoted path (`SecRuleScript`, and the
/// directives with a path value).
pub fn is_path(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"_/.*: \\()-".contains(&c)
}

/// A class of characters a value is made of.
#[derive(Debug, Clone, Copy)]
pub enum Class {
    /// A number: `[0-9]+`.
    Number,
    /// A path: the bytes [`is_path`] accepts.
    Path,
    /// Text up to a quote, `|` or line feed: `[^"|\n]+`.
    FreeTextNewLine,
    /// A word: `[^, \t"\n\r]+`.
    Word,
    /// Audit log part letters (`ABCDEFGHJKIZ`).
    AuditParts,
    /// Any byte but a quote. Between quotes ([`Pattern::SepQuoted`]) it is
    /// `([^"]|([^\\]\\"))+`: a quote after a backslash is part of the text.
    FreeText,
}

impl Class {
    fn contains(self, c: u8) -> bool {
        match self {
            Class::Number => c.is_ascii_digit(),
            Class::Path => is_path(c),
            Class::FreeTextNewLine => !matches!(c, b'"' | b'|' | b'\n'),
            Class::Word => !matches!(c, b',' | b' ' | b'\t' | b'"' | b'\n' | b'\r'),
            Class::AuditParts => is_audit_part(c),
            Class::FreeText => c != b'"',
        }
    }

    /// The length of the longest prefix of `s` made of this class.
    fn run(self, s: &[u8]) -> usize {
        s.iter().position(|&c| !self.contains(c)).unwrap_or(s.len())
    }
}

/// How the value of a directive is written after its keyword.
#[derive(Debug, Clone, Copy)]
pub enum Pattern {
    /// `[ \t]+CLASS`
    Sep(Class),
    /// `[ \t]+"CLASS"`
    SepQuoted(Class),
    /// `CLASS`, right after the keyword.
    Direct(Class),
    /// `[ \t]+[^"|\n]+[ ]+[0-9]+`: a file and a code page
    /// (`SecUnicodeMapFile`).
    UnicodeMap,
    /// `[ ][^ ]+[ ][^\n\r ]+`: a key and a URL (`SecRemoteRules`).
    Remote,
}

/// Which part of what a pattern matched is the value.
///
/// The value follows a separator, the first space or tab. What else
/// around it is part of the value depends on the directive: the C++
/// scanner cut each value out at a fixed place, and what that left (white
/// space, a closing quote) is part of the language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// What follows the first space or tab, as written: the white space
    /// after it, quotes, and the spaces at the end are part of the value
    /// (`SecAuditLog  /a.log` is ` /a.log`).
    Written,
    /// What follows the first space or tab, without the quotes around it
    /// as for [`Part::Bare`] (`SecMarker "END"`).
    Unquoted,
    /// What follows the white space, without the quotes around it
    /// (`Include`).
    AfterWhiteSpace,
    /// The value alone: what follows the first space or tab and the
    /// spaces after it, up to the spaces at the end, without the quotes
    /// around it (double quotes, then single quotes inside them). A tab
    /// after the spaces is part of the value, and so are its quotes then;
    /// a value of spaces only is one space.
    Bare,
    /// What follows the first space and the byte after it, as written: the
    /// text after the opening quote of a value that follows one space,
    /// with its closing quote (`strchr(text, ' ') + 2` in C++:
    /// `SecComponentSignature "a"` is `a"`).
    AfterQuote,
    /// [`Part::AfterQuote`] without the spaces and the quotes around it,
    /// as for [`Part::Bare`] (`SecWebAppId "my app"` is `my app"`, and
    /// `SecWebAppId  "my app"` is `my app`).
    BareAfterQuote,
}

impl Part {
    /// The value in `matched`, the text a pattern matched after the
    /// keyword.
    fn of(self, matched: &[u8]) -> &[u8] {
        let blank = |c: &u8| *c == b' ' || *c == b'\t';
        // The text `skip` bytes after the byte at `at` (nothing without
        // one).
        let after = |at: Option<usize>, skip: usize| match at {
            Some(p) => &matched[(p + skip).min(matched.len())..],
            None => &matched[matched.len()..],
        };
        let after_separator = || after(matched.iter().position(blank), 1);
        let after_quote = || after(matched.iter().position(|&c| c == b' '), 2);
        match self {
            Part::Written => after_separator(),
            Part::Unquoted => unquoted(after_separator()),
            Part::AfterWhiteSpace => unquoted(&matched[matched.iter().take_while(|c| blank(c)).count()..]),
            Part::Bare => bare(after_separator()),
            Part::AfterQuote => after_quote(),
            Part::BareAfterQuote => bare(after_quote()),
        }
    }
}

/// The value in `text`, the text after a separator: without the spaces
/// before it and at the end, and without its quotes. The spaces of a
/// value of spaces only are one space.
fn bare(text: &[u8]) -> &[u8] {
    let space = |c: &&u8| **c == b' ';
    let lead = text.iter().take_while(space).count().min(text.len().saturating_sub(1));
    let text = &text[lead..];
    let trail = text.iter().rev().take_while(space).count().min(text.len().saturating_sub(1));
    unquoted(&text[..text.len() - trail])
}

/// `text` without the double quotes around it, then without the single
/// quotes around what is inside them.
fn unquoted(text: &[u8]) -> &[u8] {
    fn inside(text: &[u8], quote: u8) -> &[u8] {
        match text {
            [open, inner @ .., close] if *open == quote && *close == quote => inner,
            _ => text,
        }
    }
    inside(inside(text, b'"'), b'\'')
}

/// A value read from the rest of a directive's line.
#[derive(Debug, PartialEq, Eq)]
pub struct Value<'a> {
    /// The value: the [`Part`] of the text the pattern matched.
    pub text: &'a [u8],
    /// Which of the forms matched.
    pub form: usize,
}

/// Why the rest of a line is not the value of its directive.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused<'a> {
    /// It is not a value the directive takes: the text, without the
    /// whitespace before it.
    NotAValue(&'a [u8]),
    /// There is something after the value other than whitespace and a
    /// comment: that text.
    Trailing(&'a [u8]),
}

/// Reads the value of a directive from the `rest` of its line, written in
/// one of `forms`.
pub fn read<'a>(rest: &'a [u8], forms: &[(Pattern, Part)]) -> Result<Value<'a>, Refused<'a>> {
    let Some((end, part, form)) = longest(rest, forms) else {
        return Err(Refused::NotAValue(rest.trim_ascii_start()));
    };
    if !ignorable(&rest[end..]) {
        return Err(Refused::Trailing(&rest[end..]));
    }
    Ok(Value { text: part.of(&rest[..end]), form })
}

/// Reads one of `words` (in any case) from the `rest` of a directive's
/// line, and gives it as it is written in `words`. Without `words`, the
/// directive takes no value, and the empty word is given.
pub fn word<'a>(rest: &'a [u8], words: &[&'static str]) -> Result<&'static str, Refused<'a>> {
    if words.is_empty() {
        return if ignorable(rest) { Ok("") } else { Err(Refused::Trailing(rest)) };
    }
    let r = rest.trim_ascii_start();
    let word_end = r.iter().position(|&c| matches!(c, b' ' | b'\t' | b'\r' | b'#')).unwrap_or(r.len());
    let word = String::from_utf8_lossy(&r[..word_end]);
    let separated = rest.first().is_some_and(|&c| c == b' ' || c == b'\t');
    match words.iter().find(|w| w.eq_ignore_ascii_case(&word)) {
        Some(w) if separated && ignorable(&r[word_end..]) => Ok(w),
        _ => Err(Refused::NotAValue(r)),
    }
}

/// The longest match of `forms` at the start of `rest` (the first form
/// among those of the same length): its length, the part of it that is
/// the value and which form it is.
fn longest(rest: &[u8], forms: &[(Pattern, Part)]) -> Option<(usize, Part, usize)> {
    let mut best: Option<(usize, Part, usize)> = None;
    for (i, &(p, e)) in forms.iter().enumerate() {
        if let Some(n) = match_pattern(rest, p)
            && best.is_none_or(|(b, _, _)| n > b)
        {
            best = Some((n, e, i));
        }
    }
    best
}

/// The length of the longest match of `p` at the start of `rest`.
fn match_pattern(rest: &[u8], p: Pattern) -> Option<usize> {
    let ws = rest.iter().take_while(|&&c| c == b' ' || c == b'\t').count();
    let mut best = None;
    match p {
        Pattern::Direct(class) => {
            let n = class.run(rest);
            return (n > 0).then_some(n);
        }
        Pattern::Sep(class) => {
            for k in 1..=ws {
                let n = class.run(&rest[k..]);
                if n > 0 {
                    best = best.max(Some(k + n));
                }
            }
        }
        Pattern::SepQuoted(class) => {
            for k in 1..=ws {
                if rest.get(k) != Some(&b'"') {
                    continue;
                }
                let content = &rest[k + 1..];
                if let Class::FreeText = class {
                    // `([^"]|([^\\]\\"))+` followed by `"`: the last quote
                    // that closes a valid text.
                    let mut valid = vec![false; content.len() + 1];
                    valid[0] = true;
                    for i in 1..=content.len() {
                        valid[i] = (valid[i - 1] && content[i - 1] != b'"')
                            || (i >= 3
                                && valid[i - 3]
                                && content[i - 3] != b'\\'
                                && content[i - 2] == b'\\'
                                && content[i - 1] == b'"');
                    }
                    for i in 1..content.len() {
                        if valid[i] && content[i] == b'"' {
                            best = best.max(Some(k + 1 + i + 1));
                        }
                    }
                } else {
                    let n = class.run(content);
                    if n > 0 && content.get(n) == Some(&b'"') {
                        best = best.max(Some(k + 1 + n + 1));
                    }
                }
            }
        }
        Pattern::UnicodeMap => {
            for k in 1..=ws {
                let s = &rest[k..];
                let l = Class::FreeTextNewLine.run(s);
                for e in (1..=l).rev() {
                    if !s[e - 1].is_ascii_digit() {
                        continue;
                    }
                    let digits_start = s[..e].iter().rposition(|c| !c.is_ascii_digit()).map_or(0, |i| i + 1);
                    if digits_start >= 2 && s[digits_start - 1] == b' ' {
                        best = best.max(Some(k + e));
                        break;
                    }
                }
            }
        }
        Pattern::Remote => {
            if rest.first() != Some(&b' ') {
                return None;
            }
            let key = rest[1..].iter().take_while(|&&c| c != b' ').count();
            if key == 0 || rest.get(1 + key) != Some(&b' ') {
                return None;
            }
            let url = rest[2 + key..].iter().take_while(|&&c| !matches!(c, b'\n' | b'\r' | b' ')).count();
            return (url > 0).then_some(2 + key + url);
        }
    }
    best
}

/// What may follow a directive on its line: spaces, carriage returns and a
/// comment.
fn ignorable(s: &[u8]) -> bool {
    let n = s.iter().take_while(|&&c| matches!(c, b' ' | b'\t' | b'\r')).count();
    n == s.len() || s[n] == b'#'
}

#[cfg(test)]
mod tests {
    use super::Class::*;
    use super::Part::*;
    use super::Pattern::*;
    use super::*;

    #[test]
    fn spaces_around_a_value() {
        for (text, bare_value) in [
            ("", ""),
            (" ", " "),
            ("   ", " "),
            ("a", "a"),
            (" a", "a"),
            ("a  ", "a"),
            ("  a b  ", "a b"),
            (" \ta ", "\ta"),
        ] {
            assert_eq!(bare(text.as_bytes()), bare_value.as_bytes(), "{text:?}");
        }
    }

    /// The value read from `rest` and the pattern it was written as.
    fn value<'a>(rest: &'a str, forms: &[(Pattern, Part)]) -> Result<(String, usize), Refused<'a>> {
        read(rest.as_bytes(), forms).map(|v| (String::from_utf8(v.text.to_vec()).unwrap(), v.form))
    }

    fn got(text: &str, pattern: usize) -> Result<(String, usize), Refused<'static>> {
        Ok((text.to_string(), pattern))
    }

    #[test]
    fn a_number() {
        let number = &[(Sep(Number), Written)];
        assert_eq!(value(" 12", number), got("12", 0));
        assert_eq!(value("\t12", number), got("12", 0));
        assert_eq!(value(" 12 # a comment", number), got("12", 0));
        assert_eq!(value(" 12 \r", number), got("12", 0));
        // Only the first space or tab is the separator: the others stay.
        assert_eq!(value("  12", number), got(" 12", 0));
        assert_eq!(value(" 12 x", number), Err(Refused::Trailing(b" x")));
        assert_eq!(value(" 12x", number), Err(Refused::Trailing(b"x")));
        assert_eq!(value("  x", number), Err(Refused::NotAValue(b"x")));
        assert_eq!(value("12", number), Err(Refused::NotAValue(b"12")));
        assert_eq!(value("", number), Err(Refused::NotAValue(b"")));
    }

    #[test]
    fn a_path_plain_or_quoted() {
        let path = &[(Sep(Path), Bare), (SepQuoted(Path), Bare)];
        assert_eq!(value(" /var/log/a.log", path), got("/var/log/a.log", 0));
        assert_eq!(value(" \"/var/log/a.log\"", path), got("/var/log/a.log", 1));
        // A path may have spaces: the ones around it are trimmed.
        assert_eq!(value("   /a b/c  ", path), got("/a b/c", 0));
        assert_eq!(value(" /a,b", path), Err(Refused::Trailing(b",b")));
        assert_eq!(value(" \"/a", path), Err(Refused::NotAValue(b"\"/a")));
        // As written: the spaces after the first stay.
        assert_eq!(value("  /a", &[(Sep(Path), Written)]), got(" /a", 0));
    }

    #[test]
    fn quoted_text() {
        // `strchr(text, ' ') + 2`: the value starts two bytes after the
        // first space, whatever is there, and keeps the closing quote.
        let text = &[(SepQuoted(FreeText), AfterQuote)];
        assert_eq!(value(" \"OWASP_CRS/4.0\"", text), got("OWASP_CRS/4.0\"", 0));
        assert_eq!(value("  \"a\"", text), got("\"a\"", 0));
        assert_eq!(value(" \"a b\"", text), got("a b\"", 0));
        // An escaped quote stays in the text; a plain one ends it.
        assert_eq!(value(" \"a\\\"b\"", text), got("a\\\"b\"", 0));
        assert_eq!(value(" \"a\" \"b\"", text), Err(Refused::Trailing(b" \"b\"")));
        assert_eq!(value(" a", text), Err(Refused::NotAValue(b"a")));
        assert_eq!(value(" \"a", text), Err(Refused::NotAValue(b"\"a")));
        // The bare value keeps the closing quote too: the opening one is
        // already gone (`SecWebAppId "my app"` is `my app"`).
        assert_eq!(value(" \"my app\"", &[(SepQuoted(FreeText), BareAfterQuote)]), got("my app\"", 0));
        assert_eq!(value("  \"my app\"", &[(SepQuoted(FreeText), BareAfterQuote)]), got("my app", 0));
    }

    #[test]
    fn the_longest_pattern_wins_and_the_first_breaks_ties() {
        // SecArgumentSeparator.
        let separator = &[(SepQuoted(Word), Bare), (Sep(Word), Bare), (Sep(FreeTextNewLine), Written)];
        assert_eq!(value(" \"&\"", separator), got("&", 0));
        assert_eq!(value(" &", separator), got("&", 1));
        assert_eq!(value(" & ;", separator), got("& ;", 2));
        // SecMarker.
        let marker = &[(SepQuoted(Word), Unquoted), (Sep(Word), Unquoted)];
        assert_eq!(value(" \"END\"", marker), got("END", 0));
        assert_eq!(value(" END", marker), got("END", 1));
        assert_eq!(value("  \"END\"", marker), got(" \"END\"", 0));
        // As written, a quoted word keeps its quotes.
        assert_eq!(value(" \"END\"", &[(SepQuoted(Word), Written)]), got("\"END\"", 0));
    }

    #[test]
    fn a_file_and_a_code_page() {
        let map = &[(UnicodeMap, Written)];
        assert_eq!(value(" unicode.mapping 20127", map), got("unicode.mapping 20127", 0));
        assert_eq!(value(" a file.map  20127", map), got("a file.map  20127", 0));
        assert_eq!(value(" unicode.mapping", map), Err(Refused::NotAValue(b"unicode.mapping")));
        assert_eq!(value(" unicode.mapping 20127x", map), Err(Refused::Trailing(b"x")));
    }

    #[test]
    fn a_key_and_a_url() {
        let remote = &[(Remote, Written)];
        assert_eq!(value(" key https://example.com/rules", remote), got("key https://example.com/rules", 0));
        assert_eq!(value(" key https://example.com/rules extra", remote), Err(Refused::Trailing(b" extra")));
        assert_eq!(value("  key url", remote), Err(Refused::NotAValue(b"key url")));
        assert_eq!(value(" key", remote), Err(Refused::NotAValue(b"key")));
    }

    #[test]
    fn text_right_after_the_keyword() {
        let direct = &[(Direct(FreeTextNewLine), Written)];
        assert_eq!(value(" 10", direct), got("10", 0));
        assert_eq!(value("x 10", direct), got("10", 0));
        assert_eq!(value("x", direct), got("", 0));
        assert_eq!(value("", direct), Err(Refused::NotAValue(b"")));
    }

    #[test]
    fn one_of_some_words() {
        let on_off = &["On", "Off"];
        assert_eq!(word(b" On", on_off), Ok("On"));
        assert_eq!(word(b"\t  oFF  # a comment", on_off), Ok("Off"));
        assert_eq!(word(b" On\r", on_off), Ok("On"));
        assert_eq!(word(b"On", on_off), Err(Refused::NotAValue(b"On")));
        assert_eq!(word(b" On x", on_off), Err(Refused::NotAValue(b"On x")));
        assert_eq!(word(b" Maybe", on_off), Err(Refused::NotAValue(b"Maybe")));
        assert_eq!(word(b"", on_off), Err(Refused::NotAValue(b"")));
        // A directive without a value.
        assert_eq!(word(b"", &[]), Ok(""));
        assert_eq!(word(b"  # a comment", &[]), Ok(""));
        assert_eq!(word(b" x", &[]), Err(Refused::Trailing(b" x")));
    }

    #[test]
    fn quotes_around_a_value() {
        for (text, bare_value) in [
            ("  \"a b\" ", "a b"),
            ("'a'", "a"),
            ("\"'a'\"", "a"),
            ("'\"a\"'", "\"a\""),
            ("\"\"", ""),
            ("\"", "\""),
            ("\"a", "\"a"),
            ("\t\"a\"", "\t\"a\""),
        ] {
            assert_eq!(bare(text.as_bytes()), bare_value.as_bytes(), "{text:?}");
        }
    }

    #[test]
    fn after_the_white_space() {
        let include = &[(Sep(Path), AfterWhiteSpace), (SepQuoted(Path), AfterWhiteSpace)];
        assert_eq!(value(" \t /a b ", include), got("/a b ", 0));
        assert_eq!(value("  \"/a b\"", include), got("/a b", 1));
    }
}
