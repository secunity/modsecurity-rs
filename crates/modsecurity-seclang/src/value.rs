//! The values of the setting directives (`SecRuleEngine On`,
//! `SecAuditLog /var/log/audit.log`, `SecMarker "END"`).
//!
//! The grammar gives a setting as its keyword and the rest of its line.
//! How that rest is read depends on the directive: each has one or more
//! forms, a [`Pattern`] (how the value is written, which says where the
//! value is in it) and the [`Quotes`] around the value that are not part
//! of it. The longest match is read
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
///
/// The white space before a value separates it from the keyword, and the
/// white space after it is not part of it either.
#[derive(Debug, Clone, Copy)]
pub enum Pattern {
    /// `[ \t]+CLASS`
    Sep(Class),
    /// `[ \t]+"CLASS"`: the value is between the quotes.
    SepQuoted(Class),
    /// `CLASS`, right after the keyword.
    Direct(Class),
    /// `[ \t]+[^"|\n]+[ ]+[0-9]+`: a file and a code page
    /// (`SecUnicodeMapFile`).
    UnicodeMap,
    /// `[ ][^ ]+[ ][^\n\r ]+`: a key and a URL (`SecRemoteRules`).
    Remote,
}

/// Which quotes around a value are not part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quotes {
    /// Double quotes ([`Pattern::SepQuoted`]): `'a b'` is `'a b'`.
    Double,
    /// Double quotes, and single quotes around the value or just inside
    /// its double quotes: `'a b'` and `"'a b'"` are `a b`.
    DoubleAndSingle,
}

/// A value read from the rest of a directive's line.
#[derive(Debug, PartialEq, Eq)]
pub struct Value<'a> {
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
pub fn read<'a>(rest: &'a [u8], forms: &[(Pattern, Quotes)]) -> Result<Value<'a>, Refused<'a>> {
    let Some((m, quotes, form)) = longest(rest, forms) else {
        return Err(Refused::NotAValue(rest.trim_ascii_start()));
    };
    if !ignorable(&rest[m.end..]) {
        return Err(Refused::Trailing(&rest[m.end..]));
    }
    let text = &rest[m.value];
    let text = match (quotes, text) {
        (Quotes::DoubleAndSingle, [b'\'', inner @ .., b'\'']) => inner,
        _ => text,
    };
    Ok(Value { text, form })
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

/// What a pattern matched: up to where, and where the value is in it.
#[derive(Debug, Clone)]
struct Match {
    end: usize,
    value: std::ops::Range<usize>,
}

/// The longest match of `forms` at the start of `rest` (the first form
/// among those of the same length), its quotes and which form it is.
fn longest(rest: &[u8], forms: &[(Pattern, Quotes)]) -> Option<(Match, Quotes, usize)> {
    let mut best: Option<(Match, Quotes, usize)> = None;
    for (i, &(p, q)) in forms.iter().enumerate() {
        if let Some(m) = match_pattern(rest, p)
            && best.as_ref().is_none_or(|(b, _, _)| m.end > b.end)
        {
            best = Some((m, q, i));
        }
    }
    best
}

fn is_blank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

/// The length of `text` without the white space at its end.
fn without_blanks_at_end(text: &[u8]) -> usize {
    text.len() - text.iter().rev().take_while(|&&c| is_blank(c)).count()
}

/// The match of `p` at the start of `rest`.
fn match_pattern(rest: &[u8], p: Pattern) -> Option<Match> {
    let ws = rest.iter().take_while(|&&c| is_blank(c)).count();
    let after = &rest[ws..];
    match p {
        Pattern::Direct(class) => {
            let n = class.run(rest);
            let value_end = without_blanks_at_end(&rest[..n]);
            (n > 0).then_some(Match { end: n, value: ws.min(value_end)..value_end })
        }
        Pattern::Sep(class) => {
            let n = without_blanks_at_end(&after[..class.run(after)]);
            (ws > 0 && n > 0).then_some(Match { end: ws + n, value: ws..ws + n })
        }
        Pattern::SepQuoted(class) => {
            if ws == 0 || after.first() != Some(&b'"') {
                return None;
            }
            let content = &after[1..];
            let n = if let Class::FreeText = class {
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
                (1..content.len()).rev().find(|&i| valid[i] && content[i] == b'"')?
            } else {
                let n = class.run(content);
                (n > 0 && content.get(n) == Some(&b'"')).then_some(n)?
            };
            Some(Match { end: ws + 1 + n + 1, value: ws + 1..ws + 1 + n })
        }
        Pattern::UnicodeMap => {
            if ws == 0 {
                return None;
            }
            let l = Class::FreeTextNewLine.run(after);
            (1..=l).rev().find_map(|e| {
                if !after[e - 1].is_ascii_digit() {
                    return None;
                }
                let digits_start = after[..e].iter().rposition(|c| !c.is_ascii_digit()).map_or(0, |i| i + 1);
                (digits_start >= 2 && after[digits_start - 1] == b' ')
                    .then_some(Match { end: ws + e, value: ws..ws + e })
            })
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
            let end = 2 + key + url;
            (url > 0).then_some(Match { end, value: 1..end })
        }
    }
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
    use super::Pattern::*;
    use super::Quotes::*;
    use super::*;

    /// The value read from `rest` and the form it was written in.
    fn value<'a>(rest: &'a str, forms: &[(Pattern, Quotes)]) -> Result<(String, usize), Refused<'a>> {
        read(rest.as_bytes(), forms).map(|v| (String::from_utf8(v.text.to_vec()).unwrap(), v.form))
    }

    fn got(text: &str, form: usize) -> Result<(String, usize), Refused<'static>> {
        Ok((text.to_string(), form))
    }

    #[test]
    fn a_number() {
        let number = &[(Sep(Number), Double)];
        assert_eq!(value(" 12", number), got("12", 0));
        assert_eq!(value("\t12", number), got("12", 0));
        assert_eq!(value(" \t 12", number), got("12", 0));
        assert_eq!(value(" 12 # a comment", number), got("12", 0));
        assert_eq!(value(" 12 \r", number), got("12", 0));
        assert_eq!(value(" 12 x", number), Err(Refused::Trailing(b" x")));
        assert_eq!(value(" 12x", number), Err(Refused::Trailing(b"x")));
        assert_eq!(value("  x", number), Err(Refused::NotAValue(b"x")));
        assert_eq!(value("12", number), Err(Refused::NotAValue(b"12")));
        assert_eq!(value("", number), Err(Refused::NotAValue(b"")));
    }

    #[test]
    fn a_path_plain_or_quoted() {
        let path = &[(Sep(Path), DoubleAndSingle), (SepQuoted(Path), DoubleAndSingle)];
        assert_eq!(value(" /var/log/a.log", path), got("/var/log/a.log", 0));
        assert_eq!(value(" \"/var/log/a.log\"", path), got("/var/log/a.log", 1));
        // A path may have spaces; the white space around it is not part of
        // it.
        assert_eq!(value(" \t /a b/c  ", path), got("/a b/c", 0));
        assert_eq!(value("\t\"/a b \" ", path), got("/a b ", 1));
        assert_eq!(value(" /a,b", path), Err(Refused::Trailing(b",b")));
        assert_eq!(value(" \"/a", path), Err(Refused::NotAValue(b"\"/a")));
        // White space only is not a value.
        assert_eq!(value("   ", path), Err(Refused::NotAValue(b"")));
    }

    #[test]
    fn quoted_text() {
        // The value is between the quotes.
        let text = &[(SepQuoted(FreeText), DoubleAndSingle)];
        assert_eq!(value(" \"OWASP_CRS/4.0\"", text), got("OWASP_CRS/4.0", 0));
        assert_eq!(value(" \" a b \"", text), got(" a b ", 0));
        // An escaped quote stays in the text; a plain one ends it.
        assert_eq!(value(" \"a\\\"b\"", text), got("a\\\"b", 0));
        assert_eq!(value(" \"a\" \"b\"", text), Err(Refused::Trailing(b" \"b\"")));
        assert_eq!(value(" a", text), Err(Refused::NotAValue(b"a")));
        // A quote that is not closed is not a value.
        assert_eq!(value(" \"a", text), Err(Refused::NotAValue(b"\"a")));
    }

    #[test]
    fn single_quotes() {
        let text = &[(Sep(FreeTextNewLine), DoubleAndSingle), (SepQuoted(FreeTextNewLine), DoubleAndSingle)];
        assert_eq!(value(" 'a b' ", text), got("a b", 0));
        assert_eq!(value(" \"'a b'\"", text), got("a b", 1));
        assert_eq!(value(" \"' a '\"", text), got(" a ", 1));
        assert_eq!(value(" 'a", text), got("'a", 0));
        assert_eq!(value(" '", text), got("'", 0));
        assert_eq!(value(" ''", text), got("", 0));
        // Single quotes are part of a value whose form says so.
        assert_eq!(value(" 'a b' ", &[(Sep(FreeTextNewLine), Double)]), got("'a b'", 0));
    }

    #[test]
    fn the_longest_pattern_wins_and_the_first_breaks_ties() {
        // SecArgumentSeparator.
        let separator =
            &[(SepQuoted(Word), DoubleAndSingle), (Sep(Word), DoubleAndSingle), (Sep(FreeTextNewLine), Double)];
        assert_eq!(value(" \"&\"", separator), got("&", 0));
        assert_eq!(value(" &", separator), got("&", 1));
        // White space after the value does not make a form longer.
        assert_eq!(value(" &  ", separator), got("&", 1));
        assert_eq!(value(" & ;", separator), got("& ;", 2));
    }

    #[test]
    fn a_file_and_a_code_page() {
        let map = &[(UnicodeMap, Double)];
        assert_eq!(value(" unicode.mapping 20127", map), got("unicode.mapping 20127", 0));
        assert_eq!(value("  a file.map  20127 ", map), got("a file.map  20127", 0));
        assert_eq!(value(" unicode.mapping", map), Err(Refused::NotAValue(b"unicode.mapping")));
        assert_eq!(value(" unicode.mapping 20127x", map), Err(Refused::Trailing(b"x")));
    }

    #[test]
    fn a_key_and_a_url() {
        let remote = &[(Remote, Double)];
        assert_eq!(value(" key https://example.com/rules", remote), got("key https://example.com/rules", 0));
        assert_eq!(value(" key https://example.com/rules extra", remote), Err(Refused::Trailing(b" extra")));
        assert_eq!(value("  key url", remote), Err(Refused::NotAValue(b"key url")));
        assert_eq!(value(" key", remote), Err(Refused::NotAValue(b"key")));
    }

    #[test]
    fn text_right_after_the_keyword() {
        let direct = &[(Direct(FreeTextNewLine), Double)];
        assert_eq!(value(" 10 ", direct), got("10", 0));
        assert_eq!(value("x 10", direct), got("x 10", 0));
        assert_eq!(value("  ", direct), got("", 0));
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
}
