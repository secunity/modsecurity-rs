//! The values directives get: what is left of the text after a directive's
//! keyword once the white space and the quotes around the value are taken
//! away, for the setting directives (read by `value::read`) and for the
//! directives with a grammar of their own (`SecRuleUpdate...`,
//! `SecRuleScript`).

use modsecurity_seclang::value::{self, Class, Extract, Pattern, Refused};
use modsecurity_seclang::{Directive, Source, parse_statement};

/// How the value of a setting is written, as the engine declares it for
/// its directives.
#[derive(Debug, Clone, Copy)]
enum Form {
    /// A path, plain or quoted (`SecUploadDir`, `SecAuditLogStorageDir`).
    Path,
    /// `SecAuditLog`, `SecDebugLog`: a plain path as written, a quoted one
    /// without its quotes.
    LogPath,
    /// A number (`SecRequestBodyLimit`).
    Number,
    /// Text up to the end of the line, as written (`SecHttpBlKey`).
    Text,
    /// Text up to the end of the line, plain or quoted
    /// (`SecRuleRemoveByTag`).
    CleanText,
    /// `SecRuleRemoveById`.
    IdList,
    /// `SecMarker`.
    Marker,
    /// `Include`.
    Include,
    /// `SecComponentSignature`.
    QuotedText,
    /// `SecWebAppId`.
    WebAppId,
}

/// The value of a setting written as `form` in `rest` (what follows the
/// keyword), or why it is refused.
fn setting(form: Form, rest: &str) -> Result<String, String> {
    use Class::*;
    use Extract::*;
    use Pattern::*;
    let patterns: &[(Pattern, Extract)] = match form {
        Form::Path => &[(Sep(Path), SanFindSep), (SepQuoted(Path), SanFindSep)],
        Form::LogPath => &[(Sep(Path), FindSep), (SepQuoted(Path), SanFindSep)],
        Form::Number => &[(Sep(Number), FindSep)],
        Form::Text => &[(Sep(FreeTextNewLine), FindSep)],
        Form::CleanText => &[(Sep(FreeTextNewLine), SanFindSep), (SepQuoted(FreeTextNewLine), SanFindSep)],
        Form::IdList => &[(Sep(FreeTextNewLine), SanFindSep)],
        Form::Marker => &[(SepQuoted(Word), FindSep), (Sep(Word), FindSep)],
        Form::Include => &[(Sep(Path), FindSep), (SepQuoted(Path), FindSep)],
        Form::QuotedText => &[(SepQuoted(FreeText), Strchr2)],
        Form::WebAppId => &[(SepQuoted(FreeText), SanStrchr2), (Sep(FreeTextNewLine), SanFindSep)],
    };
    match value::read("SecDirective", rest.as_bytes(), patterns) {
        Ok(v) => {
            let text = String::from_utf8(v.bytes).unwrap();
            Ok(match form {
                Form::Marker => value::remove_brackets_if_needed(text),
                Form::Include => {
                    let token = std::str::from_utf8(v.token).unwrap();
                    let t = token.trim_start_matches([' ', '\t']);
                    if t.starts_with('"') { t[1..t.len() - 1].to_string() } else { t.to_string() }
                }
                _ => text,
            })
        }
        Err(Refused::NotAValue(t)) => Err(format!("not a value: {}", String::from_utf8_lossy(t))),
        Err(Refused::Trailing(t)) => Err(format!("trailing: {}", String::from_utf8_lossy(t))),
    }
}

/// The selector of a `SecRuleUpdateTargetBy...` or the id of a
/// `SecRuleUpdateActionById`, or the path of a `SecRuleScript`, in `line`.
fn directive_value(line: &str) -> String {
    let source = Source::new(line.as_bytes());
    let (statement, _) = parse_statement(source.text(), 0).unwrap();
    let v = match statement.unwrap().directive {
        Directive::UpdateTarget { selector, .. } => selector,
        Directive::UpdateAction { id, .. } => id,
        // The engine takes an unquoted path as written (and refuses it
        // unless it is made of the characters of a path).
        Directive::Script { path, .. } if !path.quoted => return path.text.to_string(),
        Directive::Script { path, .. } => return value::sanitize(format!("\"{}\"", path.text)),
        d => panic!("not a directive with a value: {d:?}"),
    };
    let text = if v.quoted { format!("{}\"{}\"", v.lead, v.text) } else { format!("{}{}", v.lead, v.text) };
    value::sanitize(text)
}

fn ok(s: &str) -> Result<String, String> {
    Ok(s.to_string())
}

#[test]
fn white_space_around_a_value() {
    for (rest, value) in [
        (" /a", "/a"),
        ("  /a", "/a"),
        ("\t/a", "/a"),
        ("\t\t/a", "\t/a"),
        (" /a  ", "/a"),
        (" /a \r", "/a"),
        ("   /a b  ", "/a b"),
        (" /a b # c", "/a b"),
        // After the first space or tab, only spaces are white space before
        // the value: a tab after them is part of it.
        (" \t/a", "\t/a"),
        ("  \t /a", "\t /a"),
    ] {
        assert_eq!(setting(Form::Path, rest), ok(value), "{rest:?}");
    }
    for (rest, value) in
        [(" 'a b'", "a b"), (" a b  ", "a b"), ("\ta\tb\t", "a\tb\t"), (" ' a ' ", " a "), (" a \r", "a \r")]
    {
        assert_eq!(setting(Form::CleanText, rest), ok(value), "{rest:?}");
    }
}

#[test]
fn values_as_written() {
    // Only the first space or tab separates the value: the white space
    // after it is part of the value, and so are its quotes and the spaces
    // at its end.
    assert_eq!(setting(Form::Number, " 12"), ok("12"));
    assert_eq!(setting(Form::Number, "\t12"), ok("12"));
    assert_eq!(setting(Form::Number, "  12"), ok(" 12"));
    assert_eq!(setting(Form::Number, " \t12 "), ok("\t12"));
    assert_eq!(setting(Form::LogPath, " /a.log"), ok("/a.log"));
    assert_eq!(setting(Form::LogPath, "  /a.log "), ok(" /a.log "));
    assert_eq!(setting(Form::Text, " 'a b' "), ok("'a b' "));
    assert_eq!(setting(Form::Text, "\t a\tb"), ok(" a\tb"));
    assert_eq!(setting(Form::Text, " a # c"), ok("a # c"));
}

#[test]
fn quoted_values() {
    for (form, rest, value) in [
        (Form::Path, " \"/a b\"", "/a b"),
        (Form::Path, "  \"/a b\" ", "/a b"),
        (Form::Path, "\t\"/a\"", "/a"),
        // A tab before the quote: the quotes are part of the value.
        (Form::Path, " \t\"/a\"", "\t\"/a\""),
        (Form::LogPath, " \"/a b\"", "/a b"),
        // The spaces inside the quotes are part of the value.
        (Form::CleanText, " \" a b \"", " a b "),
        (Form::CleanText, " \"'a'\"", "a"),
        (Form::CleanText, " \"' a '\"", " a "),
        (Form::CleanText, " \"'\"", "'"),
    ] {
        assert_eq!(setting(form, rest), ok(value), "{form:?} {rest:?}");
    }
    assert_eq!(setting(Form::Path, " \"/a"), Err("not a value: \"/a".to_string()));
    assert_eq!(setting(Form::CleanText, " \"a\" b"), Err("trailing:  b".to_string()));
    assert_eq!(setting(Form::CleanText, " \"\""), Err("not a value: \"\"".to_string()));
}

#[test]
fn values_of_white_space_only() {
    // What is left of a value of spaces is one space.
    assert_eq!(setting(Form::Path, "  "), ok(" "));
    assert_eq!(setting(Form::Path, "    "), ok(" "));
    assert_eq!(setting(Form::CleanText, "\t  "), ok(" "));
    assert_eq!(setting(Form::CleanText, " \t"), ok("\t"));
    assert_eq!(setting(Form::IdList, "   "), ok(" "));
    assert_eq!(setting(Form::Text, "   "), ok("  "));
    assert_eq!(setting(Form::Path, " "), Err("not a value: ".to_string()));
    assert_eq!(setting(Form::Path, ""), Err("not a value: ".to_string()));
}

#[test]
fn markers() {
    for (rest, marker) in [
        (" END", "END"),
        ("\tEND", "END"),
        (" \"END\"", "END"),
        (" 'END'", "END"),
        (" \"'END'\"", "END"),
        (" \"END\"  # comment", "END"),
        (" 'END", "'END"),
        (" '", "'"),
        (" ''", ""),
        // Only the first space or tab separates the marker.
        ("  END", " END"),
        ("  \"END\"", " \"END\""),
        (" \t'END'", "\t'END'"),
    ] {
        assert_eq!(setting(Form::Marker, rest), ok(marker), "{rest:?}");
    }
    assert_eq!(setting(Form::Marker, " END x"), Err("trailing:  x".to_string()));
    assert_eq!(setting(Form::Marker, " \"END"), Err("not a value: \"END".to_string()));
}

#[test]
fn included_files() {
    for (rest, file) in [
        (" /a.conf", "/a.conf"),
        ("  /a.conf", "/a.conf"),
        (" \t /a.conf", "/a.conf"),
        (" \"/a b.conf\"", "/a b.conf"),
        ("\t\"/a.conf\"  # comment", "/a.conf"),
        // The spaces at the end of a plain path are part of it.
        (" /a.conf  ", "/a.conf  "),
        (" /a b.conf", "/a b.conf"),
    ] {
        assert_eq!(setting(Form::Include, rest), ok(file), "{rest:?}");
    }
}

#[test]
fn id_lists() {
    for (rest, list) in [
        (" 1 2  3-5", "1 2  3-5"),
        ("  1 2  3-5  ", "1 2  3-5"),
        (" '1 2  3-5'", "1 2  3-5"),
        (" '1' '2'", "1' '2"),
        (" 1\t2", "1\t2"),
    ] {
        assert_eq!(setting(Form::IdList, rest), ok(list), "{rest:?}");
    }
    // A double quote ends the text: a quoted list is not a value.
    assert_eq!(setting(Form::IdList, " \"1 2  3-5\""), Err("not a value: \"1 2  3-5\"".to_string()));
    assert_eq!(setting(Form::IdList, " 1 \"2\""), Err("trailing: \"2\"".to_string()));
}

#[test]
fn text_after_the_opening_quote() {
    // The value starts two bytes after the first space and keeps the
    // closing quote, as C++ reads it (`strchr(text, ' ') + 2`).
    for (rest, value) in [
        (" \"OWASP_CRS/4.0\"", "OWASP_CRS/4.0\""),
        (" \"a b\"", "a b\""),
        ("  \"a\"", "\"a\""),
        (" \"a\\\"b\"", "a\\\"b\""),
        ("\t\"a\"", ""),
        ("\t\"a b\"", "\""),
        ("\t\"a bc\"", "c\""),
    ] {
        assert_eq!(setting(Form::QuotedText, rest), ok(value), "{rest:?}");
    }
    for (rest, value) in [
        (" \"my app\"", "my app\""),
        (" \" my app\"", "my app\""),
        ("  \"my app\"", "my app"),
        ("  \"'my app'\"", "my app"),
        ("   \" my app \"", " my app "),
        (" my app ", "my app"),
        (" 'my app'", "my app"),
        ("\t\"a \\\"b\"", "b"),
    ] {
        assert_eq!(setting(Form::WebAppId, rest), ok(value), "{rest:?}");
    }
}

#[test]
fn update_selectors() {
    for (line, value) in [
        ("SecRuleUpdateTargetById 1 ARGS", "1"),
        ("SecRuleUpdateTargetById  1 ARGS", "1"),
        ("SecRuleUpdateTargetById\t1 ARGS", "1"),
        ("SecRuleUpdateTargetById \t 1 ARGS", "\t 1"),
        ("SecRuleUpdateTargetById \"1\" ARGS", "1"),
        ("SecRuleUpdateTargetById  \"1\"\tARGS", "1"),
        ("SecRuleUpdateTargetById '1' ARGS", "1"),
        ("SecRuleUpdateTargetById \"'1'\" ARGS", "1"),
        ("SecRuleUpdateTargetById \"1-5\" ARGS", "1-5"),
        ("SecRuleUpdateTargetByTag \"a b\" ARGS", "a b"),
        ("SecRuleUpdateTargetByTag \" a b \" ARGS", " a b "),
        ("SecRuleUpdateTargetByTag \"' a '\" ARGS", " a "),
        ("SecRuleUpdateTargetByTag 'a'b' ARGS", "a'b"),
        ("SecRuleUpdateTargetByTag 'a ARGS", "'a"),
        ("SecRuleUpdateTargetByTag ' ARGS", "'"),
        ("SecRuleUpdateTargetByTag '' ARGS", ""),
        ("SecRuleUpdateTargetByTag \"\" ARGS", ""),
        ("SecRuleUpdateTargetByTag \"'\" ARGS", "'"),
        ("SecRuleUpdateTargetByTag \"''\" ARGS", ""),
        // A tab after the spaces is part of the value, quotes included.
        ("SecRuleUpdateTargetByMsg  \t\"a b\" ARGS", "\t\"a b\""),
        ("SecRuleUpdateTargetByMsg \t'a' ARGS", "\t'a'"),
        ("SecRuleUpdateTargetByMsg\t\t'a' ARGS", "\t'a'"),
        ("SecRuleUpdateActionById 1 \"pass\"", "1"),
        ("SecRuleUpdateActionById   \"1\" \"pass\"", "1"),
        ("SecRuleUpdateActionById '1' pass", "1"),
        ("SecRuleUpdateActionById\t \t1 pass", "\t1"),
    ] {
        assert_eq!(directive_value(line), value, "{line:?}");
    }
}

#[test]
fn script_paths() {
    for (line, path) in [
        ("SecRuleScript a.lua \"id:1\"", "a.lua"),
        ("SecRuleScript  a.lua \"id:1\"", "a.lua"),
        ("SecRuleScript \"a.lua\" \"id:1\"", "a.lua"),
        ("SecRuleScript \" a b.lua \" \"id:1\"", " a b.lua "),
        ("SecRuleScript \"'a.lua'\" \"id:1\"", "a.lua"),
        ("SecRuleScript \"''\" \"id:1\"", ""),
        ("SecRuleScript \"'\" \"id:1\"", "'"),
        ("SecRuleScript \"'a\" \"id:1\"", "'a"),
        // An unquoted path is as written (and refused: a path has no
        // quotes).
        ("SecRuleScript 'a.lua' \"id:1\"", "'a.lua'"),
    ] {
        assert_eq!(directive_value(line), path, "{line:?}");
    }
}
