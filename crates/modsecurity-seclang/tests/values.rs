//! The values directives get: what is left of the text after a directive's
//! keyword once the white space and the quotes around the value are taken
//! away, for the setting directives (read by `value::read`) and for the
//! directives with a grammar of their own (`SecRuleUpdate...`,
//! `SecRuleScript`).

use modsecurity_seclang::value::{self, Class, Pattern, Quotes, Refused};
use modsecurity_seclang::{Directive, Source, parse_statement};

/// How the value of a setting is written, as the engine declares it for
/// its directives.
#[derive(Debug, Clone, Copy)]
enum Form {
    /// A path, plain or quoted (`SecUploadDir`, `SecAuditLogStorageDir`).
    Path,
    /// `SecAuditLog`, `SecDebugLog`.
    LogPath,
    /// A number (`SecRequestBodyLimit`).
    Number,
    /// Text up to the end of the line, single quotes included
    /// (`SecHttpBlKey`).
    Text,
    /// Text up to the end of the line, plain or quoted, in double or
    /// single quotes (`SecRuleRemoveByTag`).
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
    use Pattern::*;
    use Quotes::*;
    let forms: &[(Pattern, Quotes)] = match form {
        Form::Path | Form::LogPath | Form::Include => &[(Sep(Path), Double), (SepQuoted(Path), Double)],
        Form::Number => &[(Sep(Number), Double)],
        Form::Text => &[(Sep(FreeTextNewLine), Double)],
        Form::CleanText => &[(Sep(FreeTextNewLine), DoubleAndSingle), (SepQuoted(FreeTextNewLine), DoubleAndSingle)],
        Form::IdList => &[(Sep(FreeTextNewLine), DoubleAndSingle)],
        Form::Marker => &[(SepQuoted(Word), DoubleAndSingle), (Sep(Word), DoubleAndSingle)],
        Form::QuotedText => &[(SepQuoted(FreeText), DoubleAndSingle)],
        Form::WebAppId => &[(SepQuoted(FreeText), DoubleAndSingle), (Sep(FreeTextNewLine), DoubleAndSingle)],
    };
    match value::read(rest.as_bytes(), forms) {
        Ok(v) => Ok(String::from_utf8(v.text.to_vec()).unwrap()),
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
        Directive::Script { path, .. } => path,
        d => panic!("not a directive with a value: {d:?}"),
    };
    v.text.to_string()
}

fn ok(s: &str) -> Result<String, String> {
    Ok(s.to_string())
}

#[test]
fn white_space_around_a_value() {
    // The white space before a value separates it from the keyword, and
    // the white space after it is not part of it either.
    for (rest, value) in [
        (" /a", "/a"),
        ("  /a", "/a"),
        ("\t/a", "/a"),
        ("\t\t/a", "/a"),
        (" \t/a", "/a"),
        ("  \t /a", "/a"),
        (" /a  ", "/a"),
        (" /a \t", "/a"),
        (" /a \r", "/a"),
        ("   /a b  ", "/a b"),
        (" /a b # c", "/a b"),
    ] {
        assert_eq!(setting(Form::Path, rest), ok(value), "{rest:?}");
        assert_eq!(setting(Form::LogPath, rest), ok(value), "{rest:?}");
    }
    for (rest, value) in [
        (" 'a b'", "a b"),
        (" a b  ", "a b"),
        ("\ta\tb\t", "a\tb"),
        (" \t a ", "a"),
        (" ' a ' ", " a "),
        (" \t'a'", "a"),
    ] {
        assert_eq!(setting(Form::CleanText, rest), ok(value), "{rest:?}");
    }
    for (rest, value) in [(" 12", "12"), ("\t12", "12"), ("  12", "12"), (" \t12 ", "12")] {
        assert_eq!(setting(Form::Number, rest), ok(value), "{rest:?}");
    }
    for (rest, value) in [(" 'a b' ", "'a b'"), ("\t a\tb", "a\tb")] {
        assert_eq!(setting(Form::Text, rest), ok(value), "{rest:?}");
    }
}

#[test]
fn trailing_comments() {
    // A `#` after a free text value is part of it (the configuration has
    // comment lines, not comments at the end of a line); after a value
    // that cannot have one, it starts a comment.
    assert_eq!(setting(Form::Text, " a # c"), ok("a # c"));
    assert_eq!(setting(Form::CleanText, " a # c"), ok("a # c"));
    assert_eq!(setting(Form::IdList, " 1 2 # c"), ok("1 2 # c"));
    assert_eq!(setting(Form::Number, " 12 # c"), ok("12"));
    assert_eq!(setting(Form::Path, " /a # c"), ok("/a"));
    assert_eq!(setting(Form::Marker, " END # c"), ok("END"));
    assert_eq!(setting(Form::CleanText, " \"a\" # c"), ok("a"));
}

#[test]
fn quoted_values() {
    for (form, rest, value) in [
        (Form::Path, " \"/a b\"", "/a b"),
        (Form::Path, "  \"/a b\" ", "/a b"),
        (Form::Path, "\t\"/a\"", "/a"),
        (Form::Path, " \t\"/a\"", "/a"),
        (Form::LogPath, " \"/a b\"", "/a b"),
        // The white space inside the quotes is part of the value.
        (Form::Path, " \" /a b \"", " /a b "),
        (Form::CleanText, " \"\ta\tb\t\"", "\ta\tb\t"),
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
    // White space only is no value.
    for form in [Form::Path, Form::CleanText, Form::IdList, Form::Text, Form::Number, Form::Marker] {
        for rest in ["", " ", "  ", " \t ", "\t"] {
            assert_eq!(setting(form, rest), Err("not a value: ".to_string()), "{form:?} {rest:?}");
        }
    }
}

#[test]
fn markers() {
    for (rest, marker) in [
        (" END", "END"),
        ("\tEND", "END"),
        ("  END", "END"),
        (" \t'END' ", "END"),
        (" \"END\"", "END"),
        ("  \"END\"", "END"),
        (" 'END'", "END"),
        (" \"'END'\"", "END"),
        (" \"END\"  # comment", "END"),
        (" 'END", "'END"),
        (" '", "'"),
        (" ''", ""),
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
        (" /a.conf  ", "/a.conf"),
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
        (" \t1 2\t", "1 2"),
        (" '1 2  3-5'", "1 2  3-5"),
        (" '1' '2'", "1' '2"),
        (" 1\t2", "1\t2"),
    ] {
        assert_eq!(setting(Form::IdList, rest), ok(list), "{rest:?}");
    }
    // A double quote ends the text: a quoted list is not a value.
    assert_eq!(setting(Form::IdList, " \"1 2  3-5\""), Err("not a value: \"1 2  3-5\"".to_string()));
    assert_eq!(setting(Form::IdList, " 1 \"2\""), Err("trailing:  \"2\"".to_string()));
}

#[test]
fn quoted_text() {
    // The value is between the quotes, both of them.
    for (rest, value) in [
        (" \"OWASP_CRS/4.0\"", "OWASP_CRS/4.0"),
        (" \"a b\"", "a b"),
        (" \" a b \"", " a b "),
        (" \"a\\\"b\"", "a\\\"b"),
        ("\t\"a b\"", "a b"),
    ] {
        assert_eq!(setting(Form::QuotedText, rest), ok(value), "{rest:?}");
    }
    for (rest, value) in [
        (" \"my app\"", "my app"),
        (" \" my app\"", " my app"),
        (" \"'my app'\"", "my app"),
        (" my app ", "my app"),
        (" 'my app'", "my app"),
        ("\t\"a \\\"b\"", "a \\\"b"),
    ] {
        assert_eq!(setting(Form::WebAppId, rest), ok(value), "{rest:?}");
    }
    // A quote that is not closed is not a value.
    assert_eq!(setting(Form::QuotedText, " \"abc"), Err("not a value: \"abc".to_string()));
    assert_eq!(setting(Form::WebAppId, " \"abc"), Err("not a value: \"abc".to_string()));
    assert_eq!(setting(Form::WebAppId, " abc\""), Err("trailing: \"".to_string()));
}

#[test]
fn update_selectors() {
    for (line, value) in [
        ("SecRuleUpdateTargetById 1 ARGS", "1"),
        ("SecRuleUpdateTargetById  1 ARGS", "1"),
        ("SecRuleUpdateTargetById\t1 ARGS", "1"),
        ("SecRuleUpdateTargetById \t 1 ARGS", "1"),
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
        ("SecRuleUpdateTargetByMsg  \t\"a b\" ARGS", "a b"),
        ("SecRuleUpdateTargetByMsg \t'a' ARGS", "a"),
        ("SecRuleUpdateTargetByMsg\t\t'a' ARGS", "a"),
        ("SecRuleUpdateActionById 1 \"pass\"", "1"),
        ("SecRuleUpdateActionById   \"1\" \"pass\"", "1"),
        ("SecRuleUpdateActionById '1' pass", "1"),
        ("SecRuleUpdateActionById\t \t1 pass", "1"),
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
