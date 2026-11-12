//! JSON support replacing the yajl library used by the C++ code.
//!
//! * [`JsonGen`] mirrors `yajl_gen` with the options used by ModSecurity
//!   (compact output, no UTF-8 validation, `/` not escaped), producing byte
//!   strings.
//! * [`parse`] mirrors `yajl_parse` + `yajl_complete_parse` with the default
//!   options (UTF-8 validated strings, no comments, no trailing garbage, no
//!   partial values), driving a [`JsonHandler`] like yajl's callbacks.
//!   Errors are reported with yajl's non-verbose wording, e.g.
//!   `"parse error: premature EOF\n"`.
//! * [`JsonValue`] / [`parse_tree`] mirror `yajl_tree` (objects keep their
//!   key order and duplicate keys).
//!
//! The parser is iterative, so deeply nested input cannot overflow the
//! stack (yajl is iterative as well).

/// `yajl_gen`
#[derive(Debug, Default)]
pub struct JsonGen {
    buf: Vec<u8>,
    /// Per open container: (is_map, number of items written).
    stack: Vec<(bool, usize)>,
}

impl JsonGen {
    pub fn new() -> Self {
        Self::default()
    }

    fn before_value(&mut self) {
        if let Some((is_map, n)) = self.stack.last_mut() {
            if *is_map {
                // keys and values alternate: n counts both
                if *n % 2 == 0 {
                    if *n > 0 {
                        self.buf.push(b',');
                    }
                } else {
                    self.buf.push(b':');
                }
            } else if *n > 0 {
                self.buf.push(b',');
            }
            *n += 1;
        }
    }

    /// `yajl_gen_string`
    pub fn string(&mut self, s: &[u8]) {
        self.before_value();
        self.buf.push(b'"');
        escape_into(&mut self.buf, s);
        self.buf.push(b'"');
    }

    /// `yajl_gen_integer`
    pub fn integer(&mut self, v: i64) {
        self.before_value();
        self.buf.extend_from_slice(v.to_string().as_bytes());
    }

    /// `yajl_gen_number`: raw number text.
    pub fn number(&mut self, raw: &[u8]) {
        self.before_value();
        self.buf.extend_from_slice(raw);
    }

    /// `yajl_gen_bool`
    pub fn bool(&mut self, v: bool) {
        self.before_value();
        self.buf.extend_from_slice(if v { b"true" } else { b"false" });
    }

    /// `yajl_gen_null`
    pub fn null(&mut self) {
        self.before_value();
        self.buf.extend_from_slice(b"null");
    }

    /// `yajl_gen_map_open`
    pub fn map_open(&mut self) {
        self.before_value();
        self.buf.push(b'{');
        self.stack.push((true, 0));
    }

    /// `yajl_gen_map_close`
    pub fn map_close(&mut self) {
        self.stack.pop();
        self.buf.push(b'}');
    }

    /// `yajl_gen_array_open`
    pub fn array_open(&mut self) {
        self.before_value();
        self.buf.push(b'[');
        self.stack.push((false, 0));
    }

    /// `yajl_gen_array_close`
    pub fn array_close(&mut self) {
        self.stack.pop();
        self.buf.push(b']');
    }

    /// `LOGFY_ADD(key, value)`
    pub fn add(&mut self, key: &str, value: &[u8]) {
        self.string(key.as_bytes());
        self.string(value);
    }

    /// `LOGFY_ADD_NUM(key, value)`
    pub fn add_num(&mut self, key: &str, value: i64) {
        self.string(key.as_bytes());
        self.integer(value);
    }

    /// `yajl_gen_get_buf`
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_buf(self) -> Vec<u8> {
        self.buf
    }
}

/// yajl's string escaping (`yajl_string_encode` without solidus escaping).
pub fn escape_into(out: &mut Vec<u8>, s: &[u8]) {
    for &c in s {
        match c {
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            0x0c => out.extend_from_slice(b"\\f"),
            0x08 => out.extend_from_slice(b"\\b"),
            b'\t' => out.extend_from_slice(b"\\t"),
            c if c < 0x20 => {
                out.extend_from_slice(b"\\u00");
                const H: &[u8; 16] = b"0123456789ABCDEF";
                out.push(H[(c >> 4) as usize]);
                out.push(H[(c & 0xf) as usize]);
            }
            c => out.push(c),
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// yajl callbacks. Returning `false` cancels the parse ("client cancelled
/// parse via callback return value").
pub trait JsonHandler {
    fn null(&mut self) -> bool;
    fn boolean(&mut self, v: bool) -> bool;
    /// Raw number text (`yajl_number`).
    fn number(&mut self, raw: &[u8]) -> bool;
    /// Decoded string bytes.
    fn string(&mut self, s: &[u8]) -> bool;
    fn start_map(&mut self) -> bool;
    fn map_key(&mut self, key: &[u8]) -> bool;
    fn end_map(&mut self) -> bool;
    fn start_array(&mut self) -> bool;
    fn end_array(&mut self) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    MapStart,
    MapNeedKey,
    MapSep,
    MapNeedVal,
    MapGotVal,
    ArrayStart,
    ArrayNeedVal,
    ArrayGotVal,
    ParseComplete,
}

fn parse_error(msg: &str) -> String {
    format!("parse error: {}\n", msg)
}

fn lexical_error(msg: &str) -> String {
    format!("lexical error: {}\n", msg)
}

enum Tok {
    Str(Vec<u8>),
    Num(Vec<u8>),
    True,
    False,
    Null,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Colon,
    Comma,
}

struct Lexer<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.s.len() && matches!(self.s[self.pos], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            self.pos += 1;
        }
    }

    /// Ok(None) at end of input.
    fn next(&mut self) -> Result<Option<Tok>, String> {
        self.skip_ws();
        let Some(&c) = self.s.get(self.pos) else {
            return Ok(None);
        };
        match c {
            b'{' => {
                self.pos += 1;
                Ok(Some(Tok::LBrace))
            }
            b'}' => {
                self.pos += 1;
                Ok(Some(Tok::RBrace))
            }
            b'[' => {
                self.pos += 1;
                Ok(Some(Tok::LBracket))
            }
            b']' => {
                self.pos += 1;
                Ok(Some(Tok::RBracket))
            }
            b':' => {
                self.pos += 1;
                Ok(Some(Tok::Colon))
            }
            b',' => {
                self.pos += 1;
                Ok(Some(Tok::Comma))
            }
            b'"' => self.string().map(|s| Some(Tok::Str(s))),
            b't' => self.literal(b"true", Tok::True),
            b'f' => self.literal(b"false", Tok::False),
            b'n' => self.literal(b"null", Tok::Null),
            b'-' | b'0'..=b'9' => self.number().map(|n| Some(Tok::Num(n))),
            b'/' => Err(lexical_error("probable comment found in input text, comments are not enabled.")),
            _ => Err(lexical_error("invalid char in json text.")),
        }
    }

    fn literal(&mut self, lit: &[u8], tok: Tok) -> Result<Option<Tok>, String> {
        let end = self.pos + lit.len();
        let avail = &self.s[self.pos..self.s.len().min(end)];
        if avail == lit {
            self.pos = end;
            return Ok(Some(tok));
        }
        if lit.starts_with(avail) {
            // ran out of input in the middle of a literal
            return Err(parse_error("premature EOF"));
        }
        Err(lexical_error("invalid string in json text."))
    }

    fn number(&mut self) -> Result<Vec<u8>, String> {
        let start = self.pos;
        let s = self.s;
        let mut p = self.pos;
        if s[p] == b'-' {
            p += 1;
            if p >= s.len() {
                return Err(parse_error("premature EOF"));
            }
            if !s[p].is_ascii_digit() {
                return Err(lexical_error("malformed number, a digit is required after the minus sign."));
            }
        }
        if s[p] == b'0' {
            p += 1;
        } else {
            while p < s.len() && s[p].is_ascii_digit() {
                p += 1;
            }
        }
        if p < s.len() && s[p] == b'.' {
            p += 1;
            if p >= s.len() {
                return Err(parse_error("premature EOF"));
            }
            if !s[p].is_ascii_digit() {
                return Err(lexical_error("malformed number, a digit is required after the decimal point."));
            }
            while p < s.len() && s[p].is_ascii_digit() {
                p += 1;
            }
        }
        if p < s.len() && (s[p] == b'e' || s[p] == b'E') {
            p += 1;
            if p < s.len() && (s[p] == b'+' || s[p] == b'-') {
                p += 1;
            }
            if p >= s.len() {
                return Err(parse_error("premature EOF"));
            }
            if !s[p].is_ascii_digit() {
                return Err(lexical_error("malformed number, a digit is required after the exponent."));
            }
            while p < s.len() && s[p].is_ascii_digit() {
                p += 1;
            }
        }
        self.pos = p;
        Ok(s[start..p].to_vec())
    }

    fn hex4(&self, p: usize) -> Result<u32, String> {
        if p + 4 > self.s.len() {
            return Err(parse_error("premature EOF"));
        }
        let mut v = 0u32;
        for i in 0..4 {
            let c = self.s[p + i];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(lexical_error("invalid (non-hex) character occurs after '\\u' inside string.")),
            };
            v = v * 16 + d as u32;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<Vec<u8>, String> {
        let s = self.s;
        let mut p = self.pos + 1;
        let mut out = Vec::new();
        loop {
            let Some(&c) = s.get(p) else {
                return Err(parse_error("premature EOF"));
            };
            match c {
                b'"' => {
                    self.pos = p + 1;
                    return Ok(out);
                }
                b'\\' => {
                    let Some(&e) = s.get(p + 1) else {
                        return Err(parse_error("premature EOF"));
                    };
                    p += 2;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut cp = self.hex4(p)?;
                            p += 4;
                            if (0xD800..0xDC00).contains(&cp) {
                                // surrogate pair (yajl decodes it if the low
                                // half follows, otherwise emits '?')
                                if s.get(p) == Some(&b'\\') && s.get(p + 1) == Some(&b'u') {
                                    let lo = self.hex4(p + 2)?;
                                    if (0xDC00..0xE000).contains(&lo) {
                                        cp = 0x10000 + (((cp & 0x3FF) << 10) | (lo & 0x3FF));
                                        p += 6;
                                    } else {
                                        cp = '?' as u32;
                                    }
                                } else {
                                    cp = '?' as u32;
                                }
                            }
                            utf8_encode(cp, &mut out);
                        }
                        _ => {
                            return Err(lexical_error(
                                "inside a string, '\\' occurs before a character which it may not.",
                            ));
                        }
                    }
                }
                c if c < 0x20 => {
                    return Err(lexical_error("invalid character inside string."));
                }
                c if c < 0x80 => {
                    out.push(c);
                    p += 1;
                }
                _ => {
                    let n = utf8_seq_len(&s[p..]);
                    match n {
                        Some(n) => {
                            out.extend_from_slice(&s[p..p + n]);
                            p += n;
                        }
                        None => {
                            // a truncated sequence at the very end is an EOF
                            if utf8_truncated(&s[p..]) {
                                return Err(parse_error("premature EOF"));
                            }
                            return Err(lexical_error("invalid bytes in UTF8 string."));
                        }
                    }
                }
            }
        }
    }
}

/// yajl's `Utf32toUtf8`.
fn utf8_encode(cp: u32, out: &mut Vec<u8>) {
    if cp < 0x80 {
        out.push(cp as u8);
    } else if cp < 0x800 {
        out.push(0xC0 | (cp >> 6) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    } else if cp < 0x10000 {
        out.push(0xE0 | (cp >> 12) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    } else if cp < 0x200000 {
        out.push(0xF0 | (cp >> 18) as u8);
        out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
        out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        out.push(0x80 | (cp & 0x3F) as u8);
    } else {
        out.push(b'?');
    }
}

/// Length of the (yajl-valid) UTF-8 sequence at the start of `s`.
fn utf8_seq_len(s: &[u8]) -> Option<usize> {
    let c = s[0];
    let n = if c >> 5 == 0x6 {
        2
    } else if c >> 4 == 0xE {
        3
    } else if c >> 3 == 0x1E {
        4
    } else {
        return None;
    };
    if s.len() < n {
        return None;
    }
    if s[1..n].iter().all(|&b| b >> 6 == 0x2) { Some(n) } else { None }
}

fn utf8_truncated(s: &[u8]) -> bool {
    let c = s[0];
    let n = if c >> 5 == 0x6 {
        2
    } else if c >> 4 == 0xE {
        3
    } else if c >> 3 == 0x1E {
        4
    } else {
        return false;
    };
    s.len() < n && s[1..].iter().all(|&b| b >> 6 == 0x2)
}

/// Parses `input` (a complete document) driving `h`. Returns yajl's error
/// message on failure.
pub fn parse<H: JsonHandler>(input: &[u8], h: &mut H) -> Result<(), String> {
    let cancelled = || parse_error("client cancelled parse via callback return value");
    let mut lx = Lexer { s: input, pos: 0 };
    let mut stack: Vec<State> = vec![State::Start];
    // When a container closes, the enclosing state already holds the "got
    // value" state that was set when the container was opened.
    loop {
        let state = *stack.last().expect("state");
        if state == State::ParseComplete {
            lx.skip_ws();
            if lx.pos < input.len() {
                return Err(parse_error("trailing garbage"));
            }
            return Ok(());
        }
        let tok = lx.next()?;
        let Some(tok) = tok else {
            return Err(parse_error("premature EOF"));
        };
        match state {
            State::Start | State::MapNeedVal | State::ArrayNeedVal | State::ArrayStart => {
                // a value is expected (or `]` right after `[`)
                if state == State::ArrayStart
                    && let Tok::RBracket = tok
                {
                    stack.pop();
                    if !h.end_array() {
                        return Err(cancelled());
                    }
                    continue;
                }
                let next_after = match state {
                    State::Start => State::ParseComplete,
                    State::MapNeedVal => State::MapGotVal,
                    _ => State::ArrayGotVal,
                };
                match tok {
                    Tok::Str(s) => {
                        if !h.string(&s) {
                            return Err(cancelled());
                        }
                        *stack.last_mut().unwrap() = next_after;
                    }
                    Tok::Num(n) => {
                        if !h.number(&n) {
                            return Err(cancelled());
                        }
                        *stack.last_mut().unwrap() = next_after;
                    }
                    Tok::True | Tok::False => {
                        if !h.boolean(matches!(tok, Tok::True)) {
                            return Err(cancelled());
                        }
                        *stack.last_mut().unwrap() = next_after;
                    }
                    Tok::Null => {
                        if !h.null() {
                            return Err(cancelled());
                        }
                        *stack.last_mut().unwrap() = next_after;
                    }
                    Tok::LBrace => {
                        if !h.start_map() {
                            return Err(cancelled());
                        }
                        *stack.last_mut().unwrap() = next_after;
                        stack.push(State::MapStart);
                    }
                    Tok::LBracket => {
                        if !h.start_array() {
                            return Err(cancelled());
                        }
                        *stack.last_mut().unwrap() = next_after;
                        stack.push(State::ArrayStart);
                    }
                    _ => return Err(parse_error("unallowed token at this point in JSON text")),
                }
            }
            State::MapStart | State::MapNeedKey => match tok {
                Tok::Str(s) => {
                    if !h.map_key(&s) {
                        return Err(cancelled());
                    }
                    *stack.last_mut().unwrap() = State::MapSep;
                }
                Tok::RBrace if state == State::MapStart => {
                    stack.pop();
                    if !h.end_map() {
                        return Err(cancelled());
                    }
                }
                _ => return Err(parse_error("invalid object key (must be a string)")),
            },
            State::MapSep => match tok {
                Tok::Colon => *stack.last_mut().unwrap() = State::MapNeedVal,
                _ => return Err(parse_error("object key and value must be separated by a colon (':')")),
            },
            State::MapGotVal => match tok {
                Tok::RBrace => {
                    stack.pop();
                    if !h.end_map() {
                        return Err(cancelled());
                    }
                }
                Tok::Comma => *stack.last_mut().unwrap() = State::MapNeedKey,
                _ => return Err(parse_error("after key and value, inside map, I expect ',' or '}'")),
            },
            State::ArrayGotVal => match tok {
                Tok::RBracket => {
                    stack.pop();
                    if !h.end_array() {
                        return Err(cancelled());
                    }
                }
                Tok::Comma => *stack.last_mut().unwrap() = State::ArrayNeedVal,
                _ => return Err(parse_error("after array element, I expect ',' or ']'")),
            },
            State::ParseComplete => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tree (`yajl_tree`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    /// Raw number text.
    Number(Vec<u8>),
    String(Vec<u8>),
    /// Key order and duplicate keys are preserved.
    Object(Vec<(Vec<u8>, JsonValue)>),
    Array(Vec<JsonValue>),
}

impl JsonValue {
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(o) => o.iter().find(|(k, _)| k == key.as_bytes()).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&[u8]> {
        match self {
            JsonValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Number(n) => std::str::from_utf8(n)
                .ok()
                .and_then(|n| n.parse::<i64>().ok().or_else(|| n.parse::<f64>().ok().map(|f| f as i64))),
            _ => None,
        }
    }
}

#[derive(Default)]
struct TreeBuilder {
    stack: Vec<(JsonValue, Option<Vec<u8>>)>,
    root: Option<JsonValue>,
    pending_key: Option<Vec<u8>>,
}

impl TreeBuilder {
    fn add(&mut self, v: JsonValue) -> bool {
        match self.stack.last_mut() {
            None => self.root = Some(v),
            Some((JsonValue::Object(o), _)) => {
                let k = self.pending_key.take().unwrap_or_default();
                o.push((k, v));
            }
            Some((JsonValue::Array(a), _)) => a.push(v),
            Some(_) => {}
        }
        true
    }
}

impl JsonHandler for TreeBuilder {
    fn null(&mut self) -> bool {
        self.add(JsonValue::Null)
    }
    fn boolean(&mut self, v: bool) -> bool {
        self.add(JsonValue::Bool(v))
    }
    fn number(&mut self, raw: &[u8]) -> bool {
        self.add(JsonValue::Number(raw.to_vec()))
    }
    fn string(&mut self, s: &[u8]) -> bool {
        self.add(JsonValue::String(s.to_vec()))
    }
    fn start_map(&mut self) -> bool {
        let k = self.pending_key.take();
        self.stack.push((JsonValue::Object(Vec::new()), k));
        true
    }
    fn map_key(&mut self, key: &[u8]) -> bool {
        self.pending_key = Some(key.to_vec());
        true
    }
    fn end_map(&mut self) -> bool {
        let (v, k) = self.stack.pop().expect("open map");
        self.pending_key = k;
        self.add(v)
    }
    fn start_array(&mut self) -> bool {
        let k = self.pending_key.take();
        self.stack.push((JsonValue::Array(Vec::new()), k));
        true
    }
    fn end_array(&mut self) -> bool {
        let (v, k) = self.stack.pop().expect("open array");
        self.pending_key = k;
        self.add(v)
    }
}

/// `yajl_tree_parse`
pub fn parse_tree(input: &[u8]) -> Result<JsonValue, String> {
    let mut b = TreeBuilder::default();
    parse(input, &mut b)?;
    Ok(b.root.unwrap_or(JsonValue::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_compact() {
        let mut g = JsonGen::new();
        g.map_open();
        g.add("a", b"x\"y\n");
        g.add_num("n", 5);
        g.string(b"arr");
        g.array_open();
        g.string(b"1");
        g.bool(true);
        g.array_close();
        g.map_close();
        assert_eq!(g.as_bytes(), br#"{"a":"x\"y\n","n":5,"arr":["1",true]}"#);
    }

    #[test]
    fn tree_and_errors() {
        let v = parse_tree(br#"{"a": [1, "b", null], "a": {"c": true}}"#).unwrap();
        match &v {
            JsonValue::Object(o) => assert_eq!(o.len(), 2),
            _ => panic!(),
        }
        assert_eq!(parse_tree(b"{\"a\":").unwrap_err(), "parse error: premature EOF\n");
        assert_eq!(parse_tree(b"{} x").unwrap_err(), "parse error: trailing garbage\n");
        assert_eq!(parse_tree(b"{a}").unwrap_err(), "lexical error: invalid char in json text.\n");
        assert_eq!(parse_tree(b"\"\xff\"").unwrap_err(), "lexical error: invalid bytes in UTF8 string.\n");
        assert_eq!(parse_tree(br#""\u00e9""#).unwrap(), JsonValue::String(vec![0xc3, 0xa9]));
    }

    #[test]
    fn deep_nesting_is_iterative() {
        let mut s = vec![b'['; 100_000];
        s.extend(std::iter::repeat_n(b']', 100_000));
        struct Count(usize);
        impl JsonHandler for Count {
            fn null(&mut self) -> bool {
                true
            }
            fn boolean(&mut self, _: bool) -> bool {
                true
            }
            fn number(&mut self, _: &[u8]) -> bool {
                true
            }
            fn string(&mut self, _: &[u8]) -> bool {
                true
            }
            fn start_map(&mut self) -> bool {
                true
            }
            fn map_key(&mut self, _: &[u8]) -> bool {
                true
            }
            fn end_map(&mut self) -> bool {
                true
            }
            fn start_array(&mut self) -> bool {
                self.0 += 1;
                true
            }
            fn end_array(&mut self) -> bool {
                true
            }
        }
        let mut c = Count(0);
        assert!(parse(&s, &mut c).is_ok());
        assert_eq!(c.0, 100_000);
    }
}
