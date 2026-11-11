//! Port of `src/request_body_processor/json.cc`, `src/request_body_processor/json.h`.
//!
//! The JSON request body processor: every scalar of the document becomes an
//! `ARGS` entry (origin "JSON") named after its path, e.g. `json.a.b` for
//! `{"a":{"b":1}}` and `json.a.array_0` for `{"a":[1]}`.
//!
//! The C++ code drove yajl's push parser with callbacks; here the yajl
//! replacement in [`crate::utils::json`] drives a [`JsonHandler`]. That
//! parser works on a whole document, so [`Json::process_chunk`] buffers the
//! data and [`Json::complete`] parses it. The transaction feeds the whole
//! body as a single chunk and then completes, so the callbacks, the
//! arguments added and the final error text are the same as with yajl (yajl
//! repeats the error of a failed `yajl_parse` on `yajl_complete_parse`).

use crate::transaction::Transaction;
use crate::utils::json::{JsonHandler, parse};

const JSON_DEPTH_LIMIT_DEFAULT: f64 = 10000.0;
const JSON_DEPTH_LIMIT_EXCEEDED_MSG: &str = ". Parsing depth limit exceeded";

/// `JSONContainer` / `JSONContainerArray` / `JSONContainerMap`.
#[derive(Debug)]
enum JsonContainer {
    /// `JSONContainerArray`: the name and `m_elementCounter`.
    Array { name: Vec<u8>, element_counter: usize },
    /// `JSONContainerMap`
    Map { name: Vec<u8> },
}

impl JsonContainer {
    fn name(&self) -> &[u8] {
        match self {
            JsonContainer::Array { name, .. } | JsonContainer::Map { name } => name,
        }
    }
}

/// `JSON`
#[derive(Debug)]
pub struct Json {
    containers: Vec<JsonContainer>,
    current_key: Vec<u8>,
    max_depth: f64,
    current_depth: i64,
    depth_limit_exceeded: bool,
    /// Data received through `process_chunk`, parsed by `complete`.
    data: Vec<u8>,
}

impl Default for Json {
    fn default() -> Self {
        Json {
            containers: Vec::new(),
            current_key: Vec::new(),
            max_depth: JSON_DEPTH_LIMIT_DEFAULT,
            current_depth: 0,
            depth_limit_exceeded: false,
            data: Vec::new(),
        }
    }
}

impl Json {
    pub fn new() -> Self {
        Self::default()
    }

    /// `setMaxDepth`
    pub fn set_max_depth(&mut self, d: u32) {
        self.max_depth = f64::from(d);
    }

    /// `init`
    pub fn init(&mut self, _t: &mut Transaction<'_>) -> bool {
        true
    }

    /// `processChunk`: feeds the parser.
    pub fn process_chunk(&mut self, _t: &mut Transaction<'_>, buf: &[u8], _error: &mut String) -> bool {
        self.data.extend_from_slice(buf);
        true
    }

    /// `complete`: wraps up the parsing process; on failure `error` gets
    /// yajl's (non-verbose) error message.
    pub fn complete(&mut self, t: &mut Transaction<'_>, error: &mut String) -> bool {
        let data = std::mem::take(&mut self.data);
        let mut parser = JsonParser { json: self, t };
        match parse(&data, &mut parser) {
            Ok(()) => true,
            Err(e) => {
                *error = e;
                if self.depth_limit_exceeded {
                    error.push_str(JSON_DEPTH_LIMIT_EXCEEDED_MSG);
                }
                false
            }
        }
    }

    /// `isPreviousArray`
    fn is_previous_array(&self) -> bool {
        matches!(self.containers.last(), Some(JsonContainer::Array { .. }))
    }

    /// `getCurrentKey(emptyIsNull = false)`
    fn get_current_key(&mut self) -> Vec<u8> {
        if self.containers.is_empty() {
            return b"json".to_vec();
        }
        if self.current_key.is_empty() {
            if self.is_previous_array() {
                return Vec::new();
            }
            return b"empty-key".to_vec();
        }
        std::mem::take(&mut self.current_key)
    }

    /// Increments the element counter of the innermost container if it is
    /// an array.
    fn count_array_element(&mut self) {
        if let Some(JsonContainer::Array { element_counter, .. }) = self.containers.last_mut() {
            *element_counter += 1;
        }
    }

    /// The `yajl_start_map` / `yajl_start_array` callbacks.
    fn start_container(&mut self, array: bool) -> bool {
        let name = self.get_current_key();
        self.containers.push(if array {
            JsonContainer::Array { name, element_counter: 0 }
        } else {
            JsonContainer::Map { name }
        });
        self.current_depth += 1;
        if self.current_depth as f64 > self.max_depth {
            self.depth_limit_exceeded = true;
            return false;
        }
        true
    }

    /// The `yajl_end_map` / `yajl_end_array` callbacks.
    fn end_container(&mut self) -> bool {
        if self.containers.is_empty() {
            self.current_depth -= 1;
            return true;
        }
        self.containers.pop();
        self.count_array_element();
        self.current_depth -= 1;
        true
    }
}

/// The yajl callback context: the processor state plus the transaction the
/// arguments go to.
struct JsonParser<'j, 't, 'a> {
    json: &'j mut Json,
    t: &'t mut Transaction<'a>,
}

impl JsonParser<'_, '_, '_> {
    /// `addArgument`
    fn add_argument(&mut self, value: &[u8]) -> bool {
        let json = &mut *self.json;
        let mut path: Vec<u8> = Vec::new();
        for c in &json.containers {
            path.extend_from_slice(c.name());
            match c {
                JsonContainer::Array { element_counter, .. } => {
                    path.extend_from_slice(b".array_");
                    path.extend_from_slice(element_counter.to_string().as_bytes());
                }
                JsonContainer::Map { .. } => path.push(b'.'),
            }
        }

        if json.is_previous_array() {
            json.count_array_element();
        } else {
            let data = json.get_current_key();
            path.extend_from_slice(&data);
        }

        // cancel parsing by returning false
        self.t.add_argument("JSON", &path, value, 0)
    }
}

impl JsonHandler for JsonParser<'_, '_, '_> {
    /// Callback for null values
    fn null(&mut self) -> bool {
        self.add_argument(b"")
    }

    /// Callback for boolean values
    fn boolean(&mut self, v: bool) -> bool {
        self.add_argument(if v { b"true" } else { b"false" })
    }

    /// Callback for numbers; yajl can use separate callbacks for
    /// integers/longs and float/double values, but since we are not
    /// interested in using the numeric values here, we use a generic handler
    /// which uses numeric strings.
    fn number(&mut self, raw: &[u8]) -> bool {
        self.add_argument(raw)
    }

    /// Callback for string values
    fn string(&mut self, s: &[u8]) -> bool {
        self.add_argument(s)
    }

    /// Callback for a new hash, which indicates a new subtree, labeled as
    /// the current argument name, is being created.
    fn start_map(&mut self) -> bool {
        self.json.start_container(false)
    }

    /// Callback for hash key values; we use those to define the variable
    /// names under ARGS. Whenever we reach a new key, we update the current
    /// key value.
    fn map_key(&mut self, key: &[u8]) -> bool {
        self.json.current_key = key.to_vec();
        true
    }

    /// Callback for end hash, meaning the current subtree is being closed,
    /// and that we should go back to the parent variable label.
    fn end_map(&mut self) -> bool {
        self.json.end_container()
    }

    fn start_array(&mut self) -> bool {
        self.json.start_container(true)
    }

    fn end_array(&mut self) -> bool {
        self.json.end_container()
    }
}

#[cfg(test)]
mod tests {
    use crate::modsecurity::ModSecurity;
    use crate::request_body_processor::multipart::test_support::{log, new_rules, run};
    use crate::transaction::RequestBodyType;

    fn args(body: &[u8], depth: Option<&str>, limit: Option<&str>) -> (Vec<(String, String)>, String) {
        let ms = ModSecurity::new();
        let mut rules = new_rules();
        if let Some(d) = depth {
            rules.properties.request_body_json_depth_limit.parse(d).unwrap();
        }
        if let Some(l) = limit {
            rules.properties.arguments_limit.parse(l).unwrap();
        }
        let t =
            run(&ms, &rules, &[(b"Content-Type", b"application/json")], body, Some(RequestBodyType::JSONRequestBody));
        let mut l = Vec::new();
        t.vars.args.resolve(&mut l);
        let mut v: Vec<(String, String)> = l
            .iter()
            .map(|v| (String::from_utf8_lossy(v.key()).into_owned(), String::from_utf8_lossy(v.value()).into_owned()))
            .collect();
        v.sort();
        let _ = log(&rules);
        (v, String::from_utf8_lossy(&t.vars.reqbody_error_msg.value).into_owned())
    }

    fn pairs(p: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = p.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        v.sort();
        v
    }

    #[test]
    fn names_follow_the_document_structure() {
        let (a, err) = args(br#"{"a":[1,[2,3],{"b":null}],"c":true,"":"e","d":{},"f":-1.5e3}"#, None, None);
        assert_eq!(err, "");
        assert_eq!(
            a,
            pairs(&[
                ("json.a.array_0", "1"),
                ("json.a.array_1.array_0", "2"),
                ("json.a.array_1.array_1", "3"),
                ("json.a.array_2.b", ""),
                ("json.c", "true"),
                ("json.empty-key", "e"),
                ("json.f", "-1.5e3"),
            ])
        );
        let (a, _) = args(b"123", None, None);
        assert_eq!(a, pairs(&[("json", "123")]));
        let (a, _) = args(br#"[1,{"x":[]},[[["deep"]]]]"#, None, None);
        assert_eq!(a, pairs(&[("json.array_0", "1"), ("json.array_2.array_0.array_0.array_0", "deep")]));
    }

    #[test]
    fn errors() {
        let (_, err) = args(b"a", None, None);
        assert_eq!(err, "JSON parsing error: lexical error: invalid char in json text.\n");
        let (a, err) = args(br#"{"a":[1,2"#, None, None);
        assert_eq!(err, "JSON parsing error: parse error: premature EOF\n");
        assert_eq!(a.len(), 2);
        let (_, err) = args(br#"{"a":1} x"#, None, None);
        assert_eq!(err, "JSON parsing error: parse error: trailing garbage\n");
    }

    #[test]
    fn limits() {
        let body = br#"{"key1":{"key2":{"key3":{"key4":{"key5":"thevalue"}}}}}"#;
        let (a, err) = args(body, Some("5"), None);
        assert_eq!(err, "");
        assert_eq!(a, pairs(&[("json.key1.key2.key3.key4.key5", "thevalue")]));
        let (a, err) = args(body, Some("4"), None);
        assert_eq!(
            err,
            "JSON parsing error: parse error: client cancelled parse via callback return value\n. Parsing depth limit exceeded"
        );
        assert!(a.is_empty());

        let (a, err) = args(br#"{"a":1,"b":2,"c":3}"#, None, Some("2"));
        assert_eq!(err, "JSON parsing error: parse error: client cancelled parse via callback return value\n");
        assert_eq!(a, pairs(&[("json.a", "1"), ("json.b", "2")]));
    }
}
