//! The JSON request body processor: every scalar of the document becomes an
//! `ARGS` entry (origin "JSON") named after its path, e.g. `json.a.b` for
//! `{"a":{"b":1}}` and `json.a.array_0` for `{"a":[1]}`.
//!
//! The parser borrows the complete body and emits arguments through a
//! callback. It does not own request bytes or borrow a transaction. Returning
//! false from the callback stops parsing at the argument limit, preserving
//! partial results and yajl-compatible errors.
//!
//! The names of the arguments of one body have a limit on their total size
//! (`crate::names`); past it, parsing stops with an error.

use modsecurity_compat::json::{JsonHandler, parse};

use crate::names::NameBudget;

const JSON_DEPTH_LIMIT_DEFAULT: u32 = 10000;
const JSON_DEPTH_LIMIT_EXCEEDED_MSG: &str = ". Parsing depth limit exceeded";
const JSON_NAMES_LIMIT_EXCEEDED_MSG: &str = ". Argument names too long";

/// An open array or object, named after the key it was found under.
#[derive(Debug)]
enum JsonContainer {
    /// An array: its name and the number of elements seen so far.
    Array { name: Vec<u8>, element_counter: usize },
    /// An object: its name.
    Map { name: Vec<u8> },
}

impl JsonContainer {
    fn name(&self) -> &[u8] {
        match self {
            JsonContainer::Array { name, .. } | JsonContainer::Map { name } => name,
        }
    }
}

/// The state of the JSON body processor: the open containers, the current
/// key and the depth limit.
#[derive(Debug)]
pub struct Json {
    containers: Vec<JsonContainer>,
    current_key: Vec<u8>,
    max_depth: u32,
    depth_limit_exceeded: bool,
}

impl Default for Json {
    fn default() -> Self {
        Json {
            containers: Vec::new(),
            current_key: Vec::new(),
            max_depth: JSON_DEPTH_LIMIT_DEFAULT,
            depth_limit_exceeded: false,
        }
    }
}

impl Json {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum nesting depth (`SecRequestBodyJsonDepthLimit`).
    pub fn set_max_depth(&mut self, d: u32) {
        self.max_depth = d;
    }

    /// Parse a borrowed body, retaining path/error state across calls as the
    /// transaction's previous processor did. The sink sees arguments in
    /// document order and can cancel parsing without buffering later values.
    /// Parsing stops with an error when the names of the arguments of
    /// `body` exceed their allowance.
    pub fn parse(&mut self, body: &[u8], on_argument: impl FnMut(&[u8], &[u8]) -> bool) -> Result<(), String> {
        let mut parser =
            JsonParser { json: self, on_argument, names: NameBudget::for_body(body.len()), names_too_long: false };
        let result = parse(body, &mut parser);
        let names_too_long = parser.names_too_long;
        result.map_err(|mut error| {
            if self.depth_limit_exceeded {
                error.push_str(JSON_DEPTH_LIMIT_EXCEEDED_MSG);
            }
            if names_too_long {
                error.push_str(JSON_NAMES_LIMIT_EXCEEDED_MSG);
            }
            error
        })
    }

    /// Whether the innermost container is an array.
    fn is_previous_array(&self) -> bool {
        matches!(self.containers.last(), Some(JsonContainer::Array { .. }))
    }

    /// Takes the current key: `json` outside any container, empty inside an
    /// array, and `empty-key` for an empty key in an object.
    fn current_key(&mut self) -> Vec<u8> {
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
        let name = self.current_key();
        self.containers.push(if array {
            JsonContainer::Array { name, element_counter: 0 }
        } else {
            JsonContainer::Map { name }
        });
        if self.containers.len() > self.max_depth as usize {
            self.depth_limit_exceeded = true;
            return false;
        }
        true
    }

    /// The `yajl_end_map` / `yajl_end_array` callbacks.
    fn end_container(&mut self) -> bool {
        if self.containers.is_empty() {
            return true;
        }
        self.containers.pop();
        self.count_array_element();
        true
    }
}

/// Path state plus a caller-owned argument sink; no transaction lifetime or
/// intermediate argument list is needed.
struct JsonParser<'j, F> {
    json: &'j mut Json,
    on_argument: F,
    /// What is left of the allowance of argument names of the body.
    names: NameBudget,
    /// Parsing stopped because the names exceeded their allowance.
    names_too_long: bool,
}

impl<F: FnMut(&[u8], &[u8]) -> bool> JsonParser<'_, F> {
    /// Passes a scalar to the sink, named after its path; `false` cancels
    /// the parse (the sink refused it, or the name does not fit in what is
    /// left of the allowance of names).
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
            let data = json.current_key();
            path.extend_from_slice(&data);
        }

        if !self.names.take(path.len()) {
            self.names_too_long = true;
            return false;
        }

        // cancel parsing by returning false
        (self.on_argument)(&path, value)
    }
}

impl<F: FnMut(&[u8], &[u8]) -> bool> JsonHandler for JsonParser<'_, F> {
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
    use super::*;
    use crate::names::{NAMES_BASE, NAMES_PER_BODY_BYTE};

    /// Parses `body`: the number of arguments, the total size of their
    /// names, and the result.
    fn names(body: &[u8]) -> (usize, usize, Result<(), String>) {
        let (mut count, mut total) = (0, 0);
        let result = Json::new().parse(body, |name, _| {
            count += 1;
            total += name.len();
            true
        });
        (count, total, result)
    }

    /// `{"<prefix><key>":[<values>]}`, with `[`, `]` around the values
    /// `depth` times.
    fn document(key: &str, depth: usize, values: usize) -> Vec<u8> {
        let values = vec!["1"; values].join(",");
        format!("{{\"{key}\":{}{values}{}}}", "[".repeat(depth), "]".repeat(depth)).into_bytes()
    }

    /// A long key over many values is repeated in the name of each: the
    /// names stop at their allowance, with an error. A body that only
    /// gives some of its arguments always reports an error.
    #[test]
    fn total_size_of_names_is_bounded() {
        let body = document(&"k".repeat(64 << 10), 1, 10_000);
        let (count, total, result) = names(&body);
        assert_eq!(
            result.unwrap_err(),
            "parse error: client cancelled parse via callback return value\n. Argument names too long"
        );
        assert!(total <= NAMES_BASE + NAMES_PER_BODY_BYTE * body.len(), "{total}");
        assert!(count < 10_000, "{count}");

        // Names 25 times the size of the body (four arrays deep under a
        // key, a one-digit number each) are all given.
        let body = document("instances", 4, 100_000);
        let (count, total, result) = names(&body);
        assert_eq!(result, Ok(()));
        assert_eq!(count, 100_000);
        assert!(total > NAMES_BASE && total > 20 * body.len(), "{total}");
    }
}
