//! Port of `src/actions/transformations/url_decode_uni.cc`, `src/actions/transformations/url_decode_uni.h`.

use crate::rules_set_properties::UnicodeMapHolder;
use crate::transaction::Transaction;
use crate::utils::string::{valid_hex, x2c};

/// The configured unicode map (`SecUnicodeMapFile`), if any. Without a
/// transaction no map is used.
fn unicode_map<'a>(t: Option<&'a Transaction<'_>>) -> Option<&'a UnicodeMapHolder> {
    let t = t?;
    let config = &t.rules.properties.unicode_map_table;
    if config.set && config.unicode_code_page > 0.0 { config.unicode_map_table.as_deref() } else { None }
}

fn inplace(input: &mut Vec<u8>, t: Option<&Transaction<'_>>) -> bool {
    let mut changed = false;
    let input_len = input.len();
    let map = unicode_map(t);
    let mut d = 0usize;
    let mut i = 0usize;
    // Declared outside the loop as in C++ (only ever assigned while a map is
    // configured, in which case it is reassigned for every %u sequence).
    let mut hmap: i32 = -1;

    while i < input_len {
        if input[i] == b'%' {
            if i + 1 < input_len && (input[i + 1] == b'u' || input[i + 1] == b'U') {
                // Character is a percent sign.
                // IIS-specific %u encoding.
                if i + 5 < input_len {
                    // We have at least 4 data bytes.
                    if valid_hex(input[i + 2])
                        && valid_hex(input[i + 3])
                        && valid_hex(input[i + 4])
                        && valid_hex(input[i + 5])
                    {
                        if let Some(map) = map {
                            let mut code: usize = 0;
                            let mut fact: usize = 1;
                            for j in (2..=5).rev() {
                                let c = input[i + j];
                                if c.is_ascii_hexdigit() {
                                    let xv = if c >= 97 {
                                        (c - 97) as usize + 10
                                    } else if c >= 65 {
                                        (c - 65) as usize + 10
                                    } else {
                                        (c - 48) as usize
                                    };
                                    code += xv * fact;
                                    fact *= 16;
                                }
                            }
                            if code <= 65535 {
                                hmap = map.at(code);
                            }
                        }

                        if hmap != -1 {
                            input[d] = hmap as u8;
                        } else {
                            // We first make use of the lower byte here,
                            // ignoring the higher byte.
                            let mut c = x2c(&input[i + 4..i + 6]);

                            // Full width ASCII (ff01 - ff5e)
                            // needs 0x20 added
                            if c > 0x00
                                && c < 0x5f
                                && (input[i + 2] == b'f' || input[i + 2] == b'F')
                                && (input[i + 3] == b'f' || input[i + 3] == b'F')
                            {
                                c += 0x20;
                            }
                            input[d] = c;
                        }
                        d += 1;
                        i += 6;
                        changed = true;
                    } else {
                        // Invalid data, skip %u.
                        input[d] = input[i];
                        input[d + 1] = input[i + 1];
                        d += 2;
                        i += 2;
                    }
                } else {
                    // Not enough bytes (4 data bytes), skip %u.
                    input[d] = input[i];
                    input[d + 1] = input[i + 1];
                    d += 2;
                    i += 2;
                }
            } else {
                // Standard URL encoding.

                // Are there enough bytes available?
                if i + 2 < input_len {
                    // Yes.

                    // Decode a %xx combo only if it is valid.
                    let c1 = input[i + 1];
                    let c2 = input[i + 2];

                    if valid_hex(c1) && valid_hex(c2) {
                        input[d] = x2c(&input[i + 1..i + 3]);
                        d += 1;
                        i += 3;
                        changed = true;
                    } else {
                        // Not a valid encoding, skip this %
                        // (C++ also counts these in an unused `count`.)
                        input[d] = input[i];
                        d += 1;
                        i += 1;
                    }
                } else {
                    // Not enough bytes available, skip this %
                    input[d] = input[i];
                    d += 1;
                    i += 1;
                }
            }
        } else {
            // Character is not a percent sign.
            if input[i] == b'+' {
                input[d] = b' ';
                changed = true;
            } else {
                input[d] = input[i];
            }
            d += 1;
            i += 1;
        }
    }

    input.truncate(d);
    changed
}

/// Transforms `value` in place; returns whether it changed.
pub fn transform(value: &mut Vec<u8>, t: Option<&Transaction<'_>>) -> bool {
    inplace(value, t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> (Vec<u8>, bool) {
        let mut v = input.to_vec();
        let changed = inplace(&mut v, None);
        (v, changed)
    }

    #[test]
    fn decodes_without_transaction() {
        assert_eq!(run(b"%41+%u0042%uff21"), (b"A BA".to_vec(), true));
        assert_eq!(run(b"%u00"), (b"%u00".to_vec(), false));
        assert_eq!(run(b"%uzzzz"), (b"%uzzzz".to_vec(), false));
        assert_eq!(run(b"%4"), (b"%4".to_vec(), false));
        assert_eq!(run(b"%zz"), (b"%zz".to_vec(), false));
    }

    #[test]
    fn uses_the_unicode_map() {
        use crate::modsecurity::ModSecurity;
        use crate::rules_set::RulesSet;
        use std::sync::Arc;

        let ms = ModSecurity::new();
        let mut rules = RulesSet::new();
        let mut table = UnicodeMapHolder::default();
        table.change(0x0391, i32::from(b'A'));
        let config = &mut rules.properties.unicode_map_table;
        config.set = true;
        config.unicode_code_page = 20127.0;
        config.unicode_map_table = Some(Arc::new(table));
        {
            let t = Transaction::new(&ms, &rules, None);
            let mut v = b"%u0391%u00e9%uff21".to_vec();
            assert!(inplace(&mut v, Some(&t)));
            // mapped, unmapped (lower byte), unmapped full width (+0x20)
            assert_eq!(v, b"A\xe9A");
        }

        // Without a code page the map is ignored.
        rules.properties.unicode_map_table.unicode_code_page = 0.0;
        let t = Transaction::new(&ms, &rules, None);
        let mut v = b"%u0391".to_vec();
        assert!(inplace(&mut v, Some(&t)));
        assert_eq!(v, b"\x91");
    }
}
