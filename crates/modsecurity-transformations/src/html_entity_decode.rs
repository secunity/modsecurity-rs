//! The `t:htmlEntityDecode` transformation: decodes numeric and named HTML
//! entities.

use modsecurity_compat::cnum::strtoll;

/// The non-breaking space of ISO 8859-1 (`&nbsp;`).
const NBSP: u8 = 0xa0;

/// The named entities of `t:htmlEntityDecode`: `(name, character)`.
///
/// A name is compared case-insensitively with the whole name in the input:
/// the lengths must be equal. Earlier implementations compared only as many
/// bytes as the table's name has (`strncasecmp`), which decoded prefixes:
/// `&ltest;` became `<` and lost `est` (GHSA-cxqf-vgrr-xxrv).
///
/// The contents are generated, not hand-curated: a hand-written list drifts
/// from the specification (that is how `&lcub;`, `&excl;` and `&Hat;` came
/// to be missing while `&caret;`, `&hyphen;` and `&tilde;` were mapped to
/// ASCII characters the specification does not assign them). They come
/// from `tools/gen-html-entities.py` of the original ModSecurity
/// repository, which reads <https://html.spec.whatwg.org/entities.json> and
/// emits a C++ table, translated to the array below. Regenerate the table
/// rather than edit it by hand:
///
/// ```text
/// curl -sSO https://html.spec.whatwg.org/entities.json
/// python3 tools/gen-html-entities.py entities.json
/// ```
///
/// It holds every entity that expands to a single code point in
/// U+0000..U+007F, plus NBSP (U+00A0) and SOFT HYPHEN (U+00AD): 44 entries.
///
/// Case-insensitive matching collapses these distinctions of the
/// specification:
/// - `&GT;` = U+003E wins over `&Gt;` = U+226B;
/// - `&LT;` = U+003C wins over `&Lt;` = U+226A;
/// - `&colon;` = U+003A wins over `&Colon;` = U+2237;
/// - `&verbar;` = U+007C wins over `&Verbar;` = U+2016;
/// - `&vert;` = U+007C wins over `&Vert;` = U+2016.
const NAMED_ENTITIES: &[(&[u8], u8)] = &[
    (b"amp", b'&'),
    (b"apos", b'\''),
    (b"ast", b'*'),
    (b"bsol", b'\\'),
    (b"colon", b':'),
    (b"comma", b','),
    (b"commat", b'@'),
    (b"diacriticalgrave", b'`'),
    (b"dollar", b'$'),
    (b"equals", b'='),
    (b"excl", b'!'),
    (b"grave", b'`'),
    (b"gt", b'>'),
    (b"hat", b'^'),
    (b"lbrace", b'{'),
    (b"lbrack", b'['),
    (b"lcub", b'{'),
    (b"lowbar", b'_'),
    (b"lpar", b'('),
    (b"lsqb", b'['),
    (b"lt", b'<'),
    (b"midast", b'*'),
    (b"nbsp", NBSP),
    (b"newline", b'\n'),
    (b"nonbreakingspace", NBSP),
    (b"num", b'#'),
    (b"percnt", b'%'),
    (b"period", b'.'),
    (b"plus", b'+'),
    (b"quest", b'?'),
    (b"quot", b'"'),
    (b"rbrace", b'}'),
    (b"rbrack", b']'),
    (b"rcub", b'}'),
    (b"rpar", b')'),
    (b"rsqb", b']'),
    (b"semi", b';'),
    (b"shy", 0xAD),
    (b"sol", b'/'),
    (b"tab", b'\t'),
    (b"underbar", b'_'),
    (b"verbar", b'|'),
    (b"vert", b'|'),
    (b"verticalline", b'|'),
];

fn lookup_named_entity(name: &[u8]) -> Option<u8> {
    NAMED_ENTITIES.iter().find(|(n, _)| n.len() == name.len() && n.eq_ignore_ascii_case(name)).map(|&(_, ch)| ch)
}

fn inplace(input: &mut Vec<u8>) {
    let input_len = input.len();
    let mut d = 0usize;
    let mut i = 0usize;

    'outer: while i < input_len {
        let mut copy = 1usize;

        // Require an ampersand and at least one character to start
        // looking into the entity.
        'entity: {
            if input[i] == b'&' && i + 1 < input_len {
                let mut j = i + 1;

                if input[j] == b'#' {
                    // Numerical entity.
                    copy += 1;

                    if j + 1 >= input_len {
                        break 'entity; // Not enough bytes.
                    }
                    j += 1;

                    let (base, k) = if input[j] == b'x' || input[j] == b'X' {
                        // Hexadecimal entity.
                        copy += 1;

                        if j + 1 >= input_len {
                            break 'entity; // Not enough bytes.
                        }
                        j += 1; // j is the position of the first digit now.

                        let k = j;
                        while j < input_len && input[j].is_ascii_hexdigit() {
                            j += 1;
                        }
                        (16, k)
                    } else {
                        // Decimal entity.
                        let k = j;
                        while j < input_len && input[j].is_ascii_digit() {
                            j += 1;
                        }
                        (10, k)
                    };

                    if j > k {
                        // At least one digit: decode the entity as
                        // `(unsigned char) strtol(digits, nullptr, base)`,
                        // the low byte of the value, which saturates at
                        // LONG_MAX on overflow.
                        input[d] = strtoll(&input[k..j], base) as u8;
                        d += 1;

                        // Skip over the semicolon if it's there.
                        i = if j < input_len && input[j] == b';' { j + 1 } else { j };
                        continue 'outer;
                    }
                    break 'entity;
                } else {
                    // Text entity.
                    let k = j;
                    while j < input_len && input[j].is_ascii_alphanumeric() {
                        j += 1;
                    }
                    if j > k {
                        let Some(decoded) = lookup_named_entity(&input[k..j]) else {
                            // Unknown entity: copy the raw data over.
                            copy = j - k + 1;
                            break 'entity;
                        };
                        input[d] = decoded;
                        d += 1;

                        // Skip over the semicolon if it's there.
                        i = if j < input_len && input[j] == b';' { j + 1 } else { j };
                        continue 'outer;
                    }
                }
            }
        }

        // Not an entity, or an unknown one: copy `copy` bytes as they are.
        for _ in 0..copy {
            input[d] = input[i];
            d += 1;
            i += 1;
        }
    }

    input.truncate(d);
}

/// Transforms `value` in place.
pub fn transform(value: &mut Vec<u8>) {
    inplace(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8]) -> Vec<u8> {
        let mut v = input.to_vec();
        inplace(&mut v);
        v
    }

    #[test]
    fn decodes() {
        assert_eq!(run(b"&lt;&#65;&#x42&LT"), b"<AB<");
        assert_eq!(run(b"&ltest;"), b"&ltest;");
        assert_eq!(run(b"&#;&#x;&"), b"&#;&#x;&");
        assert_eq!(run(b"&nbsp;"), vec![NBSP]);
        // strtol saturates at LONG_MAX -> 0xff
        assert_eq!(run(b"&#99999999999999999999999;"), vec![0xff]);
        assert_eq!(run(b"&#x1ffffffffffffffff;"), vec![0xff]);
        assert_eq!(run(b"&#321;"), vec![321u32 as u8]);
    }

    #[test]
    fn named_entities_ignore_case() {
        assert_eq!(run(b"&quot;&apos;&amp;&QUOT;&Amp;"), b"\"'&\"&");
        assert_eq!(run(b"&lpar;&rpar;&sol;&bsol;"), b"()/\\");
        assert_eq!(run(b"&shy;"), b"\xad");
    }

    #[test]
    fn the_semicolon_is_optional() {
        assert_eq!(run(b"&amp x"), b"& x");
        assert_eq!(run(b"&#65abc"), b"Aabc");
        assert_eq!(run(b"&#X41;"), b"A");
    }

    #[test]
    fn unknown_or_incomplete_entities_are_kept() {
        assert_eq!(run(b"&ampx;"), b"&ampx;");
        assert_eq!(run(b"&nosuch;"), b"&nosuch;");
        assert_eq!(run(b"&;"), b"&;");
        assert_eq!(run(b"a&"), b"a&");
        assert_eq!(run(b"&#"), b"&#");
        assert_eq!(run(b"&#x"), b"&#x");
        assert_eq!(run(b"&#xg;"), b"&#xg;");
        assert_eq!(run(b""), b"");
    }
}
