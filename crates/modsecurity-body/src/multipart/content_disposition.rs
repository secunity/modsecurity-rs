//! The Content-Disposition header of a part: `form-data; name="a";
//! filename="b"; filename*=UTF-8'en'c`.

use modsecurity_types::ms_dbg;

use super::part::MultipartPart;
use super::{Context, Entries, Multipart, c_at, c_str};

const MIME_CHARSET_SPECIAL: &[u8] = b"!#$%&+-^_`{}~";
const ATTR_CHAR_SPECIAL: &[u8] = b"!#$&+-.^_`~";

/// Why the header was refused: the (negative) code of the C++ function,
/// which the error message shows.
type Code = i32;

/// A position in the header value, read as a C string: past its end
/// there is the NUL terminator.
struct Cursor<'a> {
    s: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    /// The byte at the position.
    fn at(&self) -> u8 {
        c_at(self.s, self.p)
    }

    /// The byte `n` after the position.
    fn ahead(&self, n: usize) -> u8 {
        c_at(self.s, self.p + n)
    }

    fn at_end(&self) -> bool {
        self.at() == 0
    }

    /// Goes over spaces and tabs.
    fn skip_blanks(&mut self) {
        while self.at() == b'\t' || self.at() == b' ' {
            self.p += 1;
        }
    }

    /// Goes over the bytes `wanted` accepts (never the end), and gives
    /// them.
    fn take_while(&mut self, wanted: impl Fn(u8) -> bool) -> &'a [u8] {
        let start = self.p;
        while !self.at_end() && wanted(self.at()) {
            self.p += 1;
        }
        &self.s[start..self.p]
    }
}

impl Multipart {
    /// Sets `MULTIPART_INVALID_QUOTING` when `data`, a value not enclosed in
    /// double quotes, contains a single quote.
    fn validate_quotes(&mut self, cx: &dyn Context, data: &[u8], quote: u8) {
        // if the value was enclosed in double quotes, then we don't care
        // about a single quote character within the name.
        if quote == b'"' {
            return;
        }
        for &c in data {
            if c == b'\'' {
                ms_dbg!(
                    cx,
                    9,
                    "Multipart: Invalid quoting detected: {} length {} bytes",
                    String::from_utf8_lossy(data),
                    data.len()
                );
                self.flags.invalid_quoting = true;
            }
        }
    }

    /// Parses the Content-Disposition header of the part `mpp`: `c_d_value`
    /// is the header value (a C string), `offset` where it starts.
    pub(super) fn parse_content_disposition(
        &mut self,
        cx: &mut dyn Context,
        mpp: &mut MultipartPart,
        c_d_value: &[u8],
        offset: usize,
    ) -> Result<(), Code> {
        let cd = c_str(c_d_value);

        // accept only what we understand
        if !cd.starts_with(b"form-data") {
            return Err(-1);
        }

        // see if there are any other parts to parse
        let mut c = Cursor { s: cd, p: 9 };
        c.skip_blanks();
        if c.at_end() {
            return Ok(()); // this is OK
        }
        if c.at() != b';' {
            return Err(-2);
        }
        c.p += 1;

        // parse the appended parts
        while !c.at_end() {
            c.skip_blanks();
            if c.at_end() {
                return Err(-3);
            }

            let name = c.take_while(|b| b != b'=' && b != b'\t' && b != b' ');
            if c.at_end() {
                return Err(-4);
            }

            c.skip_blanks();
            if c.at_end() {
                return Err(-5);
            }
            if c.at() != b'=' {
                return Err(-13);
            }
            c.p += 1;

            c.skip_blanks();
            if c.at_end() {
                return Err(-6);
            }

            let (value, quote) = if name == b"filename*" {
                (self.extended_value(cx, mpp, &mut c, offset)?, 0)
            } else if c.at() == b'"' || c.at() == b'\'' {
                self.quoted_value(&mut c)?
            } else {
                (c.take_while(Self::is_token_char).to_vec(), 0)
            };

            let value_offset = offset.wrapping_add(c.p - value.len());
            self.set_parameter(cx, mpp, name, value, quote, value_offset)?;

            // After the value: the end, or a semicolon and the next
            // parameter.
            if !c.at_end() {
                c.skip_blanks();
                if !c.at_end() {
                    if c.at() != b';' {
                        c.p -= 1;
                        if c.at() == b'\'' || c.at() == b'"' {
                            ms_dbg!(
                                cx,
                                9,
                                "Multipart: Invalid quoting detected: {} length {} bytes",
                                String::from_utf8_lossy(&cd[c.p..]),
                                cd.len() - c.p
                            );
                            self.flags.invalid_quoting = true;
                        }
                        return Err(-12);
                    }
                    c.p += 1; // move over the semi-colon
                }
            }
        }

        // filename* takes precedence over filename, so we set the variable
        // accordingly
        if !mpp.filename_star.is_empty() {
            cx.add(Entries::MultipartFileName, &mpp.name, &mpp.filename_star, mpp.filename_star_offset);

            if !mpp.filename_charset.is_empty() {
                cx.add(
                    Entries::MultipartFileNameCharset,
                    &mpp.name,
                    &mpp.filename_charset,
                    mpp.filename_charset_offset,
                );
            }
            if !mpp.filename_language.is_empty() {
                cx.add(
                    Entries::MultipartFileNameLanguage,
                    &mpp.name,
                    &mpp.filename_language,
                    mpp.filename_language_offset,
                );
            }
        } else if !mpp.filename.is_empty() {
            cx.add(Entries::MultipartFileName, &mpp.name, &mpp.filename, mpp.filename_offset);
        }

        Ok(())
    }

    /// The value of `filename*`: `charset'[language]'percent-encoded name`.
    /// Keeps the charset and the language in `mpp`, and gives the name
    /// still encoded.
    fn extended_value(
        &mut self,
        cx: &dyn Context,
        mpp: &mut MultipartPart,
        c: &mut Cursor<'_>,
        offset: usize,
    ) -> Result<Vec<u8>, Code> {
        let charset = c.take_while(|b| b.is_ascii_alphanumeric() || MIME_CHARSET_SPECIAL.contains(&b));
        if c.at() != b'\'' || charset.is_empty() {
            // Must be at least one legit char before ' for start of
            // language
            return Err(-16);
        }
        mpp.filename_charset = charset.to_vec();
        mpp.filename_charset_offset = offset.wrapping_add(c.p - charset.len());
        ms_dbg!(
            cx,
            4,
            "Multipart: Content-Disposition filename* charset: {}.",
            String::from_utf8_lossy(&mpp.filename_charset)
        );
        c.p += 1;

        let language = c.take_while(|b| b != b'\'');
        if c.at() != b'\'' {
            self.flags.invalid_quoting = true;
            return Err(-17); // Single quote for end-of-language not found
        }
        mpp.filename_language = language.to_vec();
        mpp.filename_language_offset = offset.wrapping_add(c.p - language.len());
        ms_dbg!(
            cx,
            4,
            "Multipart: Content-Disposition filename* language: {}.",
            String::from_utf8_lossy(&mpp.filename_language)
        );
        c.p += 1;

        // Now read what should be the actual filename
        let start = c.p;
        while !c.at_end() && c.at() != b';' {
            if c.at() == b'%' {
                if !c.ahead(1).is_ascii_hexdigit() || !c.ahead(2).is_ascii_hexdigit() {
                    return Err(-18);
                }
                c.p += 3;
            } else if c.at().is_ascii_alphanumeric() || ATTR_CHAR_SPECIAL.contains(&c.at()) {
                c.p += 1;
            } else {
                return Err(-19);
            }
        }
        Ok(c.s[start..c.p].to_vec())
    }

    /// A value in double or single quotes, unescaped, and the quote used.
    /// Both quotes are accepted as some backends accept them, but `'` is
    /// invalid: `MULTIPART_INVALID_QUOTING` is set so that the rules can
    /// deal with it.
    fn quoted_value(&mut self, c: &mut Cursor<'_>) -> Result<(Vec<u8>, u8), Code> {
        let quote = c.at();
        if quote == b'\'' {
            self.flags.invalid_quoting = true;
        }

        c.p += 1;
        if c.at_end() {
            return Err(-7);
        }

        let mut value = Vec::new();
        while !c.at_end() {
            if c.at() == b'\\' {
                if c.ahead(1) == 0 {
                    // improper escaping
                    return Err(-8);
                }
                // Only the quote and \ can be escaped. Anything else is
                // improper escaping, allowed because IE sends improperly
                // escaped content and there is nothing we can do about it.
                if c.ahead(1) == quote || c.ahead(1) == b'\\' {
                    c.p += 1;
                }
            } else if c.at() == quote {
                break;
            }

            value.push(c.at());
            c.p += 1;
        }

        if c.at() != quote {
            self.flags.invalid_quoting = true;
            return Err(-15); // closing quote not found
        }
        c.p += 1; // go over the quote at the end
        Ok((value, quote))
    }

    /// Stores the parameter `name` of the header in `mpp`.
    fn set_parameter(
        &mut self,
        cx: &mut dyn Context,
        mpp: &mut MultipartPart,
        name: &[u8],
        value: Vec<u8>,
        quote: u8,
        value_offset: usize,
    ) -> Result<(), Code> {
        match name {
            b"name" => {
                self.validate_quotes(cx, &value, quote);

                cx.add(Entries::MultipartName, &value, &value, value_offset);

                if !mpp.name.is_empty() {
                    self.flags.duplicate_part_header = true;
                    ms_dbg!(
                        cx,
                        4,
                        "Multipart: Warning: Duplicate Content-Disposition name: {}. Previously: {}",
                        String::from_utf8_lossy(&value),
                        String::from_utf8_lossy(&mpp.name)
                    );
                    return Err(-14);
                }
                ms_dbg!(cx, 9, "Multipart: Content-Disposition name: {}.", String::from_utf8_lossy(&value));
                mpp.name = value;
                mpp.name_offset = value_offset;
            }
            b"filename" => {
                // here we set up the 'filename' only if it's not set up
                // already (and not the filename_star)
                if !mpp.filename.is_empty() {
                    self.flags.duplicate_part_header = true;
                    ms_dbg!(
                        cx,
                        4,
                        "Multipart: Warning: Duplicate Content-Disposition filename: {}.",
                        String::from_utf8_lossy(&value)
                    );
                    return Err(-15);
                }
                self.validate_quotes(cx, &value, quote);
                ms_dbg!(cx, 9, "Multipart: Content-Disposition filename: {}.", String::from_utf8_lossy(&value));
                mpp.filename = value;
                mpp.filename_offset = value_offset;
            }
            b"filename*" => {
                // here we set up the 'filename_star' only if it's not set up
                // already (and not the filename)
                if !mpp.filename_star.is_empty() {
                    self.flags.duplicate_part_header = true;
                    ms_dbg!(
                        cx,
                        4,
                        "Multipart: Warning: Duplicate Content-Disposition filename*: {}.",
                        String::from_utf8_lossy(&value)
                    );
                    return Err(-15);
                }

                let mut invalid_count = 0;
                let mut decoded_value = value;
                modsecurity_transformations::url::urldecode_nonstrict_inplace_ext(
                    &mut decoded_value,
                    false,
                    &mut invalid_count,
                );
                if invalid_count > 0 {
                    self.flags.invalid_part = true;
                }
                mpp.filename_star = decoded_value;
                mpp.filename_star_offset = value_offset;
                ms_dbg!(
                    cx,
                    9,
                    "Multipart: Content-Disposition filename*: {}.",
                    String::from_utf8_lossy(&mpp.filename_star)
                );
            }
            _ => return Err(-11),
        }
        Ok(())
    }
}
