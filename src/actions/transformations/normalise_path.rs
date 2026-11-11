//! Port of `src/actions/transformations/normalise_path.cc`, `src/actions/transformations/normalise_path.h`.

use crate::actions::transformations::transformation::Transformation;
use crate::transaction::Transaction;

crate::transformation_struct!(NormalisePath);

impl NormalisePath {
    /// `NormalisePath::normalize_path_inplace`: normalises a path in place
    /// (removes self references, back references and repeated slashes).
    /// With `win`, backslashes are converted to forward slashes first.
    ///
    /// The C++ pointer arithmetic is kept as signed indices into `val`
    /// (`input` is index 0, `end` the index of the last byte); `dst` may
    /// briefly go below 0 when removing a back reference, as the C++
    /// pointer does.
    pub fn normalize_path_inplace(val: &mut Vec<u8>, win: bool) -> bool {
        let mut hitroot = false;
        let mut done = false;
        let mut changed = false;

        // Need at least one byte to normalize
        if val.is_empty() {
            return false;
        }

        let input_len = val.len();
        let input: isize = 0;

        // ENH: Deal with UNC and drive letters?

        let mut src: isize = input;
        let mut dst: isize = input;
        let end: isize = (input_len - 1) as isize;

        let at = |v: &[u8], p: isize| v[p as usize];

        let relative = !(val[0] == b'/' || (win && val[0] == b'\\'));
        let trailing = at(val, end) == b'/' || (win && at(val, end) == b'\\');

        while !done && src <= end && dst <= end {
            // Convert backslash to forward slash on Windows only.
            if win {
                if at(val, src) == b'\\' {
                    val[src as usize] = b'/';
                    changed = true;
                }
                if src < end && at(val, src + 1) == b'\\' {
                    val[(src + 1) as usize] = b'/';
                    changed = true;
                }
            }

            // `goto copy` / `goto skip_copy` of the C++ code.
            let mut normalize = true;
            let mut skip_copy = false;

            // Always normalize at the end of the input.
            if src == end {
                done = true;
            } else if at(val, src + 1) != b'/' {
                // Skip normalization if this is NOT the
                // end of the path segment.
                normalize = false;
            }

            if normalize {
                // *** Normalize the path segment. ***

                // Could it be an empty path segment?
                if src != end && at(val, src) == b'/' {
                    // Ignore
                    changed = true;
                    // Copy will take care of this.
                } else if at(val, src) == b'.' {
                    // Could it be a back or self reference?

                    // Back-reference?
                    if dst > input && at(val, dst - 1) == b'.' {
                        // If a relative path and either our normalization has
                        // already hit the rootdir, or this is a backref with no
                        // previous path segment, then mark that the rootdir was
                        // hit and just copy the backref as no normilization is
                        // possible.
                        if relative && (hitroot || (dst - 2) <= input) {
                            hitroot = true;
                            // Skip normalization.
                        } else {
                            // Remove backreference and the previous path segment.
                            dst -= 3;
                            while dst > input && at(val, dst) != b'/' {
                                dst -= 1;
                            }

                            // But do not allow going above rootdir.
                            if dst <= input {
                                hitroot = true;
                                dst = input;

                                // Need to leave the root slash if this
                                // is not a relative path and the end was reached
                                // on a backreference.
                                if !relative && src == end {
                                    dst += 1;
                                }
                            }

                            if done {
                                skip_copy = true; // Skip the copy.
                            } else {
                                src += 1;
                                changed = true;
                            }
                        }
                    } else if dst == input {
                        // Relative Self-reference?
                        changed = true;

                        // Ignore.

                        if done {
                            skip_copy = true; // Skip the copy.
                        } else {
                            src += 1;
                        }
                    } else if at(val, dst - 1) == b'/' {
                        // Self-reference?
                        changed = true;

                        // Ignore.

                        if done {
                            skip_copy = true; // Skip the copy.
                        } else {
                            dst -= 1;
                            src += 1;
                        }
                    }
                } else if dst > input {
                    // Found a regular path segment.
                    hitroot = false;
                }
            }

            if skip_copy {
                continue;
            }

            // copy:
            // *** Copy the byte if required. ***

            // Skip to the last forward slash when multiple are used.
            if at(val, src) == b'/' {
                let oldsrc = src;

                while src < end && (at(val, src + 1) == b'/' || (win && at(val, src + 1) == b'\\')) {
                    src += 1;
                }
                if oldsrc != src {
                    changed = true;
                }

                // Do not copy the forward slash to the root
                // if it is not a relative path.  Instead
                // move over the slash to the next segment.
                if relative && dst == input {
                    src += 1;
                    continue; // Skip the copy
                }
            }

            val[dst as usize] = val[src as usize];
            dst += 1;
            src += 1;
        }

        // Make sure that there is not a trailing slash in the
        // normalized form if there was not one in the original form.
        if !trailing && dst > input && at(val, dst - 1) == b'/' {
            dst -= 1;
        }

        val.truncate(dst as usize);
        changed
    }
}

impl Transformation for NormalisePath {
    fn transform(&self, value: &mut Vec<u8>, _t: Option<&Transaction<'_>>) -> bool {
        NormalisePath::normalize_path_inplace(value, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8], win: bool) -> Vec<u8> {
        let mut v = input.to_vec();
        NormalisePath::normalize_path_inplace(&mut v, win);
        v
    }

    #[test]
    fn normalises() {
        assert_eq!(run(b"/foo/./bar/../baz", false), b"/foo/baz");
        assert_eq!(run(b"//a//b/", false), b"/a/b/");
        assert_eq!(run(b"../../x", false), b"../../x");
        assert_eq!(run(b"/../x", false), b"/x");
        assert_eq!(run(b"a\\b\\..\\c", true), b"a/c");
        assert_eq!(run(b".", false), b"");
    }
}
