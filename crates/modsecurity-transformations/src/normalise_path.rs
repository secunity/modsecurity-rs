//! The `t:normalisePath` and `t:normalisePathWin` transformations: remove
//! self references, back references and repeated slashes from a path.

/// Normalises a path in place (removes self references, back references
/// and repeated slashes). With `win`, backslashes are converted to forward
/// slashes first.
///
/// The positions are signed indices into `val` (`input` is index 0,
/// `end` the index of the last byte) because `dst` may briefly go below
/// 0 when removing a back reference.
pub fn normalize_path_inplace(val: &mut Vec<u8>, win: bool) {
    let mut hitroot = false;
    let mut done = false;

    // Need at least one byte to normalize.
    if val.is_empty() {
        return;
    }

    let input_len = val.len();
    let input: isize = 0;

    // UNC paths (`\\server\share`) and drive letters (`C:`) get no special
    // treatment.
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
            }
            if src < end && at(val, src + 1) == b'\\' {
                val[(src + 1) as usize] = b'/';
            }
        }

        // Whether this step normalizes the segment, and whether it then
        // skips the copy.
        let mut normalize = true;
        let mut skip_copy = false;

        // Always normalize at the end of the input.
        if src == end {
            done = true;
        } else if at(val, src + 1) != b'/' {
            // Skip normalization if this is not the end of the path
            // segment.
            normalize = false;
        }

        if normalize {
            // Normalize the path segment.

            // Could it be an empty path segment?
            if src != end && at(val, src) == b'/' {
                // Nothing to do: the copy below collapses repeated
                // slashes.
            } else if at(val, src) == b'.' {
                // Could it be a back or self reference?

                // Back-reference?
                if dst > input && at(val, dst - 1) == b'.' {
                    // In a relative path, when the normalization has
                    // already hit the root, or this back reference has no
                    // previous segment, mark that the root was hit and copy
                    // the back reference: there is nothing to remove.
                    if relative && (hitroot || (dst - 2) <= input) {
                        hitroot = true;
                        // Copied as it is.
                    } else {
                        // Remove the back reference and the previous segment.
                        dst -= 3;
                        while dst > input && at(val, dst) != b'/' {
                            dst -= 1;
                        }

                        // But do not go above the root.
                        if dst <= input {
                            hitroot = true;
                            dst = input;

                            // Leave the root slash if this is not a
                            // relative path and the end was reached on a
                            // back reference.
                            if !relative && src == end {
                                dst += 1;
                            }
                        }

                        if done {
                            skip_copy = true;
                        } else {
                            src += 1;
                        }
                    }
                } else if dst == input {
                    // A self reference at the start of the output: dropped.
                    if done {
                        skip_copy = true;
                    } else {
                        src += 1;
                    }
                } else if at(val, dst - 1) == b'/' {
                    // A self reference after a slash: dropped.
                    if done {
                        skip_copy = true;
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

        // Copy the byte.
        // Skip to the last forward slash when multiple are used.
        if at(val, src) == b'/' {
            while src < end && (at(val, src + 1) == b'/' || (win && at(val, src + 1) == b'\\')) {
                src += 1;
            }

            // A relative path does not start with a slash in its
            // normalized form: move over the slash to the next segment.
            if relative && dst == input {
                src += 1;
                continue;
            }
        }

        val[dst as usize] = val[src as usize];
        dst += 1;
        src += 1;
    }

    // No trailing slash in the normalized form unless the original has
    // one.
    if !trailing && dst > input && at(val, dst - 1) == b'/' {
        dst -= 1;
    }

    val.truncate(dst as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &[u8], win: bool) -> Vec<u8> {
        let mut v = input.to_vec();
        normalize_path_inplace(&mut v, win);
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

    #[test]
    fn self_references_are_removed() {
        assert_eq!(run(b"/a/./b", false), b"/a/b");
        assert_eq!(run(b"./a", false), b"a");
        assert_eq!(run(b"/a/.", false), b"/a");
    }

    #[test]
    fn back_references_do_not_go_above_the_root() {
        assert_eq!(run(b"/a/b/../c", false), b"/a/c");
        // Known quirk: the root slash is then removed as a trailing slash.
        assert_eq!(run(b"/a/..", false), b"");
        assert_eq!(run(b"/a/../", false), b"/");
        assert_eq!(run(b"/../../a", false), b"/a");
    }

    #[test]
    fn a_trailing_slash_is_kept_only_if_there_was_one() {
        assert_eq!(run(b"/a/b/", false), b"/a/b/");
        assert_eq!(run(b"/a//", false), b"/a/");
        assert_eq!(run(b"/a/b", false), b"/a/b");
    }

    #[test]
    fn backslashes_are_separators_on_windows_only() {
        assert_eq!(run(b"\\a\\.\\b", true), b"/a/b");
        assert_eq!(run(b"a\\\\b", true), b"a/b");
        assert_eq!(run(b"a\\..\\b", false), b"a\\..\\b");
        assert_eq!(run(b"", true), b"");
    }
}
