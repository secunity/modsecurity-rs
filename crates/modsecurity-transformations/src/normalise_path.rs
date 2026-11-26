//! The `t:normalisePath` and `t:normalisePathWin` transformations: remove
//! self references, back references and repeated slashes from a path.

/// Normalises a path in place (removes self references, back references
/// and repeated slashes). With `win`, backslashes are separators too: they
/// become forward slashes first.
///
/// The path is rewritten byte by byte: `val[..dst]` is the normalised path
/// so far, `val[src..]` what is left of the input (`dst <= src`). A segment
/// is handled when its last byte is read. That is what decides these
/// cases, kept as they are:
/// - A segment that ends in `..` is a back reference, `a..` too: `/xa../b`
///   becomes `/b`. A segment `.` is a self reference.
/// - An absolute path that ends in a back reference to its root keeps the
///   root slash, but then loses it as a trailing slash: `/a/..` becomes an
///   empty path, `/a/../` becomes `/`.
pub fn normalize_path_inplace(val: &mut Vec<u8>, win: bool) {
    if win {
        for c in val.iter_mut().filter(|c| **c == b'\\') {
            *c = b'/';
        }
    }
    let Some(&last) = val.last() else {
        return;
    };
    let end = val.len() - 1;
    let relative = val[0] != b'/';
    let trailing = last == b'/';
    // Whether the back references reached the start of the path: in a
    // relative path, more of them are then kept as they are.
    let mut hit_root = false;
    let mut src = 0;
    let mut dst = 0;

    while src <= end {
        let at_end = src == end;

        // The last byte of a segment.
        if at_end || val[src + 1] == b'/' {
            let c = val[src];
            if c == b'/' && !at_end {
                // An empty segment: the copy below collapses the slashes.
            } else if c == b'.' && dst > 0 && val[dst - 1] == b'.' {
                // A back reference.
                if relative && (hit_root || dst <= 2) {
                    // Nothing to remove: copied as it is.
                    hit_root = true;
                } else {
                    // Remove it and the previous segment, but not above
                    // the root.
                    dst = dst.saturating_sub(3);
                    while dst > 0 && val[dst] != b'/' {
                        dst -= 1;
                    }
                    if dst == 0 {
                        hit_root = true;
                        // An absolute path that ends here keeps its root.
                        if !relative && at_end {
                            dst = 1;
                        }
                    }
                    if at_end {
                        break;
                    }
                    src += 1;
                }
            } else if c == b'.' && dst == 0 {
                // A self reference at the start: dropped.
                if at_end {
                    break;
                }
                src += 1;
            } else if c == b'.' && val[dst - 1] == b'/' {
                // A self reference after a slash: dropped with the slash.
                if at_end {
                    break;
                }
                dst -= 1;
                src += 1;
            } else if c != b'.' && dst > 0 {
                // A regular segment.
                hit_root = false;
            }
        }

        if val[src] == b'/' {
            // Repeated slashes: only the last one is copied.
            while src < end && val[src + 1] == b'/' {
                src += 1;
            }
            // A relative path does not start with a slash.
            if relative && dst == 0 {
                src += 1;
                continue;
            }
        }
        val[dst] = val[src];
        dst += 1;
        src += 1;
    }

    // No trailing slash unless the input has one.
    if !trailing && dst > 0 && val[dst - 1] == b'/' {
        dst -= 1;
    }
    val.truncate(dst);
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
    fn segments_ending_in_dots_are_references() {
        assert_eq!(run(b"/xa../b", false), b"/b");
        assert_eq!(run(b"/a/b./c", false), b"/a/b./c");
    }

    #[test]
    fn every_backslash_is_a_separator_on_windows() {
        assert_eq!(run(b"a\\\\b", true), b"a/b");
        // Runs of three or more separators used to keep their last
        // backslash, which then did not separate segments.
        assert_eq!(run(b"a\\\\\\b", true), b"a/b");
        assert_eq!(run(b"a//\\b", true), b"a/b");
        assert_eq!(run(b"..\\\\\\..\\\\\\windows", true), b"../../windows");
        assert_eq!(run(b"\\a\\\\\\b\\..\\c", true), b"/a/c");
    }

    #[test]
    fn backslashes_are_separators_on_windows_only() {
        assert_eq!(run(b"\\a\\.\\b", true), b"/a/b");
        assert_eq!(run(b"a\\\\b", true), b"a/b");
        assert_eq!(run(b"a\\..\\b", false), b"a\\..\\b");
        assert_eq!(run(b"", true), b"");
    }
}
