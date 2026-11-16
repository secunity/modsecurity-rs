//! PCRE2's JIT code reads the byte after the subject (C++ subjects are
//! `std::string`s, so one is always there). Here the subjects end at, or
//! just before, the end of mapped memory, where reading past them faults:
//! the wrapper has to give PCRE2 a padded copy. A failure of these tests is
//! a crash (SIGSEGV) of the test process.

use modsecurity_native::regex::Regex;

/// Two pages, the second inaccessible; returns the address of the boundary.
fn guarded() -> *mut u8 {
    let page = 4096usize.max(unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize);
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            2 * page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(p, libc::MAP_FAILED);
        assert_eq!(libc::mprotect(p.cast::<u8>().add(page).cast(), page, libc::PROT_NONE), 0);
        p.cast::<u8>().add(page)
    }
}

#[test]
fn subjects_at_the_end_of_a_page() {
    let end = guarded();
    let patterns = [
        "^(?:a|<)",
        "(a)(b)?",
        "(?i)(error|<script)",
        "(?i)^application/json",
        "(?i)xml",
        ".",
        "ab",
        "(?i)select.+from",
        "\\d{13,16}",
        "<script",
    ];
    let seed = b"</a>';'|abxml<script error select 1 from 4111111111111111 application/json";
    for pattern in patterns {
        let re = Regex::compile(pattern.as_bytes(), false, true).expect("valid pattern");
        for (len, gap) in (0..=seed.len()).flat_map(|len| [0, 1, 2, 15, 16, 63, 64].map(|gap| (len, gap))) {
            for start in 0..(seed.len() - len).min(8) + 1 {
                let bytes = &seed[start..start + len];
                // `gap` bytes separate the subject from the end of the page.
                let subject = unsafe {
                    let at = end.sub(len + gap);
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), at, len);
                    std::slice::from_raw_parts(at, len)
                };
                let mut captures = Vec::new();
                for limit in [0, 5000] {
                    captures.clear();
                    let _ = re.search_one_match(subject, &mut captures, limit);
                    captures.clear();
                    let _ = re.search_global(subject, &mut captures, limit);
                }
                re.is_match(subject);
            }
        }
    }
}

/// The byte after the subject does not change any result.
#[test]
fn the_byte_after_the_subject_is_not_used() {
    let end = guarded();
    let patterns = [
        "^(?:a|<)",
        "(a)(b)?",
        "(?i)(error|<script)",
        "a$",
        "^",
        "$",
        "a\\b",
        "\\ba",
        "a(?=b)",
        "a(?!b)",
        "\\n^b",
        "a\\Z",
        "a\\z",
        ".",
        "(?i)xml",
        "a*",
        "\\w+",
        "[^a]",
        "a\\R?",
        "(?s)a.",
        "a\\N?",
    ];
    let seed = b"<a>a\nb a\r\nxml ab aa a";
    for pattern in patterns {
        let re = Regex::compile(pattern.as_bytes(), false, true).unwrap_or_else(|_| panic!("{pattern}"));
        for len in 0..=seed.len() {
            for start in 0..=(seed.len() - len) {
                let bytes = &seed[start..start + len];
                let mut results = Vec::new();
                for after in [0u8, b'\n', b'\r', b'a', b'b', b'<', b' ', 0xff] {
                    // One readable byte follows the subject.
                    let subject = unsafe {
                        let at = end.sub(len + 1);
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), at, len);
                        *end.sub(1) = after;
                        std::slice::from_raw_parts(at, len)
                    };
                    let mut one = Vec::new();
                    let r1 = re.search_one_match(subject, &mut one, 0);
                    let mut all = Vec::new();
                    let r2 = re.search_global(subject, &mut all, 0);
                    let groups = |c: &[modsecurity_native::regex::SMatchCapture]| {
                        c.iter().map(|c| (c.group, c.offset, c.length)).collect::<Vec<_>>()
                    };
                    results.push((r1, groups(&one), r2, groups(&all), re.is_match(subject)));
                }
                assert!(
                    results.windows(2).all(|w| w[0] == w[1]),
                    "{pattern:?} on {:?}",
                    String::from_utf8_lossy(bytes)
                );
            }
        }
    }
}
