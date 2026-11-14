//! Operating system helpers: environment, files and directories, resource
//! lookup, CPU time and local time formatting.

use jiff::fmt::strtime;
use jiff::tz::TimeZone;
use jiff::{Timestamp, Zoned};

pub use modsecurity_native::posix::{mkstemp, set_env};

/// The process CPU time in seconds.
pub fn cpu_seconds() -> f64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    t.tv_sec as f64 + (t.tv_nsec as f64 / 1_000_000_000.0)
}

/// The result of [`find_resource`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLookup {
    /// Where the resource was found. A name matched through shell expansion
    /// is returned unexpanded (as in C++), so opening it can still fail.
    pub path: Option<String>,
    /// `Looking at: '…', '…'`: the places tried before, for error messages
    /// (also when the resource was found).
    pub looked_at: String,
}

/// Looks for `resource` as given, through shell expansion, and relative to
/// the directory of `config`.
pub fn find_resource(resource: &str, config: &str) -> ResourceLookup {
    let relative = format!("{}/{}", parent_dir(config), resource);
    // Each name is tried as a file, then through shell expansion.
    let attempts = [(resource, false), (resource, true), (relative.as_str(), false), (relative.as_str(), true)];
    let mut looked_at = "Looking at: ".to_string();
    for (i, &(candidate, expand)) in attempts.iter().enumerate() {
        let found = if expand { !expand_env(candidate, 0).is_empty() } else { std::fs::File::open(candidate).is_ok() };
        if found {
            return ResourceLookup { path: Some(candidate.to_string()), looked_at };
        }
        let separator = if i + 1 == attempts.len() { "." } else { ", " };
        looked_at.push_str(&format!("'{}'{}", candidate, separator));
    }
    ResourceLookup { path: None, looked_at }
}

/// The directory part of `file`. As in C++, a name without any
/// separator is returned unchanged (`npos > 0` and `substr(0, npos)`), and a
/// separator at position 0 yields an empty string.
pub fn parent_dir(file: &str) -> String {
    match file.rfind(['/', '\\']) {
        Some(0) => String::new(),
        Some(found) => file[..found].to_string(),
        None => file.to_string(),
    }
}

/// The `wordexp(3)` expansion (no command substitution) of `var`, keeping
/// only the results that can be opened.
pub fn expand_env(var: &str, flags: i32) -> Vec<String> {
    use modsecurity_native::posix::{WRDE_NOCMD, word_expansion};
    word_expansion(var, flags | WRDE_NOCMD).into_iter().filter(|w| std::fs::File::open(w).is_ok()).collect()
}

/// Creates the directory `dir` (`mkdir(dir, mode)`), accepting an existing
/// one.
pub fn create_dir(dir: &str, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.contains('\0') {
        // C++ cannot pass such a name to mkdir; it fails without a message.
        return Err(String::new());
    }
    match std::fs::DirBuilder::new().mode(mode).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        Err(e) => Err(format!("Not able to create directory: {}: {}.", dir, strerror(e.raw_os_error().unwrap_or(0)))),
    }
}

/// Whether `f` is a regular file that can be opened for reading.
pub fn is_file(f: &str) -> bool {
    match std::fs::metadata(f) {
        Ok(m) => std::fs::File::open(f).is_ok() && m.is_file(),
        Err(_) => false,
    }
}

/// `strerror(errno)`: the text of an error number (through std, which
/// uses the thread safe `strerror_r`).
pub fn strerror(errnum: i32) -> String {
    let text = std::io::Error::from_raw_os_error(errnum).to_string();
    let suffix = format!(" (os error {})", errnum);
    text.strip_suffix(&suffix).map(str::to_owned).unwrap_or(text)
}

/// `t` (seconds since the epoch) in the local time zone: `localtime_r`.
///
/// The zone comes from `TZ` or the system configuration (`/etc/localtime`),
/// as for libc; UTC if neither can be determined.
pub fn localtime(t: i64) -> Zoned {
    Timestamp::from_second(t).unwrap_or(Timestamp::UNIX_EPOCH).to_zoned(TimeZone::system())
}

/// Formats `t` in the local time zone: `strftime(fmt, localtime_r(t))`.
///
/// Formatting is that of the C ("POSIX") locale: `%c` is
/// `%a %b %e %H:%M:%S %Y` and names are English. C++'s `strftime` follows
/// the process `LC_TIME` locale instead, which only differs when the
/// embedding application changes it with `setlocale` (nginx does not).
pub fn strftime_local(t: i64, fmt: &str) -> String {
    let config = strtime::Config::new().custom(strtime::PosixCustom::new());
    strtime::BrokenDownTime::from(&localtime(t)).to_string_with_config(&config, fmt).unwrap_or_default()
}

/// The current time in seconds since the epoch.
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use modsecurity_native::testing;

    /// Every format the library uses gives the same text as glibc in the C
    /// locale, in whatever zone `TZ` selects (run with several, e.g.
    /// `TZ=America/New_York`, `TZ=Asia/Kolkata`, `TZ=Australia/Lord_Howe`).
    #[test]
    fn strftime_local_matches_libc() {
        const FORMATS: &[&str] = &[
            "%c",
            "[%d/%b/%Y:%H:%M:%S %z]",
            "/%Y%m%d",
            "/%Y%m%d-%H%M",
            "/%Y%m%d-%H%M%S",
            "%Y%m%d",
            "%H:%M:%S",
            "%u",
            "%H",
            "%M",
            "%d",
            "%Y",
            "%S",
        ];
        // Every ~37 hours from 1970 to 2040 (all weekdays, months, hours and
        // DST transitions), plus the epoch and leap-day edges.
        let mut times: Vec<i64> = (0..2_200_000_000i64).step_by(133_337).collect();
        times.extend([0, 951_782_400, 951_868_799, 1_709_164_800, 2_147_483_647]);
        for &t in &times {
            for fmt in FORMATS {
                assert_eq!(strftime_local(t, fmt), testing::strftime_local(t, fmt), "t={t} fmt={fmt:?}");
            }
            let tm_mon = testing::localtime_month(t);
            assert_eq!(i32::from(localtime(t).month()), tm_mon + 1, "t={t}");
        }
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("msrs-system-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn find_resource_trace() {
        let d = temp_dir("find");
        let dir = d.to_str().unwrap();
        std::fs::write(d.join("a.conf"), "x").unwrap();
        let config = format!("{dir}/main.conf");

        // Found as given: nothing tried before.
        let a = format!("{dir}/a.conf");
        assert_eq!(find_resource(&a, "").path.as_deref(), Some(a.as_str()));
        assert_eq!(find_resource(&a, "").looked_at, "Looking at: ");

        // Found relative to the configuration file.
        let r = find_resource("a.conf", &config);
        assert_eq!(r.path, Some(format!("{dir}/a.conf")));
        assert_eq!(r.looked_at, "Looking at: 'a.conf', 'a.conf', ");

        // Found through shell expansion: returned unexpanded.
        let glob = format!("{dir}/*.conf");
        let r = find_resource(&glob, "");
        assert_eq!(r.path.as_deref(), Some(glob.as_str()));
        assert_eq!(r.looked_at, format!("Looking at: '{glob}', "));

        // Not found.
        let r = find_resource("missing.txt", &config);
        assert_eq!(r.path, None);
        assert_eq!(
            r.looked_at,
            format!("Looking at: 'missing.txt', 'missing.txt', '{dir}/missing.txt', '{dir}/missing.txt'.")
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn create_dir_results() {
        let d = temp_dir("mkdir");
        let sub = d.join("sub");
        let sub = sub.to_str().unwrap();
        assert_eq!(create_dir(sub, 0o750), Ok(()));
        assert!(std::path::Path::new(sub).is_dir());
        // An existing directory is fine.
        assert_eq!(create_dir(sub, 0o750), Ok(()));
        let deep = format!("{}/x/y", d.to_str().unwrap());
        assert_eq!(
            create_dir(&deep, 0o750),
            Err(format!("Not able to create directory: {deep}: No such file or directory."))
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn strerror_matches_libc() {
        for errnum in 0..200 {
            let c = testing::strerror(errnum);
            assert_eq!(strerror(errnum), c, "errno {errnum}");
        }
    }
}
