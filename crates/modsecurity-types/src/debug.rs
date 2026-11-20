//! The debug log as the code that writes to it sees it: [`DebugSink`], and
//! the [`ms_dbg`](crate::ms_dbg) macro that formats a message only when
//! its level is logged.

/// Something that takes debug log messages: a transaction, or one of the
/// contexts that stand for it (of an operator, an action, a body
/// processor).
pub trait DebugSink {
    /// Whether the debug log takes messages of `level`.
    fn debug_enabled(&self, level: u8) -> bool;

    /// Writes `message` to the debug log.
    fn debug(&self, level: u8, message: &str);
}

impl<T: DebugSink + ?Sized> DebugSink for &T {
    fn debug_enabled(&self, level: u8) -> bool {
        (**self).debug_enabled(level)
    }

    fn debug(&self, level: u8, message: &str) {
        (**self).debug(level, message);
    }
}

impl<T: DebugSink + ?Sized> DebugSink for &mut T {
    fn debug_enabled(&self, level: u8) -> bool {
        (**self).debug_enabled(level)
    }

    fn debug(&self, level: u8, message: &str) {
        (**self).debug(level, message);
    }
}

/// Writes to the debug log of a [`DebugSink`](crate::DebugSink) (given by
/// value or by reference): the message is only formatted when the debug
/// level is high enough.
#[macro_export]
macro_rules! ms_dbg {
    ($sink:expr, $lvl:expr, $($arg:tt)*) => {{
        if $crate::DebugSink::debug_enabled(&$sink, $lvl) {
            $crate::DebugSink::debug(&$sink, $lvl, &format!($($arg)*));
        }
    }};
}

/// [`ms_dbg`](crate::ms_dbg) where the sink is optional: nothing is logged
/// without one.
#[macro_export]
macro_rules! ms_dbg_opt {
    ($sink:expr, $lvl:expr, $($arg:tt)*) => {{
        if let Some(sink) = $sink {
            $crate::ms_dbg!(sink, $lvl, $($arg)*);
        }
    }};
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::DebugSink;

    struct Lines {
        level: u8,
        lines: RefCell<Vec<String>>,
    }

    impl DebugSink for Lines {
        fn debug_enabled(&self, level: u8) -> bool {
            level <= self.level
        }

        fn debug(&self, level: u8, message: &str) {
            self.lines.borrow_mut().push(format!("[{level}] {message}"));
        }
    }

    /// A trait with the sink as its supertrait, as the contexts are.
    trait Context: DebugSink {}
    impl Context for Lines {}

    #[test]
    fn formats_only_what_is_logged() {
        let mut sink = Lines { level: 4, lines: RefCell::default() };
        let formatted = RefCell::new(0);
        let text = |s: &str| {
            *formatted.borrow_mut() += 1;
            s.to_string()
        };
        crate::ms_dbg!(sink, 4, "by value {}", text("a"));
        crate::ms_dbg!(sink, 5, "too detailed {}", text("b"));
        {
            let by_ref: &mut dyn Context = &mut sink;
            crate::ms_dbg!(by_ref, 1, "through a context {}", text("c"));
            crate::ms_dbg_opt!(Some(&*by_ref), 2, "optional {}", text("d"));
            crate::ms_dbg_opt!(None::<&dyn Context>, 2, "absent {}", text("e"));
        }
        assert_eq!(*sink.lines.borrow(), ["[4] by value a", "[1] through a context c", "[2] optional d"]);
        assert_eq!(*formatted.borrow(), 3);
    }
}
