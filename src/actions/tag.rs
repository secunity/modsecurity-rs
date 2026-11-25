//! `tag:'...'` — a tag (with macro expansion) that categorises the rule.
//!
//! A rule or a chain may have several tags. They appear in the logs with
//! the other rule metadata, so that events can be sorted automatically;
//! forward slashes make a hierarchy of categories:
//!
//! ```text
//! SecRule ARGS "@rx \bgetparentfolder\b" "id:958016,block,tag:'WEB_ATTACK/XSS',tag:'PCI/6.5.1'"
//! ```

use crate::actions::action::Action;
use crate::actions::context::ActionContext;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;

#[derive(Debug)]
pub struct Tag {
    pub string: RunTimeString,
}

impl Tag {
    pub fn with_rts(z: RunTimeString) -> Self {
        Tag { string: z }
    }

    /// The tag, with its macros expanded for `t`.
    pub fn tag(&self, t: &Transaction<'_>) -> Vec<u8> {
        self.string.expand(t, None).into_owned()
    }
}

impl Action for Tag {
    fn name(&self) -> &str {
        "tag"
    }

    fn evaluate(&self, cx: &mut ActionContext<'_, '_, '_>) {
        let tag = cx.expand(&self.string);
        crate::ms_dbg!(cx, 9, "Rule tag: {}", String::from_utf8_lossy(&tag));
        cx.add_tag(tag);
    }
}
