//! Port of `src/actions/tag.cc`, `src/actions/tag.h`.
//!
//! Description: Assigns a tag (category) to a rule or a chain.
//!
//! Action Group: Meta-data
//!
//! Example:
//!
//! ```text
//! SecRule REQUEST_FILENAME|ARGS_NAMES|ARGS|XML:/* "\bgetparentfolder\b" \
//!         "phase:2,rev:'2.1.3',capture,t:none,t:htmlEntityDecode,t:compressWhiteSpace,t:lowercase,ctl:auditLogParts=+E,block,msg:'Cross-site Scripting (XSS) Attack',id:'958016',tag:'WEB_ATTACK/XSS',tag:'WASCTC/WASC-8',tag:'WASCTC/WASC-22',tag:'OWASP_TOP_10/A2',tag:'OWASP_AppSensor/IE1',tag:'PCI/6.5.1',logdata:'% \
//!         {TX.0}',severity:'2',setvar:'tx.msg=%{rule.msg}',setvar:tx.xss_score=+%{tx.critical_anomaly_score},setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-WEB_ATTACK/XSS-%{matched_var_name}=%{tx.0}"
//! ```
//!
//! The tag information appears along with other rule metadata. The
//! purpose of the tagging mechanism to allow easy automated categorization
//! of events. Multiple tags can be specified on the same rule. Use forward
//! slashes to create a hierarchy of categories (as in the example). Since
//! ModSecurity 2.6.0 tag supports macro expansion.

use crate::actions::action::Action;
use crate::rule_message::RuleMessage;
use crate::rule_with_actions::RuleWithActions;
use crate::run_time_string::RunTimeString;
use crate::transaction::Transaction;
use crate::utils::string::lossy;

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
        self.string.evaluate(Some(t))
    }
}

impl Action for Tag {
    fn name(&self) -> &str {
        "tag"
    }

    fn evaluate(&self, _rule: &RuleWithActions, t: &mut Transaction<'_>, rm: &mut RuleMessage<'_>) {
        let tag = self.tag(t);
        crate::ms_dbg_a!(t, 9, "Rule tag: {}", lossy(&tag));
        rm.tags.push(tag);
    }
}
