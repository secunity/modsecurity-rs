//! [`ActionContext`]: what an action may do when it runs.

use crate::actions::disruptive::allow::AllowType;
use crate::audit_log::{AuditLogStatus, Parts, PartsChange};
use crate::collection::Persistent;
use crate::intervention::Intervention;
use crate::rule::Rule;
use crate::rule::message::{LogParts, RuleMessage};
use crate::rules_set::properties::{ParseXmlIntoArgs, RuleEngine};
use crate::run_time_string::RunTimeString;
use crate::transaction::{RequestBodyType, Transaction};

/// What an action may do while it runs: write to the debug log, expand
/// its text, fill in the rule message, decide the intervention, steer
/// rule evaluation, change `ctl:` settings, and set collection keys and
/// identifiers. Actions see the transaction only through this.
///
/// (`setvar`, `exec` and `block` are part of the engine: they resolve
/// variables, run Lua or re-run the phase's default actions, and reach the
/// transaction with [`ActionContext::engine`].)
pub struct ActionContext<'c, 't, 'm> {
    t: &'c mut Transaction<'t>,
    rule: &'c Rule,
    rm: &'c mut RuleMessage<'m>,
}

impl<'c, 't, 'm> ActionContext<'c, 't, 'm> {
    pub fn new(t: &'c mut Transaction<'t>, rule: &'c Rule, rm: &'c mut RuleMessage<'m>) -> Self {
        ActionContext { t, rule, rm }
    }

    /// The transaction and the rule, for the actions that are part of the
    /// engine (`setvar`, `exec`, `block`).
    pub fn engine(&mut self) -> (&mut Transaction<'t>, &'c Rule) {
        (self.t, self.rule)
    }

    // --- text ----------------------------------------------------------

    /// `string` with its macros expanded for this transaction.
    pub fn expand(&self, string: &RunTimeString) -> Vec<u8> {
        string.evaluate(Some(self.t))
    }

    // --- rule message --------------------------------------------------

    /// Whether the rule's message goes to the logs (`log`, `nolog`, ...).
    pub fn set_save_message(&mut self, save: bool) {
        self.rm.save_message = save;
    }

    /// Whether the rule's message stays out of the audit log
    /// (`noauditlog`, `auditlog`).
    pub fn set_no_audit_log(&mut self, no_audit_log: bool) {
        self.rm.no_audit_log = no_audit_log;
    }

    /// `msg`.
    pub fn set_message(&mut self, message: Vec<u8>) {
        self.rm.message = message;
    }

    /// `logdata`.
    pub fn set_log_data(&mut self, data: Vec<u8>) {
        self.rm.data = data;
    }

    /// `tag`.
    pub fn add_tag(&mut self, tag: Vec<u8>) {
        self.rm.tags.push(tag);
    }

    /// `severity` of the rule message.
    pub fn set_severity(&mut self, severity: u8) {
        self.rm.severity = severity;
    }

    // --- intervention --------------------------------------------------

    /// The status of the pending intervention (200 when none was set).
    pub fn intervention_status(&self) -> u16 {
        self.t.outcome.intervention.status
    }

    pub fn set_intervention_status(&mut self, status: u16) {
        self.t.outcome.intervention.status = status;
    }

    /// The URL of a redirection.
    pub fn set_intervention_url(&mut self, url: Vec<u8>) {
        self.t.outcome.intervention.url = Some(url);
    }

    /// Makes the intervention disruptive: the rule message is marked
    /// disruptive and its log line becomes the intervention's log.
    pub fn disrupt(&mut self) {
        self.t.outcome.intervention.disruptive = true;
        self.rm.is_disruptive = true;
        self.t.outcome.intervention.log = Some(self.rm.log(self.t, LogParts::CLIENT, None));
    }

    /// Drops the pending intervention (`pass`): status, URL and log.
    pub fn reset_intervention(&mut self) {
        self.t.outcome.intervention = Intervention::default();
    }

    /// The highest severity so far (`HIGHEST_SEVERITY`; 255 when none).
    pub fn highest_severity(&self) -> u8 {
        self.t.outcome.highest_severity_action
    }

    pub fn set_highest_severity(&mut self, severity: u8) {
        self.t.outcome.highest_severity_action = severity;
    }

    // --- rule evaluation -----------------------------------------------

    /// `skip`: the number of rules to skip.
    pub fn skip_next(&mut self, rules: usize) {
        self.t.eval.skip_next = rules;
    }

    /// `skipAfter`: skips rules up to the `SecMarker` `name`.
    pub fn skip_after(&mut self, name: &str) {
        self.t.add_marker(name);
    }

    /// `allow`.
    pub fn allow(&mut self, allow_type: AllowType) {
        self.t.eval.allow_type = Some(allow_type);
    }

    // --- ctl: ------------------------------------------------------------

    pub fn set_rule_engine(&mut self, state: RuleEngine) {
        self.t.ctl.rule_engine = Some(state);
    }

    pub fn set_request_body_access(&mut self, access: bool) {
        self.t.ctl.request_body_access = Some(access);
    }

    pub fn set_parse_xml_into_args(&mut self, value: ParseXmlIntoArgs) {
        self.t.ctl.parse_xml_into_args = Some(value);
    }

    pub fn set_audit_engine(&mut self, status: AuditLogStatus) {
        self.t.ctl.audit_engine = Some(status);
    }

    pub fn change_audit_log_parts(&mut self, change: PartsChange, parts: Parts) {
        self.t.ctl.audit_log_modifier.push((change, parts));
    }

    pub fn remove_rules_by_id(&mut self, ids: &[std::ops::RangeInclusive<crate::rule::Id>]) {
        self.t.ctl.rule_remove_by_id.extend_from_slice(ids);
    }

    pub fn remove_rules_by_tag(&mut self, tag: String) {
        self.t.ctl.rule_remove_by_tag.push(tag);
    }

    pub fn remove_target_by_id(&mut self, id: crate::rule::Id, target: String) {
        self.t.ctl.rule_remove_target_by_id.push((id, target));
    }

    pub fn remove_target_by_tag(&mut self, tag: String, target: String) {
        self.t.ctl.rule_remove_target_by_tag.push((tag, target));
    }

    /// `ctl:requestBodyProcessor=JSON|XML`: the processor, and
    /// `REQBODY_PROCESSOR` set to `name`.
    pub fn set_request_body_processor(&mut self, processor: RequestBodyType, name: &[u8]) {
        self.t.body.request_body_processor = processor;
        self.set_reqbody_processor_variable(name);
    }

    /// `ctl:requestBodyProcessor=URLENCODED`: sets the body *type* (not the
    /// processor), and `REQBODY_PROCESSOR` to `name`.
    pub fn set_request_body_type(&mut self, body_type: RequestBodyType, name: &[u8]) {
        self.t.body.request_body_type = body_type;
        self.set_reqbody_processor_variable(name);
    }

    fn set_reqbody_processor_variable(&mut self, name: &[u8]) {
        let offset = self.t.vars.offset;
        self.t.vars.reqbody_processor.set(name, offset);
    }

    // --- collections and identifiers -----------------------------------

    /// `setrsc`: `RESOURCE` and the key of the resource collection.
    pub fn set_resource(&mut self, key: Vec<u8>) {
        let offset = self.t.vars.offset;
        self.t.vars.resource.set(&key, offset);
        self.t.collections.resource.key = key;
    }

    /// `setsid`: `SESSIONID` and the key of the session collection.
    pub fn set_session_id(&mut self, key: Vec<u8>) {
        let offset = self.t.vars.offset;
        self.t.vars.session_id.set(&key, offset);
        self.t.collections.session.key = key;
    }

    /// `setuid`: `USERID` and the key of the user collection.
    pub fn set_user_id(&mut self, key: Vec<u8>) {
        let offset = self.t.vars.offset;
        self.t.vars.user_id.set(&key, offset);
        self.t.collections.user.key = key;
    }

    /// `initcol`: the key of a persistent collection.
    pub fn init_collection(&mut self, collection: Persistent, key: Vec<u8>) {
        self.t.collections.persistent_mut(collection).key = key;
    }

    /// The key of a persistent collection.
    pub fn collection_key(&self, collection: Persistent) -> &[u8] {
        &self.t.collections.persistent(collection).key
    }

    /// `expirevar`: `name` of `collection` expires in `seconds`.
    pub fn expire(&mut self, collection: Persistent, name: &[u8], seconds: u64) {
        let set =
            self.t.collections.persistent(collection).set_expiry(name, self.t.rules.properties.web_app_id(), seconds);
        self.t.stored(set);
    }

    /// `setenv`: `name` in the transaction's `ENV`.
    pub fn set_env(&mut self, name: Vec<u8>, value: Vec<u8>) {
        self.t.variable_envs.insert(name, value);
    }
}

impl crate::DebugSink for ActionContext<'_, '_, '_> {
    fn debug_enabled(&self, level: u8) -> bool {
        self.t.debug_enabled(level)
    }

    fn debug(&self, level: u8, message: &str) {
        self.t.debug(level, message);
    }
}
