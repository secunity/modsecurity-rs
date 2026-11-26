//! The `ctl:` actions: settings changed for one transaction.

pub mod audit_engine;
pub mod audit_log_parts;
pub mod parse_xml_into_args;
pub mod request_body_access;
pub mod request_body_processor_json;
pub mod request_body_processor_urlencoded;
pub mod request_body_processor_xml;
pub mod rule_engine;
pub mod rule_remove_by_id;
pub mod rule_remove_by_tag;
pub mod rule_remove_target_by_id;
pub mod rule_remove_target_by_tag;

/// The variable a `ctl:ruleRemoveTarget*` action names, as a rule's
/// targets read it: a key in single quotes is inside them (`ARGS:'a'` is
/// `ARGS:a`).
fn target_name(target: String) -> String {
    let Some(sep) = target.find([':', '.']) else {
        return target;
    };
    match target[sep + 1..].strip_prefix('\'').and_then(|k| k.strip_suffix('\'')) {
        Some(key) if !key.is_empty() => format!("{}{}", &target[..=sep], key),
        _ => target,
    }
}
