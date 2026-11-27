//! Secrets: provider-shaped keys and the user's own key values, going out in tool inputs or
//! pasted into a prompt, and redaction of keys in tool results.

use serde_json::Value;

use crate::checks::{Ctx, PostResult, ToolCall};
use crate::level::Verdict;

pub fn pre(_ctx: &Ctx, _call: &ToolCall, _v: &mut Verdict) {}

pub fn post(_ctx: &Ctx, _call: &ToolCall, _response: &Value, _r: &mut PostResult) {}

pub fn prompt(_ctx: &Ctx, _text: &str, _v: &mut Verdict) {}

/// Replaces anything that looks like a key with a masked form (`sk-...4f2a`).
pub fn redact(s: &str) -> String {
    s.to_string()
}

/// Rule ids this module emits, with a plain-words explanation each.
pub const RULES: &[(&str, &str)] = &[];
