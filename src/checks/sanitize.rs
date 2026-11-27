//! Cleaning tool results before Claude reads them: terminal escapes, invisible Unicode, hidden
//! instructions in MCP, connector and web results.

use serde_json::Value;

use crate::checks::{Ctx, PostResult, ToolCall};

pub fn post(_ctx: &Ctx, _call: &ToolCall, _response: &Value, _r: &mut PostResult) {}

/// Rule ids this module emits, with a plain-words explanation each.
pub const RULES: &[(&str, &str)] = &[];
