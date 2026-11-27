//! Per-session state: setup changes since the last session (new MCP servers, hooks, plugins), and
//! the "lethal trifecta" (untrusted content and private data read, then data sent out).

use serde_json::Value;

use crate::checks::{Ctx, PostResult, ToolCall};
use crate::level::Verdict;

pub fn pre(_ctx: &Ctx, _call: &ToolCall, _v: &mut Verdict) {}

pub fn post(_ctx: &Ctx, _call: &ToolCall, _response: &Value, _r: &mut PostResult) {}

pub fn start(_ctx: &Ctx, _v: &mut Verdict) {}
