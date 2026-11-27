//! Protected files and credential stores: Claude's settings, hooks and MCP configs, Agent Guard's
//! own directory, and files such as `~/.ssh/id_*` or `~/.aws/credentials`.

use crate::checks::{Ctx, ToolCall};
use crate::level::Verdict;

pub fn pre(_ctx: &Ctx, _call: &ToolCall, _v: &mut Verdict) {}

/// Rule ids this module emits, with a plain-words explanation each.
pub const RULES: &[(&str, &str)] = &[];
