//! Git: repository config and hooks that run commands, and clones on a vulnerable git.

use crate::checks::{Ctx, ToolCall};
use crate::level::Verdict;

pub fn pre(_ctx: &Ctx, _call: &ToolCall, _v: &mut Verdict) {}

pub fn session_start(_ctx: &Ctx, _v: &mut Verdict) {}

/// Rule ids this module emits, with a plain-words explanation each.
pub const RULES: &[(&str, &str)] = &[];
