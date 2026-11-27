//! Network: hosts the agent sends data to (Bash, WebFetch, MCP arguments), unknown hosts, raw IPs,
//! uploads, pipe-to-shell, and risky package installs.

use crate::checks::{Ctx, ToolCall};
use crate::level::Verdict;

pub fn pre(_ctx: &Ctx, _call: &ToolCall, _v: &mut Verdict) {}

/// `guard trust review`: lists recently seen hosts and lets the user trust them.
pub fn review(_config: &mut crate::config::Config) -> anyhow::Result<()> {
    anyhow::bail!("not implemented yet")
}
