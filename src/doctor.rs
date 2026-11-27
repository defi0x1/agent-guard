//! `guard doctor`: checks the agent setup on this machine (Claude Code settings, MCP configs,
//! git) and fixes what is unsafe, with a backup for every fix.

pub fn run(_fix: Option<&str>, _undo: bool) -> anyhow::Result<()> {
    anyhow::bail!("not implemented yet")
}
