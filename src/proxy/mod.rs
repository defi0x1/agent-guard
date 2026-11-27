//! `guard proxy -- <server>`: a stdio MCP proxy that checks tool definitions (normalise, pin,
//! quarantine changed tools) and keeps the server environment small.

pub mod net;

pub fn run(_command: &[String]) -> anyhow::Result<()> {
    anyhow::bail!("not implemented yet")
}
