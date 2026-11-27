//! Keys in the OS keychain: `guard secret move|list|rm` and `guard run --secret NAME=ENV -- cmd`.

#[derive(clap::Subcommand)]
pub enum SecretCmd {
    /// List keys stored by Agent Guard.
    List,
}

pub fn run(_cmd: SecretCmd) -> anyhow::Result<()> {
    anyhow::bail!("not implemented yet")
}

pub fn exec(_secrets: &[String], _command: &[String]) -> anyhow::Result<()> {
    anyhow::bail!("not implemented yet")
}
