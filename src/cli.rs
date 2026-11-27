//! The `guard` command line.

use clap::{Parser, Subcommand};

use crate::config::{self, Preset, TrustedHost};
use crate::text::term_safe;
use crate::{doctor, home, hook, install, pause, proxy, report, scan, top, vault};

#[derive(Parser)]
#[command(
    name = "guard",
    version,
    about = "A local security layer for AI coding agents."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Claude Code hook entry point (reads the event as JSON on stdin).
    Hook,
    /// Live view of every agent's tool calls, processes and connections.
    Top,
    /// One line for Claude Code's status line.
    Statusline {
        /// Also run the status line `guard install` wrapped, below Agent Guard's line.
        #[arg(long)]
        wrap: bool,
    },
    /// Check this machine's agent setup and fix what is unsafe.
    Doctor {
        /// Fix one finding by id (for example D03), or `all`.
        #[arg(long)]
        fix: Option<String>,
        /// Undo the last fix.
        #[arg(long)]
        undo: bool,
    },
    /// Scan installed plugins, skills, MCP servers and hooks; label each green, yellow or red.
    Scan,
    /// Run an MCP server through Agent Guard: `guard proxy -- npx some-server`.
    Proxy {
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Local HTTP(S) proxy that shows and filters the hosts agents connect to.
    NetProxy {
        #[arg(long, default_value = "127.0.0.1:8899")]
        listen: String,
    },
    /// Trusted hosts (calls to them are green).
    #[command(subcommand)]
    Trust(TrustCmd),
    /// Keys kept in the OS keychain instead of config files.
    #[command(subcommand)]
    Secret(vault::SecretCmd),
    /// Run a command with keys from the keychain: `guard run --secret GH=GITHUB_TOKEN -- cmd`.
    Run {
        #[arg(long = "secret", value_name = "NAME=ENV")]
        secrets: Vec<String>,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Summary of recent decisions.
    Report {
        /// How far back, for example `24h` or `7d`.
        #[arg(long, default_value = "24h")]
        since: String,
    },
    /// Explain a rule in plain words.
    Explain { rule: String },
    /// Set the default strictness.
    Level { preset: Preset },
    /// Pause checks (run this yourself, in a terminal; agents are blocked from it).
    Pause {
        #[arg(default_value = "15m")]
        duration: String,
    },
    /// End a pause early.
    Resume,
    /// Show whether Agent Guard is on, the level, and today's counts.
    Status,
    /// Add Agent Guard to Claude Code (hooks and status line).
    Install,
    /// Remove Agent Guard from Claude Code.
    Uninstall,
    /// Check that the hooks really block, ask and clean on this Claude Code version.
    Selftest,
}

#[derive(Subcommand)]
enum TrustCmd {
    /// Trust a host: `guard trust add api.example.com --ttl 1d`.
    Add {
        host: String,
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        process: Option<String>,
        /// How long, for example `1h` or `7d`. Forever if not set.
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Stop trusting a host.
    Rm { host: String },
    /// List trusted hosts, repositories and blocked hosts.
    List,
    /// Trust a repository's git hooks and config (default: the current directory).
    Repo { path: Option<std::path::PathBuf> },
    /// Block a host: calls to it are red, and the net proxy refuses it.
    Block { host: String },
    /// Review hosts seen recently and trust the ones you recognise.
    Review,
}

pub fn run() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Hook => hook::run(),
        Cmd::Top => top::run(),
        Cmd::Statusline { wrap } => crate::statusline::run(wrap),
        Cmd::Doctor { fix, undo } => doctor::run(fix.as_deref(), undo),
        Cmd::Scan => scan::run(),
        Cmd::Proxy { command } => proxy::run(&command),
        Cmd::NetProxy { listen } => proxy::net::run(&listen),
        Cmd::Trust(t) => trust(t),
        Cmd::Secret(s) => vault::run(s),
        Cmd::Run { secrets, command } => vault::exec(&secrets, &command),
        Cmd::Report { since } => report::run(&since),
        Cmd::Explain { rule } => report::explain(&rule),
        Cmd::Level { preset } => {
            let mut c = config::load().config;
            c.preset = preset;
            c.save()?;
            println!("level set to {preset:?}");
            Ok(())
        }
        Cmd::Pause { duration } => {
            let secs = pause::parse_duration(&duration)
                .ok_or_else(|| anyhow::anyhow!("bad duration {duration:?}; try 15m or 1h"))?;
            pause::pause_until(home::now() + secs)?;
            println!("Agent Guard paused for {duration}. `guard resume` ends it early.");
            Ok(())
        }
        Cmd::Resume => {
            pause::resume()?;
            println!("Agent Guard resumed.");
            Ok(())
        }
        Cmd::Status => report::status(),
        Cmd::Install => install::install(),
        Cmd::Uninstall => install::uninstall(),
        Cmd::Selftest => install::selftest(),
    }
}

fn trust(cmd: TrustCmd) -> anyhow::Result<()> {
    let mut c = config::load().config;
    match cmd {
        TrustCmd::Add {
            host,
            agent,
            process,
            ttl,
        } => {
            let expires_at = match ttl {
                Some(t) => Some(
                    home::now()
                        + pause::parse_duration(&t)
                            .ok_or_else(|| anyhow::anyhow!("bad ttl {t:?}; try 1h or 7d"))?,
                ),
                None => None,
            };
            c.trust.hosts.retain(|t| t.host != host);
            c.trust.hosts.push(TrustedHost {
                host: host.clone(),
                agent,
                process,
                expires_at,
            });
            c.save()?;
            println!("trusted {}", term_safe(&host));
        }
        TrustCmd::Rm { host } => {
            let before = c.trust.hosts.len();
            c.trust.hosts.retain(|t| t.host != host);
            if c.trust.hosts.len() == before {
                anyhow::bail!("{host} is not in the trusted list");
            }
            c.save()?;
            println!("removed {}", term_safe(&host));
        }
        TrustCmd::List => {
            if c.trust.hosts.is_empty() {
                println!("no trusted hosts");
            }
            for t in &c.trust.hosts {
                let mut extra = Vec::new();
                if let Some(a) = &t.agent {
                    extra.push(format!("agent={}", term_safe(a)));
                }
                if let Some(p) = &t.process {
                    extra.push(format!("process={}", term_safe(p)));
                }
                if let Some(e) = t.expires_at {
                    extra.push(format!(
                        "expires in {}m",
                        e.saturating_sub(home::now()) / 60
                    ));
                }
                println!("{}  {}", term_safe(&t.host), extra.join(" "));
            }
            for r in &c.trust.repos {
                println!("repo {}", term_safe(r));
            }
            for b in &c.trust.blocked {
                println!("blocked {}", term_safe(b));
            }
        }
        TrustCmd::Repo { path } => {
            let p = match path {
                Some(p) => p,
                None => std::env::current_dir()?,
            };
            let p = std::fs::canonicalize(&p)?.to_string_lossy().into_owned();
            if !c.trust.repos.contains(&p) {
                c.trust.repos.push(p.clone());
            }
            c.save()?;
            println!("trusted repository {}", term_safe(&p));
        }
        TrustCmd::Block { host } => {
            if !c.trust.blocked.contains(&host) {
                c.trust.blocked.push(host.clone());
            }
            c.save()?;
            println!("blocked {}", term_safe(&host));
        }
        TrustCmd::Review => crate::checks::net::review(&mut c)?,
    }
    Ok(())
}
