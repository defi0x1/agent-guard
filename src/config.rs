//! The user's settings: `config.toml` in the Agent Guard directory. Read on every hook call, so
//! edits apply at once. A missing file means defaults; a broken file also means defaults
//! (Recommended), never "no protection".

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::home;
use crate::level::Level;

/// How strict the defaults are. Presets only move rules between levels.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    Relaxed,
    #[default]
    Recommended,
    Strict,
}

/// A host the user trusts. Calls to it are green unless a secret of another provider goes there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedHost {
    /// `api.example.com`, or `*.example.com` for every subdomain.
    pub host: String,
    /// Only for this agent (for example `claude`), if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Only for this MCP server or process name, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    /// Unix time after which the entry no longer applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// A user override for one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleOverride {
    pub level: Level,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trust {
    #[serde(default)]
    pub hosts: Vec<TrustedHost>,
    /// Repositories (absolute paths) whose git hooks and config the user trusts.
    #[serde(default)]
    pub repos: Vec<String>,
    /// Hosts the user blocked: calls to them are red, and `guard net-proxy` refuses them.
    #[serde(default)]
    pub blocked: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub preset: Preset,
    #[serde(default)]
    pub trust: Trust,
    /// Rule id to level, for example `"network.raw_ip" = { level = "red" }`.
    #[serde(default)]
    pub rules: BTreeMap<String, RuleOverride>,
}

/// The loaded config, and the parse error if the file was broken (then `config` is the default).
pub struct Loaded {
    pub config: Config,
    pub error: Option<String>,
}

pub fn path() -> std::io::Result<PathBuf> {
    Ok(home::dir()?.join("config.toml"))
}

pub fn load_from(p: &Path) -> Loaded {
    match fs::read_to_string(p) {
        Err(_) => Loaded {
            config: Config::default(),
            error: None,
        },
        Ok(text) => match toml::from_str(&text) {
            Ok(config) => Loaded {
                config,
                error: None,
            },
            Err(e) => Loaded {
                config: Config::default(),
                error: Some(format!("{}: {e}", p.display())),
            },
        },
    }
}

pub fn load() -> Loaded {
    match path() {
        Ok(p) => load_from(&p),
        Err(e) => Loaded {
            config: Config::default(),
            error: Some(e.to_string()),
        },
    }
}

impl Config {
    pub fn save(&self) -> anyhow::Result<()> {
        home::ensure()?;
        let text = toml::to_string_pretty(self)?;
        home::write_private(&path()?, text.as_bytes())?;
        Ok(())
    }

    /// The level for `rule`: the user's override, else the preset's default.
    pub fn level_for(&self, rule: &str, default: impl Fn(Preset) -> Level) -> Level {
        self.rules
            .get(rule)
            .map_or_else(|| default(self.preset), |o| o.level)
    }

    /// Whether the user blocked `host`.
    pub fn host_blocked(&self, host: &str) -> bool {
        self.trust.blocked.iter().any(|b| host_matches(b, host))
    }

    /// Whether the repository at `path` (absolute) is trusted.
    pub fn repo_trusted(&self, path: &Path) -> bool {
        self.trust.repos.iter().any(|r| Path::new(r) == path)
    }

    /// Whether `host` is trusted for this agent and process at time `now`.
    pub fn host_trusted(
        &self,
        host: &str,
        agent: Option<&str>,
        process: Option<&str>,
        now: u64,
    ) -> bool {
        self.trust.hosts.iter().any(|t| {
            t.expires_at.is_none_or(|e| now < e)
                && t.agent.as_deref().is_none_or(|a| Some(a) == agent)
                && t.process.as_deref().is_none_or(|p| Some(p) == process)
                && host_matches(&t.host, host)
        })
    }
}

/// `pattern` is a host or `*.domain`. Case-insensitive; a port and a trailing dot are ignored.
/// `*.example.com` matches subdomains, not `example.com` itself.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let norm = |h: &str| {
        let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
        // Strip a port, but not from a bracketed IPv6 address's inside.
        match h.rsplit_once(':') {
            Some((name, port))
                if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                name.to_string()
            }
            _ => h,
        }
    };
    let (p, h) = (norm(pattern), norm(host));
    match p.strip_prefix("*.") {
        Some(domain) => h.len() > domain.len() + 1 && h.ends_with(&format!(".{domain}")),
        None => p == h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_patterns() {
        assert!(host_matches("api.github.com", "API.github.com."));
        assert!(host_matches("api.github.com", "api.github.com:443"));
        assert!(host_matches("*.github.com", "api.github.com"));
        assert!(host_matches("*.github.com", "a.b.github.com"));
        assert!(!host_matches("*.github.com", "github.com"));
        assert!(!host_matches("*.github.com", "evilgithub.com"));
        assert!(!host_matches("*.github.com", "github.com.evil.io"));
        assert!(!host_matches("api.github.com", "api.github.com.evil.io"));
    }

    #[test]
    fn trust_respects_agent_process_and_expiry() {
        let c = Config {
            trust: Trust {
                hosts: vec![
                    TrustedHost {
                        host: "api.openai.com".into(),
                        agent: Some("codex".into()),
                        process: None,
                        expires_at: None,
                    },
                    TrustedHost {
                        host: "*.ngrok-free.app".into(),
                        agent: None,
                        process: None,
                        expires_at: Some(100),
                    },
                ],
                ..Trust::default()
            },
            ..Config::default()
        };
        assert!(c.host_trusted("api.openai.com", Some("codex"), None, 0));
        assert!(!c.host_trusted("api.openai.com", Some("claude"), None, 0));
        assert!(c.host_trusted("x.ngrok-free.app", None, None, 99));
        assert!(!c.host_trusted("x.ngrok-free.app", None, None, 100));
    }

    #[test]
    fn broken_file_falls_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.toml");
        std::fs::write(&p, "preset = 'nonsense'").unwrap();
        let l = load_from(&p);
        assert_eq!(l.config, Config::default());
        assert!(l.error.is_some());
        std::fs::write(
            &p,
            "preset = 'strict'\n[rules]\n'network.raw_ip' = { level = 'red' }\n",
        )
        .unwrap();
        let l = load_from(&p);
        assert!(l.error.is_none());
        assert_eq!(l.config.preset, Preset::Strict);
        assert_eq!(
            l.config.level_for("network.raw_ip", |_| Level::Yellow),
            Level::Red
        );
        assert_eq!(
            l.config.level_for("other", |_| Level::Yellow),
            Level::Yellow
        );
    }
}
