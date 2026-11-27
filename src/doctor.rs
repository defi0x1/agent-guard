//! `guard doctor`: checks the agent setup on this machine (Claude Code settings, MCP configs,
//! git) and fixes what is unsafe, with a backup for every fix.
//!
//! `guard doctor` only reads. `--fix <id|all>` changes files, after saving a copy in
//! `<guard home>/backups/<timestamp>/`; `--undo` puts the newest backup back.

mod backup;
mod checks;
mod files;
mod fixes;
mod secret;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{self, Config};
use crate::home;
use crate::level::Level;

/// Everything the doctor reads from the machine. Every path is a field, so tests use temp dirs.
pub struct Env {
    /// The user's home directory (`~`).
    pub home: PathBuf,
    /// Agent Guard's directory; backups go in `backups/` under it.
    pub guard_home: PathBuf,
    /// The current project.
    pub cwd: PathBuf,
    /// Claude Desktop's `claude_desktop_config.json`.
    pub desktop_config: PathBuf,
    pub config: Config,
    /// The environment Claude Code would start with.
    pub vars: BTreeMap<String, String>,
    /// Output of `claude --version`, if it ran.
    pub claude_version: Option<String>,
    /// Output of `git --version`, if it ran.
    pub git_version: Option<String>,
    /// The current version of an npm package (`npm view <pkg> version`).
    pub npm_version: fn(&str) -> Option<String>,
    /// Unix seconds, for the backup name.
    pub now: u64,
}

impl Env {
    /// The real machine: `$HOME`, the current directory, and the installed tools.
    pub fn from_system() -> anyhow::Result<Env> {
        let home = PathBuf::from(
            std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME is not set"))?,
        );
        let desktop_config = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/Claude/claude_desktop_config.json")
        } else {
            home.join(".config/Claude/claude_desktop_config.json")
        };
        Ok(Env {
            guard_home: home::dir()?,
            cwd: std::env::current_dir()?,
            desktop_config,
            config: config::load().config,
            vars: std::env::vars().collect(),
            claude_version: output("claude", &["--version"]),
            git_version: output("git", &["--version"]),
            npm_version: |pkg| output("npm", &["view", pkg, "version"]),
            now: home::now(),
            home,
        })
    }

    pub fn claude_json(&self) -> PathBuf {
        self.home.join(".claude.json")
    }

    pub fn user_settings(&self) -> PathBuf {
        self.home.join(".claude/settings.json")
    }

    pub fn mcp_json(&self) -> PathBuf {
        self.cwd.join(".mcp.json")
    }

    /// User, project and project-local settings, lowest precedence first, without repeats.
    pub fn settings_paths(&self) -> Vec<PathBuf> {
        let mut out = vec![self.user_settings()];
        for p in [
            self.cwd.join(".claude/settings.json"),
            self.cwd.join(".claude/settings.local.json"),
        ] {
            if !out.contains(&p) {
                out.push(p);
            }
        }
        out
    }

    /// `path` with the home directory shown as `~`.
    pub fn tilde(&self, path: &Path) -> String {
        match path.strip_prefix(&self.home) {
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => path.display().to_string(),
        }
    }
}

/// A program's trimmed stdout, if it ran and succeeded.
fn output(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !text.is_empty()).then_some(text)
}

/// Runs git in the project, with `env.home` as the home for `--global`. Stdout on success.
fn git(env: &Env, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(&env.cwd)
        .env("HOME", &env.home)
        .env_remove("XDG_CONFIG_HOME")
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// How a finding is fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    /// `guard doctor --fix <id>` fixes it.
    Auto,
    /// What the user should do.
    Advice(String),
    /// Nothing to do (passing checks).
    None,
}

/// One line of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Check id, for example `D03`.
    pub id: &'static str,
    pub level: Level,
    /// One plain sentence. Never contains a raw secret.
    pub message: String,
    pub fix: Fix,
}

impl Item {
    /// `[D03] <sentence> fix: guard doctor --fix D03`.
    pub fn line(&self) -> String {
        match &self.fix {
            Fix::Auto => format!(
                "[{}] {} fix: guard doctor --fix {}",
                self.id, self.message, self.id
            ),
            Fix::Advice(a) => format!("[{}] {} fix: {a}", self.id, self.message),
            Fix::None => format!("[{}] {}", self.id, self.message),
        }
    }
}

/// The rule id for a check: `doctor.d03`.
fn rule_id(id: &str) -> String {
    format!("doctor.{}", id.to_ascii_lowercase())
}

/// A report item at the user's level for this check (or `default`).
fn item(env: &Env, id: &'static str, default: Level, message: impl Into<String>, fix: Fix) -> Item {
    Item {
        id,
        level: env.config.level_for(&rule_id(id), |_| default),
        message: message.into(),
        fix,
    }
}

/// Rule ids this module emits, with a plain-words explanation each.
pub const RULES: &[(&str, &str)] = &[
    (
        "doctor.d00",
        "Agent Guard's hooks are missing or all hooks are disabled, so nothing checks Claude; run guard install.",
    ),
    (
        "doctor.d01",
        "A key is saved as plain text in an MCP config any program can read; move it with guard secret move <server> <VAR> and rotate it.",
    ),
    (
        "doctor.d02",
        "A key is in a git-tracked project file and can be pushed with your code; remove it and rotate it.",
    ),
    (
        "doctor.d03",
        "An MCP server downloads its newest version on every start; pin it with guard doctor --fix D03.",
    ),
    (
        "doctor.d04",
        "An MCP server's start command does more than start a tool (sudo, sh -c, curl | sh); review it.",
    ),
    (
        "doctor.d06",
        "Bypass mode lets Claude act without asking; guard doctor --fix D06 turns it off.",
    ),
    (
        "doctor.d07",
        "A broad allow rule, or one holding a key, removes your main safety check; guard doctor --fix D07 removes it.",
    ),
    (
        "doctor.d08",
        "enableAllProjectMcpServers lets any project start its own tools; guard doctor --fix D08 sets it false.",
    ),
    (
        "doctor.d09",
        "No deny rules keep Claude out of your credential files; guard doctor --fix D09 adds them.",
    ),
    (
        "doctor.d10",
        "Claude Code's sandbox is off, so commands can touch any file; guard doctor --fix D10 turns it on.",
    ),
    (
        "doctor.d11",
        "A filesystem MCP server can see your whole disk or home folder; narrow it to the project.",
    ),
    (
        "doctor.d13",
        "This project's settings run network commands or base64 in hooks, apiKeyHelper or env; review them.",
    ),
    (
        "doctor.d17",
        "A config or .env file can be read by other accounts; guard doctor --fix D17 makes it private.",
    ),
    (
        "doctor.d19",
        "Tools get your full environment, or raw tool data goes to telemetry; set CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1.",
    ),
    (
        "doctor.d22",
        "Claude Code is older than 2.1.300 and misses fixes Agent Guard relies on; run claude update.",
    ),
    (
        "doctor.d26",
        "Your git has known flaws that let a cloned repository run code; update git.",
    ),
    (
        "doctor.d27",
        "Global git clone protections are off; guard doctor --fix D27 sets them.",
    ),
];

/// Runs every check. A passing check gets one green line.
pub fn check(env: &Env) -> Vec<Item> {
    let s = files::State::load(env);
    let mut out = Vec::new();
    for (id, ok, f) in checks::CHECKS {
        let mut items = Vec::new();
        f(env, &s, &mut items);
        if items.is_empty() {
            items.push(Item {
                id,
                level: Level::Green,
                message: (*ok).to_string(),
                fix: Fix::None,
            });
        }
        out.extend(items);
    }
    out
}

/// The report, grouped red, yellow, green.
pub fn render(items: &[Item]) -> String {
    let mut out = String::new();
    for (name, levels) in [
        ("red", &[Level::HardBlock, Level::Red][..]),
        ("yellow", &[Level::Yellow][..]),
        ("green", &[Level::Green][..]),
    ] {
        let group: Vec<&Item> = items.iter().filter(|i| levels.contains(&i.level)).collect();
        if group.is_empty() {
            continue;
        }
        out.push_str(&format!("{name}\n"));
        for i in group {
            out.push_str(&format!("  {}\n", i.line()));
        }
    }
    out
}

/// Applies the fix for `which` (a check id, or `all` for every automatic fix that is due).
/// Saves a backup first; if a fix fails, what it already changed is put back.
pub fn fix(env: &Env, which: &str) -> anyhow::Result<Vec<String>> {
    let items = check(env);
    let ids: Vec<&'static str> = if which.eq_ignore_ascii_case("all") {
        let mut ids: Vec<&'static str> = items
            .iter()
            .filter(|i| i.fix == Fix::Auto && i.level != Level::Green)
            .map(|i| i.id)
            .collect();
        ids.dedup();
        ids
    } else {
        let id = checks::CHECKS
            .iter()
            .map(|c| c.0)
            .find(|c| c.eq_ignore_ascii_case(which))
            .ok_or_else(|| anyhow::anyhow!("unknown check {which:?}; ids look like D03"))?;
        vec![id]
    };
    let mut backup = backup::Backup::new(env);
    let mut done = Vec::new();
    for id in ids {
        if !items.iter().any(|i| i.id == id && i.fix == Fix::Auto) {
            done.push(format!("{id}: nothing to fix automatically"));
            continue;
        }
        match fixes::apply(env, id, &mut backup) {
            Ok(lines) => done.extend(lines.into_iter().map(|l| format!("{id}: {l}"))),
            Err(e) => {
                backup.restore(env)?;
                return Err(e.context(format!("{id} failed; nothing was changed")));
            }
        }
    }
    if !backup.is_empty() {
        done.push("backup saved; guard doctor --undo puts it back".into());
    }
    Ok(done)
}

/// Restores the newest backup. Returns what was put back.
pub fn undo(env: &Env) -> anyhow::Result<Vec<String>> {
    backup::undo_last(env)
}

/// `guard doctor [--fix <id|all>] [--undo]`.
pub fn run(fix_id: Option<&str>, undo_last: bool) -> anyhow::Result<()> {
    let env = Env::from_system()?;
    let lines = match (fix_id, undo_last) {
        (Some(_), true) => anyhow::bail!("use either --fix or --undo, not both"),
        (_, true) => undo(&env)?,
        (Some(id), false) => fix(&env, id)?,
        (None, false) => {
            print!("{}", render(&check(&env)));
            return Ok(());
        }
    };
    for l in lines {
        println!("{l}");
    }
    Ok(())
}
