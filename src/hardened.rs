//! Hardened mode: Agent Guard's hooks and policy in Claude Code's managed settings, which only
//! root can change and nothing below them can override, plus Claude Code's sandbox with an
//! explicit deny list. The guard binary and the pause and trust state live in root-owned
//! folders, so an agent running as the user cannot turn any of it off.
//!
//! Each layer covers a gap in the others: the sandbox stops Bash and its child processes,
//! `permissions.deny` stops the Read, Edit and Write tools (the sandbox does not cover them),
//! and managed settings keep the hooks on and bypass mode off.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use serde_json::{Map, Value, json};

use crate::config::Config;

/// Hosts sandboxed commands may reach out of the box: Anthropic's API, git over HTTPS to GitHub
/// and the npm, PyPI and crates.io registries. `guard trust add` extends the list.
pub const DEFAULT_DOMAINS: &[&str] = &[
    "api.anthropic.com",
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "index.crates.io",
];

/// Credential stores no tool or command may read: (path under `~`, is a folder).
const SECRETS: &[(&str, bool)] = &[
    (".ssh", true),
    (".aws", true),
    (".config/gcloud", true),
    (".kube", true),
    (".gnupg", true),
    ("Library/Keychains", true),
    (".docker/config.json", false),
    (".netrc", false),
    (".npmrc", false),
    (".claude/.credentials.json", false),
    (".agent-guard", true),
];

/// Places that run code later or hold settings, which no tool or command may change.
const PROTECTED: &[(&str, bool)] = &[
    (".zshrc", false),
    (".zshenv", false),
    (".zprofile", false),
    (".zlogin", false),
    (".bashrc", false),
    (".bash_profile", false),
    (".profile", false),
    (".config/fish", true),
    ("Library/LaunchAgents", true),
    (".local/bin", true),
    (".gitconfig", false),
    (".config/git", true),
];

/// The hook events, and whether each one takes a tool matcher.
const EVENTS: [(&str, bool); 4] = [
    ("PreToolUse", true),
    ("PostToolUse", true),
    ("UserPromptSubmit", false),
    ("SessionStart", false),
];

const PAUSE_FILE: &str = "pause.until";
const HOSTS_FILE: &str = "trusted-hosts";

/// Where hardened mode puts things. [`Paths::system`] on a real machine; tests use temp dirs.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Claude Code's managed settings file.
    pub managed_settings: PathBuf,
    /// The root-owned copy of the guard binary the hooks run.
    pub binary: PathBuf,
    /// The root-owned folder with the pause state and trusted hosts.
    pub policy_dir: PathBuf,
}

impl Paths {
    pub fn system() -> Paths {
        let (managed, policy) = if cfg!(target_os = "macos") {
            (
                "/Library/Application Support/ClaudeCode/managed-settings.json",
                "/Library/Application Support/AgentGuard",
            )
        } else {
            ("/etc/claude-code/managed-settings.json", "/etc/agent-guard")
        };
        Paths {
            managed_settings: managed.into(),
            binary: "/usr/local/libexec/agent-guard/guard".into(),
            policy_dir: policy.into(),
        }
    }

    fn binary_dir(&self) -> &Path {
        self.binary.parent().unwrap_or(Path::new("/"))
    }

    fn managed_dir(&self) -> &Path {
        self.managed_settings.parent().unwrap_or(Path::new("/"))
    }

    /// The root-owned folders, for the deny lists.
    fn root_dirs(&self) -> [&Path; 3] {
        [self.binary_dir(), &self.policy_dir, self.managed_dir()]
    }
}

/// A permission rule path: `~/x` stays, an absolute `/x` becomes `//x` (a single leading slash
/// would anchor at the settings file, not the filesystem root).
fn rule_path(p: &str, dir: bool) -> String {
    let p = if p.starts_with('/') {
        format!("/{p}")
    } else {
        p.to_string()
    };
    if dir { format!("{p}/**") } else { p }
}

fn home(p: &str) -> String {
    format!("~/{p}")
}

/// `permissions.deny`: reads of credential stores, and edits of settings, guard files and the
/// places that run code later. Deny rules apply to tool calls only, never to Claude Code's
/// own writes (such as `~/.claude.json`), so those keep working.
pub fn deny_rules(paths: &Paths) -> Vec<String> {
    let mut out = Vec::new();
    for (p, dir) in SECRETS {
        let r = rule_path(&home(p), *dir);
        out.push(format!("Read({r})"));
        out.push(format!("Edit({r})"));
    }
    let mut edit: Vec<String> = vec![
        "~/.claude/settings*".into(),
        rule_path("~/.claude/plugins", true),
        "~/.claude.json".into(),
    ];
    edit.extend(PROTECTED.iter().map(|(p, dir)| rule_path(&home(p), *dir)));
    edit.extend(
        paths
            .root_dirs()
            .iter()
            .map(|d| rule_path(&d.to_string_lossy(), true)),
    );
    out.extend(edit.into_iter().map(|r| format!("Edit({r})")));
    out
}

/// The `sandbox` block. `trusted` are the user's extra hosts.
pub fn sandbox(paths: &Paths, trusted: &[String]) -> Value {
    let deny_read: Vec<String> = SECRETS.iter().map(|(p, _)| home(p)).collect();
    let mut deny_write: Vec<String> =
        vec![home(".agent-guard"), home(".claude"), home(".claude.json")];
    deny_write.extend(PROTECTED.iter().map(|(p, _)| home(p)));
    deny_write.extend(
        paths
            .root_dirs()
            .iter()
            .map(|d| d.to_string_lossy().into_owned()),
    );
    json!({
        "enabled": true,
        "failIfUnavailable": true,
        "allowUnsandboxedCommands": false,
        "filesystem": {
            "denyRead": deny_read,
            "denyWrite": deny_write,
            "allowManagedReadPathsOnly": true,
        },
        "network": {
            "allowedDomains": domains(trusted),
            "allowManagedDomainsOnly": true,
        },
    })
}

/// The default hosts plus `trusted`, without repeats or broad entries.
pub fn domains(trusted: &[String]) -> Vec<String> {
    let mut out: Vec<String> = DEFAULT_DOMAINS.iter().map(|d| d.to_string()).collect();
    for h in trusted {
        let h = h.trim().to_ascii_lowercase();
        if !h.is_empty() && !broad_domain(&h) && !out.contains(&h) {
            out.push(h);
        }
    }
    out
}

/// The managed settings hardened mode writes: hooks that run `binary hook` directly (no shell),
/// fail closed, and are the only hooks allowed; bypass mode off; deny rules; the sandbox.
pub fn managed_settings(paths: &Paths, trusted: &[String]) -> Value {
    let mut hooks = Map::new();
    for (event, matcher) in EVENTS {
        let hook = json!({
            "type": "command",
            "command": paths.binary,
            "args": ["hook"],
            "timeout": 10,
            "onFailure": "block",
        });
        let group = if matcher {
            json!({"matcher": "*", "hooks": [hook]})
        } else {
            json!({"hooks": [hook]})
        };
        hooks.insert(event.into(), json!([group]));
    }
    json!({
        "allowManagedHooksOnly": true,
        "hooks": hooks,
        "permissions": {
            "disableBypassPermissionsMode": "disable",
            "deny": deny_rules(paths),
        },
        "sandbox": sandbox(paths, trusted),
    })
}

/// The hosts from the user's config that can go into the sandbox allowlist: entries for every
/// agent or for `claude`, for every process, and without an expiry (the allowlist is static).
pub fn trusted_from_config(c: &Config) -> Vec<String> {
    c.trust
        .hosts
        .iter()
        .filter(|t| t.agent.as_deref().is_none_or(|a| a == "claude"))
        .filter(|t| t.process.is_none() && t.expires_at.is_none())
        .map(|t| t.host.clone())
        .collect()
}

/// Whether an allowlist entry opens too much: `*`, or a wildcard over a whole top-level
/// domain such as `*.com`.
pub fn broad_domain(d: &str) -> bool {
    let d = d.trim().trim_end_matches('.');
    match d.strip_prefix("*.") {
        _ if d == "*" || d.is_empty() => true,
        Some(rest) => !rest.contains('.') || rest.contains('*'),
        None => d.contains('*'),
    }
}

/// Programs that run anything they are given; excluding one from the sandbox excludes all.
const ESCAPES: &[&str] = &[
    "*",
    "docker",
    "podman",
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "env",
    "sudo",
    "python",
    "python3",
    "node",
    "deno",
    "bun",
    "ruby",
    "perl",
    "osascript",
    "nerdctl",
    "lima",
    "colima",
];

/// Sandbox settings in `settings` that break the boundary, one phrase each.
pub fn dangers(settings: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(sb) = settings.get("sandbox") else {
        return out;
    };
    if sb.get("allowAppleEvents") == Some(&json!(true)) {
        out.push("sandbox.allowAppleEvents is true (AppleScript can drive any app)".into());
    }
    if sb.get("allowUnsandboxedCommands") == Some(&json!(true)) {
        out.push(
            "sandbox.allowUnsandboxedCommands is true (commands can leave the sandbox)".into(),
        );
    }
    if sb.pointer("/network/allowAllUnixSockets") == Some(&json!(true)) {
        out.push("sandbox.network.allowAllUnixSockets is true (the Docker socket is root)".into());
    }
    for c in strings(sb.get("excludedCommands")) {
        let inner = c
            .strip_prefix("Bash(")
            .and_then(|s| s.strip_suffix(')'))
            .unwrap_or(c);
        let program = inner.split_whitespace().next().unwrap_or("");
        let program = program.rsplit('/').next().unwrap_or(program);
        if program.starts_with('*') || ESCAPES.contains(&program) {
            out.push(format!(
                "sandbox.excludedCommands has \"{c}\", which runs anything outside the sandbox"
            ));
        }
    }
    for d in strings(sb.pointer("/network/allowedDomains")) {
        if broad_domain(d) {
            out.push(format!(
                "sandbox.network.allowedDomains has \"{d}\", which opens most of the internet"
            ));
        }
    }
    out
}

fn strings(v: Option<&Value>) -> Vec<&str> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// The programs of the hardened (`args: ["hook"]`) guard hooks in `settings`.
pub fn guard_hook_binaries(settings: &Value) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let Some(hooks) = settings.get("hooks").and_then(Value::as_object) else {
        return out;
    };
    for groups in hooks.values().filter_map(Value::as_array) {
        for g in groups {
            for h in g
                .get("hooks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if is_guard_hook(h) {
                    let p = PathBuf::from(h["command"].as_str().unwrap_or(""));
                    if !out.contains(&p) {
                        out.push(p);
                    }
                }
            }
        }
    }
    out
}

fn is_guard_hook(h: &Value) -> bool {
    h.get("args") == Some(&json!(["hook"]))
        && h.get("command")
            .and_then(Value::as_str)
            .map(Path::new)
            .and_then(Path::file_name)
            .is_some_and(|n| n == "guard" || n == "agent-guard")
}

/// Reads a JSON settings file; `None` if missing or unreadable.
pub fn read_json(p: &Path) -> Option<Value> {
    serde_json::from_str(&fs::read_to_string(p).ok()?).ok()
}

/// Whether hardened mode is installed: the managed settings run the guard hook.
pub fn installed(paths: &Paths) -> bool {
    read_json(&paths.managed_settings).is_some_and(|v| !guard_hook_binaries(&v).is_empty())
}

/// The first of `path` and its existing ancestors that the user could change: not owned by
/// root, or writable by group or others. `None` when the whole chain is root's.
pub fn unsafe_ancestor(path: &Path) -> Option<PathBuf> {
    for p in path.ancestors() {
        let Ok(m) = fs::symlink_metadata(p) else {
            continue;
        };
        let sticky_dir = m.is_dir() && m.mode() & 0o1000 != 0;
        if m.uid() != 0 || (m.mode() & 0o022 != 0 && !sticky_dir) {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// Whether the process runs as root (`/usr/bin/id -u` prints 0).
pub fn is_root() -> bool {
    Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "0")
}

/// In hardened mode, `what` (pause, trust, level) needs root. Errors with the sudo command.
pub fn require_root(paths: &Paths, what: &str, root: bool) -> anyhow::Result<()> {
    if installed(paths) && !root {
        bail!(
            "hardened mode is on, so {what} needs root; run it again with sudo: sudo guard {what} ..."
        );
    }
    Ok(())
}

/// The pause file hardened mode reads (the user's `~/.agent-guard/pause.until` is ignored).
pub fn pause_file(paths: &Paths) -> PathBuf {
    paths.policy_dir.join(PAUSE_FILE)
}

pub fn pause_until(paths: &Paths, until: u64) -> io::Result<()> {
    write_file(&pause_file(paths), until.to_string().as_bytes(), 0o644)
}

pub fn resume(paths: &Paths) -> io::Result<()> {
    match fs::remove_file(pause_file(paths)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// The pause end time, if a hardened-mode pause is active at `now`.
pub fn pause_active(paths: &Paths, now: u64) -> Option<u64> {
    let until: u64 = fs::read_to_string(pause_file(paths))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    (now < until).then_some(until)
}

/// The trusted hosts hardened mode put in the sandbox allowlist.
pub fn trusted_hosts(paths: &Paths) -> Vec<String> {
    fs::read_to_string(paths.policy_dir.join(HOSTS_FILE))
        .map(|t| {
            t.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Saves `hosts` as the trusted hosts and rewrites the managed allowlist to match. Run as root
/// by `guard trust add|rm` in hardened mode.
pub fn set_trusted_hosts(paths: &Paths, hosts: &[String]) -> anyhow::Result<()> {
    let mut s = read_json(&paths.managed_settings).context("hardened mode is not installed")?;
    s["sandbox"]["network"]["allowedDomains"] = json!(domains(hosts));
    write_file(
        &paths.policy_dir.join(HOSTS_FILE),
        hosts_text(hosts).as_bytes(),
        0o644,
    )?;
    write_file(&paths.managed_settings, pretty(&s)?.as_bytes(), 0o644)?;
    Ok(())
}

fn hosts_text(hosts: &[String]) -> String {
    hosts.iter().map(|h| format!("{h}\n")).collect()
}

fn pretty(v: &Value) -> anyhow::Result<String> {
    let mut t = serde_json::to_string_pretty(v)?;
    t.push('\n');
    Ok(t)
}

/// `existing` (an admin's managed settings, if any) with hardened mode's settings added:
/// objects merge, lists gain the missing entries, our values win, and old guard hooks go.
fn merge(existing: Option<Value>, ours: Value) -> Value {
    let Some(mut base) = existing else {
        return ours;
    };
    if let Some(hooks) = base.get_mut("hooks").and_then(Value::as_object_mut) {
        for groups in hooks.values_mut().filter_map(Value::as_array_mut) {
            groups.retain_mut(|g| match g.get_mut("hooks").and_then(Value::as_array_mut) {
                Some(list) => {
                    list.retain(|h| !is_guard_hook(h));
                    !list.is_empty()
                }
                None => true,
            });
        }
    }
    merge_value(&mut base, ours);
    base
}

fn merge_value(base: &mut Value, ours: Value) {
    match (base, ours) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(slot) => merge_value(slot, v),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (Value::Array(b), Value::Array(o)) => {
            for v in o {
                if !b.contains(&v) {
                    b.push(v);
                }
            }
        }
        (slot, v) => *slot = v,
    }
}

/// One root-owned file operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Create the folder (and parents), mode 0755, owned by root.
    Dir(PathBuf),
    /// Copy the binary, mode 0755, owned by root.
    Copy { from: PathBuf, to: PathBuf },
    /// Copy a file aside before it is replaced.
    Backup { from: PathBuf, to: PathBuf },
    /// Write a file, mode 0644, owned by root.
    Write { path: PathBuf, content: String },
    /// Move a backup back into place.
    Restore { from: PathBuf, to: PathBuf },
    /// Delete a file or folder.
    Remove(PathBuf),
}

/// What `guard install --hardened` or `guard uninstall --hardened` will do.
#[derive(Debug, Default)]
pub struct Plan {
    pub steps: Vec<Step>,
}

/// The install plan. `exe` is the binary to copy, `trusted` the user's hosts, `now` the
/// backup suffix. Refuses when the merged settings would hold a boundary-breaking entry.
pub fn install_plan(
    paths: &Paths,
    exe: &Path,
    trusted: &[String],
    now: u64,
) -> anyhow::Result<Plan> {
    let existing = match fs::read_to_string(&paths.managed_settings) {
        Ok(t) => Some(serde_json::from_str::<Value>(&t).with_context(|| {
            format!(
                "{} is not valid JSON; fix it first",
                paths.managed_settings.display()
            )
        })?),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).context(format!("reading {}", paths.managed_settings.display())),
    };
    let ours_already = existing
        .as_ref()
        .is_some_and(|v| !guard_hook_binaries(v).is_empty());
    let hosts = domains(trusted)
        .into_iter()
        .filter(|d| !DEFAULT_DOMAINS.contains(&d.as_str()))
        .collect::<Vec<_>>();
    let settings = merge(existing, managed_settings(paths, &hosts));
    let bad = dangers(&settings);
    if !bad.is_empty() {
        bail!(
            "{} has settings that break the sandbox, so hardened mode was not installed: {}",
            paths.managed_settings.display(),
            bad.join("; ")
        );
    }

    let mut steps = vec![Step::Dir(paths.binary_dir().to_path_buf())];
    if fs::canonicalize(exe).ok() != fs::canonicalize(&paths.binary).ok() {
        steps.push(Step::Copy {
            from: exe.to_path_buf(),
            to: paths.binary.clone(),
        });
    }
    steps.push(Step::Dir(paths.policy_dir.clone()));
    steps.push(Step::Write {
        path: paths.policy_dir.join(HOSTS_FILE),
        content: hosts_text(&hosts),
    });
    steps.push(Step::Dir(paths.managed_dir().to_path_buf()));
    // Only an admin's own file is backed up, so uninstall restores it and not an older copy
    // of ours.
    if paths.managed_settings.exists() && !ours_already {
        steps.push(Step::Backup {
            from: paths.managed_settings.clone(),
            to: backup_name(&paths.managed_settings, now),
        });
    }
    steps.push(Step::Write {
        path: paths.managed_settings.clone(),
        content: pretty(&settings)?,
    });
    Ok(Plan { steps })
}

/// The uninstall plan: the newest backup goes back (or our file is deleted), and the binary and
/// policy folder are removed.
pub fn uninstall_plan(paths: &Paths) -> Plan {
    let mut steps = Vec::new();
    if let Some(b) = newest_backup(&paths.managed_settings) {
        steps.push(Step::Restore {
            from: b,
            to: paths.managed_settings.clone(),
        });
    } else if installed(paths) {
        steps.push(Step::Remove(paths.managed_settings.clone()));
    }
    if paths.binary.exists() {
        steps.push(Step::Remove(paths.binary.clone()));
    }
    if paths.policy_dir.exists() {
        steps.push(Step::Remove(paths.policy_dir.clone()));
    }
    Plan { steps }
}

fn backup_name(file: &Path, now: u64) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(format!(".bak.{now}"));
    PathBuf::from(name)
}

fn newest_backup(file: &Path) -> Option<PathBuf> {
    let dir = file.parent()?;
    let prefix = format!("{}.bak.", file.file_name()?.to_string_lossy());
    fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            let ts: u64 = n.strip_prefix(&prefix)?.parse().ok()?;
            Some((ts, e.path()))
        })
        .max()
        .map(|(_, p)| p)
}

impl Plan {
    /// The plan in plain lines, with every file's full content.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        for s in &self.steps {
            let line = match s {
                Step::Dir(p) => format!("create folder {} (root, 0755)", p.display()),
                Step::Copy { from, to } => {
                    format!("copy {} to {} (root, 0755)", from.display(), to.display())
                }
                Step::Backup { from, to } => {
                    format!("back up {} to {}", from.display(), to.display())
                }
                Step::Write { path, content } => {
                    format!("write {} (root, 0644):\n{content}", path.display())
                }
                Step::Restore { from, to } => {
                    format!("restore {} from {}", to.display(), from.display())
                }
                Step::Remove(p) => format!("remove {}", p.display()),
            };
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    /// Runs the plan. With `as_root`, every created file and folder is handed to root (uid and
    /// gid 0); tests run without it on temp paths.
    pub fn apply(&self, as_root: bool) -> anyhow::Result<()> {
        let own = |p: &Path| -> anyhow::Result<()> {
            if as_root {
                std::os::unix::fs::chown(p, Some(0), Some(0))
                    .with_context(|| format!("giving {} to root", p.display()))?;
            }
            Ok(())
        };
        for s in &self.steps {
            match s {
                Step::Dir(p) => {
                    fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
                    fs::set_permissions(p, fs::Permissions::from_mode(0o755))?;
                    own(p)?;
                }
                Step::Copy { from, to } => {
                    let data =
                        fs::read(from).with_context(|| format!("reading {}", from.display()))?;
                    write_file(to, &data, 0o755)
                        .with_context(|| format!("writing {}", to.display()))?;
                    own(to)?;
                }
                Step::Backup { from, to } => {
                    fs::copy(from, to).with_context(|| format!("backing up {}", from.display()))?;
                }
                Step::Write { path, content } => {
                    write_file(path, content.as_bytes(), 0o644)
                        .with_context(|| format!("writing {}", path.display()))?;
                    own(path)?;
                }
                Step::Restore { from, to } => {
                    fs::rename(from, to).with_context(|| format!("restoring {}", to.display()))?;
                }
                Step::Remove(p) => {
                    let r = if p.is_dir() {
                        fs::remove_dir_all(p)
                    } else {
                        fs::remove_file(p)
                    };
                    r.with_context(|| format!("removing {}", p.display()))?;
                    if let Some(dir) = p.parent().filter(|_| p.ends_with("guard")) {
                        // The binary's own folder, once empty.
                        let _ = fs::remove_dir(dir);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Writes `data` to `path` atomically (a new temp file in the same folder, then rename) with
/// `mode`.
fn write_file(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(data)?;
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths(dir: &Path) -> Paths {
        Paths {
            managed_settings: dir.join("ClaudeCode/managed-settings.json"),
            binary: dir.join("libexec/agent-guard/guard"),
            policy_dir: dir.join("AgentGuard"),
        }
    }

    #[test]
    fn managed_settings_golden() {
        let paths = Paths::system();
        let s = managed_settings(&paths, &["api.example.com".into()]);
        // Round-trips as JSON.
        let text = pretty(&s).unwrap();
        let s: Value = serde_json::from_str(&text).unwrap();

        assert_eq!(s["allowManagedHooksOnly"], true);
        for (event, matcher) in EVENTS {
            let group = &s["hooks"][event][0];
            assert_eq!(group.get("matcher").is_some(), matcher, "{event}");
            let h = &group["hooks"][0];
            assert_eq!(h["type"], "command");
            assert_eq!(h["command"], "/usr/local/libexec/agent-guard/guard");
            assert_eq!(h["args"], json!(["hook"]), "{event} runs without a shell");
            assert_eq!(h["timeout"], 10);
            assert_eq!(h["onFailure"], "block", "{event} fails closed");
        }
        assert_eq!(s["permissions"]["disableBypassPermissionsMode"], "disable");
        let deny = strings(s.pointer("/permissions/deny"));
        for r in [
            "Read(~/.ssh/**)",
            "Read(~/.aws/**)",
            "Read(~/.config/gcloud/**)",
            "Read(~/.kube/**)",
            "Read(~/.gnupg/**)",
            "Read(~/Library/Keychains/**)",
            "Read(~/.claude/.credentials.json)",
            "Read(~/.docker/config.json)",
            "Read(~/.netrc)",
            "Read(~/.npmrc)",
            "Edit(~/.ssh/**)",
            "Edit(~/.claude/settings*)",
            "Edit(~/.claude.json)",
            "Edit(~/.agent-guard/**)",
            "Edit(~/.zshrc)",
            "Edit(~/Library/LaunchAgents/**)",
            "Edit(~/.gitconfig)",
            "Edit(//usr/local/libexec/agent-guard/**)",
        ] {
            assert!(deny.contains(&r), "missing {r}");
        }
        // Absolute paths in rules always start with `//`.
        assert!(deny.iter().all(|r| r.contains("(~/") || r.contains("(//")));

        let sb = &s["sandbox"];
        assert_eq!(sb["enabled"], true);
        assert_eq!(sb["failIfUnavailable"], true);
        assert_eq!(sb["allowUnsandboxedCommands"], false);
        assert_eq!(sb["filesystem"]["allowManagedReadPathsOnly"], true);
        let read = strings(sb.pointer("/filesystem/denyRead"));
        for p in [
            "~/.ssh",
            "~/.aws",
            "~/.claude/.credentials.json",
            "~/.agent-guard",
        ] {
            assert!(read.contains(&p), "denyRead misses {p}");
        }
        let write = strings(sb.pointer("/filesystem/denyWrite"));
        for p in [
            "~/.agent-guard",
            "~/.claude",
            "~/.zshrc",
            "~/Library/LaunchAgents",
            "~/.local/bin",
            "~/.gitconfig",
            "/usr/local/libexec/agent-guard",
        ] {
            assert!(write.contains(&p), "denyWrite misses {p}");
        }
        let net = strings(sb.pointer("/network/allowedDomains"));
        assert!(net.contains(&"api.anthropic.com"));
        assert!(net.contains(&"api.example.com"));
        assert_eq!(sb["network"]["allowManagedDomainsOnly"], true);
        assert!(dangers(&s).is_empty());
    }

    #[test]
    fn broad_domains_never_reach_the_allowlist() {
        assert!(broad_domain("*"));
        assert!(broad_domain("*.com"));
        assert!(broad_domain("*.io."));
        assert!(broad_domain("git*.com"));
        assert!(!broad_domain("*.github.com"));
        assert!(!broad_domain("github.com"));
        let d = domains(&[
            "*.com".into(),
            "API.Example.com".into(),
            "github.com".into(),
        ]);
        assert!(!d.contains(&"*.com".to_string()));
        assert!(d.contains(&"api.example.com".to_string()));
        assert_eq!(d.iter().filter(|x| *x == "github.com").count(), 1);
    }

    #[test]
    fn dangerous_sandbox_settings() {
        let s = json!({"sandbox": {
            "allowAppleEvents": true,
            "allowUnsandboxedCommands": true,
            "excludedCommands": ["docker *", "Bash(python3 -c *)", "git push *", "*"],
            "network": {"allowedDomains": ["*.com", "pypi.org"]}
        }});
        let d = dangers(&s);
        assert_eq!(d.len(), 6, "{d:?}");
        assert!(dangers(&json!({"sandbox": {"excludedCommands": ["git push *"]}})).is_empty());
        assert!(dangers(&json!({})).is_empty());
    }

    #[test]
    fn install_and_uninstall_on_temp_paths() {
        let dir = tempfile::tempdir().unwrap();
        let paths = temp_paths(dir.path());
        let exe = dir.path().join("guard-build");
        fs::write(&exe, b"#!/bin/sh\n").unwrap();
        fs::create_dir_all(paths.managed_settings.parent().unwrap()).unwrap();
        let admin = r#"{"companyAnnouncements": ["hi"], "permissions": {"deny": ["Bash(rm *)"]}}"#;
        fs::write(&paths.managed_settings, admin).unwrap();

        let plan = install_plan(&paths, &exe, &["api.example.com".into()], 100).unwrap();
        let text = plan.describe();
        assert!(text.contains("\"allowManagedHooksOnly\": true"));
        assert!(text.contains("back up"));
        plan.apply(false).unwrap();

        assert!(installed(&paths));
        assert_eq!(fs::read(&paths.binary).unwrap(), b"#!/bin/sh\n");
        let mode = fs::metadata(&paths.binary).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        let s = read_json(&paths.managed_settings).unwrap();
        assert_eq!(s["companyAnnouncements"][0], "hi");
        let deny = strings(s.pointer("/permissions/deny"));
        assert_eq!(deny[0], "Bash(rm *)");
        assert!(deny.contains(&"Read(~/.ssh/**)"));
        assert_eq!(trusted_hosts(&paths), ["api.example.com"]);

        // A second install keeps the admin's backup as the one to restore, and adds no
        // second set of hooks.
        install_plan(&paths, &exe, &[], 200)
            .unwrap()
            .apply(false)
            .unwrap();
        let s = read_json(&paths.managed_settings).unwrap();
        assert_eq!(s["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert!(!backup_name(&paths.managed_settings, 200).exists());

        uninstall_plan(&paths).apply(false).unwrap();
        assert_eq!(fs::read_to_string(&paths.managed_settings).unwrap(), admin);
        assert!(!paths.binary.exists());
        assert!(!paths.policy_dir.exists());
        assert!(!installed(&paths));
    }

    #[test]
    fn fresh_install_is_removed_on_uninstall() {
        let dir = tempfile::tempdir().unwrap();
        let paths = temp_paths(dir.path());
        let exe = dir.path().join("guard-build");
        fs::write(&exe, b"x").unwrap();
        install_plan(&paths, &exe, &[], 1)
            .unwrap()
            .apply(false)
            .unwrap();
        assert!(installed(&paths));
        uninstall_plan(&paths).apply(false).unwrap();
        assert!(!paths.managed_settings.exists());
    }

    #[test]
    fn install_refuses_an_admin_file_that_breaks_the_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let paths = temp_paths(dir.path());
        fs::create_dir_all(paths.managed_settings.parent().unwrap()).unwrap();
        fs::write(
            &paths.managed_settings,
            r#"{"sandbox": {"excludedCommands": ["docker *"]}}"#,
        )
        .unwrap();
        let err = install_plan(&paths, Path::new("/bin/ls"), &[], 1).unwrap_err();
        assert!(err.to_string().contains("docker *"), "{err}");
    }

    #[test]
    fn pause_and_trust_live_in_the_policy_dir() {
        let dir = tempfile::tempdir().unwrap();
        let paths = temp_paths(dir.path());
        let exe = dir.path().join("guard-build");
        fs::write(&exe, b"x").unwrap();
        install_plan(&paths, &exe, &[], 1)
            .unwrap()
            .apply(false)
            .unwrap();

        assert!(require_root(&paths, "pause", false).is_err());
        assert!(require_root(&paths, "pause", true).is_ok());
        let off = temp_paths(&dir.path().join("none"));
        assert!(require_root(&off, "pause", false).is_ok());

        pause_until(&paths, 500).unwrap();
        assert_eq!(pause_active(&paths, 499), Some(500));
        assert_eq!(pause_active(&paths, 500), None);
        resume(&paths).unwrap();
        assert_eq!(pause_active(&paths, 0), None);

        set_trusted_hosts(&paths, &["api.example.com".into()]).unwrap();
        assert_eq!(trusted_hosts(&paths), ["api.example.com"]);
        let s = read_json(&paths.managed_settings).unwrap();
        assert!(strings(s.pointer("/sandbox/network/allowedDomains")).contains(&"api.example.com"));
        assert!(installed(&paths));
    }

    #[test]
    fn ownership_chain() {
        // System binaries are root's all the way up; a temp dir is the user's.
        assert_eq!(unsafe_ancestor(Path::new("/bin/ls")), None);
        let dir = tempfile::tempdir().unwrap();
        assert!(unsafe_ancestor(dir.path()).is_some());
    }

    #[test]
    fn config_hosts_for_the_allowlist() {
        use crate::config::TrustedHost;
        let host = |h: &str, agent: Option<&str>, exp: Option<u64>| TrustedHost {
            host: h.into(),
            agent: agent.map(String::from),
            process: None,
            expires_at: exp,
        };
        let mut c = Config::default();
        c.trust.hosts = vec![
            host("a.example.com", None, None),
            host("b.example.com", Some("claude"), None),
            host("c.example.com", Some("codex"), None),
            host("d.example.com", None, Some(5)),
        ];
        assert_eq!(trusted_from_config(&c), ["a.example.com", "b.example.com"]);
    }
}
