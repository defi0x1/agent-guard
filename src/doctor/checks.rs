//! The doctor's checks. Each one reads the loaded [`State`] (and, for git and versions, the
//! [`Env`]) and adds an [`Item`] per problem; a check with no items passes.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use super::files::{Server, State, strings_at};
use super::secret::{self, Secret};
use super::{Env, Fix, Item, git, item};
use crate::audit::clip;
use crate::hardened;
use crate::level::Level;

/// A check: id, the sentence shown when it passes, and the function.
pub type Check = (&'static str, &'static str, fn(&Env, &State, &mut Vec<Item>));

/// Every check, in report order.
pub const CHECKS: &[Check] = &[
    (
        "D00",
        "Agent Guard's hooks are in your Claude Code settings.",
        d00,
    ),
    ("D01", "No plain-text keys in your MCP server configs.", d01),
    (
        "D02",
        "No keys in this project's tracked config or .env files.",
        d02,
    ),
    ("D03", "Your MCP servers are pinned to fixed versions.", d03),
    ("D04", "Your MCP servers start with plain commands.", d04),
    ("D06", "Claude asks before acting; bypass mode is off.", d06),
    ("D07", "Your allow rules are narrow and hold no keys.", d07),
    ("D08", "Project MCP servers need your approval.", d08),
    ("D09", "Claude is denied your credential files.", d09),
    ("D10", "Claude Code's sandbox is on.", d10),
    ("D11", "No filesystem server can see your whole disk.", d11),
    (
        "D13",
        "This project's settings run no network commands.",
        d13,
    ),
    ("D17", "Your config and .env files are private to you.", d17),
    (
        "D19",
        "Tools get a scrubbed environment and no raw tool data goes to telemetry.",
        d19,
    ),
    ("D22", "Claude Code is new enough.", d22),
    (
        "D26",
        "Your git has the fixes for known clone attacks.",
        d26,
    ),
    ("D27", "Global git config has clone protections on.", d27),
];

/// A hardened-mode check: like [`Check`], but it also reads the managed settings, guard binary
/// and policy folder at the given [`hardened::Paths`] (`Paths::system()` on a real machine).
pub type HardenedCheck = (
    &'static str,
    &'static str,
    fn(&hardened::Paths, &Env, &State, &mut Vec<Item>),
);

/// The hardened-mode checks, in report order. `check` in doctor.rs runs them after [`CHECKS`]
/// once `Env` carries the hardened paths.
pub const HARDENED_CHECKS: &[HardenedCheck] = &[
    (
        "D30",
        "Hardened mode is on: hooks and policy are in root-owned managed settings.",
        d30_at,
    ),
    ("D31", "The sandbox is on in the settings that win.", d31_at),
    ("D32", "No setting opens a hole in the sandbox.", d32_at),
    (
        "D33",
        "The guard binary and policy folder are root's and only root can change them.",
        d33_at,
    ),
];

/// Where a server is configured, for messages: `server "github" in ~/.claude.json`.
fn at(env: &Env, s: &Server) -> String {
    format!("server \"{}\" in {}", s.name, env.tilde(&s.file))
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => {
            matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
        }
        Some(Value::Number(n)) => n.as_u64() == Some(1),
        _ => false,
    }
}

fn d00(env: &Env, s: &State, out: &mut Vec<Item>) {
    let user = env.user_settings();
    let ours = s
        .settings
        .iter()
        .find(|(p, _)| *p == user)
        .is_some_and(|(_, v)| {
            let mut cmds = Vec::new();
            if let Some(h) = v.get("hooks") {
                crate::checks::collect_strings(h, &mut cmds);
            }
            cmds.iter()
                .any(|c| c.contains("guard hook") || c.contains("agent-guard hook"))
        });
    if !ours {
        out.push(item(
            env,
            "D00",
            Level::Red,
            "Agent Guard's hooks are not in ~/.claude/settings.json, so nothing checks what Claude does.",
            Fix::Advice("run guard install".into()),
        ));
    }
    for (p, v) in &s.settings {
        if truthy(v.get("disableAllHooks")) {
            out.push(item(
                env,
                "D00",
                Level::Red,
                format!(
                    "{} sets disableAllHooks, which turns Agent Guard off.",
                    env.tilde(p)
                ),
                Fix::Advice(format!("remove disableAllHooks from {}", env.tilde(p))),
            ));
        }
    }
}

/// Keys in a server's env, headers and args.
fn server_secrets(s: &Server) -> Vec<(Secret, String, String)> {
    let mut found = Vec::new();
    for (k, v) in &s.env {
        if let Some(sec) = secret::named(k, v) {
            found.push((sec, format!("env {k}"), k.clone()));
        }
    }
    for (k, v) in &s.headers {
        if let Some(sec) = secret::named(k, v) {
            let var = k.to_ascii_uppercase().replace('-', "_");
            found.push((sec, format!("header {k}"), var));
        }
    }
    for (i, a) in s.args.iter().enumerate() {
        if let Some(sec) = secret::in_arg(a, s.args.get(i + 1).map(String::as_str)) {
            found.push((sec, "its arguments".into(), "<VAR>".into()));
        }
    }
    found
}

fn d01(env: &Env, s: &State, out: &mut Vec<Item>) {
    for srv in &s.servers {
        for (sec, place, var) in server_secrets(srv) {
            out.push(item(
                env,
                "D01",
                Level::Red,
                format!(
                    "{} is saved as plain text in {}, {place}.",
                    capitalize(&sec.describe()),
                    at(env, srv)
                ),
                Fix::Advice(format!(
                    "guard secret move {} {var}, then rotate the key",
                    srv.name
                )),
            ));
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// Whether a tracked path is one D02 scans.
fn d02_scans(path: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path);
    path == ".mcp.json"
        || (path.starts_with(".claude/settings") && path.ends_with(".json"))
        || base.starts_with(".env")
}

/// Keys in a JSON document: provider keys in any string, and secret-named settings.
fn json_secrets(v: &Value, name: Option<&str>, out: &mut Vec<Secret>) {
    match v {
        Value::String(s) => out.extend(match name {
            Some(n) => secret::named(n, s),
            None => secret::provider(s),
        }),
        Value::Array(a) => a.iter().for_each(|x| json_secrets(x, None, out)),
        Value::Object(m) => m.iter().for_each(|(k, x)| json_secrets(x, Some(k), out)),
        _ => {}
    }
}

/// Keys in a `.env` file's `NAME=value` lines.
fn env_file_secrets(text: &str) -> Vec<Secret> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            let l = l.strip_prefix("export ").unwrap_or(l);
            let (k, v) = l.split_once('=')?;
            if k.starts_with('#') {
                return None;
            }
            secret::named(k.trim(), v.trim().trim_matches(['"', '\'']))
        })
        .collect()
}

fn d02(env: &Env, _s: &State, out: &mut Vec<Item>) {
    let Some(list) = git(env, &["ls-files", "-z"]) else {
        return;
    };
    for path in list.split('\0').filter(|p| d02_scans(p)) {
        let Ok(text) = fs::read_to_string(env.cwd.join(path)) else {
            continue;
        };
        let found = if path.ends_with(".json") {
            let mut found = Vec::new();
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                json_secrets(&v, None, &mut found);
            }
            found
        } else {
            env_file_secrets(&text)
        };
        let advice = if path.ends_with(".json") {
            format!("replace it with a ${{VAR}} reference in {path}, then rotate the key")
        } else {
            format!("git rm --cached {path}, add it to .gitignore, then rotate the key")
        };
        for sec in found {
            out.push(item(
                env,
                "D02",
                Level::Red,
                format!(
                    "{} is in {path}, which git tracks, so it can be pushed with your code.",
                    capitalize(&sec.describe())
                ),
                Fix::Advice(advice.clone()),
            ));
        }
    }
}

/// An npm package spec split into name and version: `@scope/pkg@1.2.3`, `pkg`.
pub fn npm_spec(spec: &str) -> (&str, Option<&str>) {
    let at = if let Some(rest) = spec.strip_prefix('@') {
        rest.find('@').map(|i| i + 1)
    } else {
        spec.find('@')
    };
    match at {
        Some(i) => (&spec[..i], Some(&spec[i + 1..])),
        None => (spec, None),
    }
}

/// An exact version such as `1.2.3` or `1.2.3-beta.1`.
fn exact_version(v: &str) -> bool {
    let core = v.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The index of the package argument of an `npx` command.
pub fn npx_package(args: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-p" || a == "--package" {
            return (i + 1 < args.len()).then_some(i + 1);
        }
        if !a.starts_with('-') {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// The npx package of a server that is not pinned to an exact version.
pub fn unpinned_npx(s: &Server) -> Option<(usize, &str)> {
    if s.program() != "npx" {
        return None;
    }
    let i = npx_package(&s.args)?;
    let (name, version) = npm_spec(&s.args[i]);
    (!version.is_some_and(exact_version)).then_some((i, name))
}

/// Docker options that take a value, so the next argument is not the image.
const DOCKER_VALUE_FLAGS: &[&str] = &[
    "-e",
    "--env",
    "-v",
    "--volume",
    "--name",
    "-p",
    "--publish",
    "--network",
    "--env-file",
    "-w",
    "--workdir",
    "-u",
    "--user",
    "--mount",
    "--entrypoint",
    "--platform",
    "-l",
    "--label",
    "--add-host",
    "--cap-add",
    "--cap-drop",
    "-m",
    "--memory",
    "--cpus",
    "-h",
    "--hostname",
];

/// The image of a `docker run` command.
fn docker_image(args: &[String]) -> Option<&str> {
    let run = args.iter().position(|a| a == "run")?;
    let mut it = args[run + 1..].iter();
    while let Some(a) = it.next() {
        if DOCKER_VALUE_FLAGS.contains(&a.as_str()) {
            it.next();
        } else if !a.starts_with('-') {
            return Some(a);
        }
    }
    None
}

fn d03(env: &Env, s: &State, out: &mut Vec<Item>) {
    for srv in &s.servers {
        if let Some((_, name)) = unpinned_npx(srv) {
            out.push(item(
                env,
                "D03",
                Level::Yellow,
                format!(
                    "{} runs the newest {name} on every start; a hijacked release would run on your computer.",
                    capitalize(&at(env, srv))
                ),
                Fix::Auto,
            ));
        }
        match srv.program() {
            "uvx" => {
                let pkg = srv.args.iter().find(|a| !a.starts_with('-'));
                let pinned = pkg.is_some_and(|p| {
                    p.contains("==")
                        || p.split_once('@')
                            .is_some_and(|(_, v)| v.starts_with(|c: char| c.is_ascii_digit()))
                });
                if let (Some(p), false) = (pkg, pinned) {
                    out.push(item(
                        env,
                        "D03",
                        Level::Yellow,
                        format!(
                            "{} runs the newest {p} on every start.",
                            capitalize(&at(env, srv))
                        ),
                        Fix::Advice(format!(
                            "pin it as {p}==<version> in {}",
                            env.tilde(&srv.file)
                        )),
                    ));
                }
            }
            "docker" => {
                if let Some(img) = docker_image(&srv.args).filter(|i| !i.contains("@sha256:")) {
                    out.push(item(
                        env,
                        "D03",
                        Level::Yellow,
                        format!(
                            "{} uses image {img} without a digest, so it can change under you.",
                            capitalize(&at(env, srv))
                        ),
                        Fix::Advice(format!(
                            "pin it as {img}@sha256:<digest> (docker inspect shows it) in {}",
                            env.tilde(&srv.file)
                        )),
                    ));
                }
            }
            _ => {}
        }
    }
}

/// Startup command patterns that do more than start a tool.
static RISKY: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("sudo", r"(?:^|[\s/])sudo\s"),
        ("a shell -c command", r"(?:^|[\s/])(?:sh|bash|zsh)\s+-c\b"),
        ("chained commands (&&)", r"&&"),
        (
            "a downloaded script piped to a shell",
            r"(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b",
        ),
        ("base64 decoding", r"base64\s+(?:-d|-D|--decode)\b"),
        ("eval", r"\beval\b"),
    ]
    .into_iter()
    .filter_map(|(what, re)| Regex::new(re).ok().map(|r| (what, r)))
    .collect()
});

/// What is risky about a startup command line, if anything.
pub fn risky_startup(env: &Env, line: &str) -> Vec<&'static str> {
    let mut found: Vec<&str> = RISKY
        .iter()
        .filter(|(_, re)| re.is_match(line))
        .map(|(what, _)| *what)
        .collect();
    let home = env.home.to_string_lossy();
    let secret_dir = ["~", "$HOME", "${HOME}", &home]
        .iter()
        .any(|h| line.contains(&format!("{h}/.ssh")) || line.contains(&format!("{h}/.aws")));
    if secret_dir {
        found.push("a path into ~/.ssh or ~/.aws");
    }
    found
}

fn d04(env: &Env, s: &State, out: &mut Vec<Item>) {
    for srv in s.servers.iter().filter(|s| !s.command.is_empty()) {
        let line = srv.line();
        let found = risky_startup(env, &line);
        if !found.is_empty() {
            out.push(item(
                env,
                "D04",
                Level::Red,
                format!(
                    "{} starts with {}: \"{}\".",
                    capitalize(&at(env, srv)),
                    found.join(", "),
                    clip(&secret::redact(&line), 80)
                ),
                Fix::Advice(
                    "none; review the command and remove the server if you did not add it".into(),
                ),
            ));
        }
    }
}

/// Shell startup files where an alias could turn off Claude's permission prompts.
const RC_FILES: &[&str] = &[
    ".zshrc",
    ".zprofile",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".config/fish/config.fish",
];

fn d06(env: &Env, s: &State, out: &mut Vec<Item>) {
    for (p, v) in &s.settings {
        if v.pointer("/permissions/defaultMode")
            .and_then(Value::as_str)
            == Some("bypassPermissions")
        {
            out.push(item(
                env,
                "D06",
                Level::Red,
                format!(
                    "{} starts Claude in bypass mode, so it never asks before acting.",
                    env.tilde(p)
                ),
                Fix::Auto,
            ));
        }
    }
    let claude_json = env.claude_json();
    let docs = s
        .settings
        .iter()
        .map(|(p, v)| (p.as_path(), v))
        .chain(s.claude_json.as_ref().map(|v| (claude_json.as_path(), v)));
    for (p, v) in docs {
        if truthy(v.get("skipDangerousModePermissionPrompt")) {
            out.push(item(
                env,
                "D06",
                Level::Red,
                format!("{} skips the warning before bypass mode.", env.tilde(p)),
                Fix::Auto,
            ));
        }
    }
    for rc in RC_FILES {
        let p = env.home.join(rc);
        let Ok(text) = fs::read_to_string(&p) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            let l = line.trim();
            if !l.starts_with('#') && l.contains("--dangerously-skip-permissions") {
                out.push(item(
                    env,
                    "D06",
                    Level::Red,
                    format!(
                        "{} line {} runs Claude with --dangerously-skip-permissions, so it never asks.",
                        env.tilde(&p),
                        n + 1
                    ),
                    Fix::Advice(format!("remove that line from {}", env.tilde(&p))),
                ));
            }
        }
    }
}

/// MCP server names that suggest it can write or send on your behalf.
const WRITE_SERVERS: &[&str] = &[
    "github",
    "gitlab",
    "slack",
    "gmail",
    "mail",
    "discord",
    "telegram",
    "whatsapp",
    "notion",
    "jira",
    "linear",
    "filesystem",
    "postgres",
    "mysql",
    "supabase",
    "stripe",
    "twitter",
    "shell",
    "terminal",
    "exec",
    "browser",
    "puppeteer",
    "playwright",
];

static BROAD_NET_BASH: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^Bash\((?:curl|wget|nc|ssh|scp)(?::\*| \*|\*)\)$").ok());

/// Why an allow rule is too broad, if it is.
pub fn broad_rule(rule: &str) -> Option<&'static str> {
    let r = rule.trim();
    if matches!(r, "Bash" | "Bash(*)" | "Bash(:*)") {
        return Some("lets Claude run any command without asking");
    }
    if BROAD_NET_BASH.as_ref().is_some_and(|re| re.is_match(r)) {
        return Some("lets Claude send data anywhere without asking");
    }
    if matches!(r, "WebFetch" | "WebFetch(*)") {
        return Some("lets Claude fetch any web address without asking");
    }
    let rest = r.strip_prefix("mcp__")?;
    let server = match rest.split_once("__") {
        None => rest,
        Some((s, "*")) => s,
        Some(_) => return None,
    };
    let lower = server.to_ascii_lowercase();
    WRITE_SERVERS
        .iter()
        .any(|w| lower.contains(w))
        .then_some("lets a server that can write or send act without asking")
}

/// A key inside an allow rule, such as a `curl -H "Authorization: Bearer ..."` approval.
pub fn rule_secret(rule: &str) -> Option<Secret> {
    secret::provider(rule).or_else(|| {
        let (_, after) = rule.split_once("Bearer ")?;
        let token: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || "-_.=".contains(*c))
            .collect();
        secret::named("Authorization", &token)
    })
}

fn d07(env: &Env, s: &State, out: &mut Vec<Item>) {
    for (p, v) in &s.settings {
        for rule in strings_at(v, "/permissions/allow") {
            if let Some(sec) = rule_secret(rule) {
                out.push(item(
                    env,
                    "D07",
                    Level::Red,
                    format!(
                        "An allow rule in {} contains {}. Rotate the key.",
                        env.tilde(p),
                        sec.describe()
                    ),
                    Fix::Auto,
                ));
            } else if let Some(why) = broad_rule(rule) {
                out.push(item(
                    env,
                    "D07",
                    Level::Yellow,
                    format!("The allow rule {rule} in {} {why}.", env.tilde(p)),
                    Fix::Auto,
                ));
            }
        }
    }
}

fn d08(env: &Env, s: &State, out: &mut Vec<Item>) {
    let claude_json = env.claude_json();
    let mut places: Vec<&Path> = s
        .settings
        .iter()
        .filter(|(_, v)| truthy(v.get("enableAllProjectMcpServers")))
        .map(|(p, _)| p.as_path())
        .collect();
    let in_projects = s
        .claude_json
        .as_ref()
        .and_then(|v| v.get("projects"))
        .and_then(Value::as_object)
        .is_some_and(|m| {
            m.values()
                .any(|p| truthy(p.get("enableAllProjectMcpServers")))
        });
    if in_projects {
        places.push(&claude_json);
    }
    for p in places {
        out.push(item(
            env,
            "D08",
            Level::Yellow,
            format!(
                "{} sets enableAllProjectMcpServers, so any project you open can start its own tools.",
                env.tilde(p)
            ),
            Fix::Auto,
        ));
    }
}

/// The credential files every setup should deny Claude.
pub const CREDENTIAL_DENY: &[&str] = &[
    "Read(~/.ssh/id_*)",
    "Read(~/.aws/credentials)",
    "Read(~/.config/gh/hosts.yml)",
    "Read(~/.netrc)",
    "Read(~/.npmrc)",
    "Read(~/.docker/config.json)",
    "Read(~/.kube/config)",
    "Read(~/.gnupg/**)",
];

/// Whether the deny rule `rule` covers `want` (exactly, or as a wider glob).
fn covers(rule: &str, want: &str) -> bool {
    let inner = |r: &str| {
        r.trim()
            .strip_prefix("Read(")?
            .strip_suffix(')')
            .map(str::to_string)
    };
    if rule.trim() == "Read" {
        return true;
    }
    match (inner(rule), inner(want)) {
        (Some(r), Some(w)) => {
            r == w
                || r.strip_suffix("**").is_some_and(|p| w.starts_with(p))
                || r.strip_suffix('*')
                    .is_some_and(|p| w.starts_with(p) && !w[p.len()..].contains('/'))
        }
        _ => false,
    }
}

/// The credential deny rules none of the settings files has.
pub fn missing_deny(s: &State) -> Vec<&'static str> {
    let rules: Vec<&str> = s
        .settings
        .iter()
        .flat_map(|(_, v)| strings_at(v, "/permissions/deny"))
        .collect();
    CREDENTIAL_DENY
        .iter()
        .filter(|w| !rules.iter().any(|r| covers(r, w)))
        .copied()
        .collect()
}

fn d09(env: &Env, s: &State, out: &mut Vec<Item>) {
    let missing = missing_deny(s);
    if missing.is_empty() {
        return;
    }
    let names: Vec<&str> = missing
        .iter()
        .take(2)
        .map(|r| r.trim_start_matches("Read(").trim_end_matches(')'))
        .collect();
    let more = match missing.len().saturating_sub(2) {
        0 => String::new(),
        n => format!(" and {n} more"),
    };
    out.push(item(
        env,
        "D09",
        Level::Yellow,
        format!(
            "Claude can open your credential files; no deny rule covers {}{more}.",
            names.join(", ")
        ),
        Fix::Auto,
    ));
}

fn d10(env: &Env, s: &State, out: &mut Vec<Item>) {
    if !truthy(s.effective("/sandbox/enabled")) {
        out.push(item(
            env,
            "D10",
            Level::Yellow,
            "Claude Code's sandbox is off, so commands Claude runs can read and change any file you can.",
            Fix::Auto,
        ));
    }
}

fn d11(env: &Env, s: &State, out: &mut Vec<Item>) {
    let home = env.home.to_string_lossy();
    let home = home.trim_end_matches('/');
    for srv in &s.servers {
        let is_fs = srv.name.to_ascii_lowercase().contains("filesystem")
            || srv.args.iter().any(|a| a.contains("server-filesystem"));
        if !is_fs {
            continue;
        }
        let wide = srv.args.iter().find(|a| {
            let a = a.as_str();
            a == "/"
                || matches!(a.trim_end_matches('/'), "~" | "$HOME" | "${HOME}")
                || a.trim_end_matches('/') == home
        });
        if let Some(a) = wide {
            out.push(item(
                env,
                "D11",
                Level::Yellow,
                format!(
                    "{} can see {a}, not just your project.",
                    capitalize(&at(env, srv))
                ),
                Fix::Advice(format!(
                    "narrow it to the project folder in {}",
                    env.tilde(&srv.file)
                )),
            ));
        }
    }
}

static NET_CMD: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\b(?:curl|wget|nc|ncat|netcat)\b|(?i:base64)").ok());

fn d13(env: &Env, s: &State, out: &mut Vec<Item>) {
    let project = env.cwd.join(".claude/settings.json");
    if project == env.user_settings() {
        return;
    }
    let Some((_, v)) = s.settings.iter().find(|(p, _)| *p == project) else {
        return;
    };
    let mut found: Vec<(&str, &str)> = Vec::new();
    for (key, what) in [
        ("hooks", "a hook"),
        ("apiKeyHelper", "apiKeyHelper"),
        ("env", "an env value"),
    ] {
        let mut strs = Vec::new();
        if let Some(val) = v.get(key) {
            crate::checks::collect_strings(val, &mut strs);
        }
        found.extend(strs.into_iter().map(|s| (what, s)));
    }
    for (what, text) in found {
        if NET_CMD.as_ref().is_some_and(|re| re.is_match(text)) {
            out.push(item(
                env,
                "D13",
                Level::Red,
                format!(
                    "This project's .claude/settings.json has {what} that may send data out: \"{}\".",
                    clip(&secret::redact(text), 60)
                ),
                Fix::Advice(
                    "review it; for repos you do not trust, start Claude with --setting-sources user".into(),
                ),
            ));
        }
    }
}

/// The files D17 checks: agent configs, and `.env` files at the top of the project.
pub fn private_files(env: &Env) -> Vec<std::path::PathBuf> {
    let mut list = env.settings_paths();
    list.extend([
        env.claude_json(),
        env.mcp_json(),
        env.desktop_config.clone(),
    ]);
    if let Ok(dir) = fs::read_dir(&env.cwd) {
        let mut dotenv: Vec<_> = dir
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".env"))
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        dotenv.sort();
        list.extend(dotenv);
    }
    list.dedup();
    list
}

/// The file's permission bits, if others or the group can read or write it.
pub fn loose_mode(p: &Path) -> Option<u32> {
    let mode = fs::metadata(p).ok()?.permissions().mode() & 0o777;
    (mode & 0o077 != 0).then_some(mode)
}

fn d17(env: &Env, _s: &State, out: &mut Vec<Item>) {
    for p in private_files(env) {
        if let Some(mode) = loose_mode(&p) {
            out.push(item(
                env,
                "D17",
                Level::Yellow,
                format!(
                    "Other accounts on this computer can read {} (mode {mode:o}).",
                    env.tilde(&p)
                ),
                Fix::Auto,
            ));
        }
    }
}

fn d19(env: &Env, s: &State, out: &mut Vec<Item>) {
    let var = |name: &str| -> bool {
        truthy(s.effective(&format!("/env/{name}")))
            || truthy(
                env.vars
                    .get(name)
                    .map(|v| Value::String(v.clone()))
                    .as_ref(),
            )
    };
    if !var("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB") {
        out.push(item(
            env,
            "D19",
            Level::Yellow,
            "Commands and servers Claude starts get every secret in your environment; CLAUDE_CODE_SUBPROCESS_ENV_SCRUB is not set.",
            Fix::Advice(
                "add \"CLAUDE_CODE_SUBPROCESS_ENV_SCRUB\": \"1\" under env in ~/.claude/settings.json".into(),
            ),
        ));
    }
    if var("OTEL_LOG_TOOL_CONTENT") {
        out.push(item(
            env,
            "D19",
            Level::Yellow,
            "OTEL_LOG_TOOL_CONTENT is on, so raw tool data, keys included, goes to your telemetry server.",
            Fix::Advice("unset OTEL_LOG_TOOL_CONTENT".into()),
        ));
    }
}

/// The first `x.y.z` in `s`.
pub fn version(s: &str) -> Option<(u32, u32, u32)> {
    s.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find_map(|w| {
            let mut it = w.split('.').map(|p| p.parse::<u32>().ok());
            match (it.next(), it.next(), it.next()) {
                (Some(Some(a)), Some(Some(b)), Some(Some(c))) => Some((a, b, c)),
                _ => None,
            }
        })
}

/// The oldest Claude Code version Agent Guard's hooks and fixes are tested with.
const MIN_CLAUDE: (u32, u32, u32) = (2, 1, 300);

fn d22(env: &Env, _s: &State, out: &mut Vec<Item>) {
    let Some(v) = env.claude_version.as_deref() else {
        out.push(item(
            env,
            "D22",
            Level::Green,
            "Claude Code was not found, so its version was not checked.",
            Fix::None,
        ));
        return;
    };
    if let Some(found) = version(v).filter(|&f| f < MIN_CLAUDE) {
        out.push(item(
            env,
            "D22",
            Level::Yellow,
            format!(
                "Claude Code {}.{}.{} is older than 2.1.300 and misses safety fixes Agent Guard relies on.",
                found.0, found.1, found.2
            ),
            Fix::Advice("run claude update".into()),
        ));
    }
}

/// First fixed release per minor series, and the release that fixes every later series.
struct Advisory {
    cve: &'static str,
    fixed: &'static [(u32, u32, u32)],
}

/// From the git security advisories (GHSA-8h77-4q3w-gfgv, GHSA-vwqx-4fm8-6qc9).
const GIT_ADVISORIES: &[Advisory] = &[
    Advisory {
        cve: "CVE-2024-32002",
        fixed: &[
            (2, 39, 4),
            (2, 40, 2),
            (2, 41, 1),
            (2, 42, 2),
            (2, 43, 4),
            (2, 44, 1),
            (2, 45, 1),
        ],
    },
    Advisory {
        cve: "CVE-2025-48384",
        fixed: &[
            (2, 43, 7),
            (2, 44, 4),
            (2, 45, 4),
            (2, 46, 4),
            (2, 47, 3),
            (2, 48, 2),
            (2, 49, 1),
            (2, 50, 1),
        ],
    },
];

/// The advisories `v` is vulnerable to.
pub fn git_cves(v: (u32, u32, u32)) -> Vec<&'static str> {
    GIT_ADVISORIES
        .iter()
        .filter(|a| {
            let newest = a.fixed.iter().max().copied().unwrap_or_default();
            let patched = v >= newest
                || a.fixed
                    .iter()
                    .any(|f| f.0 == v.0 && f.1 == v.1 && v.2 >= f.2);
            !patched
        })
        .map(|a| a.cve)
        .collect()
}

fn d26(env: &Env, _s: &State, out: &mut Vec<Item>) {
    let Some(found) = env.git_version.as_deref().and_then(version) else {
        return;
    };
    let cves = git_cves(found);
    if !cves.is_empty() {
        out.push(item(
            env,
            "D26",
            Level::Yellow,
            format!(
                "git {}.{}.{} has known flaws ({}) that let a cloned repository run code.",
                found.0,
                found.1,
                found.2,
                cves.join(", ")
            ),
            Fix::Advice("update git (2.50.1 or newer)".into()),
        ));
    }
}

/// Global git settings that make cloning safer: key, wanted value.
pub const GIT_HARDENING: &[(&str, &str)] = &[
    ("transfer.fsckObjects", "true"),
    ("safe.bareRepository", "explicit"),
    ("protocol.file.allow", "user"),
];

/// The hardening settings whose global value is not the wanted one.
pub fn git_missing(env: &Env) -> Vec<(&'static str, &'static str)> {
    GIT_HARDENING
        .iter()
        .filter(|(k, want)| {
            git(env, &["config", "--global", "--get", k])
                .is_none_or(|v| !v.trim().eq_ignore_ascii_case(want))
        })
        .copied()
        .collect()
}

fn d27(env: &Env, _s: &State, out: &mut Vec<Item>) {
    if env.git_version.is_none() {
        return;
    }
    let missing = git_missing(env);
    if !missing.is_empty() {
        let list: Vec<String> = missing.iter().map(|(k, v)| format!("{k}={v}")).collect();
        out.push(item(
            env,
            "D27",
            Level::Yellow,
            format!(
                "Global git config is missing clone protections: {}.",
                list.join(", ")
            ),
            Fix::Auto,
        ));
    }
}

const HARDEN: &str = "sudo guard install --hardened";

fn d30_at(paths: &hardened::Paths, env: &Env, _: &State, out: &mut Vec<Item>) {
    if !hardened::installed(paths) {
        out.push(item(
            env,
            "D30",
            Level::Yellow,
            "Only the light mode is on: an agent running as you can still turn the hooks off or pause them.",
            Fix::Advice(HARDEN.into()),
        ));
    }
}

/// Managed settings win over every other file, so their value counts first.
fn d31_at(paths: &hardened::Paths, env: &Env, s: &State, out: &mut Vec<Item>) {
    // Without managed settings, D10 covers the sandbox for the light mode.
    let Some(managed) = hardened::read_json(&paths.managed_settings) else {
        return;
    };
    let enabled = managed
        .pointer("/sandbox/enabled")
        .or_else(|| s.effective("/sandbox/enabled"));
    if !truthy(enabled) {
        out.push(item(
            env,
            "D31",
            Level::Red,
            "The sandbox is off, so any command Claude runs can read your keys and change your settings.",
            Fix::Advice(HARDEN.into()),
        ));
    }
}

fn d32_at(paths: &hardened::Paths, env: &Env, s: &State, out: &mut Vec<Item>) {
    let managed =
        hardened::read_json(&paths.managed_settings).map(|v| (paths.managed_settings.clone(), v));
    for (p, v) in s.settings.iter().chain(managed.iter()) {
        for d in hardened::dangers(v) {
            out.push(item(
                env,
                "D32",
                Level::Red,
                format!("{} sets {d}.", env.tilde(p)),
                Fix::Advice(format!("remove it from {}", env.tilde(p))),
            ));
        }
    }
}

fn d33_at(paths: &hardened::Paths, env: &Env, _: &State, out: &mut Vec<Item>) {
    let Some(managed) = hardened::read_json(&paths.managed_settings) else {
        return;
    };
    let mut check = |p: &Path, what: &str| {
        if !p.exists() {
            out.push(item(
                env,
                "D33",
                Level::Red,
                format!("The {what} {} is missing.", p.display()),
                Fix::Advice(HARDEN.into()),
            ));
        } else if let Some(bad) = hardened::unsafe_ancestor(p) {
            out.push(item(
                env,
                "D33",
                Level::Red,
                format!(
                    "The {what} {} can be changed without root ({} is not root's alone), so an agent could replace it.",
                    p.display(),
                    bad.display()
                ),
                Fix::Advice(HARDEN.into()),
            ));
        }
    };
    for bin in hardened::guard_hook_binaries(&managed) {
        check(&bin, "guard binary the managed hooks run");
    }
    if paths.policy_dir.exists() {
        check(&paths.policy_dir, "policy folder");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn npm_specs() {
        assert_eq!(npm_spec("pkg"), ("pkg", None));
        assert_eq!(npm_spec("pkg@1.2.3"), ("pkg", Some("1.2.3")));
        assert_eq!(npm_spec("@scope/pkg"), ("@scope/pkg", None));
        assert_eq!(
            npm_spec("@scope/pkg@latest"),
            ("@scope/pkg", Some("latest"))
        );
        assert!(exact_version("1.2.3"));
        assert!(exact_version("1.2.3-beta.1"));
        assert!(!exact_version("latest"));
        assert!(!exact_version("^1.2.3"));
        assert!(!exact_version("1.x"));
    }

    #[test]
    fn docker_images() {
        let args = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        assert_eq!(
            docker_image(&args("run -i --rm -e TOKEN -v /a:/b ghcr.io/x/y:1")),
            Some("ghcr.io/x/y:1")
        );
        assert_eq!(docker_image(&args("run --rm=true img")), Some("img"));
    }

    #[test]
    fn broad_rules() {
        assert!(broad_rule("Bash").is_some());
        assert!(broad_rule("Bash(*)").is_some());
        assert!(broad_rule("Bash(curl:*)").is_some());
        assert!(broad_rule("WebFetch").is_some());
        assert!(broad_rule("mcp__github__*").is_some());
        assert!(broad_rule("mcp__slack").is_some());
        assert!(broad_rule("Bash(npm test:*)").is_none());
        assert!(broad_rule("Bash(curl https://api.github.com/repos)").is_none());
        assert!(broad_rule("WebFetch(domain:docs.rs)").is_none());
        assert!(broad_rule("mcp__github__get_issue").is_none());
        assert!(broad_rule("mcp__context7__*").is_none());
    }

    #[test]
    fn secrets_in_rules() {
        assert!(
            rule_secret("Bash(curl -H \"Authorization: Bearer a8f9d7c6b5e4a3f2d1c0\" x)").is_some()
        );
        assert!(rule_secret("Bash(export K=ghp_abcdefghijklmnopqrstuvwxyz0123456789)").is_some());
        assert!(rule_secret("Bash(curl -H \"Authorization: Bearer $TOKEN\" x)").is_none());
        assert!(rule_secret("Bash(git push:*)").is_none());
    }

    #[test]
    fn deny_coverage() {
        assert!(covers("Read(~/.ssh/**)", "Read(~/.ssh/id_*)"));
        assert!(covers("Read(~/.ssh/id_*)", "Read(~/.ssh/id_*)"));
        assert!(covers("Read(~/.aws/*)", "Read(~/.aws/credentials)"));
        assert!(!covers("Read(~/.ssh/known_hosts)", "Read(~/.ssh/id_*)"));
        assert!(!covers("Edit(~/.ssh/**)", "Read(~/.ssh/id_*)"));
    }

    #[test]
    fn versions_and_git_cves() {
        assert_eq!(version("2.1.300 (Claude Code)"), Some((2, 1, 300)));
        assert_eq!(
            version("git version 2.39.5 (Apple Git-154)"),
            Some((2, 39, 5))
        );
        assert_eq!(version("none"), None);
        assert_eq!(git_cves((2, 50, 1)), Vec::<&str>::new());
        assert_eq!(git_cves((2, 51, 0)), Vec::<&str>::new());
        assert_eq!(git_cves((2, 49, 1)), Vec::<&str>::new());
        assert_eq!(git_cves((2, 50, 0)), ["CVE-2025-48384"]);
        assert_eq!(git_cves((2, 45, 1)), ["CVE-2025-48384"]);
        assert_eq!(git_cves((2, 39, 5)), ["CVE-2025-48384"]);
        assert_eq!(git_cves((2, 39, 3)), ["CVE-2024-32002", "CVE-2025-48384"]);
        assert_eq!(git_cves((2, 45, 0)), ["CVE-2024-32002", "CVE-2025-48384"]);
    }

    #[test]
    fn env_files() {
        let found = env_file_secrets(
            "# comment\nexport OPENAI_API_KEY=\"sk-proj-abcdefghijklmnopqrstuv4f2a\"\nDEBUG=1\nAPI_KEY=${API_KEY}\n",
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].masked, "sk-...4f2a");
        assert!(d02_scans(".env.local"));
        assert!(d02_scans("apps/web/.env"));
        assert!(d02_scans(".claude/settings.local.json"));
        assert!(!d02_scans("src/settings.json"));
    }

    fn hardened_env(dir: &Path) -> (Env, hardened::Paths) {
        let env = Env {
            home: dir.join("home"),
            guard_home: dir.join("guard"),
            cwd: dir.join("project"),
            desktop_config: dir.join("desktop.json"),
            config: crate::config::Config::default(),
            vars: Default::default(),
            claude_version: None,
            git_version: None,
            npm_version: |_| None,
            now: 0,
            hardened: hardened::Paths {
                managed_settings: dir.join("ClaudeCode/managed-settings.json"),
                binary: dir.join("libexec/agent-guard/guard"),
                policy_dir: dir.join("AgentGuard"),
            },
        };
        let paths = env.hardened.clone();
        (env, paths)
    }

    fn no_settings() -> State {
        State {
            settings: Vec::new(),
            claude_json: None,
            servers: Vec::new(),
        }
    }

    fn write_managed(paths: &hardened::Paths, v: &Value) {
        fs::create_dir_all(paths.managed_settings.parent().unwrap()).unwrap();
        fs::write(&paths.managed_settings, v.to_string()).unwrap();
    }

    type CheckAt = fn(&hardened::Paths, &Env, &State, &mut Vec<Item>);

    fn run_at(f: CheckAt, paths: &hardened::Paths, env: &Env, s: &State) -> Vec<Item> {
        let mut out = Vec::new();
        f(paths, env, s, &mut out);
        out
    }

    #[test]
    fn d30_hardened_mode_missing_is_yellow() {
        let dir = tempfile::tempdir().unwrap();
        let (env, paths) = hardened_env(dir.path());
        let items = run_at(d30_at, &paths, &env, &no_settings());
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].level, Level::Yellow);
        assert!(items[0].line().contains("sudo guard install --hardened"));

        write_managed(&paths, &hardened::managed_settings(&paths, &[]));
        assert!(run_at(d30_at, &paths, &env, &no_settings()).is_empty());
    }

    #[test]
    fn d31_sandbox_off_in_hardened_mode_is_red_and_managed_wins() {
        let dir = tempfile::tempdir().unwrap();
        let (env, paths) = hardened_env(dir.path());
        let user = |v: Value| State {
            settings: vec![(env.user_settings(), v)],
            ..no_settings()
        };
        // Without hardened mode, D10 reports the sandbox instead.
        assert!(run_at(d31_at, &paths, &env, &no_settings()).is_empty());
        let on = user(json!({"sandbox": {"enabled": true}}));

        // Managed settings turn it off for everyone, whatever the user file says.
        write_managed(&paths, &json!({"sandbox": {"enabled": false}}));
        let items = run_at(d31_at, &paths, &env, &on);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].level, Level::Red);
        write_managed(&paths, &hardened::managed_settings(&paths, &[]));
        let off = user(json!({"sandbox": {"enabled": false}}));
        assert!(run_at(d31_at, &paths, &env, &off).is_empty());
    }

    #[test]
    fn d32_holes_in_the_sandbox_are_red() {
        let dir = tempfile::tempdir().unwrap();
        let (env, paths) = hardened_env(dir.path());
        let s = State {
            settings: vec![(
                env.user_settings(),
                json!({"sandbox": {
                    "allowAppleEvents": true,
                    "excludedCommands": ["docker *", "git push *"],
                }}),
            )],
            ..no_settings()
        };
        write_managed(
            &paths,
            &json!({"sandbox": {
                "allowUnsandboxedCommands": true,
                "network": {"allowedDomains": ["*", "pypi.org"]},
            }}),
        );
        let items = run_at(d32_at, &paths, &env, &s);
        assert_eq!(items.len(), 4, "{items:#?}");
        assert!(items.iter().all(|i| i.level == Level::Red));
        assert!(items[0].message.starts_with("~/.claude/settings.json sets"));
        assert!(items.iter().any(|i| i.message.contains("\"*\"")));

        write_managed(&paths, &hardened::managed_settings(&paths, &[]));
        assert!(run_at(d32_at, &paths, &env, &no_settings()).is_empty());
    }

    #[test]
    fn d33_binary_the_user_can_change_is_red() {
        let dir = tempfile::tempdir().unwrap();
        let (env, paths) = hardened_env(dir.path());
        // No managed settings: nothing to check.
        assert!(run_at(d33_at, &paths, &env, &no_settings()).is_empty());

        // Managed hooks pointing at a missing binary.
        write_managed(&paths, &hardened::managed_settings(&paths, &[]));
        let items = run_at(d33_at, &paths, &env, &no_settings());
        assert_eq!(items.len(), 1);
        assert!(items[0].message.contains("missing"));

        // A binary in a folder the user owns, and a user-owned policy folder.
        fs::create_dir_all(paths.binary.parent().unwrap()).unwrap();
        fs::write(&paths.binary, "x").unwrap();
        fs::create_dir_all(&paths.policy_dir).unwrap();
        let items = run_at(d33_at, &paths, &env, &no_settings());
        assert_eq!(items.len(), 2, "{items:#?}");
        assert!(items.iter().all(|i| i.level == Level::Red));
        assert!(items[0].message.contains("without root"));
        // A root-owned chain passes: see hardened::tests::ownership_chain.
    }
}
