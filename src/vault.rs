//! Keys in the OS keychain: `guard secret move|list|rm` and `guard run --secret NAME=ENV -- cmd`.
//!
//! Values live in the macOS keychain (`security`) or the Secret Service on Linux (`secret-tool`),
//! under the service `agent-guard`. Values never appear on a command line: they go to the tools on
//! stdin. Agent Guard keeps the stored names (never values) in `<home>/secrets` for `list`.

use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, bail};
use serde_json::Value;

use crate::home;

/// Keychain service name for every key Agent Guard stores.
const SERVICE: &str = "agent-guard";

/// `guard secret ...` subcommands.
#[derive(clap::Subcommand)]
pub enum SecretCmd {
    /// List keys stored by Agent Guard (names only).
    List,
    /// Move a key from an MCP server's config into the keychain: `guard secret move github GITHUB_TOKEN`.
    Move {
        /// The MCP server name.
        server: String,
        /// The environment variable holding the key.
        var: String,
        /// The config file (default ~/.claude.json).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Delete a stored key.
    Rm { name: String },
}

/// Where key values are kept. The OS keychain in real use; an in-memory map in tests.
pub trait Store {
    /// Saves `value` under `name`, replacing any old value.
    fn set(&self, name: &str, value: &str) -> anyhow::Result<()>;
    /// The value under `name`, or `None` if there is none.
    fn get(&self, name: &str) -> anyhow::Result<Option<String>>;
    /// Deletes `name`.
    fn remove(&self, name: &str) -> anyhow::Result<()>;
}

/// The OS keychain: `security` on macOS, `secret-tool` elsewhere.
pub struct Keychain;

impl Store for Keychain {
    fn set(&self, name: &str, value: &str) -> anyhow::Result<()> {
        check_name(name)?;
        if cfg!(target_os = "macos") {
            // `security -i` reads the command from stdin, so the hex value never shows in `ps`.
            let line = format!(
                "add-generic-password -U -s {SERVICE} -a {name} -X {}\n",
                hex(value.as_bytes())
            );
            tool("security", &["-i"], Some(line.as_bytes()))?;
        } else {
            let label = format!("Agent Guard: {name}");
            tool(
                "secret-tool",
                &["store", "--label", &label, "service", SERVICE, "name", name],
                Some(value.as_bytes()),
            )?;
        }
        Ok(())
    }

    fn get(&self, name: &str) -> anyhow::Result<Option<String>> {
        check_name(name)?;
        let out = if cfg!(target_os = "macos") {
            Command::new("security")
                .args(["find-generic-password", "-s", SERVICE, "-a", name, "-w"])
                .stderr(Stdio::null())
                .output()
        } else {
            Command::new("secret-tool")
                .args(["lookup", "service", SERVICE, "name", name])
                .stderr(Stdio::null())
                .output()
        }
        .context("could not run the keychain tool")?;
        if !out.status.success() {
            // Both tools fail with no output when the item is missing.
            return Ok(None);
        }
        let mut value = String::from_utf8(out.stdout).context("stored key is not text")?;
        if value.ends_with('\n') {
            value.pop();
        }
        Ok(Some(value))
    }

    fn remove(&self, name: &str) -> anyhow::Result<()> {
        check_name(name)?;
        if cfg!(target_os = "macos") {
            tool(
                "security",
                &["delete-generic-password", "-s", SERVICE, "-a", name],
                None,
            )?;
        } else {
            tool(
                "secret-tool",
                &["clear", "service", SERVICE, "name", name],
                None,
            )?;
        }
        Ok(())
    }
}

/// Runs a keychain tool, feeding `stdin` if given, and fails on a non-zero exit.
fn tool(prog: &str, args: &[&str], stdin: Option<&[u8]>) -> anyhow::Result<()> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("could not run {prog}"))?;
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(data)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().next().unwrap_or("").trim();
        bail!("{prog} failed: {first}");
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Names are `<server>.<var>`: letters, digits, `.`, `_` and `-` only, so they are safe to pass
/// to the keychain tools.
fn check_name(name: &str) -> anyhow::Result<()> {
    let ok = !name.is_empty()
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !ok {
        bail!("bad key name {name:?}; use letters, digits, '.', '_' and '-'");
    }
    Ok(())
}

/// Runs `guard secret ...`.
pub fn run(cmd: SecretCmd) -> anyhow::Result<()> {
    let dir = home::ensure()?;
    match cmd {
        SecretCmd::List => {
            let names = names(&dir)?;
            if names.is_empty() {
                println!("no keys stored");
            }
            for n in names {
                println!("{n}");
            }
        }
        SecretCmd::Move { server, var, file } => {
            let file = match file {
                Some(f) => f,
                None => {
                    let h = std::env::var_os("HOME").context("HOME is not set")?;
                    PathBuf::from(h).join(".claude.json")
                }
            };
            println!(
                "{}",
                move_key(&Keychain, &dir, &file, &server, &var, home::now())?
            );
        }
        SecretCmd::Rm { name } => {
            remove_key(&Keychain, &dir, &name)?;
            println!("removed {name}");
        }
    }
    Ok(())
}

/// Runs `command` with each `NAME=ENV` key from the keychain set as `ENV`, replacing this process.
pub fn exec(secrets: &[String], command: &[String]) -> anyhow::Result<()> {
    let vars = secret_env(&Keychain, secrets)?;
    let Some((prog, args)) = command.split_first() else {
        bail!("no command given");
    };
    let err = Command::new(prog).args(args).envs(vars).exec();
    bail!("could not run {prog}: {err}")
}

/// Reads each `NAME=ENV` from `store` and returns the `(ENV, value)` pairs.
fn secret_env(store: &dyn Store, secrets: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let mut vars = Vec::new();
    for spec in secrets {
        let (name, env) = spec
            .split_once('=')
            .filter(|(n, e)| !n.is_empty() && !e.is_empty())
            .with_context(|| format!("bad --secret {spec:?}; use NAME=ENV"))?;
        let value = store.get(name)?.with_context(|| {
            format!("no key named {name} in the keychain; add it with `guard secret move`")
        })?;
        vars.push((env.to_string(), value));
    }
    Ok(vars)
}

/// Moves the literal value of env var `var` of MCP server `server` in `file` to `store`, rewrites
/// the server to launch through `guard run`, and returns the text to print.
fn move_key(
    store: &dyn Store,
    dir: &Path,
    file: &Path,
    server: &str,
    var: &str,
    now: u64,
) -> anyhow::Result<String> {
    let name = format!("{server}.{var}");
    check_name(&name)?;
    let text =
        fs::read_to_string(file).with_context(|| format!("could not read {}", file.display()))?;
    let mut config: Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not valid JSON", file.display()))?;
    let (value, count) = rewrite(&mut config, server, var, &name)?;

    let backups = dir.join("backups");
    crate::home::private_dir(&backups)?;
    let base = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config".into());
    let backup = backups.join(format!("{base}.{now}"));
    home::write_private(&backup, text.as_bytes())?;

    store.set(&name, &value)?;
    add_name(dir, &name)?;
    let mut out = serde_json::to_string_pretty(&config)?;
    out.push('\n');
    home::write_private(file, out.as_bytes())?;

    let places = if count == 1 { "place" } else { "places" };
    let revoke = revoke_url(var, &value).unwrap_or("at your provider");
    Ok(format!(
        "done: {var} of {server} is now in the keychain as {name} ({count} {places} in {}). Backup: {}\n\
         This key was saved in plain text before. Make a new key and revoke the old one: {revoke}",
        file.display(),
        backup.display()
    ))
}

/// Rewrites every definition of `server` (top level and per project) that sets `var`, and returns
/// the key's value and how many definitions changed.
fn rewrite(
    config: &mut Value,
    server: &str,
    var: &str,
    name: &str,
) -> anyhow::Result<(String, usize)> {
    let mut found: Vec<&mut Value> = servers_mut(config, server)
        .into_iter()
        .filter(|s| s.get("env").and_then(|e| e.get(var)).is_some())
        .collect();
    if found.is_empty() {
        bail!("no MCP server {server:?} with env {var} found");
    }
    let mut value: Option<String> = None;
    for s in &found {
        let Some(v) = s["env"][var].as_str() else {
            bail!("{var} of {server} is not a string");
        };
        if v.is_empty() || v.starts_with("${") {
            bail!("{var} of {server} is not a literal key ({v:?}); nothing to move");
        }
        if value.as_deref().is_some_and(|old| old != v) {
            bail!(
                "{server} sets {var} to different values in different projects; move them by hand"
            );
        }
        if s.get("command").and_then(Value::as_str).is_none() {
            bail!("{server} has no command; only local (stdio) servers can be moved");
        }
        value = Some(v.to_string());
    }
    let value = value.context("no value found")?;

    let spec = format!("{name}={var}");
    for s in &mut found {
        let Some(obj) = s.as_object_mut() else {
            continue;
        };
        let command = obj
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let mut args: Vec<Value> = obj
            .get("args")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if command == "guard" && args.first().and_then(Value::as_str) == Some("run") {
            // Already launched through Agent Guard: add one more key.
            args.splice(1..1, [Value::from("--secret"), Value::from(spec.clone())]);
        } else {
            let mut new: Vec<Value> = ["run", "--secret", &spec, "--", &command]
                .into_iter()
                .map(Value::from)
                .collect();
            new.append(&mut args);
            args = new;
        }
        obj.insert("command".into(), Value::from("guard"));
        obj.insert("args".into(), Value::from(args));
        if let Some(env) = obj.get_mut("env").and_then(Value::as_object_mut) {
            env.remove(var);
        }
    }
    Ok((value, found.len()))
}

/// Every definition of `server`: top-level `mcpServers` and `projects.*.mcpServers`.
fn servers_mut<'a>(config: &'a mut Value, server: &str) -> Vec<&'a mut Value> {
    let mut out = Vec::new();
    let Some(root) = config.as_object_mut() else {
        return out;
    };
    for (key, v) in root.iter_mut() {
        match key.as_str() {
            "mcpServers" => out.extend(v.get_mut(server)),
            "projects" => {
                if let Some(projects) = v.as_object_mut() {
                    for p in projects.values_mut() {
                        out.extend(p.get_mut("mcpServers").and_then(|m| m.get_mut(server)));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// The provider's page for revoking a key, guessed from the variable name and the key's prefix.
fn revoke_url(var: &str, value: &str) -> Option<&'static str> {
    let var = var.to_ascii_uppercase();
    let has = |p: &str| value.starts_with(p);
    if has("sk-ant-") || var.contains("ANTHROPIC") {
        Some("https://console.anthropic.com/settings/keys")
    } else if has("ghp_") || has("github_pat_") || has("gho_") || var.contains("GITHUB") {
        Some("https://github.com/settings/tokens")
    } else if has("xox") || var.contains("SLACK") {
        Some("https://api.slack.com/apps")
    } else if has("sk_live_") || has("rk_live_") || has("sk_test_") || var.contains("STRIPE") {
        Some("https://dashboard.stripe.com/apikeys")
    } else if has("AKIA") || var.starts_with("AWS_") {
        Some("https://console.aws.amazon.com/iam/home#/security_credentials")
    } else if has("sk-") || var.contains("OPENAI") {
        Some("https://platform.openai.com/api-keys")
    } else {
        None
    }
}

/// Deletes `name` from `store` and from the list of names.
fn remove_key(store: &dyn Store, dir: &Path, name: &str) -> anyhow::Result<()> {
    let mut list = names(dir)?;
    if !list.iter().any(|n| n == name) && store.get(name)?.is_none() {
        bail!("no key named {name}");
    }
    store.remove(name)?;
    list.retain(|n| n != name);
    save_names(dir, &list)
}

fn names_file(dir: &Path) -> PathBuf {
    dir.join("secrets")
}

/// The names of stored keys, sorted.
fn names(dir: &Path) -> anyhow::Result<Vec<String>> {
    match fs::read_to_string(names_file(dir)) {
        Ok(t) => Ok(t
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

fn add_name(dir: &Path, name: &str) -> anyhow::Result<()> {
    let mut list = names(dir)?;
    if !list.iter().any(|n| n == name) {
        list.push(name.to_string());
        list.sort();
    }
    save_names(dir, &list)
}

fn save_names(dir: &Path, list: &[String]) -> anyhow::Result<()> {
    let mut text = list.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    home::write_private(&names_file(dir), text.as_bytes())?;
    Ok(())
}

/// An in-memory [`Store`] for tests.
#[cfg(test)]
#[derive(Default)]
struct MemStore(std::cell::RefCell<std::collections::HashMap<String, String>>);

#[cfg(test)]
impl Store for MemStore {
    fn set(&self, name: &str, value: &str) -> anyhow::Result<()> {
        self.0.borrow_mut().insert(name.into(), value.into());
        Ok(())
    }
    fn get(&self, name: &str) -> anyhow::Result<Option<String>> {
        Ok(self.0.borrow().get(name).cloned())
    }
    fn remove(&self, name: &str) -> anyhow::Result<()> {
        self.0.borrow_mut().remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

    fn setup(config: &Value) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(".claude.json");
        fs::write(&file, serde_json::to_string(config).unwrap()).unwrap();
        (dir, file)
    }

    #[test]
    fn move_rewrites_server_and_stores_key() {
        let config = json!({
            "mcpServers": {"github": {
                "command": "npx", "args": ["-y", "@mcp/github"],
                "env": {"GITHUB_TOKEN": KEY, "OTHER": "x"}
            }},
            "projects": {"/p": {"mcpServers": {"github": {
                "command": "npx", "args": [], "env": {"GITHUB_TOKEN": KEY}
            }}}}
        });
        let (dir, file) = setup(&config);
        let store = MemStore::default();
        let msg = move_key(&store, dir.path(), &file, "github", "GITHUB_TOKEN", 42).unwrap();

        assert_eq!(
            store.get("github.GITHUB_TOKEN").unwrap().as_deref(),
            Some(KEY)
        );
        let text = fs::read_to_string(&file).unwrap();
        assert!(!text.contains(KEY));
        let new: Value = serde_json::from_str(&text).unwrap();
        let s = &new["mcpServers"]["github"];
        assert_eq!(s["command"], "guard");
        assert_eq!(
            s["args"],
            json!([
                "run",
                "--secret",
                "github.GITHUB_TOKEN=GITHUB_TOKEN",
                "--",
                "npx",
                "-y",
                "@mcp/github"
            ])
        );
        assert_eq!(s["env"], json!({"OTHER": "x"}));
        assert_eq!(
            new["projects"]["/p"]["mcpServers"]["github"]["command"],
            "guard"
        );

        let backup = dir.path().join("backups/.claude.json.42");
        assert!(fs::read_to_string(backup).unwrap().contains(KEY));
        assert!(!msg.contains(KEY));
        assert!(msg.contains("https://github.com/settings/tokens"));
        assert_eq!(names(dir.path()).unwrap(), vec!["github.GITHUB_TOKEN"]);
    }

    #[test]
    fn second_move_adds_to_existing_launcher() {
        let config = json!({"mcpServers": {"s": {
            "command": "node", "args": ["srv.js"], "env": {"A_KEY": "aaa", "B_KEY": "bbb"}
        }}});
        let (dir, file) = setup(&config);
        let store = MemStore::default();
        move_key(&store, dir.path(), &file, "s", "A_KEY", 1).unwrap();
        move_key(&store, dir.path(), &file, "s", "B_KEY", 2).unwrap();
        let new: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(
            new["mcpServers"]["s"]["args"],
            json!([
                "run",
                "--secret",
                "s.B_KEY=B_KEY",
                "--secret",
                "s.A_KEY=A_KEY",
                "--",
                "node",
                "srv.js"
            ])
        );
        assert_eq!(names(dir.path()).unwrap(), vec!["s.A_KEY", "s.B_KEY"]);
    }

    #[test]
    fn move_refuses_references_and_missing_servers() {
        let config = json!({"mcpServers": {
            "ref": {"command": "x", "env": {"T": "${T}"}},
            "http": {"url": "https://example.com", "env": {"T": "abc"}}
        }});
        let (dir, file) = setup(&config);
        let store = MemStore::default();
        assert!(move_key(&store, dir.path(), &file, "ref", "T", 1).is_err());
        assert!(move_key(&store, dir.path(), &file, "http", "T", 1).is_err());
        assert!(move_key(&store, dir.path(), &file, "none", "T", 1).is_err());
        assert!(move_key(&store, dir.path(), &file, "ref", "MISSING", 1).is_err());
        // Nothing changed and nothing stored.
        let now: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(now, config);
        assert!(store.0.borrow().is_empty());
    }

    #[test]
    fn move_refuses_conflicting_values() {
        let config = json!({
            "mcpServers": {"s": {"command": "x", "env": {"T": "one"}}},
            "projects": {"/p": {"mcpServers": {"s": {"command": "x", "env": {"T": "two"}}}}}
        });
        let (dir, file) = setup(&config);
        assert!(move_key(&MemStore::default(), dir.path(), &file, "s", "T", 1).is_err());
    }

    #[test]
    fn bad_names_are_rejected() {
        assert!(check_name("github.GITHUB_TOKEN").is_ok());
        assert!(check_name("my-server.KEY").is_ok());
        for bad in ["", "-w", "a b", "a;rm", "a\nb", "a$(x)"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn secret_env_reads_keys_and_reports_missing() {
        let store = MemStore::default();
        store.set("gh.T", "v1").unwrap();
        let vars = secret_env(&store, &["gh.T=GITHUB_TOKEN".into()]).unwrap();
        assert_eq!(vars, vec![("GITHUB_TOKEN".to_string(), "v1".to_string())]);
        let err = secret_env(&store, &["nope=X".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("nope"));
        assert!(secret_env(&store, &["noequals".into()]).is_err());
        assert!(secret_env(&store, &["=X".into()]).is_err());
    }

    #[test]
    fn remove_deletes_key_and_name() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemStore::default();
        store.set("a.B", "v").unwrap();
        add_name(dir.path(), "a.B").unwrap();
        remove_key(&store, dir.path(), "a.B").unwrap();
        assert!(store.get("a.B").unwrap().is_none());
        assert!(names(dir.path()).unwrap().is_empty());
        assert!(remove_key(&store, dir.path(), "a.B").is_err());
    }

    #[test]
    fn revoke_urls_by_provider() {
        assert_eq!(
            revoke_url("KEY", "sk-ant-api03-x"),
            Some("https://console.anthropic.com/settings/keys")
        );
        assert_eq!(
            revoke_url("KEY", "sk-proj-x"),
            Some("https://platform.openai.com/api-keys")
        );
        assert_eq!(
            revoke_url("SLACK_BOT_TOKEN", "x"),
            Some("https://api.slack.com/apps")
        );
        assert_eq!(
            revoke_url("KEY", "sk_live_x"),
            Some("https://dashboard.stripe.com/apikeys")
        );
        assert!(revoke_url("AWS_SECRET_ACCESS_KEY", "x").is_some());
        assert_eq!(revoke_url("NOTION_TOKEN", "secret_x"), None);
    }

    #[test]
    fn hex_encodes_bytes() {
        assert_eq!(hex(b"a b\"c"), "6120622263");
    }
}
