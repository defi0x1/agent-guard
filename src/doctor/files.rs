//! Reading and writing the agent's config files: Claude Code settings, `~/.claude.json`,
//! `.mcp.json` and Claude Desktop's config. Writes keep every other key, in order, and are atomic.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::Env;

/// One MCP server entry in a config file.
#[derive(Debug, Clone)]
pub struct Server {
    /// The file it is in.
    pub file: PathBuf,
    /// JSON pointer to the entry, for edits.
    pub pointer: String,
    pub name: String,
    /// The program, or empty for a remote server.
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
}

impl Server {
    /// The command's program name without its directory (`npx`, `uvx`, `docker`).
    pub fn program(&self) -> &str {
        self.command.rsplit('/').next().unwrap_or("")
    }

    /// The command line as one string.
    pub fn line(&self) -> String {
        std::iter::once(self.command.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Everything the checks read, loaded once.
pub struct State {
    /// Settings files that exist and parse, in precedence order: user, project, project local.
    pub settings: Vec<(PathBuf, Value)>,
    pub claude_json: Option<Value>,
    pub servers: Vec<Server>,
}

impl State {
    pub fn load(env: &Env) -> State {
        let settings = env
            .settings_paths()
            .into_iter()
            .filter_map(|p| read_json(&p).map(|v| (p, v)))
            .collect();
        let claude_json = read_json(&env.claude_json());
        let mut servers = Vec::new();
        if let Some(v) = &claude_json {
            servers_in(&env.claude_json(), v, "", &mut servers);
            if let Some(projects) = v.get("projects").and_then(Value::as_object) {
                for (dir, p) in projects {
                    servers_in(
                        &env.claude_json(),
                        p,
                        &format!("/projects/{}", escape(dir)),
                        &mut servers,
                    );
                }
            }
        }
        for file in [env.mcp_json(), env.desktop_config.clone()] {
            if let Some(v) = read_json(&file) {
                servers_in(&file, &v, "", &mut servers);
            }
        }
        State {
            settings,
            claude_json,
            servers,
        }
    }

    /// The value at `pointer` in the settings file that wins (project local, project, user).
    pub fn effective(&self, pointer: &str) -> Option<&Value> {
        self.settings
            .iter()
            .rev()
            .find_map(|(_, v)| v.pointer(pointer))
    }
}

/// The servers under `base/mcpServers` in `doc`.
fn servers_in(file: &Path, doc: &Value, base: &str, out: &mut Vec<Server>) {
    let Some(map) = doc.get("mcpServers").and_then(Value::as_object) else {
        return;
    };
    for (name, s) in map {
        let strings = |key: &str| -> Vec<(String, String)> {
            s.get(key)
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                        .collect()
                })
                .unwrap_or_default()
        };
        out.push(Server {
            file: file.to_path_buf(),
            pointer: format!("{base}/mcpServers/{}", escape(name)),
            name: name.clone(),
            command: s
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            args: s
                .get("args")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            env: strings("env"),
            headers: strings("headers"),
        });
    }
}

/// Escapes a key for a JSON pointer.
pub fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// The parsed file, or `None` if it is missing or not valid JSON.
pub fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

/// Writes `value` as pretty JSON, atomically: a temp file next to the real one (through a
/// symlink, to its target), then a rename. Keeps the file's mode; a new file gets 0600.
pub fn write_json(path: &Path, value: &Value) -> io::Result<()> {
    let mut text = serde_json::to_string_pretty(value).map_err(io::Error::other)?;
    text.push('\n');
    write_atomic(path, text.as_bytes())
}

/// Replaces `path` with `data` atomically, keeping its mode (0600 if it is new).
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let target = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mode = fs::metadata(&target).map_or(0o600, |m| m.permissions().mode() & 0o7777);
    if let Some(dir) = target.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut tmp = target.clone().into_os_string();
    tmp.push(".guard-tmp");
    let tmp = PathBuf::from(tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, &target)
}

/// The object at `key` in `obj`, created (or replaced, if it is not an object) as needed.
pub fn object<'a>(obj: &'a mut Value, key: &str) -> Option<&'a mut Map<String, Value>> {
    let map = obj.as_object_mut()?;
    let entry = map
        .entry(key.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !entry.is_object() {
        *entry = Value::Object(Map::new());
    }
    entry.as_object_mut()
}

/// The strings in the array at `pointer`.
pub fn strings_at<'a>(doc: &'a Value, pointer: &str) -> Vec<&'a str> {
    doc.pointer(pointer)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_keeps_order_mode_and_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.json");
        fs::write(&p, r#"{"zeta": 1, "alpha": {"b": 2, "a": 3}}"#).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        let mut v = read_json(&p).unwrap();
        v["new"] = Value::Bool(true);
        write_json(&p, &v).unwrap();
        let text = fs::read_to_string(&p).unwrap();
        let (z, a, n) = (
            text.find("zeta").unwrap(),
            text.find("alpha").unwrap(),
            text.find("new").unwrap(),
        );
        assert!(z < a && a < n);
        assert!(text.find("\"b\"").unwrap() < text.find("\"a\"").unwrap());
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(!dir.path().join("s.json.guard-tmp").exists());
    }

    #[test]
    fn write_goes_through_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        let link = dir.path().join("link.json");
        fs::write(&real, "{}").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        write_json(&link, &serde_json::json!({"a": 1})).unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(fs::read_to_string(&real).unwrap().contains("\"a\""));
    }
}
