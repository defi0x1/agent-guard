//! The user's own secret values, kept only as salted SHA-256 fingerprints in
//! `<home>/fingerprints.json` (mode 0600). Sources: credential-named environment variables, the
//! project `.env`, and the `env` and `headers` of MCP servers in `~/.claude.json` and `.mcp.json`.
//! Files are parsed again only when their modification time or size changes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::home;

/// Shortest value worth fingerprinting.
pub const MIN_LEN: usize = 12;

/// One fingerprinted value. `label` and `owner` are names, never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    hash: String,
    len: usize,
    /// What the value is, for messages: `NOTION_TOKEN value`, `notion Authorization header`.
    pub label: String,
    /// A lowercase name hinting at the value's own service (`notion` for `NOTION_TOKEN`, the
    /// server name for MCP values): sending the value there is expected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Data {
    salt: String,
    #[serde(default)]
    values: Vec<Entry>,
    /// Source file path to the stamp (modification time and size) it had when last read.
    #[serde(default)]
    sources: BTreeMap<String, String>,
}

/// The loaded fingerprints, indexed for lookup.
pub struct Store {
    data: Data,
    index: HashMap<String, usize>,
    lens: HashSet<usize>,
}

impl Default for Store {
    fn default() -> Self {
        Store::new()
    }
}

impl Store {
    /// An empty store with a fresh random salt.
    pub fn new() -> Store {
        Store::from_data(Data {
            salt: new_salt(),
            ..Data::default()
        })
    }

    fn from_data(data: Data) -> Store {
        let index = data
            .values
            .iter()
            .enumerate()
            .map(|(i, e)| (e.hash.clone(), i))
            .collect();
        let lens = data.values.iter().map(|e| e.len).collect();
        Store { data, index, lens }
    }

    /// Reads the store; a missing or broken file gives an empty store with a new salt.
    pub fn load(path: &Path) -> Store {
        fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Data>(&b).ok())
            .filter(|d| !d.salt.is_empty())
            .map_or_else(Store::new, Store::from_data)
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let text = serde_json::to_vec(&self.data).map_err(std::io::Error::other)?;
        home::write_private(path, &text)
    }

    pub fn is_empty(&self) -> bool {
        self.data.values.is_empty()
    }

    fn hash(&self, value: &str) -> String {
        let mut h = Sha256::new();
        h.update(self.data.salt.as_bytes());
        h.update(value.as_bytes());
        hex(&h.finalize())
    }

    /// Adds `value` unless it is already known. Returns whether the store changed.
    pub fn add(&mut self, value: &str, label: &str, owner: Option<String>) -> bool {
        let hash = self.hash(value);
        if self.index.contains_key(&hash) {
            return false;
        }
        self.index.insert(hash.clone(), self.data.values.len());
        self.lens.insert(value.len());
        self.data.values.push(Entry {
            hash,
            len: value.len(),
            label: label.to_string(),
            owner,
        });
        true
    }

    /// The entry for `value`, if it is one of the user's secrets.
    pub fn lookup(&self, value: &str) -> Option<&Entry> {
        if !self.lens.contains(&value.len()) {
            return None;
        }
        self.index
            .get(&self.hash(value))
            .and_then(|&i| self.data.values.get(i))
    }

    /// Adds credential-named variables from `vars`. Returns whether the store changed.
    pub fn add_env(&mut self, vars: impl Iterator<Item = (String, String)>) -> bool {
        let mut changed = false;
        for (name, value) in vars {
            if credential_name(&name) && looks_secret(&value) {
                changed |= self.add(&value, &format!("{name} value"), owner_of(&name));
            }
        }
        changed
    }

    /// Reads `path` (a `.env` file, or JSON with `mcpServers`) if it changed since last time.
    /// Returns whether the store changed.
    pub fn add_file(&mut self, path: &Path) -> bool {
        let key = path.to_string_lossy().into_owned();
        let Some(stamp) = stamp(path) else {
            return self.data.sources.remove(&key).is_some();
        };
        if self.data.sources.get(&key) == Some(&stamp) {
            return false;
        }
        let mut text = String::new();
        if fs::File::open(path)
            .and_then(|mut f| f.read_to_string(&mut text))
            .is_err()
        {
            return false;
        }
        if path.extension().is_some_and(|e| e == "json") {
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                self.add_mcp_json(&v);
            }
        } else {
            self.add_dotenv(&text);
        }
        self.data.sources.insert(key, stamp);
        true
    }

    fn add_dotenv(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            let value = unquote(value.trim());
            if !line.starts_with('#') && credential_name(name.trim()) && looks_secret(value) {
                let name = name.trim();
                self.add(value, &format!("{name} value"), owner_of(name));
            }
        }
    }

    /// Walks the JSON for `mcpServers` objects (top level, and per project in `~/.claude.json`).
    fn add_mcp_json(&mut self, v: &Value) {
        let Value::Object(map) = v else {
            return;
        };
        for (k, child) in map {
            match (k.as_str(), child) {
                ("mcpServers", Value::Object(servers)) => {
                    for (server, cfg) in servers {
                        self.add_server(server, cfg);
                    }
                }
                (_, Value::Object(_)) => self.add_mcp_json(child),
                _ => {}
            }
        }
    }

    fn add_server(&mut self, server: &str, cfg: &Value) {
        let owner = Some(server.to_ascii_lowercase());
        if let Some(Value::Object(env)) = cfg.get("env") {
            for (name, value) in env {
                if let Some(value) = value.as_str()
                    && credential_name(name)
                    && looks_secret(value)
                {
                    self.add(value, &format!("{name} value"), owner.clone());
                }
            }
        }
        if let Some(Value::Object(headers)) = cfg.get("headers") {
            for (name, value) in headers {
                let Some(value) = value.as_str() else {
                    continue;
                };
                let value = strip_scheme(value);
                if auth_header(name) && looks_secret(value) {
                    let label = format!("{server} {name} header");
                    self.add(value, &label, owner.clone());
                }
            }
        }
    }
}

/// Loads the store from `home`, adds what the current environment and source files hold, and
/// saves it if anything changed.
pub fn refreshed(home: &Path, cwd: &Path) -> Store {
    let path = home.join("fingerprints.json");
    let mut store = Store::load(&path);
    let mut changed = store.add_env(std::env::vars());
    let mut files = vec![cwd.join(".env"), cwd.join(".mcp.json")];
    if let Some(h) = std::env::var_os("HOME") {
        files.push(PathBuf::from(h).join(".claude.json"));
    }
    for f in &files {
        changed |= store.add_file(f);
    }
    if changed && let Err(e) = store.save(&path) {
        eprintln!("agent-guard: fingerprints: {e}");
    }
    store
}

const CREDENTIAL_WORDS: &[&str] = &[
    "KEY",
    "APIKEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PAT",
    "CREDENTIAL",
    "CREDENTIALS",
];

/// Whether a variable name says it holds a credential: a word of it (split on `_`, `-` or `.`)
/// is one of KEY, TOKEN, SECRET, PASSWORD, PAT, CREDENTIAL, or ends in TOKEN, SECRET or
/// PASSWORD. `PATH` and `TOKENIZERS_PARALLELISM` do not count.
pub fn credential_name(name: &str) -> bool {
    name.to_ascii_uppercase().split(['_', '-', '.']).any(|w| {
        CREDENTIAL_WORDS.contains(&w)
            || ["TOKEN", "SECRET", "PASSWORD", "APIKEY"]
                .iter()
                .any(|s| w.len() > s.len() && w.ends_with(s))
    })
}

/// Words that say nothing about which service a value belongs to.
const GENERIC: &[&str] = &[
    "api", "app", "my", "auth", "access", "secret", "private", "client", "user", "service",
    "default", "personal", "admin", "master", "root", "db", "x",
];

/// The service hinted by a variable name: its first word, unless generic (`NOTION_TOKEN` gives
/// `notion`, `API_KEY` gives nothing).
fn owner_of(name: &str) -> Option<String> {
    let first = name.split(['_', '-', '.']).next()?.to_ascii_lowercase();
    (first.len() >= 3 && !GENERIC.contains(&first.as_str()) && !credential_name(&first))
        .then_some(first)
}

/// Whether `v` could be a secret rather than a setting: long enough, one token, varied, and
/// not a path, a number, a reference or a placeholder.
pub fn looks_secret(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    let distinct: HashSet<char> = v.chars().collect();
    v.len() >= MIN_LEN
        && !v.chars().any(char::is_whitespace)
        && distinct.len() >= 6
        && !v
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
        && !["/", "~", "./", "../", "$", "op://", "file:"]
            .iter()
            .any(|p| v.starts_with(p))
        && ![
            "your",
            "example",
            "changeme",
            "placeholder",
            "xxxx",
            "<",
            "replace",
        ]
        .iter()
        .any(|p| lower.contains(p))
}

/// Whether a header name carries a credential (`Authorization`, `X-API-Key`, `Cookie`), not a
/// setting such as `Content-Type`.
fn auth_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["auth", "key", "token", "secret", "cookie", "password"]
        .iter()
        .any(|w| n.contains(w))
}

fn strip_scheme(v: &str) -> &str {
    for scheme in ["Bearer ", "bearer ", "Basic ", "basic ", "Token ", "token "] {
        if let Some(rest) = v.strip_prefix(scheme) {
            return rest.trim();
        }
    }
    v.trim()
}

fn unquote(v: &str) -> &str {
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|s| s.strip_suffix(q)) {
            return inner;
        }
    }
    v
}

fn stamp(path: &Path) -> Option<String> {
    let m = fs::metadata(path).ok()?;
    let t = m.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some(format!("{}:{}", t.as_nanos(), m.len()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 16 random bytes from the system, hex encoded. Falls back to a hash of the time and process
/// id if the random device cannot be read.
fn new_salt() -> String {
    let mut buf = [0u8; 16];
    if fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok()
    {
        return hex(&buf);
    }
    let seed = format!("{:?}{}", std::time::SystemTime::now(), std::process::id());
    hex(&Sha256::digest(seed.as_bytes())[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const VALUE: &str = "n0t-a-real-Secret-9f3k";

    #[test]
    fn credential_names() {
        for n in [
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "GH_PAT",
            "DB_PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
            "NPMTOKEN",
            "client-secret",
            "GOOGLE_CREDENTIALS",
        ] {
            assert!(credential_name(n), "{n}");
        }
        for n in [
            "PATH",
            "PWD",
            "TOKENIZERS_PARALLELISM",
            "KEYCHAIN_PROFILE",
            "MONKEY",
            "HOME",
        ] {
            assert!(!credential_name(n), "{n}");
        }
    }

    #[test]
    fn skips_obvious_non_secrets() {
        assert!(looks_secret(VALUE));
        for v in [
            "short",
            "/Users/me/.ssh/id_ed25519",
            "~/keys/key.pem",
            "${GITHUB_TOKEN}",
            "12345678901234",
            "aaaaaaaaaaaaaaaa",
            "your-api-key-here",
            "op://vault/item/field",
            "two words here please",
        ] {
            assert!(!looks_secret(v), "{v}");
        }
    }

    #[test]
    fn owners() {
        assert_eq!(owner_of("NOTION_TOKEN").as_deref(), Some("notion"));
        assert_eq!(owner_of("API_KEY"), None);
        assert_eq!(owner_of("TOKEN"), None);
    }

    #[test]
    fn stores_only_salted_hashes_with_private_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fingerprints.json");
        let mut s = Store::new();
        assert!(s.add_env([("MY_TOKEN".to_string(), VALUE.to_string())].into_iter()));
        assert!(!s.add_env([("OTHER_TOKEN".to_string(), VALUE.to_string())].into_iter()));
        s.save(&path).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(VALUE));
        assert!(text.contains("MY_TOKEN"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let again = Store::load(&path);
        assert_eq!(again.lookup(VALUE).unwrap().label, "MY_TOKEN value");
        assert!(again.lookup("n0t-a-real-Secret-9f3X").is_none());
        // A different salt gives different hashes.
        assert_ne!(Store::new().hash(VALUE), again.hash(VALUE));
    }

    #[test]
    fn reads_dotenv_and_mcp_configs_once() {
        let dir = tempfile::tempdir().unwrap();
        let env = dir.path().join(".env");
        fs::write(
            &env,
            format!("# DB_PASSWORD=commented-out-value\nexport STRIPE_KEY=\"{VALUE}\"\nAPP_NAME=my-awesome-app-name\n"),
        )
        .unwrap();
        let mcp = dir.path().join(".mcp.json");
        let cfg = serde_json::json!({
            "projects": { "/p": { "mcpServers": { "notion": {
                "env": { "NOTION_TOKEN": "ntn_abcdefghijklmnop12", "LOG_LEVEL": "debug-verbose-mode" },
                "headers": {
                    "Authorization": "Bearer hdr-Value-1234567",
                    "Content-Type": "application/json"
                }
            }}}}
        });
        fs::write(&mcp, cfg.to_string()).unwrap();

        let mut s = Store::new();
        assert!(s.add_file(&env));
        assert!(s.add_file(&mcp));
        assert!(!s.add_file(&env), "unchanged file is not read again");
        assert!(!s.add_file(&dir.path().join("missing.json")));
        assert_eq!(s.lookup(VALUE).unwrap().owner.as_deref(), Some("stripe"));
        assert!(s.lookup("commented-out-value").is_none());
        assert!(s.lookup("my-awesome-app-name").is_none());
        let n = s.lookup("ntn_abcdefghijklmnop12").unwrap();
        assert_eq!(n.owner.as_deref(), Some("notion"));
        assert!(s.lookup("debug-verbose-mode").is_none());
        let h = s.lookup("hdr-Value-1234567").unwrap();
        assert_eq!(h.label, "notion Authorization header");
        assert!(s.lookup("application/json").is_none());
    }

    #[test]
    fn broken_store_starts_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fingerprints.json");
        fs::write(&path, "{not json").unwrap();
        assert!(Store::load(&path).is_empty());
    }
}
