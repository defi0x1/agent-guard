//! A small detector for keys saved in config files: provider-shaped keys anywhere, and values of
//! settings whose name says they hold a secret. Only masked forms ever leave this module.

use std::sync::LazyLock;

use regex::Regex;

/// A key found in a file, described without its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// What it is, for example "OpenAI key".
    pub kind: &'static str,
    /// A masked form such as `sk-...4f2a`.
    pub masked: String,
}

impl Secret {
    /// "your OpenAI key (sk-...4f2a)".
    pub fn describe(&self) -> String {
        format!("your {} ({})", self.kind, self.masked)
    }
}

/// Provider key shapes. More specific patterns come first.
static PROVIDERS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("Anthropic key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
        ("OpenAI key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
        (
            "GitHub token",
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b",
        ),
        ("GitHub token", r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
        ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
        ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
        ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}"),
        ("Stripe key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}"),
        ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
        ("Hugging Face token", r"\bhf_[A-Za-z0-9]{30,}"),
        ("private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ]
    .into_iter()
    .filter_map(|(kind, re)| Regex::new(re).ok().map(|r| (kind, r)))
    .collect()
});

/// Setting names that say the value is a secret.
static SECRET_NAME: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(api[_-]?key|apikey|secret|token|passw(or)?d|pwd|authorization|credential|private[_-]?key|access[_-]?key)",
    )
    .ok()
});

/// Values that are clearly not a real key.
const PLACEHOLDERS: &[&str] = &[
    "your",
    "xxx",
    "example",
    "changeme",
    "placeholder",
    "replace",
    "dummy",
    "<",
    "...",
];

/// The first provider-shaped key in `s`.
pub fn provider(s: &str) -> Option<Secret> {
    PROVIDERS.iter().find_map(|(kind, re)| {
        re.find(s).map(|m| Secret {
            kind,
            masked: mask_provider(m.as_str()),
        })
    })
}

/// A key in the setting `name` with value `value`: a provider-shaped key, or a value that looks
/// like a real secret under a name such as `API_KEY` or `Authorization`.
pub fn named(name: &str, value: &str) -> Option<Secret> {
    if let Some(s) = provider(value) {
        return Some(s);
    }
    if !SECRET_NAME.as_ref().is_some_and(|re| re.is_match(name)) {
        return None;
    }
    let v = value.trim();
    let v = ["Bearer ", "Basic ", "token "]
        .iter()
        .find_map(|p| v.strip_prefix(p))
        .unwrap_or(v);
    let lower = v.to_ascii_lowercase();
    let looks_real = v.len() >= 12
        && !v.contains(char::is_whitespace)
        && !v.starts_with('$')
        && !v.contains("${")
        && !v.contains("://")
        && !v.starts_with(['/', '~', '.'])
        && v.chars().any(|c| c.is_ascii_alphabetic())
        && v.chars().any(|c| c.is_ascii_digit())
        && !PLACEHOLDERS.iter().any(|p| lower.contains(p));
    looks_real.then(|| Secret {
        kind: "secret",
        masked: mask_tail(v),
    })
}

/// A key passed as a command-line argument: provider-shaped, or the value of a flag such as
/// `--api-key=...` or `--token ...`. `next` is the argument after `arg`.
pub fn in_arg(arg: &str, next: Option<&str>) -> Option<Secret> {
    if let Some(s) = provider(arg) {
        return Some(s);
    }
    let flag = arg.strip_prefix("--")?;
    match flag.split_once('=') {
        Some((name, value)) => named(name, value),
        None => named(flag, next?),
    }
}

/// `s` with every provider-shaped key masked, for showing a command line.
pub fn redact(s: &str) -> String {
    PROVIDERS.iter().fold(s.to_string(), |acc, (_, re)| {
        re.replace_all(&acc, |c: &regex::Captures| mask_provider(&c[0]))
            .into_owned()
    })
}

/// Keeps the public prefix (`sk-`, `ghp_`, `AKIA`) and the last 4 characters.
fn mask_provider(key: &str) -> String {
    if key.contains("PRIVATE KEY") {
        return "BEGIN PRIVATE KEY".into();
    }
    let head = match key.find(['-', '_']) {
        Some(i) if i < 8 => &key[..=i],
        _ => key.get(..4).unwrap_or(""),
    };
    format!("{head}...{}", last4(key))
}

/// Shows only the last 4 characters, and none of a short value.
fn mask_tail(v: &str) -> String {
    if v.len() >= 16 {
        format!("...{}", last4(v))
    } else {
        "...".into()
    }
}

fn last4(s: &str) -> &str {
    let start = s.char_indices().rev().nth(3).map_or(0, |(i, _)| i);
    &s[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    const GH: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

    #[test]
    fn finds_provider_keys_and_masks_them() {
        let s = provider("sk-proj-abcdefghijklmnopqrstuv4f2a").unwrap();
        assert_eq!(s.kind, "OpenAI key");
        assert_eq!(s.masked, "sk-...4f2a");
        assert_eq!(provider(GH).unwrap().masked, "ghp_...6789");
        assert_eq!(
            provider("AKIAABCDEFGHIJKLMNOP").unwrap().masked,
            "AKIA...MNOP"
        );
        assert_eq!(
            provider("sk-ant-api03-abcdefghijklmnopqrstuvwxyz")
                .unwrap()
                .kind,
            "Anthropic key"
        );
        assert!(
            provider("-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
                .unwrap()
                .masked
                .contains("PRIVATE KEY")
        );
    }

    #[test]
    fn ignores_ordinary_text() {
        assert_eq!(provider("task-abcdefghijklmnopqrstuvwxyz"), None);
        assert_eq!(provider("@modelcontextprotocol/server-github"), None);
        assert_eq!(provider("ghp_short"), None);
    }

    #[test]
    fn named_values_need_a_secret_name_and_a_real_looking_value() {
        assert!(named("API_KEY", "a8f9d7c6b5e4a3f2d1c0").is_some());
        assert!(named("Authorization", "Bearer a8f9d7c6b5e4a3f2d1c0").is_some());
        assert_eq!(named("API_KEY", "${API_KEY}"), None);
        assert_eq!(named("API_KEY", "$API_KEY"), None);
        assert_eq!(named("API_KEY", "your-api-key-here-123"), None);
        assert_eq!(named("TOKEN_URL", "https://auth.example.com/v1"), None);
        assert_eq!(named("MAX_TOKENS", "4096"), None);
        assert_eq!(named("LOG_LEVEL", "a8f9d7c6b5e4a3f2d1c0"), None);
        assert_eq!(named("TOKEN_FILE", "/home/me/.token1234567"), None);
        // A provider key is found whatever the name.
        assert!(named("FOO", GH).is_some());
    }

    #[test]
    fn generic_masks_never_show_the_start() {
        let s = named("DB_PASSWORD", "hunter2hunter2hunter2").unwrap();
        assert_eq!(s.masked, "...ter2");
        assert_eq!(named("PASSWORD", "abc123abc123").unwrap().masked, "...");
    }

    #[test]
    fn flags_with_keys() {
        assert!(in_arg("--api-key=a8f9d7c6b5e4a3f2d1c0", None).is_some());
        assert!(in_arg("--token", Some("a8f9d7c6b5e4a3f2d1c0")).is_some());
        assert!(in_arg("--port", Some("8080")).is_none());
        assert!(in_arg("/Users/me/projects", None).is_none());
    }

    #[test]
    fn redact_masks_keys_in_text() {
        let r = redact(&format!("run --key {GH} now"));
        assert_eq!(r, "run --key ghp_...6789 now");
    }
}
