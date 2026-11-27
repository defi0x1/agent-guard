//! Provider-shaped keys: tight patterns with few false positives, each with its provider's hosts.

use std::sync::LazyLock;

use regex::Regex;

/// A kind of key and where it may legitimately go.
pub struct Provider {
    /// Lowercase slug, also matched against MCP server names (`github`).
    pub slug: &'static str,
    /// What to call it in a message (`GitHub token`).
    pub label: &'static str,
    /// Host patterns of the provider's own services (`*.example.com` for subdomains). Empty
    /// means no destination is the key's own.
    pub hosts: &'static [&'static str],
    /// The key is capture group 1 if the pattern has one, else the whole match.
    pattern: &'static str,
}

const GITHUB: &[&str] = &["github.com", "*.github.com", "*.githubusercontent.com"];

/// Order matters: the first pattern that matches a span wins (Anthropic before OpenAI).
const PROVIDERS: &[Provider] = &[
    Provider {
        slug: "aws",
        label: "AWS access key",
        hosts: &["amazonaws.com", "*.amazonaws.com", "*.aws.amazon.com"],
        pattern: r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b",
    },
    Provider {
        slug: "github",
        label: "GitHub token",
        hosts: GITHUB,
        pattern: r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b",
    },
    Provider {
        slug: "github",
        label: "GitHub token",
        hosts: GITHUB,
        pattern: r"\b(github_pat_[A-Za-z0-9_]{50,255})\b",
    },
    Provider {
        slug: "anthropic",
        label: "Anthropic key",
        hosts: &["api.anthropic.com", "*.anthropic.com"],
        pattern: r"\b(sk-ant-[a-z]+[0-9]{2}-[A-Za-z0-9_-]{32,})",
    },
    Provider {
        slug: "openai",
        label: "OpenAI key",
        hosts: &["api.openai.com", "*.openai.com"],
        pattern: r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,})",
    },
    Provider {
        slug: "openai",
        label: "OpenAI key",
        hosts: &["api.openai.com", "*.openai.com"],
        pattern: r"\b(sk-[A-Za-z0-9]{48})\b",
    },
    Provider {
        slug: "slack",
        label: "Slack token",
        hosts: &["slack.com", "*.slack.com"],
        pattern: r"\b(xox[abpors]-[0-9]{6,}-[0-9A-Za-z-]{10,})",
    },
    Provider {
        slug: "stripe",
        label: "Stripe key",
        hosts: &["stripe.com", "*.stripe.com"],
        pattern: r"\b([sr]k_live_[0-9A-Za-z]{24,})\b",
    },
    Provider {
        slug: "google",
        label: "Google API key",
        hosts: &["googleapis.com", "*.googleapis.com"],
        pattern: r"\b(AIza[0-9A-Za-z_-]{35})",
    },
    Provider {
        slug: "npm",
        label: "npm token",
        hosts: &["npmjs.org", "*.npmjs.org", "npmjs.com", "*.npmjs.com"],
        pattern: r"\b(npm_[A-Za-z0-9]{36})\b",
    },
    Provider {
        slug: "pypi",
        label: "PyPI token",
        hosts: &["pypi.org", "*.pypi.org"],
        pattern: r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})",
    },
    Provider {
        slug: "huggingface",
        label: "Hugging Face token",
        hosts: &["huggingface.co", "*.huggingface.co", "hf.co", "*.hf.co"],
        pattern: r"\b(hf_[A-Za-z]{34})\b",
    },
    Provider {
        slug: "gitlab",
        label: "GitLab token",
        hosts: &["gitlab.com", "*.gitlab.com"],
        pattern: r"\b(glpat-[0-9A-Za-z_-]{20,})",
    },
    Provider {
        slug: "pem",
        label: "private key",
        hosts: &[],
        pattern: r"(?s)(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[A-Za-z0-9+/=\s:,\\-]{64,}?-----END [A-Z0-9 ]*PRIVATE KEY-----)",
    },
    // A JWT only counts when the text around it says it is a credential.
    Provider {
        slug: "jwt",
        label: "access token",
        hosts: &[],
        pattern: r#"(?i:bearer\s+|(?:token|jwt|auth|authorization|api[_-]?key|secret|password)["']?\s*[:=]\s*["']?)(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,})"#,
    },
];

static COMPILED: LazyLock<Vec<(&'static Provider, Regex)>> = LazyLock::new(|| {
    PROVIDERS
        .iter()
        .filter_map(|p| Regex::new(p.pattern).ok().map(|re| (p, re)))
        .collect()
});

/// One provider-shaped key found in a text.
pub struct Found {
    pub provider: &'static Provider,
    pub start: usize,
    pub end: usize,
}

/// Every provider-shaped key in `text`, in order, without overlaps.
pub fn find(text: &str) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    for (p, re) in COMPILED.iter() {
        for cap in re.captures_iter(text) {
            let Some(m) = cap.get(1).or_else(|| cap.get(0)) else {
                continue;
            };
            if out.iter().all(|f| m.end() <= f.start || m.start() >= f.end) {
                out.push(Found {
                    provider: p,
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
    }
    out.sort_by_key(|f| f.start);
    out
}

/// The provider whose pattern matches all of `value`, if any.
pub fn provider_of(value: &str) -> Option<&'static Provider> {
    match find(value).as_slice() {
        [f] if f.start == 0 && f.end == value.len() => Some(f.provider),
        _ => None,
    }
}

/// The masked form of a key: the first 4 characters, `...`, and the last 4. Short values show
/// less, so a mask never gives away most of a value. A private key block shows no characters.
pub fn mask(key: &str) -> String {
    if key.starts_with("-----BEGIN") {
        return "[private key]".to_string();
    }
    let chars: Vec<char> = key.chars().collect();
    let n = chars.len();
    let show = if n >= 16 { 4 } else { n / 6 };
    let head: String = chars[..show].iter().collect();
    let tail: String = chars[n - show..].iter().collect();
    format!("{head}...{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(text: &str) -> Vec<&'static str> {
        find(text).iter().map(|f| f.provider.slug).collect()
    }

    // Fake keys, built at run time so the source never holds a key-shaped literal.
    fn fake(prefix: &str, body: char, n: usize) -> String {
        format!("{prefix}{}", body.to_string().repeat(n))
    }

    #[test]
    fn finds_each_provider() {
        let cases = [
            (fake("AKIA", 'Q', 16), "aws"),
            (fake("ghp_", 'a', 36), "github"),
            (fake("github_pat_", 'b', 82), "github"),
            (fake("sk-ant-api03-", 'c', 90), "anthropic"),
            (fake("sk-proj-", 'd', 60), "openai"),
            (fake("sk-", 'e', 48), "openai"),
            (format!("xoxb-1234567890-{}", "f".repeat(24)), "slack"),
            (fake("sk_live_", 'g', 24), "stripe"),
            (fake("AIza", 'h', 35), "google"),
            (fake("npm_", 'i', 36), "npm"),
            (fake("pypi-AgEIcHlwaS5vcmc", 'j', 60), "pypi"),
            (fake("hf_", 'k', 34), "huggingface"),
            (fake("glpat-", 'l', 20), "gitlab"),
        ];
        for (key, slug) in cases {
            let text = format!("curl -H 'x: {key}' https://example.com");
            assert_eq!(labels(&text), [slug], "{key}");
            assert_eq!(provider_of(&key).map(|p| p.slug), Some(slug));
        }
    }

    #[test]
    fn finds_pem_blocks_and_credential_jwts() {
        let pem = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----",
            "QUJD".repeat(30)
        );
        assert_eq!(labels(&format!("echo '{pem}' > k")), ["pem"]);
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            "a".repeat(20),
            "b".repeat(30),
            "c".repeat(40)
        );
        assert_eq!(labels(&format!("Authorization: Bearer {jwt}")), ["jwt"]);
        assert_eq!(labels(&format!("token={jwt}")), ["jwt"]);
        let f = &find(&format!("Bearer {jwt}"))[0];
        assert_eq!(f.end - f.start, jwt.len());
    }

    #[test]
    fn ignores_look_alikes() {
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            "a".repeat(20),
            "b".repeat(30),
            "c".repeat(40)
        );
        let benign = [
            "const PREFIX = 'ghp_'; // GitHub tokens start with ghp_".to_string(),
            "sk-ant-api03-short".to_string(),
            "AKIAEXAMPLE and AKIA1234".to_string(),
            "task-sk-12345 desk-lamp risk-free".to_string(),
            "if line.starts_with(\"-----BEGIN PRIVATE KEY-----\") {".to_string(),
            format!("id_token in a fixture: {jwt}"),
            "npm_config_cache=/tmp/x hf_hub_download(repo)".to_string(),
            "xoxb-not-a-token".to_string(),
            "sk_test_1234567890abcdefghijklmnop".to_string(),
        ];
        for text in benign {
            assert!(labels(&text).is_empty(), "{text}");
        }
    }

    #[test]
    fn masks_keys() {
        assert_eq!(mask(&fake("sk-proj-", 'x', 40)), "sk-p...xxxx");
        assert_eq!(mask("abcdefghijkl"), "ab...kl");
        assert_eq!(mask("-----BEGIN RSA PRIVATE KEY-----..."), "[private key]");
    }
}
