//! The event log: one JSON line per decision in `audit.jsonl` (mode 0600). Hook, proxy and the
//! network sampler all write this shape, so `top`, `report` and the status line agree.
//! Never write a raw secret here: callers pass redacted targets.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::home;
use crate::level::Level;

/// One thing an agent did, and what Agent Guard decided.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unix seconds.
    pub ts: u64,
    /// `claude`, `codex`, `proxy`, `net`.
    pub agent: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session: String,
    /// Where it came from: `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SessionStart`,
    /// `proxy`, `net`.
    pub source: String,
    /// `Bash`, `Read`, `WebFetch`, `mcp__github__create_issue`, `net`...
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool: String,
    /// A short, redacted description: a command, a path, a URL, `host:port`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub level: Option<Level>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
}

pub fn path() -> io::Result<PathBuf> {
    Ok(home::dir()?.join("audit.jsonl"))
}

/// Appends one event. Concurrent hook processes append whole lines (O_APPEND, one write).
pub fn append(e: &Event) -> io::Result<()> {
    let dir = home::ensure()?;
    let mut line = serde_json::to_vec(e).map_err(io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(dir.join("audit.jsonl"))?;
    f.write_all(&line)
}

/// Every event in the log, oldest first. Unreadable lines are skipped.
pub fn read_all() -> io::Result<Vec<Event>> {
    let p = path()?;
    let f = match fs::File::open(&p) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect())
}

/// Shortens `s` to at most `max` characters, marking the cut.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_marks_the_cut() {
        assert_eq!(clip("abc", 5), "abc");
        assert_eq!(clip("abcdef", 4), "abc…");
    }
}
