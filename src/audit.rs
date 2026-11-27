//! The event log: one JSON line per decision in `audit.jsonl` (mode 0600). Hook, proxy and the
//! network sampler all write this shape, so `top`, `report` and the status line agree.
//! Never write a raw secret here: callers pass redacted targets.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

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

/// The log is moved to `audit.jsonl.1` (replacing the older one) once it is larger than this.
const MAX_LOG: u64 = 10 * 1024 * 1024;

/// Appends one event. Concurrent hook processes append whole lines (O_APPEND, one write).
pub fn append(e: &Event) -> io::Result<()> {
    let path = home::ensure()?.join("audit.jsonl");
    rotate(&path, MAX_LOG)?;
    let mut line = serde_json::to_vec(e).map_err(io::Error::other)?;
    line.push(b'\n');
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    f.write_all(&line)
}

/// Moves `path` to `<path>.1` if it is larger than `max` bytes.
fn rotate(path: &Path, max: u64) -> io::Result<()> {
    match fs::metadata(path) {
        Ok(m) if m.len() > max => match fs::rename(path, path.with_extension("jsonl.1")) {
            // Another process rotated it first.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        },
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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
    fn large_log_is_rotated_once() {
        let d = tempfile::tempdir().unwrap();
        let log = d.path().join("audit.jsonl");
        rotate(&log, 10).unwrap();
        fs::write(&log, "0123456789").unwrap();
        rotate(&log, 10).unwrap();
        assert!(log.exists(), "at the limit it stays");
        fs::write(&log, "0123456789a").unwrap();
        rotate(&log, 10).unwrap();
        assert!(!log.exists());
        assert_eq!(
            fs::read_to_string(d.path().join("audit.jsonl.1")).unwrap(),
            "0123456789a"
        );
    }

    #[test]
    fn clip_marks_the_cut() {
        assert_eq!(clip("abc", 5), "abc");
        assert_eq!(clip("abcdef", 4), "abc…");
    }
}
