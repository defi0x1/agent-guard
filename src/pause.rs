//! `guard pause 15m`: a way out when the guard misbehaves. Run by the user from a terminal; the
//! hook hard-blocks the agent from running it. The pause expires on its own.

use std::fs;
use std::io;

use crate::{hardened, home};

const FILE: &str = "pause.until";

/// The pause end time `guard off` writes: never, until `guard on`.
pub const OFF: u64 = u64::MAX;

/// Pauses checks until `until` (Unix seconds). In hardened mode the pause lives in the
/// root-owned policy folder and needs root; the user's own pause file is then ignored.
pub fn pause_until(until: u64) -> anyhow::Result<()> {
    let hp = hardened::Paths::system();
    if hardened::installed(&hp) {
        hardened::require_root(&hp, "off", hardened::is_root())?;
        return Ok(hardened::pause_until(&hp, until)?);
    }
    let dir = home::ensure()?;
    Ok(home::write_private(
        &dir.join(FILE),
        until.to_string().as_bytes(),
    )?)
}

pub fn resume() -> anyhow::Result<()> {
    let hp = hardened::Paths::system();
    if hardened::installed(&hp) {
        hardened::require_root(&hp, "on", hardened::is_root())?;
        return Ok(hardened::resume(&hp)?);
    }
    match fs::remove_file(home::dir()?.join(FILE)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// The pause end time, if a pause is active at `now`.
pub fn active(now: u64) -> Option<u64> {
    let hp = hardened::Paths::system();
    if hardened::installed(&hp) {
        return hardened::pause_active(&hp, now);
    }
    let text = fs::read_to_string(home::dir().ok()?.join(FILE)).ok()?;
    let until: u64 = text.trim().parse().ok()?;
    (now < until).then_some(until)
}

/// Parses `90s`, `15m`, `2h`, `1d`; a bare number is minutes.
pub fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, "m"),
    };
    let n: u64 = num.parse().ok()?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return None,
    };
    n.checked_mul(mult).filter(|&v| v > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90s"), Some(90));
        assert_eq!(parse_duration("15m"), Some(900));
        assert_eq!(parse_duration("15"), Some(900));
        assert_eq!(parse_duration("2h"), Some(7200));
        assert_eq!(parse_duration("1d"), Some(86400));
        assert_eq!(parse_duration("0m"), None);
        assert_eq!(parse_duration("5y"), None);
        assert_eq!(parse_duration(""), None);
    }
}
