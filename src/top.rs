//! `guard top` (live terminal view) and `guard statusline`.

pub mod data;

use crate::{audit, home, pause};
use data::Counts;

pub fn run() -> anyhow::Result<()> {
    anyhow::bail!("not implemented yet")
}

/// Whether colors are off (`NO_COLOR` set to anything non-empty).
pub fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

/// Prints one line for Claude Code's status line: the last 24 hours' red, yellow and green
/// counts, and whether Agent Guard is paused. Reads only the end of the log.
pub fn statusline() -> anyhow::Result<()> {
    let now = home::now();
    let counts = data::recent_counts(&audit::path()?, now.saturating_sub(data::DAY))?;
    let paused = pause::active(now).is_some();
    println!("{}", status_text(counts, paused, !no_color()));
    Ok(())
}

/// The status line text, with ANSI colors when `color` is set.
fn status_text(c: Counts, paused: bool, color: bool) -> String {
    let dot = |code: &str| {
        if color {
            format!("\x1b[{code}m●\x1b[0m")
        } else {
            "●".to_string()
        }
    };
    let mut s = format!(
        "◆ guard {} {} {} {} {} {}",
        dot("31"),
        c.red,
        dot("33"),
        c.yellow,
        dot("32"),
        c.green
    );
    if paused {
        s.push_str(" paused");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_line_text() {
        let c = Counts {
            red: 1,
            yellow: 2,
            green: 30,
        };
        assert_eq!(status_text(c, false, false), "◆ guard ● 1 ● 2 ● 30");
        assert_eq!(status_text(c, true, false), "◆ guard ● 1 ● 2 ● 30 paused");
        let colored = status_text(c, false, true);
        assert!(colored.contains("\x1b[31m●\x1b[0m 1"));
        assert!(colored.contains("\x1b[33m●\x1b[0m 2"));
        assert!(colored.contains("\x1b[32m●\x1b[0m 30"));
    }
}
