//! `guard statusline`: one line for Claude Code's status line that says whether Agent Guard is
//! on. With `--wrap`, it first prints that line and then runs the status line the user had before
//! `guard install` (saved in the guard home), so tools like claude-hud keep working below it.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

use crate::install::{self, Installed};
use crate::top::data::{self, Counts};
use crate::{audit, home, pause};

/// Where `guard install` keeps the status line it wrapped.
pub const WRAPPED_FILE: &str = "statusline-wrapped.json";

/// What the line reports. Kept separate from the rendering so it can be tested.
#[derive(Debug, PartialEq, Eq)]
enum State {
    NotInstalled,
    OffInProject,
    Paused {
        until: u64,
    },
    On {
        counts: Counts,
        mode: Option<String>,
    },
}

pub fn run(wrap: bool) -> anyhow::Result<()> {
    let mut input = String::new();
    if !std::io::stdin().is_terminal() {
        std::io::stdin().read_to_string(&mut input)?;
    }
    let state = state(&input)?;
    println!("{}", render(&state, !no_color()));
    if wrap && let Some(command) = wrapped_command(&home::dir()?) {
        run_wrapped(&command, &input)?;
    }
    Ok(())
}

fn state(input: &str) -> anyhow::Result<State> {
    let now = home::now();
    let v: Value = serde_json::from_str(input).unwrap_or(Value::Null);
    if matches!(install::installed(), Installed::No) {
        return Ok(State::NotInstalled);
    }
    if project_dir(&v).is_some_and(|d| hooks_disabled(&d)) {
        return Ok(State::OffInProject);
    }
    if let Some(until) = pause::active(now) {
        return Ok(State::Paused { until });
    }
    let counts = data::recent_counts(&audit::path()?, now.saturating_sub(data::DAY))?;
    let mode = ["permission_mode", "permissionMode"]
        .iter()
        .find_map(|k| v[*k].as_str())
        .filter(|m| *m != "default")
        .map(str::to_string);
    Ok(State::On { counts, mode })
}

fn render(s: &State, color: bool) -> String {
    let paint = |code: &str, text: &str| {
        if color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    };
    match s {
        State::NotInstalled => paint("1;31", "◆ guard OFF · not installed, run `guard install`"),
        State::OffInProject => paint("1;31", "◆ guard OFF in this project (disableAllHooks)"),
        State::Paused { until } => paint(
            "1;33",
            &format!(
                "◆ guard PAUSED · {}m left",
                until.saturating_sub(home::now()) / 60 + 1
            ),
        ),
        State::On { counts, mode } => {
            let mut line = format!(
                "{} {} {} {}",
                paint("1;32", "◆ guard ON"),
                paint("31", &format!("● {}", counts.red)),
                paint("33", &format!("● {}", counts.yellow)),
                paint("32", &format!("● {}", counts.green)),
            );
            if let Some(m) = mode {
                let code = if m.contains("bypass") { "1;31" } else { "33" };
                line.push_str(&format!(" · {}", paint(code, m)));
            }
            line
        }
    }
}

/// The project directory from Claude Code's status line input.
fn project_dir(v: &Value) -> Option<PathBuf> {
    v["workspace"]["current_dir"]
        .as_str()
        .or(v["cwd"].as_str())
        .map(PathBuf::from)
}

/// Whether the project turns every hook off, Agent Guard's included. A cloned repo can ship this.
fn hooks_disabled(dir: &Path) -> bool {
    ["settings.json", "settings.local.json"].iter().any(|f| {
        read_json(&dir.join(".claude").join(f))
            .is_some_and(|s| s["disableAllHooks"] == Value::Bool(true))
    })
}

/// The command of the status line `guard install` wrapped, if any.
pub fn wrapped_command(guard_home: &Path) -> Option<String> {
    read_json(&guard_home.join(WRAPPED_FILE))?["command"]
        .as_str()
        .map(str::to_string)
}

/// Runs the wrapped status line with the same input; its output goes straight to Claude Code.
fn run_wrapped(command: &str, input: &str) -> anyhow::Result<()> {
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        // A status line that ignores its input may close stdin early; that is fine.
        let _ = stdin.write_all(input.as_bytes());
    }
    child.wait()?;
    Ok(())
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn no_color() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_for_each_state() {
        let on = State::On {
            counts: Counts {
                red: 1,
                yellow: 2,
                green: 41,
            },
            mode: Some("auto".into()),
        };
        assert_eq!(render(&on, false), "◆ guard ON ● 1 ● 2 ● 41 · auto");
        assert!(render(&State::NotInstalled, false).starts_with("◆ guard OFF"));
        assert!(render(&State::OffInProject, false).contains("in this project"));
        assert!(render(&State::Paused { until: 0 }, false).contains("PAUSED"));
        assert!(render(&on, true).contains("\x1b[1;32m◆ guard ON\x1b[0m"));
    }

    #[test]
    fn project_that_disables_hooks_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!hooks_disabled(dir.path()));
        std::fs::create_dir(dir.path().join(".claude")).unwrap();
        std::fs::write(
            dir.path().join(".claude/settings.local.json"),
            r#"{"disableAllHooks": true}"#,
        )
        .unwrap();
        assert!(hooks_disabled(dir.path()));
        let v = serde_json::json!({ "workspace": { "current_dir": dir.path() } });
        assert_eq!(project_dir(&v).as_deref(), Some(dir.path()));
    }

    #[test]
    fn wrapped_command_is_read_from_the_guard_home() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(wrapped_command(dir.path()), None);
        std::fs::write(
            dir.path().join(WRAPPED_FILE),
            r#"{"type":"command","command":"echo 'hud'","refreshInterval":5}"#,
        )
        .unwrap();
        assert_eq!(wrapped_command(dir.path()).as_deref(), Some("echo 'hud'"));
    }
}
