//! `guard top` (live terminal view) and `guard statusline`.

mod app;
pub mod data;
mod events;
mod network;
mod processes;
pub mod procs;
mod ui;

use std::io::IsTerminal;
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{self, KeyEventKind};

use crate::audit::Event;
use crate::config::{self, Config, TrustedHost};
use crate::{audit, home, pause};
use app::{Action, App};
use data::Counts;
use procs::{Monitor, Resolver};

const TAIL_EVERY: Duration = Duration::from_millis(500);
const PROCS_EVERY: Duration = Duration::from_secs(2);

/// Runs the live view until the user quits. The terminal is restored on exit and on panic.
pub fn run() -> anyhow::Result<()> {
    let path = audit::path()?;
    let now = home::now();
    let (events, end) = data::read_back(&path, now.saturating_sub(data::DAY), |e: &Event| e.ts)?;
    let mut app = App::new(events, now, !no_color(), local_offset());
    let mut tailer = data::Tailer::new(path, end);
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal, &mut app, &mut tailer);
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    tailer: &mut data::Tailer,
) -> anyhow::Result<()> {
    let mut monitor = Monitor::new();
    let mut resolver = Resolver::new();
    let hosts_file = home::dir()?.join("hosts.json");
    let mut last_tail: Option<Instant> = None;
    let mut last_procs: Option<Instant> = None;
    while !app.quit {
        if last_tail.is_none_or(|t| t.elapsed() >= TAIL_EVERY) {
            match tailer.poll() {
                Ok(new) => app.push(new),
                Err(e) => app.status = format!("Could not read the log: {e}"),
            }
            app.now = home::now();
            app.paused_until = pause::active(app.now);
            for (host, ips) in resolver.poll() {
                for ip in ips {
                    app.ip_hosts.insert(ip, host.clone());
                }
            }
            last_tail = Some(Instant::now());
        }
        if last_procs.is_none_or(|t| t.elapsed() >= PROCS_EVERY) {
            app.snap = monitor.refresh();
            app.first_seen = data::load_first_seen(&hosts_file);
            app.config = config::load().config;
            let since = app.now.saturating_sub(data::HOUR);
            for e in app.events().iter().rev().take_while(|e| e.ts >= since) {
                for h in data::hosts_of(e) {
                    resolver.ask(&h);
                }
            }
            last_procs = Some(Instant::now());
        }
        terminal.draw(|f| ui::draw(f, app))?;
        if event::poll(Duration::from_millis(200))?
            && let event::Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
            && let Some(action) = app.on_key(k)
        {
            apply(action, app, &monitor);
        }
    }
    Ok(())
}

/// Runs a side effect asked for by a key, and reports the outcome in the footer.
fn apply(action: Action, app: &mut App, monitor: &Monitor) {
    let mut config = config::load().config;
    let (saved, done) = match action {
        Action::Kill(pid) => {
            app.status = if monitor.kill(pid) {
                format!("Asked pid {pid} to stop.")
            } else {
                format!("Could not stop pid {pid}.")
            };
            return;
        }
        Action::Trust(host) => {
            trust(&mut config, &host);
            (config.save(), format!("Trusted {host}."))
        }
        Action::Block(host) => {
            block(&mut config, &host);
            (config.save(), format!("Blocked {host}."))
        }
    };
    app.status = match saved {
        Ok(()) => done,
        Err(e) => format!("Could not save the config: {e}"),
    };
    app.config = config;
}

/// Trusts `host` for every agent, forever (like `guard trust add <host>`).
fn trust(c: &mut Config, host: &str) {
    c.trust.hosts.retain(|t| t.host != host);
    c.trust.hosts.push(TrustedHost {
        host: host.to_string(),
        agent: None,
        process: None,
        expires_at: None,
    });
}

/// Blocks `host` (like `guard trust block <host>`).
fn block(c: &mut Config, host: &str) {
    if !c.trust.blocked.iter().any(|b| b == host) {
        c.trust.blocked.push(host.to_string());
    }
}

/// The local zone offset from `date +%z`, or UTC when it cannot be read.
fn local_offset() -> i64 {
    std::process::Command::new("date")
        .arg("+%z")
        .output()
        .ok()
        .and_then(|o| data::parse_offset(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or(0)
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
    let off = std::io::stdin()
        .is_terminal()
        .then(String::new)
        .or_else(|| std::io::read_to_string(std::io::stdin()).ok())
        .is_some_and(|raw| hooks_disabled(&raw));
    println!("{}", status_text(counts, paused, off, !no_color()));
    Ok(())
}

/// Whether the project in Claude Code's status line input sets `disableAllHooks`, which turns
/// every hook off, Agent Guard's included. A cloned repo can ship that setting.
fn hooks_disabled(status_input: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(status_input) else {
        return false;
    };
    let Some(dir) = v["workspace"]["current_dir"].as_str().or(v["cwd"].as_str()) else {
        return false;
    };
    ["settings.json", "settings.local.json"].iter().any(|f| {
        std::fs::read_to_string(std::path::Path::new(dir).join(".claude").join(f))
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .is_some_and(|s| s["disableAllHooks"] == serde_json::Value::Bool(true))
    })
}

/// The status line text, with ANSI colors when `color` is set.
fn status_text(c: Counts, paused: bool, off: bool, color: bool) -> String {
    if off {
        let msg = "◆ guard OFF in this project (disableAllHooks)";
        return if color {
            format!("\x1b[1;31m{msg}\x1b[0m")
        } else {
            msg.to_string()
        };
    }
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
        assert_eq!(status_text(c, false, false, false), "◆ guard ● 1 ● 2 ● 30");
        assert_eq!(
            status_text(c, true, false, false),
            "◆ guard ● 1 ● 2 ● 30 paused"
        );
        let colored = status_text(c, false, false, true);
        assert!(colored.contains("\x1b[31m●\x1b[0m 1"));
        assert!(colored.contains("\x1b[33m●\x1b[0m 2"));
        assert!(colored.contains("\x1b[32m●\x1b[0m 30"));
    }

    #[test]
    fn status_line_shows_disabled_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let input = serde_json::json!({ "workspace": { "current_dir": dir.path() } }).to_string();
        assert!(!hooks_disabled(&input));
        std::fs::create_dir(dir.path().join(".claude")).unwrap();
        std::fs::write(
            dir.path().join(".claude/settings.json"),
            r#"{"disableAllHooks": true}"#,
        )
        .unwrap();
        assert!(hooks_disabled(&input));
        let c = Counts::default();
        assert!(status_text(c, false, true, false).contains("OFF"));
    }

    #[test]
    fn trust_and_block_do_not_duplicate() {
        let mut c = Config::default();
        trust(&mut c, "paste.ee");
        trust(&mut c, "paste.ee");
        block(&mut c, "1.2.3.4");
        block(&mut c, "1.2.3.4");
        assert_eq!(c.trust.hosts.len(), 1);
        assert!(c.host_trusted("paste.ee", Some("claude"), None, 0));
        assert_eq!(c.trust.blocked, ["1.2.3.4"]);
        assert!(c.host_blocked("1.2.3.4"));
    }
}
