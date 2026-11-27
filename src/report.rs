//! `guard report`, `guard explain`, `guard status`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail};

use crate::audit::{self, Event};
use crate::config::{self, Config};
use crate::level::Level;
use crate::text::term_safe;
use crate::{checks, home, install, pause};

/// How many rules, tools and warnings the report lists.
const TOP: usize = 5;

/// `guard report --since 24h`: counts, top rules and tools, and the latest warnings.
pub fn run(since: &str) -> anyhow::Result<()> {
    let secs = pause::parse_duration(since)
        .ok_or_else(|| anyhow!("bad duration {since:?}; try 24h or 7d"))?;
    let events = audit::read_all()?;
    print!(
        "{}",
        summary(&events, home::now().saturating_sub(secs), since)
    );
    Ok(())
}

/// `guard explain <rule>`: what a rule is about and how to change its level.
pub fn explain(rule: &str) -> anyhow::Result<()> {
    let path = config::path()?;
    let text = explain_text(rule, &checks::all_rules(), &config::load().config, &path)?;
    print!("{text}");
    Ok(())
}

/// `guard status`: on or paused, level, config, hooks, and the last day's counts.
pub fn status() -> anyhow::Result<()> {
    let now = home::now();
    let loaded = config::load();
    let path = config::path()?;
    match pause::active(now) {
        Some(until) => println!(
            "Agent Guard is paused until {} ({} min left). `guard resume` turns it back on.",
            fmt_time(until),
            until.saturating_sub(now).div_ceil(60)
        ),
        None => println!("Agent Guard is on."),
    }
    if let Some(dir) = moved_home() {
        println!(
            "Home: {} (moved by AGENT_GUARD_HOME; the default is ~/.agent-guard)",
            term_safe(&dir.to_string_lossy())
        );
    }
    println!("Level: {}", preset_name(&loaded.config));
    match &loaded.error {
        Some(e) => println!(
            "Config: could not be read, so defaults apply. {}",
            term_safe(e)
        ),
        None if path.exists() => println!("Config: {} (ok)", term_safe(&path.to_string_lossy())),
        None => println!(
            "Config: {} (not created yet, defaults apply)",
            term_safe(&path.to_string_lossy())
        ),
    }
    println!("Hooks: {}", install::installed().describe());
    let events = audit::read_all()?;
    let from = now.saturating_sub(86_400);
    let day: Vec<&Event> = events.iter().filter(|e| e.ts >= from).collect();
    println!("Last 24 hours: {}", Counts::of(&day).line());
    Ok(())
}

/// Agent Guard's directory when `AGENT_GUARD_HOME` moves it away from `~/.agent-guard`. A
/// project's settings can set that variable, so the move is always shown.
pub fn moved_home() -> Option<PathBuf> {
    let set = PathBuf::from(std::env::var_os("AGENT_GUARD_HOME")?);
    let default = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".agent-guard"));
    (default.as_ref() != Some(&set)).then_some(set)
}

/// Events per level. Events without a level (plain observations) count as green.
#[derive(Debug, Default, PartialEq, Eq)]
struct Counts {
    green: usize,
    yellow: usize,
    red: usize,
    blocked: usize,
}

impl Counts {
    fn of(events: &[&Event]) -> Counts {
        let mut c = Counts::default();
        for e in events {
            match e.level.unwrap_or(Level::Green) {
                Level::Green => c.green += 1,
                Level::Yellow => c.yellow += 1,
                Level::Red => c.red += 1,
                Level::HardBlock => c.blocked += 1,
            }
        }
        c
    }

    fn line(&self) -> String {
        format!(
            "{} green, {} yellow, {} red, {} blocked",
            self.green, self.yellow, self.red, self.blocked
        )
    }
}

/// The report text for events at or after `from`; `label` names the period, such as `24h`.
fn summary(events: &[Event], from: u64, label: &str) -> String {
    let recent: Vec<&Event> = events.iter().filter(|e| e.ts >= from).collect();
    if recent.is_empty() {
        return format!("No events in the last {label}.\n");
    }
    let mut lines = vec![
        format!("Agent Guard, last {label}: {} events", recent.len()),
        format!("  {}", Counts::of(&recent).line()),
    ];
    let rules = top(recent
        .iter()
        .flat_map(|e| e.rules.iter().map(String::as_str)));
    if !rules.is_empty() {
        lines.push("Top rules:".into());
        lines.extend(
            rules
                .iter()
                .map(|(r, n)| format!("  {n:>5}  {}", term_safe(r))),
        );
    }
    let tools = top(recent.iter().map(|e| e.tool.as_str()));
    if !tools.is_empty() {
        lines.push("Top tools:".into());
        lines.extend(
            tools
                .iter()
                .map(|(t, n)| format!("  {n:>5}  {}", term_safe(t))),
        );
    }
    let alerts: Vec<&&Event> = recent
        .iter()
        .filter(|e| e.level >= Some(Level::Yellow))
        .collect();
    if !alerts.is_empty() {
        lines.push("Latest warnings:".into());
        for e in alerts.iter().rev().take(TOP) {
            lines.push(format!(
                "  {}  {}  {}  {}",
                fmt_time(e.ts),
                e.level.unwrap_or(Level::Green),
                term_safe(if e.tool.is_empty() {
                    &e.source
                } else {
                    &e.tool
                }),
                term_safe(&audit::clip(&e.target, 60))
            ));
            if !e.message.is_empty() {
                lines.push(format!("      {}", term_safe(&e.message)));
            }
        }
        lines.push("`guard explain <rule>` says what a rule means.".into());
    }
    lines.join("\n") + "\n"
}

/// The most frequent non-empty names, most frequent first, then by name.
fn top<'a>(names: impl Iterator<Item = &'a str>) -> Vec<(&'a str, usize)> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for n in names.filter(|n| !n.is_empty()) {
        *counts.entry(n).or_default() += 1;
    }
    let mut v: Vec<(&str, usize)> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.truncate(TOP);
    v
}

/// The explanation of `rule`, or of every rule it is a prefix of (such as `secrets`).
fn explain_text(
    rule: &str,
    rules: &[(&str, &str)],
    cfg: &Config,
    config_path: &Path,
) -> anyhow::Result<String> {
    let rule = rule.trim();
    if rule.is_empty() {
        bail!("name a rule, for example `guard explain secrets`");
    }
    let mut matches: Vec<&(&str, &str)> = rules.iter().filter(|(id, _)| *id == rule).collect();
    if matches.is_empty() {
        matches = rules
            .iter()
            .filter(|(id, _)| id.starts_with(rule))
            .collect();
    }
    if matches.is_empty() {
        let mut modules: Vec<&str> = rules
            .iter()
            .map(|(id, _)| id.split('.').next().unwrap_or(id))
            .collect();
        modules.dedup();
        let hint = if modules.is_empty() {
            "No rules are registered yet.".to_string()
        } else {
            format!("Try one of: {}.", modules.join(", "))
        };
        bail!("unknown rule {rule:?}. {hint}");
    }
    let mut lines = Vec::new();
    for (id, why) in matches {
        lines.push((*id).to_string());
        lines.push(format!("  {why}"));
        if let Some(o) = cfg.rules.get(*id) {
            lines.push(format!("  Your config sets it to {}.", o.level));
        }
        lines.push(format!(
            "  To change its level, add this to {}:",
            term_safe(&config_path.to_string_lossy())
        ));
        lines.push("    [rules]".into());
        lines.push(format!("    \"{id}\" = {{ level = \"yellow\" }}"));
        lines.push(String::new());
    }
    lines.push(
        "Levels: green (log only), yellow (warn, the call runs), red (ask you first).".into(),
    );
    Ok(lines.join("\n") + "\n")
}

fn preset_name(cfg: &Config) -> String {
    format!("{:?}", cfg.preset).to_lowercase()
}

/// `2026-11-27 10:02 UTC`.
fn fmt_time(ts: u64) -> String {
    let (y, m, d) = civil_from_days((ts / 86_400) as i64);
    let secs = ts % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (Howard Hinnant's method).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RuleOverride;

    fn ev(ts: u64, level: Level, tool: &str, rules: &[&str], message: &str) -> Event {
        Event {
            ts,
            agent: "claude".into(),
            source: "PreToolUse".into(),
            tool: tool.into(),
            target: format!("{tool} target"),
            level: Some(level),
            rules: rules.iter().map(|r| r.to_string()).collect(),
            message: message.into(),
            ..Event::default()
        }
    }

    #[test]
    fn times() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_time(1_795_773_720), "2026-11-27 10:02 UTC");
        assert_eq!(fmt_time(1_709_251_140), "2024-02-29 23:59 UTC");
    }

    #[test]
    fn report_counts_and_lists() {
        let mut events = vec![ev(10, Level::Red, "Bash", &["old.rule"], "too old")];
        for i in 0..3 {
            events.push(ev(100 + i, Level::Green, "Read", &[], ""));
        }
        for i in 0..7 {
            events.push(ev(
                200 + i,
                Level::Yellow,
                "Bash",
                &["net.unknown_host"],
                &format!("warning {i}"),
            ));
        }
        events.push(ev(
            300,
            Level::Red,
            "WebFetch",
            &["secrets.outbound"],
            "key out",
        ));
        let out = summary(&events, 50, "24h");
        assert!(out.contains("last 24h: 11 events"), "{out}");
        assert!(out.contains("3 green, 7 yellow, 1 red, 0 blocked"));
        assert!(out.contains("      7  net.unknown_host"));
        assert!(out.contains("      7  Bash"));
        assert!(!out.contains("old.rule"));
        assert!(out.contains("key out"));
        assert!(out.contains("warning 6"));
        // Only the latest five warnings: 6, 5, 4, 3 and the red one.
        assert!(!out.contains("warning 2"));
        assert!(!out.contains("too old"));
        let newest = out.find("key out").unwrap();
        assert!(newest < out.find("warning 6").unwrap());
    }

    #[test]
    fn report_escapes_terminal_codes() {
        let mut e = ev(
            100,
            Level::Red,
            "Bash\u{1B}[2J",
            &["r\u{7}"],
            "m\u{1B}]52;c;eA==\u{7}",
        );
        e.target = "t\u{9B}1A\nfake line".into();
        let out = summary(&[e], 0, "24h");
        assert!(!out.contains(['\u{1B}', '\u{7}', '\u{9B}']), "{out:?}");
        assert!(out.contains("Bash\\x1b[2J"));
        assert!(out.contains("t\\u{9b}1A\\nfake line"));
        assert!(out.contains("m\\x1b]52;c;eA==\\x07"));
    }

    #[test]
    fn empty_report() {
        assert_eq!(summary(&[], 0, "7d"), "No events in the last 7d.\n");
    }

    const RULES: &[(&str, &str)] = &[
        ("secrets.outbound", "A key is being sent out."),
        ("secrets.prompt", "You typed a key into chat."),
        ("net.raw_ip", "A call goes to a bare IP address."),
    ];

    #[test]
    fn explain_exact_and_prefix() {
        let p = Path::new("/h/config.toml");
        let mut cfg = Config::default();
        let t = explain_text("secrets.outbound", RULES, &cfg, p).unwrap();
        assert!(t.contains("A key is being sent out."));
        assert!(t.contains("\"secrets.outbound\" = { level = \"yellow\" }"));
        assert!(t.contains("/h/config.toml"));
        assert!(!t.contains("secrets.prompt"));

        let t = explain_text("secrets", RULES, &cfg, p).unwrap();
        assert!(t.contains("secrets.outbound") && t.contains("secrets.prompt"));
        assert!(!t.contains("net.raw_ip"));

        cfg.rules.insert(
            "net.raw_ip".into(),
            RuleOverride {
                level: Level::Green,
            },
        );
        let t = explain_text("net.raw_ip", RULES, &cfg, p).unwrap();
        assert!(t.contains("Your config sets it to green."));
    }

    #[test]
    fn explain_unknown_rule() {
        let p = Path::new("/h/config.toml");
        let e = explain_text("nope.rule", RULES, &Config::default(), p)
            .unwrap_err()
            .to_string();
        assert!(e.contains("unknown rule \"nope.rule\""), "{e}");
        assert!(e.contains("secrets, net"), "{e}");
        let e = explain_text("x", &[], &Config::default(), p)
            .unwrap_err()
            .to_string();
        assert!(e.contains("No rules are registered yet"));
        assert!(explain_text(" ", RULES, &Config::default(), p).is_err());
    }
}
