//! One row per tool call: a PreToolUse and its PostToolUse merged into one [`Call`], and what a
//! row shows (an icon, a short label, a plain reason) and the header's call rate. No terminal
//! code here.

use std::collections::HashMap;

use crate::audit::Event;
use crate::checks;
use crate::level::Level;

/// How long after its PreToolUse a PostToolUse still counts as the same call, in seconds.
pub const MERGE_WINDOW: u64 = 600;

/// One tool call, or one event that is not part of a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// Event id of the first event: the PreToolUse, or the lone event.
    pub id: usize,
    /// Event id of the matching PostToolUse, once it arrived.
    pub post: Option<usize>,
    /// Event id of the event with the worst level (the first on a tie): its reason is shown.
    pub main: usize,
    pub ts: u64,
    /// The worst level of the call's events.
    pub level: Option<Level>,
}

impl Call {
    /// Seconds from the PreToolUse to the PostToolUse.
    pub fn took(&self, events: impl Fn(usize) -> Option<u64>) -> Option<u64> {
        let post = events(self.post?)?;
        Some(post.saturating_sub(self.ts))
    }
}

/// Merges events (oldest first, with their ids) into calls, oldest first. A PostToolUse joins the
/// oldest open PreToolUse of the same session, tool and target from at most [`MERGE_WINDOW`]
/// seconds before; any other event is its own row.
pub fn merge<'a>(events: impl IntoIterator<Item = (usize, &'a Event)>) -> Vec<Call> {
    let mut calls: Vec<Call> = Vec::new();
    let mut open: HashMap<(&str, &str, &str), Vec<usize>> = HashMap::new();
    for (id, e) in events {
        let key = (e.session.as_str(), e.tool.as_str(), e.target.as_str());
        if e.source == "PostToolUse"
            && let Some(waiting) = open.get_mut(&key)
        {
            waiting.retain(|&i| calls.get(i).is_some_and(|c| c.ts + MERGE_WINDOW >= e.ts));
            if !waiting.is_empty()
                && let Some(c) = calls.get_mut(waiting.remove(0))
            {
                c.post = Some(id);
                if e.level > c.level {
                    c.level = e.level;
                    c.main = id;
                }
                continue;
            }
        }
        if e.source == "PreToolUse" {
            open.entry(key).or_default().push(calls.len());
        }
        calls.push(Call {
            id,
            post: None,
            main: id,
            ts: e.ts,
            level: e.level,
        });
    }
    calls
}

/// Whether an event is a prompt or a session start rather than a tool call.
pub fn is_prompt(e: &Event) -> bool {
    matches!(e.source.as_str(), "UserPromptSubmit" | "SessionStart")
}

/// Calls per `width`-second bucket for the last `n` buckets, oldest first; the last bucket ends
/// at `now`.
pub fn buckets(times: impl IntoIterator<Item = u64>, now: u64, width: u64, n: usize) -> Vec<u64> {
    let mut out = vec![0; n];
    let span = width * n as u64;
    for ts in times {
        let age = now.saturating_sub(ts);
        if ts <= now && age < span {
            let i = n - 1 - (age / width) as usize;
            out[i] += 1;
        }
    }
    out
}

const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Counts as a one-line chart: an empty bucket is the lowest bar, the fullest is the highest.
pub fn sparkline(counts: &[u64]) -> String {
    let max = counts.iter().copied().max().unwrap_or(0).max(1);
    counts
        .iter()
        .map(|&c| {
            if c == 0 {
                BARS[0]
            } else {
                BARS[1 + (c * 6 / max) as usize]
            }
        })
        .collect()
}

/// Seconds as `✓` (under a second), `3s`, `2m` or `1h`.
pub fn duration(secs: u64) -> String {
    match secs {
        0 => "✓".into(),
        1..60 => format!("{secs}s"),
        60..3600 => format!("{}m", secs / 60),
        _ => format!("{}h", secs / 3600),
    }
}

/// What the hook writes before the findings; the list shows the findings alone.
const PREFIXES: &[&str] = &[
    "Agent Guard blocked this:",
    "Agent Guard: risky, please confirm.",
    "Agent Guard warning:",
    "Agent Guard stopped this prompt:",
];

/// The finding message without the hook's prefix.
pub fn message(e: &Event) -> &str {
    let m = e.message.trim();
    PREFIXES
        .iter()
        .find_map(|p| m.strip_prefix(p))
        .unwrap_or(m)
        .trim()
}

/// A short plain reason for the list: the first clause of the finding message, else of the first
/// rule's explanation. Empty for a green event with neither.
pub fn why(e: &Event) -> String {
    let msg = message(e);
    if !msg.is_empty() {
        return first_clause(msg);
    }
    let all = checks::all_rules();
    let explained = e
        .rules
        .iter()
        .find_map(|r| all.iter().find(|(id, _)| id == r).map(|(_, why)| *why));
    match explained {
        Some(text) => first_clause(text),
        None if e.level.is_some_and(|l| l > Level::Green) => "flagged by a check".into(),
        None => String::new(),
    }
}

/// `s` up to its first `. `, `; ` or `, `, without a final period.
fn first_clause(s: &str) -> String {
    let end = [". ", "; ", ", "]
        .iter()
        .filter_map(|sep| s.find(sep))
        .min()
        .unwrap_or(s.len());
    s[..end].trim().trim_end_matches('.').to_string()
}

/// The icon for an event's tool.
pub fn icon(e: &Event) -> &'static str {
    let tool = e.tool.as_str();
    if tool == "net" || e.source.starts_with("net") {
        return "⇄";
    }
    if tool.starts_with("mcp__") {
        return "◇";
    }
    match tool {
        "Bash" => "$",
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => "✎",
        "Read" | "Grep" | "Glob" | "LS" => "◉",
        "WebFetch" | "WebSearch" => "⇣",
        "" => match e.source.as_str() {
            "UserPromptSubmit" => "»",
            "SessionStart" => "○",
            _ => "·",
        },
        _ => "⚙",
    }
}

/// Input fields that say what an internal tool (Agent, Task, SendMessage...) is doing.
const SUMMARY_KEYS: &[&str] = &[
    "subagent_type",
    "description",
    "skill",
    "to",
    "recipient",
    "name",
    "query",
    "prompt",
];

/// What the call is about, after its icon: the command, path or URL; `server · tool` for MCP;
/// the tool and a short summary for internal tools instead of their raw input.
pub fn label(e: &Event) -> String {
    let tool = e.tool.as_str();
    if let Some(rest) = tool.strip_prefix("mcp__") {
        return match rest.split_once("__") {
            Some((server, name)) => format!("{server} · {name}"),
            None => rest.to_string(),
        };
    }
    match icon(e) {
        "⚙" => match SUMMARY_KEYS.iter().find_map(|k| json_str(&e.target, k)) {
            Some(s) => format!("{tool} · {s}"),
            None => tool.to_string(),
        },
        "»" if e.target.is_empty() => "prompt".into(),
        "○" if e.target.is_empty() => "session start".into(),
        _ => e.target.clone(),
    }
}

/// The string value of `"key": "..."` in JSON text, which may be cut short. An escaped character is taken as is.
fn json_str(json: &str, key: &str) -> Option<String> {
    let at = json.find(&format!("\"{key}\""))? + key.len() + 2;
    let rest = json[at..].trim_start().strip_prefix(':')?.trim_start();
    let body = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut escaped = false;
    for c in body.chars() {
        match c {
            '"' if !escaped => break,
            '\\' if !escaped => escaped = true,
            _ => {
                escaped = false;
                out.push(c);
            }
        }
    }
    let out = out.trim().to_string();
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts: u64, source: &str, tool: &str, target: &str, level: Level) -> Event {
        Event {
            ts,
            agent: "claude".into(),
            session: "s".into(),
            source: source.into(),
            tool: tool.into(),
            target: target.into(),
            level: Some(level),
            ..Event::default()
        }
    }

    fn merged(es: &[Event]) -> Vec<Call> {
        merge(es.iter().enumerate())
    }

    #[test]
    fn pre_and_post_make_one_call() {
        let es = [
            ev(10, "PreToolUse", "Bash", "ls", Level::Green),
            ev(11, "PreToolUse", "Read", "a.rs", Level::Green),
            ev(13, "PostToolUse", "Bash", "ls", Level::Yellow),
            ev(14, "UserPromptSubmit", "", "", Level::Green),
        ];
        let calls = merged(&es);
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[0],
            Call {
                id: 0,
                post: Some(2),
                main: 2,
                ts: 10,
                level: Some(Level::Yellow),
            }
        );
        assert_eq!(calls[0].took(|i| es.get(i).map(|e| e.ts)), Some(3));
        assert_eq!(calls[1].post, None);
        assert_eq!(calls[2].id, 3);
    }

    #[test]
    fn post_needs_the_same_call_in_the_window() {
        let es = [
            ev(0, "PreToolUse", "Bash", "ls", Level::Red),
            ev(1, "PostToolUse", "Bash", "pwd", Level::Green),
            ev(2, "PreToolUse", "Bash", "ls", Level::Green),
            ev(3, "PostToolUse", "Bash", "ls", Level::Green),
            ev(4, "PostToolUse", "Bash", "ls", Level::Green),
            ev(5000, "PreToolUse", "Bash", "ls", Level::Green),
            ev(
                5000 + MERGE_WINDOW + 1,
                "PostToolUse",
                "Bash",
                "ls",
                Level::Green,
            ),
        ];
        let calls = merged(&es);
        let ids: Vec<(usize, Option<usize>)> = calls.iter().map(|c| (c.id, c.post)).collect();
        // The oldest open Pre gets the first Post; the worst level stays.
        assert_eq!(
            ids,
            [(0, Some(3)), (1, None), (2, Some(4)), (5, None), (6, None)]
        );
        assert_eq!(calls[0].level, Some(Level::Red));
        assert_eq!(calls[0].main, 0);
    }

    #[test]
    fn buckets_count_the_recent_window() {
        let b = buckets([100, 99, 91, 90, 89, 50, 40, 101], 100, 10, 6);
        assert_eq!(b, [1, 0, 0, 0, 2, 3]);
        assert_eq!(sparkline(&[0, 1, 3, 6]), "▁▃▅█");
        assert_eq!(sparkline(&[1, 100]), "▂█");
        assert_eq!(sparkline(&[0, 0]), "▁▁");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(0), "✓");
        assert_eq!(duration(3), "3s");
        assert_eq!(duration(150), "2m");
        assert_eq!(duration(7200), "2h");
    }

    #[test]
    fn why_is_plain_text() {
        let mut e = ev(0, "PreToolUse", "Bash", "curl", Level::Red);
        e.rules = vec!["net.exfil_service".into()];
        e.message = "Agent Guard: risky, please confirm. This uploads data to paste.ee, a paste, \
                     webhook or tunnel service. Second finding."
            .into();
        assert_eq!(why(&e), "This uploads data to paste.ee");
        e.message = "Agent Guard warning: This connects to a raw IP address (1.2.3.4).".into();
        assert_eq!(why(&e), "This connects to a raw IP address (1.2.3.4)");
        e.message.clear();
        e.rules = vec!["secrets.outbound".into()];
        assert_eq!(
            why(&e),
            "A key or one of your secret values is being sent somewhere other than its own service"
        );
        e.rules = vec!["no.such_rule".into()];
        assert_eq!(why(&e), "flagged by a check");
        assert_eq!(why(&ev(0, "PreToolUse", "Bash", "ls", Level::Green)), "");
    }

    #[test]
    fn icons_and_labels() {
        let e = |tool: &str, target: &str| ev(0, "PreToolUse", tool, target, Level::Green);
        let both = |e: Event| format!("{} {}", icon(&e), label(&e));
        assert_eq!(both(e("Bash", "ls -la")), "$ ls -la");
        assert_eq!(both(e("Edit", "src/a.rs")), "✎ src/a.rs");
        assert_eq!(both(e("Grep", "TODO")), "◉ TODO");
        assert_eq!(both(e("WebFetch", "https://docs.rs")), "⇣ https://docs.rs");
        assert_eq!(
            both(e("mcp__github__list_issues", "{}")),
            "◇ github · list_issues"
        );
        assert_eq!(
            both(e(
                "Agent",
                r#"{"description": "Find the \"top\" view", "prompt": "long"#
            )),
            "⚙ Agent · Find the \"top\" view"
        );
        assert_eq!(
            both(e("SendMessage", r#"{"to":"team-lead","message":"hi"}"#)),
            "⚙ SendMessage · team-lead"
        );
        assert_eq!(both(e("TodoWrite", r#"{"todos":[]}"#)), "⚙ TodoWrite");
        let mut net = e("net", "paste.ee:443");
        net.source = "net-proxy".into();
        assert_eq!(both(net), "⇄ paste.ee:443");
        let prompt = ev(0, "UserPromptSubmit", "", "", Level::Green);
        assert!(is_prompt(&prompt));
        assert_eq!(both(prompt), "» prompt");
    }
}
