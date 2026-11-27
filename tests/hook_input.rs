//! End to end: `guard hook` with input it cannot read, results while paused, huge results, and
//! a redirected Agent Guard directory showing in `guard status` and the status line. Each test
//! runs the binary with a temporary HOME and Agent Guard directory.

#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

use serde_json::{Value, json};

fn guard(home: &Path, args: &[&str], guard_home: Option<&Path>, stdin: &[u8]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_guard"));
    cmd.args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(g) = guard_home {
        cmd.env("AGENT_GUARD_HOME", g);
    }
    let mut child = cmd.spawn().unwrap();
    // The hook may stop reading early; a broken pipe here is fine.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().unwrap()
}

fn hook(home: &Path, input: &[u8]) -> Option<Value> {
    let out = guard(home, &["hook"], None, input);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    (!text.trim().is_empty()).then(|| serde_json::from_str(&text).unwrap())
}

fn nested(depth: usize) -> String {
    format!("{}1{}", "[".repeat(depth), "]".repeat(depth))
}

#[test]
fn unreadable_tool_calls_are_denied() {
    let dir = tempfile::tempdir().unwrap();
    let deep = format!(
        r#"{{"hook_event_name":"PreToolUse","session_id":"s","cwd":"/tmp","tool_name":"mcp__x__y","tool_input":{{"a":{}}}}}"#,
        nested(200)
    );
    let a = hook(dir.path(), deep.as_bytes()).unwrap();
    assert_eq!(a["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = a["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("nested too deeply"), "{reason}");

    let big = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{{"content":"{}"}}}}"#,
        "a".repeat(3 * 1024 * 1024)
    );
    let a = hook(dir.path(), big.as_bytes()).unwrap();
    assert_eq!(a["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        a["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("larger than 2 MB")
    );

    // Garbage, or a nested key claiming another event, is treated as a tool call.
    let a = hook(dir.path(), b"not json").unwrap();
    assert_eq!(a["hookSpecificOutput"]["permissionDecision"], "deny");
    let spoof = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_input":{{"x":{{"hook_event_name":"PostToolUse"}},"d":{}}}}}"#,
        nested(200)
    );
    let a = hook(dir.path(), spoof.as_bytes()).unwrap();
    assert_eq!(a["hookSpecificOutput"]["permissionDecision"], "deny");

    let audit = std::fs::read_to_string(dir.path().join(".agent-guard/audit.jsonl")).unwrap();
    assert_eq!(audit.matches("hook.unreadable").count(), 4);
}

#[test]
fn unreadable_tool_results_pass_with_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let deep = format!(
        r#"{{"hook_event_name":"PostToolUse","tool_name":"mcp__x__y","tool_input":{{}},"tool_response":{{"structuredContent":{}}}}}"#,
        nested(200)
    );
    let a = hook(dir.path(), deep.as_bytes()).unwrap();
    assert!(
        a["systemMessage"]
            .as_str()
            .unwrap()
            .contains("without being checked")
    );
    assert_eq!(a["hookSpecificOutput"]["hookEventName"], "PostToolUse");
    assert!(a["hookSpecificOutput"].get("updatedToolOutput").is_none());
    assert!(a["hookSpecificOutput"].get("permissionDecision").is_none());
}

#[test]
fn huge_results_are_checked_in_part_and_quickly() {
    let dir = tempfile::tempdir().unwrap();
    let text = format!(
        "{}\u{200B}{}",
        "word ".repeat(300_000),
        "tail ".repeat(60_000)
    );
    let input = json!({
        "hook_event_name": "PostToolUse",
        "session_id": "s",
        "cwd": dir.path(),
        "tool_name": "mcp__docs__fetch",
        "tool_input": {},
        "tool_response": {"content": [{"type": "text", "text": text}]},
    });
    let start = Instant::now();
    let a = hook(dir.path(), input.to_string().as_bytes()).unwrap();
    assert!(start.elapsed().as_secs() < 8, "{:?}", start.elapsed());
    let out = a["hookSpecificOutput"]["updatedToolOutput"]["content"][0]["text"]
        .as_str()
        .unwrap();
    assert!(out.len() <= 1024 * 1024 && out.len() > 1024 * 1024 - 100);
    assert!(out.starts_with("word ") && !out.contains("tail") && !out.contains('\u{200B}'));
    assert!(
        a["systemMessage"]
            .as_str()
            .unwrap()
            .contains("checked only the first 1 MB")
    );
}

#[test]
fn a_pause_never_rewrites_results() {
    let dir = tempfile::tempdir().unwrap();
    let input = json!({
        "hook_event_name": "PostToolUse",
        "session_id": "s",
        "cwd": dir.path(),
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://example.com"},
        "tool_response": {"result": "a\u{200B}b"},
    })
    .to_string();
    let a = hook(dir.path(), input.as_bytes()).unwrap();
    assert_eq!(a["hookSpecificOutput"]["updatedToolOutput"]["result"], "ab");

    assert!(
        guard(dir.path(), &["pause", "1h"], None, b"")
            .status
            .success()
    );
    assert_eq!(hook(dir.path(), input.as_bytes()), None);
}

#[test]
fn a_redirected_guard_home_is_shown() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("proj/.cache\u{1B}[8m");

    let status = guard(dir.path(), &["status"], Some(&elsewhere), b"");
    let text = String::from_utf8(status.stdout).unwrap();
    assert!(text.contains("AGENT_GUARD_HOME"), "{text}");
    assert!(text.contains("proj/.cache\\x1b[8m"), "{text}");
    let line = guard(dir.path(), &["statusline"], Some(&elsewhere), b"{}");
    let line = String::from_utf8(line.stdout).unwrap();
    assert!(line.contains(" home "), "{line}");
    assert!(line.contains("proj/.cache\\x1b[8m"), "{line}");
    assert!(!line.contains('\u{1B}'), "{line:?}");

    // The default directory, named explicitly or not, is not called out.
    let default = dir.path().join(".agent-guard");
    for g in [None, Some(default.as_path())] {
        let text = String::from_utf8(guard(dir.path(), &["status"], g, b"").stdout).unwrap();
        assert!(!text.contains("AGENT_GUARD_HOME"), "{text}");
        let line = guard(dir.path(), &["statusline"], g, b"{}");
        assert!(!String::from_utf8(line.stdout).unwrap().contains("home"));
    }
}
