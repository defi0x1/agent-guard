//! End-to-end checks of `guard install`, `uninstall`, `selftest`, `status`, `report` and
//! `explain`, run on the real binary with temporary home folders.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

fn guard(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_guard"))
        .args(args)
        .env("HOME", dir)
        .env("CLAUDE_CONFIG_DIR", dir.join("claude"))
        .env("AGENT_GUARD_HOME", dir.join("guard"))
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn install_then_uninstall() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join("claude").join("settings.json");
    std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
    std::fs::write(&settings, r#"{"model": "opus"}"#).unwrap();

    let o = guard(dir.path(), &["install"]);
    assert!(o.status.success());
    assert!(stdout(&o).contains("Restart Claude Code to apply."));
    let s: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
    let cmd = s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(cmd.starts_with('/') && cmd.ends_with("guard hook"), "{cmd}");
    assert_eq!(s["model"], "opus");

    let o = guard(dir.path(), &["status"]);
    assert!(stdout(&o).contains("installed in Claude Code settings"));
    let o = guard(dir.path(), &["install"]);
    assert!(stdout(&o).contains("already installed"));

    assert!(guard(dir.path(), &["uninstall"]).status.success());
    assert_eq!(
        std::fs::read_to_string(&settings).unwrap(),
        "{\n  \"model\": \"opus\"\n}\n"
    );
    let backups = std::fs::read_dir(dir.path().join("guard").join("backups")).unwrap();
    assert!(backups.count() >= 1);
}

#[test]
fn selftest_runs_every_case() {
    let dir = tempfile::tempdir().unwrap();
    let o = guard(dir.path(), &["selftest"]);
    let out = stdout(&o);
    assert!(
        out.contains("PASS     a harmless read stays silent"),
        "{out}"
    );
    assert!(out.contains("paste site"));
    assert!(out.contains("own folder"));
    assert!(out.contains("MCP result"));
    assert!(out.contains("Hooks: not installed"));
    // The selftest never touches the user's own Agent Guard folder.
    assert!(!dir.path().join("guard").join("audit.jsonl").exists());
}

#[test]
fn report_status_and_explain() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("guard");
    std::fs::create_dir_all(&home).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let line = format!(
        r#"{{"ts":{now},"agent":"claude","source":"PreToolUse","tool":"Bash","target":"curl paste.ee","level":"red","rules":["secrets.outbound"],"message":"Your key goes to paste.ee."}}"#
    );
    std::fs::write(home.join("audit.jsonl"), line + "\n").unwrap();

    let out = stdout(&guard(dir.path(), &["report", "--since", "1h"]));
    assert!(out.contains("0 green, 0 yellow, 1 red, 0 blocked"), "{out}");
    assert!(out.contains("secrets.outbound"));
    assert!(out.contains("Your key goes to paste.ee."));

    let out = stdout(&guard(dir.path(), &["status"]));
    assert!(out.contains("Agent Guard is on."), "{out}");
    assert!(out.contains("Last 24 hours: 0 green, 0 yellow, 1 red"));

    assert!(
        !guard(dir.path(), &["report", "--since", "soon"])
            .status
            .success()
    );
    let o = guard(dir.path(), &["explain", "no.such.rule"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("unknown rule"));
}
