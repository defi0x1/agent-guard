//! `guard hook`: Claude Code runs it for every hook event, with the event as JSON on stdin.
//! It prints Claude Code's hook answer as JSON on stdout (or nothing, for green).
//!
//! Levels map to answers:
//! - green: no output (Claude Code decides as usual; Agent Guard never says "allow");
//! - yellow: a `systemMessage` warning, the call runs;
//! - red: `permissionDecision: "ask"` with the warning as the reason;
//! - hard block: `permissionDecision: "deny"`.

use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::audit::{self, Event};
use crate::checks::{self, Ctx, ToolCall};
use crate::config;
use crate::home;
use crate::level::{Level, Verdict};
use crate::pause;

/// The fields Agent Guard reads from Claude Code's hook input. Unknown fields are ignored.
#[derive(Debug, Default, Deserialize)]
pub struct Input {
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub cwd: PathBuf,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<Value>,
    #[serde(default)]
    pub tool_response: Option<Value>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub mcp_server: Option<McpServer>,
}

#[derive(Debug, Default, Deserialize)]
pub struct McpServer {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

/// Reads stdin, decides, prints the answer. Errors go to stderr with exit code 1, which Claude
/// Code treats as a hook failure (blocking for PreToolUse when configured with onFailure).
pub fn run() -> anyhow::Result<()> {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    let input: Input = serde_json::from_str(&raw)?;
    if let Some(out) = handle(&input)? {
        println!("{out}");
    }
    Ok(())
}

/// Decides one hook event. Returns the JSON answer, or `None` for "no opinion".
pub fn handle(input: &Input) -> anyhow::Result<Option<Value>> {
    let loaded = config::load();
    let ctx = Ctx {
        config: loaded.config,
        now: home::now(),
        home: home::ensure()?,
        agent: "claude".into(),
        session: input.session_id.clone(),
        cwd: input.cwd.clone(),
    };
    let paused = pause::active(ctx.now).is_some();
    let empty = Value::Null;
    let call = input.tool_name.as_deref().map(|tool| ToolCall {
        tool,
        input: input.tool_input.as_ref().unwrap_or(&empty),
        mcp_server: input.mcp_server.as_ref().and_then(|m| m.name.as_deref()),
    });

    let mut context = Vec::new();
    let mut replaced = None;
    let verdict = match (input.hook_event_name.as_str(), &call) {
        ("PreToolUse", Some(c)) => checks::pre_tool(&ctx, c),
        ("PostToolUse", Some(c)) => {
            let r = checks::post_tool(&ctx, c, input.tool_response.as_ref().unwrap_or(&empty));
            context = r.context;
            replaced = r.replaced;
            r.verdict
        }
        ("UserPromptSubmit", _) => checks::prompt(&ctx, input.prompt.as_deref().unwrap_or("")),
        ("SessionStart", _) => {
            let mut v = checks::session_start(&ctx);
            if let Some(e) = &loaded.error {
                v.push(crate::level::Finding::new(
                    "config.invalid",
                    Level::Yellow,
                    format!("Your Agent Guard config could not be read, so defaults apply. {e}"),
                ));
            }
            v
        }
        _ => Verdict::default(),
    };

    // A pause lets everything through except the agent tampering with Agent Guard.
    let effective = if paused && verdict.level() != Level::HardBlock {
        Verdict::default()
    } else {
        verdict
    };
    log(&ctx, input, call.as_ref(), &effective, paused);
    Ok(answer(
        &input.hook_event_name,
        &effective,
        replaced,
        &context,
    ))
}

fn answer(event: &str, v: &Verdict, replaced: Option<Value>, context: &[String]) -> Option<Value> {
    let level = v.level();
    let text = message(v);
    let mut out = serde_json::Map::new();
    let mut specific = serde_json::Map::new();
    specific.insert("hookEventName".into(), json!(event));

    match (event, level) {
        ("PreToolUse", Level::HardBlock) => {
            specific.insert("permissionDecision".into(), json!("deny"));
            specific.insert("permissionDecisionReason".into(), json!(text));
        }
        ("PreToolUse", Level::Red) => {
            specific.insert("permissionDecision".into(), json!("ask"));
            specific.insert("permissionDecisionReason".into(), json!(text));
        }
        ("UserPromptSubmit", Level::Red | Level::HardBlock) => {
            out.insert("decision".into(), json!("block"));
            out.insert("reason".into(), json!(text));
        }
        (_, Level::Yellow | Level::Red | Level::HardBlock) => {
            out.insert("systemMessage".into(), json!(text));
        }
        _ => {}
    }
    if let Some(r) = replaced {
        specific.insert("updatedToolOutput".into(), r);
    }
    if !context.is_empty() {
        specific.insert("additionalContext".into(), json!(context.join(" ")));
    }
    if specific.len() > 1 {
        out.insert("hookSpecificOutput".into(), Value::Object(specific));
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

/// The user-facing text: the top findings, prefixed with the level.
fn message(v: &Verdict) -> String {
    let prefix = match v.level() {
        Level::HardBlock => "Agent Guard blocked this:",
        Level::Red => "Agent Guard: risky, please confirm.",
        Level::Yellow => "Agent Guard warning:",
        Level::Green => "",
    };
    let body: Vec<&str> = v.top().map(|f| f.message.as_str()).collect();
    format!("{prefix} {}", body.join(" ")).trim().to_string()
}

fn log(ctx: &Ctx, input: &Input, call: Option<&ToolCall>, v: &Verdict, paused: bool) {
    let target = call.map(target_of).unwrap_or_default();
    let mut rules: Vec<String> = v.findings.iter().map(|f| f.rule.clone()).collect();
    if paused {
        rules.push("paused".into());
    }
    let e = Event {
        ts: ctx.now,
        agent: ctx.agent.clone(),
        session: ctx.session.clone(),
        source: input.hook_event_name.clone(),
        tool: call.map(|c| c.tool.to_string()).unwrap_or_default(),
        target,
        level: Some(v.level()),
        rules,
        message: message(v),
        ..Event::default()
    };
    // Logging must never break the agent; a failed write is reported on stderr only.
    if let Err(err) = audit::append(&e) {
        eprintln!("agent-guard: audit log: {err}");
    }
}

/// A short, redacted description of a call for the log and `top`.
pub fn target_of(call: &ToolCall) -> String {
    let raw = ["command", "url", "file_path", "path", "pattern", "query"]
        .iter()
        .find_map(|k| call.str(k))
        .map(str::to_string)
        .unwrap_or_else(|| call.input.to_string());
    audit::clip(&checks::secrets::redact(&raw), 160)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::level::Finding;

    fn verdict(level: Level) -> Verdict {
        let mut v = Verdict::default();
        if level != Level::Green {
            v.push(Finding::new("t", level, "because"));
        }
        v
    }

    #[test]
    fn levels_map_to_answers() {
        assert_eq!(
            answer("PreToolUse", &verdict(Level::Green), None, &[]),
            None
        );
        let y = answer("PreToolUse", &verdict(Level::Yellow), None, &[]).unwrap();
        assert!(y["systemMessage"].as_str().unwrap().contains("because"));
        assert!(y.get("hookSpecificOutput").is_none());
        let r = answer("PreToolUse", &verdict(Level::Red), None, &[]).unwrap();
        assert_eq!(r["hookSpecificOutput"]["permissionDecision"], "ask");
        let h = answer("PreToolUse", &verdict(Level::HardBlock), None, &[]).unwrap();
        assert_eq!(h["hookSpecificOutput"]["permissionDecision"], "deny");
        let p = answer("UserPromptSubmit", &verdict(Level::Red), None, &[]).unwrap();
        assert_eq!(p["decision"], "block");
    }

    #[test]
    fn replaced_output_is_returned() {
        let a = answer(
            "PostToolUse",
            &verdict(Level::Yellow),
            Some(json!("clean")),
            &[],
        )
        .unwrap();
        assert_eq!(a["hookSpecificOutput"]["updatedToolOutput"], "clean");
        assert_eq!(a["hookSpecificOutput"]["hookEventName"], "PostToolUse");
    }
}
