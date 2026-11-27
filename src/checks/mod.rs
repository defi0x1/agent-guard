//! The checks. Each module looks at one kind of risk and adds findings to a [`Verdict`]; the hook
//! turns the overall level into Claude Code's answer. Checks are pure where possible: they read
//! the call and the context, and only touch the disk through the helpers they own.

pub mod dest;
pub mod git;
pub mod net;
pub mod paths;
pub mod sanitize;
pub mod secrets;
pub mod session;

use std::path::PathBuf;

use serde_json::Value;

use crate::config::Config;
use crate::level::Verdict;

/// Who is calling and with what settings. Built once per hook call.
pub struct Ctx {
    pub config: Config,
    /// Unix seconds.
    pub now: u64,
    /// Agent Guard's directory (for state files such as seen hosts and fingerprints).
    pub home: PathBuf,
    /// `claude` for Claude Code hooks.
    pub agent: String,
    pub session: String,
    /// The working directory of the agent session.
    pub cwd: PathBuf,
}

/// One tool call as the hook sees it.
pub struct ToolCall<'a> {
    /// `Bash`, `Read`, `Write`, `Edit`, `WebFetch`, `mcp__github__create_issue`...
    pub tool: &'a str,
    pub input: &'a Value,
    /// The MCP server name, for MCP tools.
    pub mcp_server: Option<&'a str>,
}

impl ToolCall<'_> {
    pub fn is_mcp(&self) -> bool {
        self.tool.starts_with("mcp__")
    }

    /// A string field of the input, if present.
    pub fn str(&self, key: &str) -> Option<&str> {
        self.input.get(key).and_then(Value::as_str)
    }

    /// Every string anywhere in the input (for scanning MCP arguments).
    pub fn strings(&self) -> Vec<&str> {
        let mut out = Vec::new();
        collect_strings(self.input, &mut out);
        out
    }
}

pub fn collect_strings<'v>(v: &'v Value, out: &mut Vec<&'v str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        Value::Object(m) => m.values().for_each(|x| collect_strings(x, out)),
        _ => {}
    }
}

/// What a PostToolUse check produced: findings, and possibly a cleaned result to show Claude.
#[derive(Default)]
pub struct PostResult {
    pub verdict: Verdict,
    pub replaced: Option<Value>,
    /// Facts for Claude's own safety classifier (never instructions).
    pub context: Vec<String>,
}

/// Before a tool runs.
pub fn pre_tool(ctx: &Ctx, call: &ToolCall) -> Verdict {
    let mut v = Verdict::default();
    paths::pre(ctx, call, &mut v);
    secrets::pre(ctx, call, &mut v);
    git::pre(ctx, call, &mut v);
    net::pre(ctx, call, &mut v);
    session::pre(ctx, call, &mut v);
    v
}

/// After a tool ran: clean the result and record what the session has seen.
pub fn post_tool(ctx: &Ctx, call: &ToolCall, response: &Value) -> PostResult {
    let mut r = PostResult::default();
    sanitize::post(ctx, call, response, &mut r);
    secrets::post(ctx, call, response, &mut r);
    session::post(ctx, call, response, &mut r);
    r
}

/// When the user submits a prompt.
pub fn prompt(ctx: &Ctx, text: &str) -> Verdict {
    let mut v = Verdict::default();
    secrets::prompt(ctx, text, &mut v);
    v
}

/// Every rule id with a plain-words explanation, for `guard explain` and `guard report`.
pub fn all_rules() -> Vec<(&'static str, &'static str)> {
    [
        paths::RULES,
        secrets::RULES,
        sanitize::RULES,
        git::RULES,
        net::RULES,
        session::RULES,
    ]
    .concat()
}

/// At session start: what changed in the agent's setup, and the current repository.
pub fn session_start(ctx: &Ctx) -> Verdict {
    let mut v = Verdict::default();
    session::start(ctx, &mut v);
    git::session_start(ctx, &mut v);
    v
}
