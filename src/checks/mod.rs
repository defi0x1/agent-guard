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
pub mod shell;

use std::path::PathBuf;

use serde_json::Value;

use crate::config::Config;
use crate::level::{Finding, Level, Verdict};

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

/// Every string anywhere in `v`, object keys included: a server controls its keys too.
pub fn collect_text<'v>(v: &'v Value, out: &mut Vec<&'v str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| collect_text(x, out)),
        Value::Object(m) => m.iter().for_each(|(k, x)| {
            out.push(k);
            collect_text(x, out);
        }),
        _ => {}
    }
}

/// Tool results are checked up to this many bytes of text (strings and keys).
pub const SCAN_LIMIT: usize = 1024 * 1024;

const TRUNCATED: &str = "hook.result_truncated";

/// Rule ids this module emits, and ids other modules may emit that are registered here.
const RULES: &[(&str, &str)] = &[
    (
        TRUNCATED,
        "A tool result was larger than 1 MB, so Agent Guard checked only its first 1 MB for hidden text, keys and instructions; web and MCP results are cut to that part before the agent reads them.",
    ),
    (
        "paths.too_complex",
        "The command is too long or too deeply nested to check; Agent Guard asks you to confirm it.",
    ),
];

/// The bytes of text in `v`: every string and object key.
fn text_len(v: &Value) -> usize {
    match v {
        Value::String(s) => s.len(),
        Value::Array(a) => a.iter().map(text_len).sum(),
        Value::Object(m) => m.iter().map(|(k, x)| k.len() + text_len(x)).sum(),
        _ => 0,
    }
}

/// A copy of `v` holding at most `budget` bytes of text: later strings and keys are cut or
/// emptied, the shape is kept.
fn cap_text(v: &Value, budget: &mut usize) -> Value {
    fn take(s: &str, budget: &mut usize) -> String {
        let mut end = s.len().min(*budget);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        *budget -= end;
        s[..end].to_string()
    }
    match v {
        Value::String(s) => Value::String(take(s, budget)),
        Value::Array(a) => Value::Array(a.iter().map(|x| cap_text(x, budget)).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| (take(k, budget), cap_text(x, budget)))
                .collect(),
        ),
        other => other.clone(),
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

/// After a tool ran: clean the result and record what the session has seen. Only the first
/// [`SCAN_LIMIT`] bytes of text are checked, so a huge result cannot stall the hook.
pub fn post_tool(ctx: &Ctx, call: &ToolCall, response: &Value) -> PostResult {
    let mut r = PostResult::default();
    let capped = (text_len(response) > SCAN_LIMIT).then(|| {
        let mut budget = SCAN_LIMIT;
        cap_text(response, &mut budget)
    });
    let checked = capped.as_ref().unwrap_or(response);
    sanitize::post(ctx, call, checked, &mut r);
    secrets::post(ctx, call, checked, &mut r);
    session::post(ctx, call, checked, &mut r);
    if let Some(capped) = capped {
        let rewrite = sanitize::rewrites(call);
        let level = ctx.config.level_for(TRUNCATED, |_| Level::Yellow);
        r.verdict.push(Finding::new(
            TRUNCATED,
            level,
            format!(
                "The {} result is larger than 1 MB; Agent Guard checked only the first 1 MB{}.",
                call.tool,
                if rewrite {
                    " and passed only that part on"
                } else {
                    ""
                }
            ),
        ));
        if rewrite {
            r.replaced.get_or_insert(capped);
            r.context.push(format!(
                "Agent Guard cut the result of {} to its first 1 MB.",
                call.tool
            ));
        }
    }
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
        crate::proxy::RULES,
        crate::scan::RULES,
        crate::doctor::RULES,
        crate::hook::RULES,
        RULES,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn caps_text_and_keeps_the_shape() {
        let v = json!({"ab": ["cdé", "fgh"], "n": 1});
        assert_eq!(text_len(&v), 2 + 4 + 3 + 1);
        let mut budget = 5;
        // "ab" fits, "cdé" is cut before the two-byte é, "fgh" gets the last byte.
        assert_eq!(cap_text(&v, &mut budget), json!({"ab": ["cd", "f"], "": 1}));
        let mut texts = Vec::new();
        collect_text(&v, &mut texts);
        assert_eq!(texts, ["ab", "cdé", "fgh", "n"]);
    }
}
