//! The automatic fixes. Each one saves what it changes in the [`Backup`] first, edits JSON in
//! place (every other key kept, in order) and returns one line per change.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Context;
use serde_json::{Value, json};

use super::backup::Backup;
use super::checks::{self, broad_rule, rule_secret};
use super::files::{self, State, object};
use super::{Env, git};

/// Runs the fix for `id`. Ids without an automatic fix change nothing.
pub fn apply(env: &Env, id: &str, backup: &mut Backup) -> anyhow::Result<Vec<String>> {
    let s = State::load(env);
    match id {
        "D03" => d03(env, &s, backup),
        "D06" => d06(env, &s, backup),
        "D07" => d07(env, &s, backup),
        "D08" => d08(env, &s, backup),
        "D09" => d09(env, &s, backup),
        "D10" => d10(env, backup),
        "D17" => d17(env, backup),
        "D27" => d27(env, backup),
        _ => Ok(Vec::new()),
    }
}

/// Applies `f` to the JSON file at `path` (an empty object if it is missing). If `f` reports
/// changes, the file is backed up and rewritten atomically.
fn edit(
    env: &Env,
    backup: &mut Backup,
    path: &Path,
    f: impl FnOnce(&mut Value) -> Vec<String>,
) -> anyhow::Result<Vec<String>> {
    let mut v = match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .with_context(|| format!("{} is not valid JSON; left unchanged", env.tilde(path)))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let changes = f(&mut v);
    if changes.is_empty() {
        return Ok(changes);
    }
    backup.save_file(path)?;
    files::write_json(path, &v, &env.write_root(path))?;
    Ok(changes
        .into_iter()
        .map(|c| format!("{c} in {}", env.tilde(path)))
        .collect())
}

fn d03(env: &Env, s: &State, backup: &mut Backup) -> anyhow::Result<Vec<String>> {
    let mut done = Vec::new();
    for srv in &s.servers {
        let Some((i, name)) = checks::unpinned_npx(srv) else {
            continue;
        };
        let Some(ver) = (env.npm_version)(name) else {
            done.push(format!(
                "could not find the current version of {name}; pin it by hand as {name}@<version> in {}",
                env.tilde(&srv.file)
            ));
            continue;
        };
        let old = srv.args[i].clone();
        let pointer = format!("{}/args/{i}", srv.pointer);
        done.extend(edit(env, backup, &srv.file, |v| {
            match v.pointer_mut(&pointer) {
                Some(slot) if slot.as_str() == Some(old.as_str()) => {
                    *slot = Value::String(format!("{name}@{ver}"));
                    vec![format!(
                        "pinned {name} to {ver} for server \"{}\"",
                        srv.name
                    )]
                }
                _ => Vec::new(),
            }
        })?);
    }
    Ok(done)
}

fn d06(env: &Env, s: &State, backup: &mut Backup) -> anyhow::Result<Vec<String>> {
    let mut done = Vec::new();
    for (p, _) in &s.settings {
        done.extend(edit(env, backup, p, |v| {
            let mut c = Vec::new();
            if let Some(perm) = v.get_mut("permissions").and_then(Value::as_object_mut)
                && perm.get("defaultMode").and_then(Value::as_str) == Some("bypassPermissions")
            {
                perm.shift_remove("defaultMode");
                c.push("removed defaultMode bypassPermissions".to_string());
            }
            if let Some(m) = v.as_object_mut()
                && m.shift_remove("skipDangerousModePermissionPrompt")
                    .is_some()
            {
                c.push("removed skipDangerousModePermissionPrompt".to_string());
            }
            c
        })?);
    }
    if s.claude_json.is_some() {
        done.extend(edit(env, backup, &env.claude_json(), |v| {
            match v
                .as_object_mut()
                .and_then(|m| m.shift_remove("skipDangerousModePermissionPrompt"))
            {
                Some(_) => vec!["removed skipDangerousModePermissionPrompt".to_string()],
                None => Vec::new(),
            }
        })?);
    }
    done.extend(edit(env, backup, &env.user_settings(), |v| {
        let Some(perm) = object(v, "permissions") else {
            return Vec::new();
        };
        if perm
            .get("disableBypassPermissionsMode")
            .and_then(Value::as_str)
            == Some("disable")
        {
            return Vec::new();
        }
        perm.insert("disableBypassPermissionsMode".into(), json!("disable"));
        vec!["set permissions.disableBypassPermissionsMode to \"disable\"".to_string()]
    })?);
    Ok(done)
}

fn d07(env: &Env, s: &State, backup: &mut Backup) -> anyhow::Result<Vec<String>> {
    let mut done = Vec::new();
    for (p, _) in &s.settings {
        done.extend(edit(env, backup, p, |v| {
            let Some(allow) = v
                .pointer_mut("/permissions/allow")
                .and_then(Value::as_array_mut)
            else {
                return Vec::new();
            };
            let mut c = Vec::new();
            allow.retain(|r| {
                let Some(rule) = r.as_str() else {
                    return true;
                };
                if rule_secret(rule).is_some() {
                    c.push("removed an allow rule holding a key".to_string());
                    false
                } else if broad_rule(rule).is_some() {
                    c.push(format!("removed the allow rule {rule}"));
                    false
                } else {
                    true
                }
            });
            c
        })?);
    }
    Ok(done)
}

fn d08(env: &Env, s: &State, backup: &mut Backup) -> anyhow::Result<Vec<String>> {
    let set_false = |obj: &mut Value| -> bool {
        match obj.get_mut("enableAllProjectMcpServers") {
            Some(slot) if slot != &json!(false) => {
                *slot = json!(false);
                true
            }
            _ => false,
        }
    };
    let mut done = Vec::new();
    for (p, _) in &s.settings {
        done.extend(edit(env, backup, p, |v| {
            if set_false(v) {
                vec!["set enableAllProjectMcpServers to false".to_string()]
            } else {
                Vec::new()
            }
        })?);
    }
    if s.claude_json.is_some() {
        done.extend(edit(env, backup, &env.claude_json(), |v| {
            let Some(projects) = v.get_mut("projects").and_then(Value::as_object_mut) else {
                return Vec::new();
            };
            projects
                .iter_mut()
                .filter_map(|(dir, p)| {
                    set_false(p)
                        .then(|| format!("set enableAllProjectMcpServers to false for {dir}"))
                })
                .collect()
        })?);
    }
    Ok(done)
}

fn d09(env: &Env, s: &State, backup: &mut Backup) -> anyhow::Result<Vec<String>> {
    let missing = checks::missing_deny(s);
    edit(env, backup, &env.user_settings(), |v| {
        let Some(perm) = object(v, "permissions") else {
            return Vec::new();
        };
        let deny = perm.entry("deny").or_insert_with(|| json!([]));
        if !deny.is_array() {
            *deny = json!([]);
        }
        let Some(list) = deny.as_array_mut() else {
            return Vec::new();
        };
        missing
            .iter()
            .map(|r| {
                list.push(json!(r));
                format!("added deny rule {r}")
            })
            .collect()
    })
}

fn d10(env: &Env, backup: &mut Backup) -> anyhow::Result<Vec<String>> {
    let mut done = edit(env, backup, &env.user_settings(), |v| {
        let Some(sandbox) = object(v, "sandbox") else {
            return Vec::new();
        };
        if sandbox.get("enabled") == Some(&json!(true)) {
            return Vec::new();
        }
        sandbox.insert("enabled".into(), json!(true));
        vec!["turned on the sandbox".to_string()]
    })?;
    if !done.is_empty() {
        done.push(
            "commands that need the network or files outside the project may now ask first or fail"
                .into(),
        );
    }
    Ok(done)
}

fn d17(env: &Env, backup: &mut Backup) -> anyhow::Result<Vec<String>> {
    let mut done = Vec::new();
    for p in checks::private_files(env) {
        if checks::loose_mode(&p).is_some() {
            backup.save_file(&p)?;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
            done.push(format!("made {} private (chmod 600)", env.tilde(&p)));
        }
    }
    Ok(done)
}

fn d27(env: &Env, backup: &mut Backup) -> anyhow::Result<Vec<String>> {
    let mut done = Vec::new();
    for (key, value) in checks::git_missing(env) {
        let old = git(env, &["config", "--global", "--get", key]).map(|v| v.trim().to_string());
        backup.save_git(key, old)?;
        if git(env, &["config", "--global", key, value]).is_none() {
            anyhow::bail!("git config --global {key} {value} failed");
        }
        done.push(format!("set git config --global {key} {value}"));
    }
    Ok(done)
}
