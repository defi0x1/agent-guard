//! Whether git would track a file, decided in process from `.gitignore` files and
//! `.git/info/exclude`. Git itself is never run: a cloned repository's config can make git run
//! commands (`core.fsmonitor`, an embedded bare repository), and the hook must not run a
//! repository's code. When unsure, the answer is "tracked", which only adds a warning.

use std::fs;
use std::path::{Component, Path, PathBuf};

/// Whether `path` is inside a git work tree and not ignored, so a commit would include it.
pub fn would_track(path: &Path) -> bool {
    let path = resolve(path);
    let Some(root) = path
        .ancestors()
        .skip(1)
        .find(|d| d.join(".git").symlink_metadata().is_ok())
    else {
        return false;
    };
    let Ok(rel) = path.strip_prefix(root) else {
        return true;
    };
    let parts: Option<Vec<&str>> = rel
        .components()
        .map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect();
    let Some(parts) = parts else {
        return true;
    };
    match parts.first() {
        None => return false,
        Some(&".git") => return false,
        Some(_) => {}
    }
    let mut rules = read_rules(&git_dir(root).join("info").join("exclude"), "");
    for i in 0..parts.len() {
        let base = parts[..i].join("/");
        rules.extend(read_rules(&root.join(&base).join(".gitignore"), &base));
        let is_dir = i + 1 < parts.len();
        // A file inside an ignored directory is ignored, whatever comes later.
        if ignored(&rules, &parts[..=i], is_dir) {
            return false;
        }
    }
    true
}

/// `path` with its longest existing prefix resolved (symlinks, `/tmp` to `/private/tmp`).
fn resolve(path: &Path) -> PathBuf {
    for anc in path.ancestors() {
        if let Ok(real) = anc.canonicalize() {
            let rest = path.strip_prefix(anc).unwrap_or(Path::new(""));
            return real.join(rest);
        }
    }
    path.to_path_buf()
}

/// The repository's git directory: `.git`, or where a `.git` file (worktree, submodule) points,
/// or the common directory a worktree shares.
fn git_dir(root: &Path) -> PathBuf {
    let dot = root.join(".git");
    let Some(target) = fs::read_to_string(&dot).ok().and_then(|t| {
        t.trim()
            .strip_prefix("gitdir:")
            .map(|g| g.trim().to_string())
    }) else {
        return dot;
    };
    let dir = root.join(target);
    match fs::read_to_string(dir.join("commondir")) {
        Ok(common) => dir.join(common.trim()),
        Err(_) => dir,
    }
}

struct Rule {
    /// Directory of the ignore file, relative to the root (`""` for the root).
    base: String,
    /// Pattern segments, each as characters.
    segs: Vec<Vec<char>>,
    negated: bool,
    dir_only: bool,
    /// Contains a slash: matched against the path from `base`, not against any name.
    anchored: bool,
}

/// The rules of one ignore file. A missing or unreadable file gives none, so more files count
/// as tracked.
fn read_rules(file: &Path, base: &str) -> Vec<Rule> {
    fs::read_to_string(file)
        .map(|t| t.lines().filter_map(|l| parse_rule(l, base)).collect())
        .unwrap_or_default()
}

fn parse_rule(line: &str, base: &str) -> Option<Rule> {
    let line = line.trim_end();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (negated, line) = match line.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, line.strip_prefix('\\').unwrap_or(line)),
    };
    let (dir_only, line) = match line.strip_suffix('/') {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let anchored = line.contains('/');
    let line = line.strip_prefix('/').unwrap_or(line);
    let segs: Vec<Vec<char>> = line
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().collect())
        .collect();
    (!segs.is_empty()).then(|| Rule {
        base: base.to_string(),
        segs,
        negated,
        dir_only,
        anchored,
    })
}

/// Whether the last rule matching `path` (segments from the root) ignores it.
fn ignored(rules: &[Rule], path: &[&str], is_dir: bool) -> bool {
    rules
        .iter()
        .rev()
        .find(|r| matches(r, path, is_dir))
        .is_some_and(|r| !r.negated)
}

fn matches(rule: &Rule, path: &[&str], is_dir: bool) -> bool {
    if rule.dir_only && !is_dir {
        return false;
    }
    let depth = if rule.base.is_empty() {
        0
    } else {
        rule.base.split('/').count()
    };
    let Some(rel) = path.get(depth..).filter(|r| !r.is_empty()) else {
        return false;
    };
    let rel: Vec<Vec<char>> = rel.iter().map(|s| s.chars().collect()).collect();
    if rule.anchored {
        path_match(&rule.segs, &rel)
    } else {
        rel.last()
            .is_some_and(|name| rule.segs.len() == 1 && seg_match(&rule.segs[0], name))
    }
}

/// Pattern segments against path segments; `**` stands for any number of segments (at least
/// one when it ends the pattern). Dynamic programming, so time is linear in their product.
fn path_match(pat: &[Vec<char>], segs: &[Vec<char>]) -> bool {
    let (p, s) = (pat.len(), segs.len());
    // m[i][j]: pat[i..] matches segs[j..].
    let mut m = vec![vec![false; s + 1]; p + 1];
    m[p][s] = true;
    for i in (0..p).rev() {
        let any = pat[i] == ['*', '*'];
        for j in (0..=s).rev() {
            m[i][j] = if any {
                (i + 1 < p && m[i + 1][j]) || (j < s && (m[i][j + 1] || m[i + 1][j + 1]))
            } else {
                j < s && m[i + 1][j + 1] && seg_match(&pat[i], &segs[j])
            };
        }
    }
    m[0][0]
}

/// One segment: `*`, `?`, `[a-z]`, `[!x]` and `\` escapes. Star backtracking, no recursion.
fn seg_match(p: &[char], s: &[char]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, si));
            pi += 1;
            continue;
        }
        if let Some(len) = (pi < p.len()).then(|| one(p, pi, s[si])).flatten() {
            pi += len;
            si += 1;
            continue;
        }
        match star {
            Some((sp, ss)) => {
                pi = sp + 1;
                si = ss + 1;
                star = Some((sp, ss + 1));
            }
            None => return false,
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// If the matcher at `p[pi]` matches `c`, how many pattern characters it used.
fn one(p: &[char], pi: usize, c: char) -> Option<usize> {
    match p[pi] {
        '?' => Some(1),
        '\\' if pi + 1 < p.len() => (p[pi + 1] == c).then_some(2),
        '[' => class(p, pi, c),
        ch => (ch == c).then_some(1),
    }
}

fn class(p: &[char], pi: usize, c: char) -> Option<usize> {
    let mut i = pi + 1;
    let neg = i < p.len() && (p[i] == '!' || p[i] == '^');
    if neg {
        i += 1;
    }
    let start = i;
    let mut hit = false;
    while i < p.len() && (p[i] != ']' || i == start) {
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            hit |= p[i] <= c && c <= p[i + 2];
            i += 3;
        } else {
            hit |= p[i] == c;
            i += 1;
        }
    }
    if i >= p.len() {
        // No closing bracket: a literal `[`.
        return (c == '[').then_some(1);
    }
    (hit != neg).then_some(i + 1 - pi)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git/info")).unwrap();
        for (path, text) in files {
            let p = dir.path().join(path);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, text).unwrap();
        }
        dir
    }

    #[test]
    fn gitignore_semantics() {
        let r = repo(&[
            (
                ".gitignore",
                "# comment\n.env\n*.log\n!keep.log\n/build\nout/\ndocs/**/secret.txt\nlogs/**\ntmp?.txt\n[Cc]ache\n",
            ),
            (".git/info/exclude", "local.txt\n"),
            ("sub/.gitignore", "!.env\nnested.txt\n"),
            ("deep/a/.gitignore", "*\n"),
        ]);
        let t = |p: &str| would_track(&r.path().join(p));
        for p in [
            "src/main.rs",
            "keep.log",
            "src/build",
            "out",
            "docs/secret.txt.bak",
            "logs",
            "tmp10.txt",
            "sub/.env",
        ] {
            assert!(t(p), "{p} should be tracked");
        }
        for p in [
            ".env",
            "a/b/.env",
            "x.log",
            "a/x.log",
            "build/x.js",
            "out/a/b.js",
            "a/out/b.js",
            "docs/secret.txt",
            "docs/a/b/secret.txt",
            "logs/x/y",
            "tmp1.txt",
            "Cache/x",
            "cache",
            "local.txt",
            "sub/nested.txt",
            "deep/a/anything",
            ".git/config",
        ] {
            assert!(!t(p), "{p} should be ignored");
        }
    }

    #[test]
    fn ignored_directory_cannot_be_re_included() {
        let r = repo(&[(".gitignore", "secrets/\n!secrets/app.env\n")]);
        assert!(!would_track(&r.path().join("secrets/app.env")));
    }

    #[test]
    fn outside_a_repository_nothing_is_tracked() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!would_track(&dir.path().join("notes.txt")));
    }

    #[test]
    fn worktree_git_file_points_to_exclude() {
        let main = tempfile::tempdir().unwrap();
        let gd = main.path().join("gd");
        fs::create_dir_all(gd.join("info")).unwrap();
        fs::write(gd.join("info/exclude"), "*.secret\n").unwrap();
        let wt = tempfile::tempdir().unwrap();
        fs::write(
            wt.path().join(".git"),
            format!("gitdir: {}\n", gd.display()),
        )
        .unwrap();
        assert!(!would_track(&wt.path().join("a.secret")));
        assert!(would_track(&wt.path().join("a.txt")));
    }

    #[test]
    fn many_stars_stay_fast() {
        let pat = format!("{}x", "*".repeat(40));
        let r = repo(&[(".gitignore", &format!("{pat}\n{}y\n", "**/".repeat(40)))]);
        let start = std::time::Instant::now();
        let name = "a".repeat(200);
        assert!(would_track(
            &r.path().join(format!("{}/{name}", "d/".repeat(30)))
        ));
        assert!(start.elapsed().as_millis() < 500, "{:?}", start.elapsed());
    }
}
