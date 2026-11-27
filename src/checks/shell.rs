//! A small shell parser shared by the checks: enough to split a command line into pipelines of
//! simple commands. Best effort: quotes, backslashes, operators, redirections, comments and
//! heredocs are understood; variables and globs are not expanded.

/// Which way a redirection moves data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redirect {
    /// `<`.
    In,
    /// `>`, `>>`, `>|`, `&>`.
    Out,
}

/// One simple command.
#[derive(Debug, Default)]
pub struct Command {
    /// Its words with quotes removed, without redirections. Command substitutions (`$(...)`,
    /// backticks, `<(...)`) stay in their word as written.
    pub args: Vec<String>,
    /// Redirected files, in order. File descriptor targets (`2>&1`, `>&-`) are left out.
    pub redirects: Vec<(Redirect, String)>,
    /// Whether its input is piped or redirected.
    pub stdin: bool,
    /// The bodies of its `<<` heredocs.
    pub heredocs: Vec<String>,
}

/// What the next word is, after a redirection operator.
#[derive(Clone, Copy)]
enum Target {
    File(Redirect),
    /// The delimiter of a `<<` heredoc.
    Heredoc,
    /// A `<<<` here-string.
    HereString,
}

#[derive(Default)]
struct Lexer {
    out: Vec<Vec<Command>>,
    pipeline: Vec<Command>,
    cmd: Command,
    cur: String,
    /// Whether a (possibly empty) quoted word has started.
    started: bool,
    target: Option<Target>,
    /// Heredoc delimiters waiting for the end of the line, with the position of their command.
    heredocs: Vec<(String, usize, usize)>,
    /// The text of every command substitution.
    subs: Vec<String>,
}

impl Lexer {
    fn word(&mut self) {
        if !self.started && self.cur.is_empty() {
            return;
        }
        let text = std::mem::take(&mut self.cur);
        self.started = false;
        match self.target.take() {
            None => self.cmd.args.push(text),
            Some(Target::File(r)) => {
                if text != "-" && !text.bytes().all(|b| b.is_ascii_digit()) {
                    self.cmd.redirects.push((r, text));
                }
            }
            Some(Target::Heredoc) => {
                let at = (text, self.out.len(), self.pipeline.len());
                self.heredocs.push(at);
            }
            Some(Target::HereString) => {}
        }
    }

    /// Ends the current command, and the pipeline too unless `pipe`.
    fn end(&mut self, pipe: bool) {
        self.word();
        self.target = None;
        self.pipeline.push(std::mem::take(&mut self.cmd));
        if pipe {
            self.cmd.stdin = true;
        } else {
            self.out.push(std::mem::take(&mut self.pipeline));
        }
    }

    /// Ends the current word, dropping it if it is a file descriptor number (`2>`).
    fn redirect(&mut self, target: Target) {
        if !self.cur.is_empty() && self.cur.bytes().all(|b| b.is_ascii_digit()) {
            self.cur.clear();
            self.started = false;
        }
        self.word();
        if !matches!(target, Target::File(Redirect::Out)) {
            self.cmd.stdin = true;
        }
        self.target = Some(target);
    }

    /// Reads the bodies of pending heredocs from the line after `i` (a newline). Returns the
    /// index of the newline that ends the last delimiter line.
    fn heredoc_bodies(&mut self, s: &[char], mut i: usize) -> usize {
        for (delim, p, c) in std::mem::take(&mut self.heredocs) {
            let mut body = String::new();
            loop {
                let start = (i + 1).min(s.len());
                let end = (start..s.len()).find(|&j| s[j] == '\n').unwrap_or(s.len());
                let line: String = s[start..end].iter().collect();
                i = end;
                if line.trim() == delim {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
                if end >= s.len() {
                    break;
                }
            }
            if let Some(cmd) = self.out.get_mut(p).and_then(|pl| pl.get_mut(c)) {
                cmd.heredocs.push(body);
            }
        }
        i
    }

    /// Appends `$(inner)` (or `<(inner)`, after `open`) to the word, records `inner`, and
    /// returns the index of the closing `)`.
    fn substitution(&mut self, s: &[char], start: usize, open: char) -> usize {
        let (inner, end) = balanced(s, start);
        self.started = true;
        self.cur.push(open);
        self.cur.push('(');
        self.cur.push_str(&inner);
        self.cur.push(')');
        self.subs.push(inner);
        end
    }

    /// Like [`Lexer::substitution`] for a backtick pair starting after the opening backtick.
    fn backtick(&mut self, s: &[char], start: usize) -> usize {
        let end = (start..s.len()).find(|&i| s[i] == '`').unwrap_or(s.len());
        let inner: String = s[start..end].iter().collect();
        self.started = true;
        self.cur.push('`');
        self.cur.push_str(&inner);
        self.cur.push('`');
        self.subs.push(inner);
        end
    }
}

/// Splits `text` into pipelines of simple commands, on `;`, `&&`, `||`, `&`, `|`, newlines and
/// parentheses. Command substitutions are also parsed, as pipelines after the others. Heredoc
/// bodies are not commands: they are kept on the command that reads them.
pub fn pipelines(text: &str) -> Vec<Vec<Command>> {
    let s: Vec<char> = text.chars().collect();
    let at = |i: usize| s.get(i).copied();
    let mut lx = Lexer::default();
    let mut i = 0;
    while let Some(c) = at(i) {
        let next = at(i + 1);
        match c {
            ' ' | '\t' | '\r' => lx.word(),
            '\n' => {
                lx.end(false);
                i = lx.heredoc_bodies(&s, i);
            }
            ';' | '(' | ')' => lx.end(false),
            '|' if next == Some('|') => {
                i += 1;
                lx.end(false);
            }
            '|' => {
                if next == Some('&') {
                    i += 1;
                }
                lx.end(true);
            }
            '&' if next == Some('&') => {
                i += 1;
                lx.end(false);
            }
            '&' if next == Some('>') => {
                i += if at(i + 2) == Some('>') { 2 } else { 1 };
                lx.redirect(Target::File(Redirect::Out));
            }
            '&' => lx.end(false),
            '<' | '>' if next == Some('(') => i = lx.substitution(&s, i + 2, c),
            '<' => match (next, at(i + 2)) {
                (Some('<'), Some('<')) => {
                    i += 2;
                    lx.redirect(Target::HereString);
                }
                (Some('<'), after) => {
                    i += if after == Some('-') { 2 } else { 1 };
                    lx.redirect(Target::Heredoc);
                }
                (after, _) => {
                    if matches!(after, Some('&' | '>')) {
                        i += 1;
                    }
                    lx.redirect(Target::File(Redirect::In));
                }
            },
            '>' => {
                if matches!(next, Some('>' | '|' | '&')) {
                    i += 1;
                }
                lx.redirect(Target::File(Redirect::Out));
            }
            '#' if !lx.started && lx.cur.is_empty() => {
                while at(i + 1).is_some_and(|d| d != '\n') {
                    i += 1;
                }
            }
            '\'' => {
                lx.started = true;
                i += 1;
                while let Some(d) = at(i).filter(|&d| d != '\'') {
                    lx.cur.push(d);
                    i += 1;
                }
            }
            '"' => {
                lx.started = true;
                i += 1;
                while let Some(d) = at(i).filter(|&d| d != '"') {
                    match (d, at(i + 1)) {
                        ('\\', Some('\n')) => i += 1,
                        ('\\', Some(e @ ('"' | '\\' | '$' | '`'))) => {
                            lx.cur.push(e);
                            i += 1;
                        }
                        ('$', Some('(')) => i = lx.substitution(&s, i + 2, '$'),
                        ('`', _) => i = lx.backtick(&s, i + 1),
                        _ => lx.cur.push(d),
                    }
                    i += 1;
                }
            }
            '\\' => {
                if let Some(d) = next {
                    if d != '\n' {
                        lx.cur.push(d);
                    }
                    i += 1;
                }
            }
            '$' if next == Some('(') => i = lx.substitution(&s, i + 2, '$'),
            '`' => i = lx.backtick(&s, i + 1),
            _ => lx.cur.push(c),
        }
        i += 1;
    }
    lx.end(false);
    let mut out = lx.out;
    for p in &mut out {
        p.retain(|c| !c.args.is_empty());
    }
    out.retain(|p| !p.is_empty());
    for sub in lx.subs {
        out.extend(pipelines(&sub));
    }
    out
}

/// Reads up to the `)` matching an already opened `(`, starting at `start`. Returns the text
/// inside and the index of the closing parenthesis (or the end).
fn balanced(chars: &[char], start: usize) -> (String, usize) {
    let mut depth = 1;
    let mut quote: Option<char> = None;
    let mut i = start;
    while i < chars.len() {
        let c = chars[i];
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '\'' | '"') => quote = Some(c),
            (None, '(') => depth += 1,
            (None, ')') => {
                depth -= 1;
                if depth == 0 {
                    return (chars[start..i].iter().collect(), i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    (chars[start..].iter().collect(), chars.len())
}

/// Wrappers and shell keywords that run the next word as the command.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "command", "builtin", "exec", "nohup", "time", "nice", "then", "do",
    "else", "elif", "if", "while", "until", "!", "{",
];

/// Wrapper flags that take a value (`sudo -u root`, `env -u NAME`); `-n` only for `nice -n 5`.
const WRAPPER_VALUE_FLAGS: &[&str] = &["-u", "-g", "-C", "-h", "-p", "-U", "-D"];

/// Drops leading `NAME=value` assignments and wrappers, returning the real command and its args.
pub fn command<S: AsRef<str>>(mut args: &[S]) -> &[S] {
    while let Some((first, rest)) = args.split_first() {
        let wrapper = basename(first.as_ref());
        if is_assignment(first.as_ref()) {
            args = rest;
        } else if WRAPPERS.contains(&wrapper) {
            args = rest;
            while let Some((flag, more)) = args.split_first() {
                let flag = flag.as_ref();
                if !flag.starts_with('-') {
                    break;
                }
                let takes_value =
                    WRAPPER_VALUE_FLAGS.contains(&flag) || (wrapper == "nice" && flag == "-n");
                args = if takes_value {
                    more.get(1..).unwrap_or(&[])
                } else {
                    more
                };
            }
        } else {
            break;
        }
    }
    args
}

/// `NAME=value`, as in `GIT_TRACE=1 git status`.
pub fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The last component of a command path (`/usr/bin/git` gives `git`).
pub fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(p: &[Command]) -> Vec<Vec<&str>> {
        p.iter()
            .map(|c| c.args.iter().map(String::as_str).collect())
            .collect()
    }

    #[test]
    fn splits_and_tags_words() {
        let p = pipelines("a 'b c' \"d\\\"e\" 2>/dev/null x>>out <in && f|g; h\\ i");
        assert_eq!(args(&p[0]), [["a", "b c", "d\"e", "x"]]);
        assert_eq!(
            p[0][0].redirects,
            [
                (Redirect::Out, "/dev/null".to_string()),
                (Redirect::Out, "out".to_string()),
                (Redirect::In, "in".to_string()),
            ]
        );
        assert!(p[0][0].stdin);
        assert_eq!(args(&p[1]), [["f"], ["g"]]);
        assert!(!p[1][0].stdin && p[1][1].stdin);
        assert_eq!(args(&p[2]), [["h i"]]);
    }

    #[test]
    fn substitutions_heredocs_and_comments() {
        let p = pipelines("echo \"a $(b `c`) d\" # e; f\ncat <<'EOF' >x 2>&1\ng\nEOF\nh");
        assert_eq!(args(&p[0]), [["echo", "a $(b `c`) d"]]);
        assert_eq!(args(&p[1]), [["cat"]]);
        assert_eq!(p[1][0].heredocs, ["g\n"]);
        assert_eq!(p[1][0].redirects, [(Redirect::Out, "x".to_string())]);
        assert_eq!(args(&p[2]), [["h"]]);
        assert_eq!(args(&p[3]), [["b", "`c`"]]);
        assert_eq!(args(&p[4]), [["c"]]);
    }

    #[test]
    fn strips_wrappers() {
        let w = [
            "FOO=1", "sudo", "-n", "-u", "root", "env", "A=b", "nice", "-n", "5", "rm", "x",
        ];
        assert_eq!(command(&w), ["rm", "x"]);
        assert!(is_assignment("_A1=x") && !is_assignment("1A=x") && !is_assignment("=x"));
    }
}
