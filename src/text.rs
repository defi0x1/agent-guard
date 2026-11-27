//! Text cleaning shared by the hook and the proxy: terminal escapes and invisible Unicode that can
//! hide instructions from the user while the model still reads them.

/// What [`clean`] removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Removed {
    pub ansi: usize,
    pub invisible: usize,
}

impl Removed {
    pub fn any(&self) -> bool {
        self.ansi + self.invisible > 0
    }
}

/// Unicode TAG characters (U+E0000..U+E007F): invisible, and read by models as ASCII.
fn is_tag(c: char) -> bool {
    ('\u{E0000}'..='\u{E007F}').contains(&c)
}

/// Bidi overrides and isolates, zero-width space, word joiner and BOM.
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200B}' | '\u{2060}' | '\u{FEFF}' | '\u{180E}')
}

/// Removes ANSI escape sequences, C0/C1 controls (except newline, tab and carriage return), TAG
/// characters (keeping emoji subdivision flags, which start with U+1F3F4), bidi controls and
/// zero-width characters.
pub fn clean(s: &str) -> (String, Removed) {
    let mut out = String::with_capacity(s.len());
    let mut removed = Removed::default();
    let mut chars = s.chars().peekable();
    let mut in_flag = false;
    while let Some(c) = chars.next() {
        if c == '\u{1B}' {
            removed.ansi += 1;
            // CSI: ESC [ ... final byte in @..~ ; OSC: ESC ] ... BEL or ESC \ ; else one char.
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    for d in chars.by_ref() {
                        if ('@'..='~').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    while let Some(d) = chars.next() {
                        if d == '\u{7}' {
                            break;
                        }
                        if d == '\u{1B}' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        if c == '\u{1F3F4}' {
            in_flag = true;
            out.push(c);
            continue;
        }
        if is_tag(c) {
            if in_flag {
                out.push(c);
                if c == '\u{E007F}' {
                    in_flag = false;
                }
            } else {
                removed.invisible += 1;
            }
            continue;
        }
        in_flag = false;
        let control = (c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
            || ('\u{80}'..='\u{9F}').contains(&c);
        if control {
            removed.ansi += 1;
        } else if is_invisible(c) {
            removed.invisible += 1;
        } else {
            out.push(c);
        }
    }
    (out, removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_escapes_and_invisible_text() {
        let (s, r) = clean("ok\u{1B}[31mred\u{1B}[0m \u{1B}]0;title\u{7}done");
        assert_eq!(s, "okred done");
        assert_eq!(r.ansi, 3);
        let hidden: String = "hi"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();
        let (s, r) = clean(&format!("a{hidden}b\u{200B}c\u{202E}d"));
        assert_eq!(s, "abcd");
        assert_eq!(r.invisible, 4);
        assert!(r.any());
    }

    #[test]
    fn keeps_flags_newlines_and_plain_text() {
        let scotland = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
        let text = format!("line 1\n\tline 2 {scotland} é 中文 👍🏽");
        assert_eq!(clean(&text), (text.clone(), Removed::default()));
    }
}
