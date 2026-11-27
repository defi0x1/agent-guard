//! Undoing the encodings an agent may use to slip a secret past a plain match: URL encoding,
//! hex and base64 (standard or URL-safe, padded or not).

/// The text `s` decodes to, if it is URL-encoded, hex or base64 of printable UTF-8.
pub fn decode(s: &str) -> Option<String> {
    let bytes = if s.contains('%') {
        percent(s)?
    } else if s.len() >= 24 && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
    {
        hex(s)?
    } else if s.len() >= 16 {
        base64(s)?
    } else {
        return None;
    };
    let text = String::from_utf8(bytes).ok()?;
    let printable = !text.is_empty()
        && text
            .chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'));
    (printable && text != s).then_some(text)
}

fn percent(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(if b[i] == b'+' { b' ' } else { b[i] });
            i += 1;
        }
    }
    Some(out)
}

fn hex(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn base64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_common_encodings() {
        let plain = "user:n0t-a-real-Secret?";
        assert_eq!(
            decode("dXNlcjpuMHQtYS1yZWFsLVNlY3JldD8=").as_deref(),
            Some(plain)
        );
        assert_eq!(
            decode("dXNlcjpuMHQtYS1yZWFsLVNlY3JldD8").as_deref(),
            Some(plain)
        );
        assert_eq!(
            decode("757365723a6e30742d612d7265616c2d5365637265743f").as_deref(),
            Some(plain)
        );
        assert_eq!(
            decode("user%3An0t-a-real-Secret%3F").as_deref(),
            Some(plain)
        );
    }

    #[test]
    fn leaves_plain_text_and_binary_alone() {
        assert_eq!(decode("getElementByIdentifier"), None);
        assert_eq!(decode("da39a3ee5e6b4b0d3255bfef95601890afd80709"), None);
        assert_eq!(decode("100%"), None);
        assert_eq!(decode("short"), None);
    }
}
