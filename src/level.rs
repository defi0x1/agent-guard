//! Verdict levels. Green is silent, yellow warns, red asks with a warning, and hard-block denies
//! without asking (only for the agent tampering with Agent Guard itself).

use std::fmt;

use serde::{Deserialize, Serialize};

/// How serious a finding is. Ordered, so the most serious finding of a call wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Safe, or trusted by the user: logged only.
    Green,
    /// Suspicious but possibly fine: the call runs and the user sees a warning.
    Yellow,
    /// Critical: the user is asked, with a warning, and can allow it.
    Red,
    /// Never allowed and never asked: the agent changing or pausing Agent Guard.
    HardBlock,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Level::Green => "green",
            Level::Yellow => "yellow",
            Level::Red => "red",
            Level::HardBlock => "hard_block",
        })
    }
}

/// One rule that matched a call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule id, for example `secrets.outbound`.
    pub rule: String,
    pub level: Level,
    /// One plain sentence for the user. Never contains a raw secret.
    pub message: String,
}

impl Finding {
    pub fn new(rule: &str, level: Level, message: impl Into<String>) -> Self {
        Finding {
            rule: rule.to_string(),
            level,
            message: message.into(),
        }
    }
}

/// The outcome for one call: every finding, and the overall level (the most serious one).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    pub findings: Vec<Finding>,
}

impl Verdict {
    pub fn push(&mut self, f: Finding) {
        self.findings.push(f);
    }

    /// Green when nothing matched.
    pub fn level(&self) -> Level {
        self.findings
            .iter()
            .map(|f| f.level)
            .max()
            .unwrap_or(Level::Green)
    }

    /// The findings at the overall level, most relevant first.
    pub fn top(&self) -> impl Iterator<Item = &Finding> {
        let level = self.level();
        self.findings.iter().filter(move |f| f.level == level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn most_serious_finding_wins() {
        let mut v = Verdict::default();
        assert_eq!(v.level(), Level::Green);
        v.push(Finding::new("a", Level::Yellow, "warn"));
        v.push(Finding::new("b", Level::Red, "ask"));
        v.push(Finding::new("c", Level::Yellow, "warn 2"));
        assert_eq!(v.level(), Level::Red);
        assert_eq!(v.top().map(|f| f.rule.as_str()).collect::<Vec<_>>(), ["b"]);
        v.push(Finding::new("d", Level::HardBlock, "never"));
        assert_eq!(v.level(), Level::HardBlock);
    }
}
