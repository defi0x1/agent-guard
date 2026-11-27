//! The state of `guard top` and what each key does. Side effects (killing a process, saving the
//! config) are returned as [`Action`]s for the main loop to run.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::audit::Event;
use crate::config::Config;
use crate::top::data::{self, Filter, HostRow, LiveConn};
use crate::top::procs::Snapshot;

/// Events kept in memory; older ones are dropped.
const MAX_EVENTS: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Live,
    Processes,
    Network,
    Alerts,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Live, Tab::Processes, Tab::Network, Tab::Alerts];

    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Normal,
    /// Typing the text filter.
    Filter,
    /// The detail pane of one event (by id).
    Detail(usize),
    /// Waiting for y/N before killing a process.
    ConfirmKill {
        pid: u32,
        name: String,
    },
}

/// Something the main loop must do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Kill(u32),
    Trust(String),
    Block(String),
}

pub struct App {
    pub tab: Tab,
    pub mode: Mode,
    /// Oldest first. An event's id is its position counting the dropped ones, so it stays stable.
    events: Vec<Event>,
    dropped: usize,
    /// While scrolling is paused, the Live tab shows only ids below this.
    pub frozen: Option<usize>,
    pub filter: Filter,
    acked: HashSet<usize>,
    selected: [usize; 4],
    pub snap: Snapshot,
    /// Addresses of hosts named in recent events.
    pub ip_hosts: HashMap<IpAddr, String>,
    pub first_seen: HashMap<String, u64>,
    pub config: Config,
    pub paused_until: Option<u64>,
    /// The last message for the footer (a saved trust, a failed kill).
    pub status: String,
    pub color: bool,
    /// Local zone offset in seconds, for times.
    pub offset: i64,
    pub now: u64,
    pub quit: bool,
}

impl App {
    pub fn new(events: Vec<Event>, now: u64, color: bool, offset: i64) -> Self {
        let mut app = App {
            tab: Tab::Live,
            mode: Mode::Normal,
            events: Vec::new(),
            dropped: 0,
            frozen: None,
            filter: Filter::default(),
            acked: HashSet::new(),
            selected: [0; 4],
            snap: Snapshot::default(),
            ip_hosts: HashMap::new(),
            first_seen: HashMap::new(),
            config: Config::default(),
            paused_until: None,
            status: String::new(),
            color,
            offset,
            now,
            quit: false,
        };
        app.push(events);
        app
    }

    /// Adds new events, dropping the oldest beyond the limit.
    pub fn push(&mut self, new: Vec<Event>) {
        self.events.extend(new);
        if self.events.len() > MAX_EVENTS {
            let n = self.events.len() - MAX_EVENTS;
            self.events.drain(..n);
            self.dropped += n;
        }
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }

    pub fn event(&self, id: usize) -> Option<&Event> {
        id.checked_sub(self.dropped)
            .and_then(|i| self.events.get(i))
    }

    /// Ids of events newest first, with their events.
    fn newest_first(&self) -> impl Iterator<Item = (usize, &Event)> {
        self.events
            .iter()
            .enumerate()
            .rev()
            .map(|(i, e)| (i + self.dropped, e))
    }

    /// The Live tab's rows: filtered, newest first, frozen while scrolling is paused.
    pub fn live(&self) -> Vec<usize> {
        self.newest_first()
            .filter(|(id, e)| self.frozen.is_none_or(|f| *id < f) && self.filter.matches(e))
            .map(|(id, _)| id)
            .collect()
    }

    /// The Alerts tab's rows: unacknowledged red, and yellow from the last hour, newest first.
    pub fn alerts(&self) -> Vec<usize> {
        self.newest_first()
            .filter(|(id, e)| data::is_alert(e, self.acked.contains(id), self.now))
            .map(|(id, _)| id)
            .collect()
    }

    /// The Network tab's rows.
    pub fn hosts(&self) -> Vec<HostRow> {
        let conns: Vec<LiveConn> = self
            .snap
            .conns
            .iter()
            .map(|c| LiveConn {
                host: self.host_of(c.remote.ip()),
                process: self.snap.name_of(c.pid).unwrap_or("?").to_string(),
            })
            .collect();
        data::group_hosts(&self.events, &conns, &self.first_seen, self.now)
    }

    /// A host name for `ip` when a recent event named one that resolves to it, else the IP.
    pub fn host_of(&self, ip: IpAddr) -> String {
        self.ip_hosts
            .get(&ip)
            .cloned()
            .unwrap_or_else(|| ip.to_string())
    }

    /// The same session's events before `id`, newest first, at most `n`.
    pub fn earlier_in_session(&self, id: usize, n: usize) -> Vec<&Event> {
        let Some(session) = self.event(id).map(|e| e.session.as_str()) else {
            return Vec::new();
        };
        if session.is_empty() {
            return Vec::new();
        }
        self.newest_first()
            .filter(|(i, e)| *i < id && e.session == session)
            .take(n)
            .map(|(_, e)| e)
            .collect()
    }

    /// The selected row of the current tab, clamped to `len` rows.
    pub fn selected(&self, len: usize) -> usize {
        self.selected[self.tab.index()].min(len.saturating_sub(1))
    }

    fn rows(&self) -> usize {
        match self.tab {
            Tab::Live => self.live().len(),
            Tab::Processes => self.snap.rows.len(),
            Tab::Network => self.hosts().len(),
            Tab::Alerts => self.alerts().len(),
        }
    }

    fn select(&mut self, delta: isize) {
        let len = self.rows();
        let cur = self.selected(len) as isize;
        let max = len.saturating_sub(1) as isize;
        self.selected[self.tab.index()] = (cur + delta).clamp(0, max) as usize;
    }

    /// Handles one key press.
    pub fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return None;
        }
        match self.mode.clone() {
            Mode::Filter => {
                match key.code {
                    KeyCode::Enter => self.mode = Mode::Normal,
                    KeyCode::Esc => {
                        self.filter.text.clear();
                        self.mode = Mode::Normal;
                    }
                    KeyCode::Backspace => {
                        self.filter.text.pop();
                    }
                    KeyCode::Char(c) => self.filter.text.push(c),
                    _ => {}
                }
                None
            }
            Mode::Detail(_) => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
                    self.mode = Mode::Normal;
                }
                None
            }
            Mode::ConfirmKill { pid, .. } => {
                self.mode = Mode::Normal;
                if key.code == KeyCode::Char('y') {
                    return Some(Action::Kill(pid));
                }
                self.status = "Not killed.".into();
                None
            }
            Mode::Normal => self.normal_key(key.code),
        }
    }

    fn normal_key(&mut self, code: KeyCode) -> Option<Action> {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char(c @ '1'..='4') => {
                self.tab = Tab::ALL[usize::from(c as u8 - b'1')];
            }
            KeyCode::Tab => self.tab = Tab::ALL[(self.tab.index() + 1) % 4],
            KeyCode::BackTab => self.tab = Tab::ALL[(self.tab.index() + 3) % 4],
            KeyCode::Up => self.select(-1),
            KeyCode::Down => self.select(1),
            KeyCode::PageUp => self.select(-20),
            KeyCode::PageDown => self.select(20),
            KeyCode::Home => self.select(isize::MIN / 2),
            KeyCode::End => self.select(isize::MAX / 2),
            KeyCode::Enter => self.open_detail(),
            _ => return self.tab_key(code),
        }
        None
    }

    fn tab_key(&mut self, code: KeyCode) -> Option<Action> {
        match (self.tab, code) {
            (Tab::Live, KeyCode::Char('x' | 'g')) => self.filter.green = !self.filter.green,
            (Tab::Live, KeyCode::Char('y')) => self.filter.yellow = !self.filter.yellow,
            (Tab::Live, KeyCode::Char('r')) => self.filter.red = !self.filter.red,
            (Tab::Live, KeyCode::Char('/')) => self.mode = Mode::Filter,
            (Tab::Live, KeyCode::Char('a')) => {
                let agents = data::agents(&self.events);
                self.filter.agent = data::next_agent(self.filter.agent.as_deref(), &agents);
            }
            (Tab::Live, KeyCode::Char(' ')) => {
                self.frozen = match self.frozen {
                    Some(_) => None,
                    None => Some(self.dropped + self.events.len()),
                };
            }
            (Tab::Processes, KeyCode::Char('k')) => {
                let rows = &self.snap.rows;
                if let Some(r) = rows.get(self.selected(rows.len())) {
                    self.mode = Mode::ConfirmKill {
                        pid: r.proc.pid,
                        name: r.proc.name.clone(),
                    };
                }
            }
            (Tab::Network, KeyCode::Char(c @ ('t' | 'b'))) => {
                let hosts = self.hosts();
                let host = hosts.get(self.selected(hosts.len()))?.host.clone();
                return Some(if c == 't' {
                    Action::Trust(host)
                } else {
                    Action::Block(host)
                });
            }
            _ => {}
        }
        None
    }

    /// Enter on an event row: opens its detail, and acknowledges it on the Alerts tab.
    fn open_detail(&mut self) {
        let ids = match self.tab {
            Tab::Live => self.live(),
            Tab::Alerts => self.alerts(),
            _ => return,
        };
        if let Some(&id) = ids.get(self.selected(ids.len())) {
            if self.tab == Tab::Alerts {
                self.acked.insert(id);
            }
            self.mode = Mode::Detail(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::level::Level;

    fn ev(ts: u64, level: Level, session: &str) -> Event {
        Event {
            ts,
            agent: "claude".into(),
            session: session.into(),
            source: "PreToolUse".into(),
            tool: "Bash".into(),
            target: format!("echo {ts}"),
            level: Some(level),
            ..Event::default()
        }
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::from(KeyCode::Char(c))
    }

    #[test]
    fn space_freezes_the_live_view() {
        let mut app = App::new(vec![ev(1, Level::Green, "s")], 10, false, 0);
        app.on_key(key(' '));
        app.push(vec![ev(2, Level::Green, "s")]);
        assert_eq!(app.live(), [0]);
        app.on_key(key(' '));
        assert_eq!(app.live(), [1, 0]);
    }

    #[test]
    fn enter_acknowledges_a_red_alert() {
        let mut app = App::new(
            vec![ev(1, Level::Red, "s"), ev(2, Level::Green, "s")],
            10,
            false,
            0,
        );
        app.on_key(key('4'));
        assert_eq!(app.alerts(), [0]);
        app.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.mode, Mode::Detail(0));
        app.on_key(KeyEvent::from(KeyCode::Esc));
        assert!(app.alerts().is_empty());
        assert!(!app.quit);
    }

    #[test]
    fn dropping_old_events_keeps_ids_stable() {
        let many: Vec<Event> = (0..MAX_EVENTS as u64 + 5)
            .map(|i| ev(i, Level::Green, "s"))
            .collect();
        let app = App::new(many, 0, false, 0);
        assert_eq!(app.events().len(), MAX_EVENTS);
        assert!(app.event(4).is_none());
        assert_eq!(app.event(5).map(|e| e.ts), Some(5));
        assert_eq!(app.live()[0], MAX_EVENTS + 4);
    }

    #[test]
    fn session_history_and_filter_typing() {
        let mut app = App::new(
            vec![
                ev(1, Level::Green, "a"),
                ev(2, Level::Green, "b"),
                ev(3, Level::Yellow, "a"),
                ev(4, Level::Green, "a"),
            ],
            10,
            false,
            0,
        );
        let ts: Vec<u64> = app.earlier_in_session(3, 5).iter().map(|e| e.ts).collect();
        assert_eq!(ts, [3, 1]);
        app.on_key(key('/'));
        app.on_key(key('3'));
        assert_eq!(app.tab, Tab::Live);
        app.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.live(), [2]);
        app.on_key(key('y'));
        assert!(app.live().is_empty());
    }

    #[test]
    fn kill_needs_a_yes() {
        let mut app = App::new(Vec::new(), 0, false, 0);
        app.snap = crate::top::procs::snapshot(
            &[crate::top::procs::Proc {
                pid: 7,
                parent: None,
                name: "claude".into(),
                ..Default::default()
            }],
            &[],
            0,
        );
        app.on_key(key('2'));
        app.on_key(key('k'));
        assert_eq!(app.on_key(key('n')), None);
        app.on_key(key('k'));
        assert_eq!(app.on_key(key('y')), Some(Action::Kill(7)));
    }
}
