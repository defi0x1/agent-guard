//! Agent processes and their TCP connections, for the Processes and Network tabs. The tree
//! building is pure; [`Monitor`] reads the live system with sysinfo and netstat2.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;

use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, Signal, System, UpdateKind};

/// Names that mark an agent's root process.
pub const AGENTS: &[&str] = &[
    "claude",
    "codex",
    "cursor-agent",
    "gemini",
    "aider",
    "opencode",
];

/// One process, as read from the system.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Proc {
    pub pid: u32,
    pub parent: Option<u32>,
    pub name: String,
    /// The command line, one word per item.
    pub cmd: Vec<String>,
    pub cpu: f32,
}

/// Interpreters whose first argument is the program they run.
const INTERPRETERS: &[&str] = &["node", "bun", "deno", "python", "python3", "ruby"];

/// Whether a process is an agent: its name, or the program it runs (the first command-line
/// word, or the script an interpreter runs, as in `node /usr/local/bin/claude`), names one.
/// Other arguments are not looked at, so `grep claude notes.txt` is not an agent.
pub fn is_agent(p: &Proc) -> bool {
    let base = |s: &str| s.rsplit('/').next().unwrap_or(s).to_ascii_lowercase();
    let mut words = vec![p.name.to_ascii_lowercase()];
    if let Some(prog) = p.cmd.first().map(|s| base(s)) {
        if INTERPRETERS.contains(&prog.as_str()) {
            words.extend(p.cmd.get(1).map(|s| base(s)));
        }
        words.push(prog);
    }
    words.iter().any(|w| AGENTS.iter().any(|a| w.contains(a)))
}

/// One row of the process tree.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub proc: Proc,
    /// 0 for an agent root.
    pub depth: usize,
    pub conns: usize,
    pub last_remote: Option<SocketAddr>,
}

/// The agent roots (agents whose ancestors are not agents) and all their descendants, depth
/// first, children by pid. `own` (this process) is left out.
pub fn tree(procs: &[Proc], own: u32) -> Vec<(usize, &Proc)> {
    let by_pid: HashMap<u32, &Proc> = procs.iter().map(|p| (p.pid, p)).collect();
    let mut children: HashMap<u32, Vec<&Proc>> = HashMap::new();
    for p in procs {
        if let Some(parent) = p.parent {
            children.entry(parent).or_default().push(p);
        }
    }
    for c in children.values_mut() {
        c.sort_by_key(|p| p.pid);
    }
    let has_agent_ancestor = |p: &Proc| {
        let mut cur = p.parent;
        // Bounded walk, in case the table holds a parent loop.
        for _ in 0..64 {
            match cur.and_then(|pid| by_pid.get(&pid)) {
                Some(a) if is_agent(a) => return true,
                Some(a) => cur = a.parent,
                None => return false,
            }
        }
        false
    };
    let mut roots: Vec<&Proc> = procs
        .iter()
        .filter(|p| p.pid != own && is_agent(p) && !has_agent_ancestor(p))
        .collect();
    roots.sort_by_key(|p| p.pid);

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack: Vec<(usize, &Proc)> = roots.into_iter().rev().map(|p| (0, p)).collect();
    while let Some((depth, p)) = stack.pop() {
        if p.pid == own || !seen.insert(p.pid) {
            continue;
        }
        out.push((depth, p));
        if let Some(c) = children.get(&p.pid) {
            stack.extend(c.iter().rev().map(|c| (depth + 1, *c)));
        }
    }
    out
}

/// One TCP connection of an agent process.
#[derive(Debug, Clone, PartialEq)]
pub struct Conn {
    pub pid: u32,
    pub remote: SocketAddr,
    pub state: String,
}

/// What the Processes and Network tabs show, read at one moment.
#[derive(Debug, Default)]
pub struct Snapshot {
    pub rows: Vec<Row>,
    pub conns: Vec<Conn>,
    /// Number of agent root processes.
    pub agents: usize,
    /// Every process's parent and name, for process chains.
    parents: HashMap<u32, (Option<u32>, String)>,
}

impl Snapshot {
    /// The names from `pid` up to the top, `claude → zsh → node`, outermost first.
    pub fn chain(&self, pid: u32) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = Some(pid);
        while let Some((parent, name)) = cur.and_then(|p| self.parents.get(&p)) {
            out.push(name.clone());
            if out.len() >= 32 {
                break;
            }
            cur = *parent;
        }
        out.reverse();
        out
    }

    /// The name of any process seen in the snapshot.
    pub fn name_of(&self, pid: u32) -> Option<&str> {
        self.parents.get(&pid).map(|(_, n)| n.as_str())
    }
}

/// Builds the snapshot rows from processes and every TCP socket's (pids, remote, state).
pub fn snapshot(procs: &[Proc], sockets: &[(Vec<u32>, SocketAddr, String)], own: u32) -> Snapshot {
    let tree = tree(procs, own);
    let in_tree: HashSet<u32> = tree.iter().map(|(_, p)| p.pid).collect();
    let mut conns = Vec::new();
    for (pids, remote, state) in sockets {
        if remote.ip().is_unspecified() || remote.port() == 0 {
            continue;
        }
        for pid in pids.iter().filter(|p| in_tree.contains(p)) {
            conns.push(Conn {
                pid: *pid,
                remote: *remote,
                state: state.clone(),
            });
        }
    }
    let rows = tree
        .iter()
        .map(|(depth, p)| {
            let mine: Vec<&Conn> = conns.iter().filter(|c| c.pid == p.pid).collect();
            Row {
                proc: (*p).clone(),
                depth: *depth,
                conns: mine.len(),
                last_remote: mine.last().map(|c| c.remote),
            }
        })
        .collect();
    Snapshot {
        rows,
        conns,
        agents: tree.iter().filter(|(d, _)| *d == 0).count(),
        parents: procs
            .iter()
            .map(|p| (p.pid, (p.parent, p.name.clone())))
            .collect(),
    }
}

/// Reads processes and sockets from the system.
pub struct Monitor {
    sys: System,
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Monitor {
    pub fn new() -> Self {
        Monitor { sys: System::new() }
    }

    /// Refreshes and returns a snapshot. Sockets that cannot be read are left out.
    pub fn refresh(&mut self) -> Snapshot {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_cpu()
                .with_cmd(UpdateKind::OnlyIfNotSet),
        );
        let procs: Vec<Proc> = self
            .sys
            .processes()
            .values()
            .map(|p| Proc {
                pid: p.pid().as_u32(),
                parent: p.parent().map(Pid::as_u32),
                name: p.name().to_string_lossy().into_owned(),
                cmd: p
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect(),
                cpu: p.cpu_usage(),
            })
            .collect();
        let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let sockets: Vec<(Vec<u32>, SocketAddr, String)> =
            netstat2::get_sockets_info(af, ProtocolFlags::TCP)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|s| match s.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(t) => Some((
                        s.associated_pids,
                        SocketAddr::new(t.remote_addr, t.remote_port),
                        t.state.to_string(),
                    )),
                    ProtocolSocketInfo::Udp(_) => None,
                })
                .collect();
        snapshot(&procs, &sockets, std::process::id())
    }

    /// Asks a process to stop (SIGTERM where supported). True if the signal was sent.
    pub fn kill(&self, pid: u32) -> bool {
        self.sys
            .process(Pid::from_u32(pid))
            .is_some_and(|p| p.kill_with(Signal::Term).unwrap_or_else(|| p.kill()))
    }
}

/// Resolves host names on a background thread, so DNS never blocks the UI. Each host is looked up
/// once; [`Resolver::poll`] returns the addresses found since the last call.
pub struct Resolver {
    asked: HashSet<String>,
    tx: mpsc::Sender<String>,
    rx: mpsc::Receiver<(String, Vec<IpAddr>)>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver {
    pub fn new() -> Self {
        let (tx, jobs) = mpsc::channel::<String>();
        let (done, rx) = mpsc::channel();
        thread::spawn(move || {
            for host in jobs {
                let ips = (host.as_str(), 443)
                    .to_socket_addrs()
                    .map(|a| a.map(|s| s.ip()).collect())
                    .unwrap_or_default();
                if done.send((host, ips)).is_err() {
                    break;
                }
            }
        });
        Resolver {
            asked: HashSet::new(),
            tx,
            rx,
        }
    }

    /// Queues `host` for lookup, unless it was asked before or is already an address.
    pub fn ask(&mut self, host: &str) {
        if host.trim_matches(['[', ']']).parse::<IpAddr>().is_err()
            && self.asked.insert(host.to_string())
        {
            // The worker only stops when the receiver is gone, so a failed send means no lookups.
            let _ = self.tx.send(host.to_string());
        }
    }

    /// Lookups finished since the last poll.
    pub fn poll(&self) -> Vec<(String, Vec<IpAddr>)> {
        self.rx.try_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, parent: u32, name: &str, cmd: &str) -> Proc {
        Proc {
            pid,
            parent: Some(parent),
            name: name.into(),
            cmd: cmd.split_whitespace().map(str::to_string).collect(),
            cpu: 0.0,
        }
    }

    #[test]
    fn agents_are_found_by_program_not_arguments() {
        assert!(is_agent(&p(1, 0, "claude", "claude")));
        assert!(is_agent(&p(1, 0, "node", "node /opt/homebrew/bin/codex")));
        assert!(is_agent(&p(1, 0, "Cursor-Agent", "")));
        assert!(!is_agent(&p(1, 0, "grep", "grep -r claude .")));
        assert!(!is_agent(&p(1, 0, "vim", "vim notes/gemini.md")));
        assert!(!is_agent(&p(1, 0, "zsh", "-zsh")));
    }

    #[test]
    fn tree_holds_agents_and_descendants_only() {
        let procs = [
            p(1, 0, "launchd", "launchd"),
            p(10, 1, "zsh", "zsh"),
            p(20, 10, "claude", "claude"),
            p(21, 20, "zsh", "zsh -c ls"),
            p(22, 21, "node", "node server.js"),
            p(23, 20, "claude", "claude mcp serve"),
            p(30, 10, "vim", "vim claude.md"),
            p(40, 1, "node", "node /usr/local/bin/gemini"),
            p(50, 21, "guard", "guard top"),
        ];
        let t: Vec<(usize, u32)> = tree(&procs, 50)
            .into_iter()
            .map(|(d, p)| (d, p.pid))
            .collect();
        assert_eq!(t, [(0, 20), (1, 21), (2, 22), (1, 23), (0, 40)]);
    }

    #[test]
    fn snapshot_counts_connections_of_tree_processes() {
        let procs = [p(20, 1, "claude", "claude"), p(30, 1, "curl", "curl x")];
        let remote: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let sockets = vec![
            (vec![20], remote, "ESTABLISHED".to_string()),
            (vec![20], "0.0.0.0:0".parse().unwrap(), "LISTEN".to_string()),
            (vec![30], remote, "ESTABLISHED".to_string()),
        ];
        let s = snapshot(&procs, &sockets, 0);
        assert_eq!(s.agents, 1);
        assert_eq!(s.rows.len(), 1);
        assert_eq!(s.rows[0].conns, 1);
        assert_eq!(s.rows[0].last_remote, Some(remote));
        assert_eq!(s.conns.len(), 1);
    }

    #[test]
    fn chain_walks_up_to_the_top() {
        let procs = [
            Proc {
                pid: 1,
                parent: None,
                name: "launchd".into(),
                ..Proc::default()
            },
            p(20, 1, "claude", "claude"),
            p(21, 20, "zsh", "zsh"),
        ];
        let s = snapshot(&procs, &[], 0);
        assert_eq!(s.chain(21), ["launchd", "claude", "zsh"]);
        assert!(s.chain(99).is_empty());
    }
}
