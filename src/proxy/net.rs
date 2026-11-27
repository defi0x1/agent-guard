//! `guard net-proxy`: an HTTP proxy for agents (set `HTTPS_PROXY` and `HTTP_PROXY`). It tunnels
//! CONNECT requests and forwards plain `http://` requests without reading TLS, refuses hosts the
//! user blocked, and logs every connection with its byte counts. A host never seen before in
//! `hosts.json` is logged yellow.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::audit::{self, Event};
use crate::config::{self, Config};
use crate::home;
use crate::level::Level;

const BLOCKED: &str = "netproxy.blocked";
const NEW_HOST: &str = "netproxy.new_host";

/// Rule ids this module emits, with a plain-words explanation each.
pub const RULES: &[(&str, &str)] = &[
    (
        BLOCKED,
        "An agent tried to reach a host on your block list, so the net proxy refused it; remove the host from trust.blocked in config.toml to allow it.",
    ),
    (
        NEW_HOST,
        "An agent connected through the net proxy to a host it never used before; if you expect it, allow it with \"guard whitelist <host>\".",
    ),
];

const MAX_CONNECTIONS: usize = 256;
const MAX_HEAD: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const RELOAD_EVERY: Duration = Duration::from_secs(2);

/// Listens on `listen` (for example `127.0.0.1:8899`) and serves until the process stops.
pub fn run(listen: &str) -> anyhow::Result<()> {
    let home = home::ensure()?;
    let listener = TcpListener::bind(listen)?;
    let addr = listener.local_addr()?;
    println!("listening on {addr} - set HTTPS_PROXY=http://{addr} for your agent");
    let proxy = Proxy::new(
        home,
        Box::new(|e| {
            if let Err(err) = audit::append(e) {
                eprintln!("agent-guard: could not write the audit log: {err}");
            }
        }),
    );
    proxy.serve(listener);
    Ok(())
}

/// One entry of `hosts.json`, shared with the network check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Seen {
    first_seen: u64,
    last_seen: u64,
    count: u64,
}

type Record = Box<dyn Fn(&Event) + Send + Sync>;

struct Proxy {
    home: PathBuf,
    /// The config and when it was loaded.
    config: Mutex<(Instant, Config)>,
    /// Serializes updates of `hosts.json` between connections.
    hosts: Mutex<()>,
    active: AtomicUsize,
    record: Record,
}

impl Proxy {
    fn new(home: PathBuf, record: Record) -> Arc<Self> {
        let config = config::load_from(&home.join("config.toml")).config;
        Arc::new(Proxy {
            home,
            config: Mutex::new((Instant::now(), config)),
            hosts: Mutex::new(()),
            active: AtomicUsize::new(0),
            record,
        })
    }

    fn serve(self: Arc<Self>, listener: TcpListener) {
        for conn in listener.incoming() {
            let Ok(mut client) = conn else { continue };
            if self.active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                let _ = client.set_write_timeout(Some(HEAD_TIMEOUT));
                let _ = reply(
                    &mut client,
                    "503 Service Unavailable",
                    "too many connections",
                );
                continue;
            }
            self.active.fetch_add(1, Ordering::SeqCst);
            let proxy = Arc::clone(&self);
            let spawned = thread::Builder::new().spawn(move || {
                let _ = proxy.handle(client);
                proxy.active.fetch_sub(1, Ordering::SeqCst);
            });
            if spawned.is_err() {
                self.active.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    /// The config, reloaded from disk at most every two seconds.
    fn config(&self) -> Config {
        let mut c = self.config.lock().unwrap_or_else(PoisonError::into_inner);
        if c.0.elapsed() >= RELOAD_EVERY {
            *c = (
                Instant::now(),
                config::load_from(&self.home.join("config.toml")).config,
            );
        }
        c.1.clone()
    }

    fn handle(&self, mut client: TcpStream) -> io::Result<()> {
        client.set_read_timeout(Some(HEAD_TIMEOUT))?;
        client.set_write_timeout(Some(IDLE_TIMEOUT))?;
        let Some((head, rest)) = read_head(&mut client)? else {
            return reply(&mut client, "400 Bad Request", "bad proxy request");
        };
        let Some(req) = parse(&head) else {
            return reply(&mut client, "400 Bad Request", "bad proxy request");
        };
        let target = req.target();
        let config = self.config();
        if config.host_blocked(&req.host) {
            (self.record)(&Event {
                level: Some(config.level_for(BLOCKED, |_| Level::Red)),
                rules: vec![BLOCKED.to_string()],
                message: format!("Refused {}: it is on your block list.", req.host),
                ..event(&target)
            });
            let body = format!("Agent Guard blocked {}", req.host);
            return reply(&mut client, "403 Forbidden", &body);
        }
        let Ok(upstream) = connect(&req.host, req.port) else {
            return reply(&mut client, "502 Bad Gateway", "could not reach the host");
        };
        let new = self.note_host(&req.host);
        let mut first = req.forward;
        if req.connect {
            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        }
        first.extend_from_slice(&rest);
        let (out, inn) = relay(client, upstream, &first)?;

        let mut e = Event {
            bytes_out: Some(out),
            bytes_in: Some(inn),
            level: Some(Level::Green),
            ..event(&target)
        };
        if new && !config.host_trusted(&req.host, Some("net"), None, home::now()) {
            e.level = Some(config.level_for(NEW_HOST, |_| Level::Yellow));
            e.rules = vec![NEW_HOST.to_string()];
            e.message = format!("First connection to {} through the net proxy.", req.host);
        }
        (self.record)(&e);
        Ok(())
    }

    /// Counts a connection to `host` in `hosts.json`. True when the host was not in it.
    fn note_host(&self, host: &str) -> bool {
        let _lock = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        let path = self.home.join("hosts.json");
        let mut map: BTreeMap<String, Seen> = match fs::read(&path) {
            Ok(data) => match serde_json::from_slice(&data) {
                Ok(m) => m,
                // Never overwrite a file we cannot read; just treat the host as new.
                Err(_) => return true,
            },
            Err(_) => BTreeMap::new(),
        };
        let now = home::now();
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        let new = !map.contains_key(&key);
        let seen = map.entry(key).or_insert(Seen {
            first_seen: now,
            last_seen: now,
            count: 0,
        });
        seen.last_seen = now;
        seen.count += 1;
        if let Ok(data) = serde_json::to_vec_pretty(&map) {
            let _ = home::write_private(&path, &data);
        }
        new
    }
}

/// The fields every net-proxy event shares.
fn event(target: &str) -> Event {
    Event {
        ts: home::now(),
        agent: "net".into(),
        source: "net-proxy".into(),
        tool: "net".into(),
        target: target.into(),
        ..Event::default()
    }
}

/// A parsed proxy request.
#[derive(Debug)]
struct Request {
    connect: bool,
    host: String,
    port: u16,
    /// What to send upstream before the client's remaining bytes (the rewritten head for HTTP).
    forward: Vec<u8>,
}

impl Request {
    fn target(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Reads up to the blank line ending the request head. Returns the head and any bytes after it,
/// or None when the head is too long or the client closed early.
fn read_head(client: &mut TcpStream) -> io::Result<Option<(String, Vec<u8>)>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok(String::from_utf8(buf).ok().map(|h| (h, rest)));
        }
        if buf.len() > MAX_HEAD {
            return Ok(None);
        }
        let n = client.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Parses a CONNECT or an absolute `http://` request head.
fn parse(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, uri, version) = (first.next()?, first.next()?, first.next()?);
    if first.next().is_some() || !version.starts_with("HTTP/") {
        return None;
    }
    if method == "CONNECT" {
        let (host, port) = split_authority(uri, 443)?;
        return Some(Request {
            connect: true,
            host,
            port,
            forward: Vec::new(),
        });
    }
    let scheme = uri.get(..7)?;
    if !scheme.eq_ignore_ascii_case("http://") {
        return None;
    }
    let rest = &uri[7..];
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(split);
    let authority = authority.rsplit('@').next()?;
    let (host, port) = split_authority(authority, 80)?;
    let path = match path {
        "" => "/".to_string(),
        p if p.starts_with('?') => format!("/{p}"),
        p => p.to_string(),
    };

    let mut out = format!("{method} {path} {version}\r\n");
    let mut has_host = false;
    for line in lines.filter(|l| !l.is_empty()) {
        let name = line.split(':').next().unwrap_or("").trim();
        let hop = [
            "connection",
            "proxy-connection",
            "keep-alive",
            "proxy-authorization",
        ];
        if hop.iter().any(|h| name.eq_ignore_ascii_case(h)) {
            continue;
        }
        has_host |= name.eq_ignore_ascii_case("host");
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !has_host {
        out.push_str(&format!("Host: {authority}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    Some(Request {
        connect: false,
        host,
        port,
        forward: out.into_bytes(),
    })
}

/// `host:port`, `host` (default port) or `[v6]:port`.
fn split_authority(a: &str, default_port: u16) -> Option<(String, u16)> {
    let (host, port) = if let Some(inner) = a.strip_prefix('[') {
        let (host, after) = inner.split_once(']')?;
        match after {
            "" => (host, None),
            p => (host, Some(p.strip_prefix(':')?)),
        }
    } else {
        match a.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, Some(p)),
            Some(_) => return None,
            None => (a, None),
        }
    };
    let port = match port {
        Some(p) => p.parse().ok()?,
        None => default_port,
    };
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':');
    if host.is_empty() || port == 0 || !host.chars().all(ok) {
        return None;
    }
    Some((host.to_string(), port))
}

fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address");
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn reply(client: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    let msg = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}\n",
        body.len() + 1
    );
    client.write_all(msg.as_bytes())
}

/// Sends `first` upstream, then copies bytes both ways until the upstream side ends. Returns
/// (bytes sent upstream, bytes sent to the client).
fn relay(client: TcpStream, upstream: TcpStream, first: &[u8]) -> io::Result<(u64, u64)> {
    for s in [&client, &upstream] {
        s.set_read_timeout(Some(IDLE_TIMEOUT))?;
        s.set_write_timeout(Some(IDLE_TIMEOUT))?;
    }
    let mut up_write = upstream.try_clone()?;
    up_write.write_all(first)?;
    let mut client_read = client.try_clone()?;
    let outbound = thread::Builder::new().spawn(move || {
        let n = copy(&mut client_read, &mut up_write);
        let _ = up_write.shutdown(Shutdown::Write);
        n
    })?;
    let mut up_read = upstream.try_clone()?;
    let mut client_write = client.try_clone()?;
    let inn = copy(&mut up_read, &mut client_write);
    // The server is done: close both sides so the outbound copy stops waiting on the client.
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    let out = outbound.join().unwrap_or(0) + first.len() as u64;
    Ok((out, inn))
}

/// Copies until end of stream or an error, and returns the bytes written.
fn copy(from: &mut TcpStream, to: &mut TcpStream) -> u64 {
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0;
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => return total,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    return total;
                }
                total += n as u64;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// Starts the proxy on a free port with `config` as its config.toml. Returns its address,
    /// the event receiver and the home directory.
    fn start(config: &str) -> (String, mpsc::Receiver<Event>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("config.toml"), config).unwrap();
        let (tx, rx) = mpsc::channel();
        let proxy = Proxy::new(
            dir.path().to_path_buf(),
            Box::new(move |e| {
                let _ = tx.send(e.clone());
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        thread::spawn(move || proxy.serve(listener));
        (addr, rx, dir)
    }

    /// A TCP server that echoes each connection back until the client closes.
    fn echo_server() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for mut s in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut r = s.try_clone().unwrap();
                    let _ = io::copy(&mut r, &mut s);
                });
            }
        });
        port
    }

    fn read_until(s: &mut TcpStream, end: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut b = [0u8; 1];
        while !out.ends_with(end) {
            if s.read(&mut b).unwrap() == 0 {
                break;
            }
            out.push(b[0]);
        }
        out
    }

    fn tunnel(proxy: &str, port: u16, payload: &[u8]) {
        let mut c = TcpStream::connect(proxy).unwrap();
        write!(c, "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let head = read_until(&mut c, b"\r\n\r\n");
        assert_eq!(head, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        c.write_all(payload).unwrap();
        let mut got = vec![0u8; payload.len()];
        c.read_exact(&mut got).unwrap();
        assert_eq!(got, payload);
        c.shutdown(Shutdown::Write).unwrap();
        let mut tail = Vec::new();
        c.read_to_end(&mut tail).unwrap();
        assert!(tail.is_empty());
    }

    fn recv(rx: &mpsc::Receiver<Event>) -> Event {
        rx.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    #[test]
    fn connect_tunnels_bytes_and_flags_new_hosts() {
        let (proxy, rx, dir) = start("");
        let port = echo_server();

        tunnel(&proxy, port, b"hello through the tunnel");
        let e = recv(&rx);
        assert_eq!(e.agent, "net");
        assert_eq!(e.source, "net-proxy");
        assert_eq!(e.tool, "net");
        assert_eq!(e.target, format!("127.0.0.1:{port}"));
        assert_eq!(e.bytes_out, Some(24));
        assert_eq!(e.bytes_in, Some(24));
        assert_eq!(e.level, Some(Level::Yellow));
        assert_eq!(e.rules, [NEW_HOST]);

        tunnel(&proxy, port, b"again");
        let e = recv(&rx);
        assert_eq!(e.level, Some(Level::Green));
        assert!(e.rules.is_empty());

        let hosts: BTreeMap<String, Seen> =
            serde_json::from_slice(&fs::read(dir.path().join("hosts.json")).unwrap()).unwrap();
        assert_eq!(hosts["127.0.0.1"].count, 2);
    }

    #[test]
    fn trusted_new_host_is_green() {
        let (proxy, rx, _dir) = start("[[trust.hosts]]\nhost = '127.0.0.1'\n");
        tunnel(&proxy, echo_server(), b"hi");
        assert_eq!(recv(&rx).level, Some(Level::Green));
    }

    #[test]
    fn blocked_host_gets_403() {
        let (proxy, rx, dir) = start("[trust]\nblocked = ['paste.ee']\n");
        let mut c = TcpStream::connect(&proxy).unwrap();
        write!(
            c,
            "CONNECT paste.ee:443 HTTP/1.1\r\nHost: paste.ee:443\r\n\r\n"
        )
        .unwrap();
        let mut resp = String::new();
        c.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{resp}");
        assert!(resp.ends_with("Agent Guard blocked paste.ee\n"));
        let e = recv(&rx);
        assert_eq!(e.level, Some(Level::Red));
        assert_eq!(e.rules, [BLOCKED]);
        assert_eq!(e.target, "paste.ee:443");
        assert!(!dir.path().join("hosts.json").exists());
    }

    #[test]
    fn user_override_changes_the_level() {
        let (proxy, rx, _dir) = start("[rules]\n'netproxy.new_host' = { level = 'green' }\n");
        tunnel(&proxy, echo_server(), b"hi");
        assert_eq!(recv(&rx).level, Some(Level::Green));
    }

    #[test]
    fn plain_http_is_forwarded_with_connection_close() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = server.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut s, _) = server.accept().unwrap();
            let head = read_until(&mut s, b"\r\n\r\n");
            write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                head.len()
            )
            .unwrap();
            s.write_all(&head).unwrap();
        });
        let (proxy, rx, _dir) = start("");
        let mut c = TcpStream::connect(&proxy).unwrap();
        write!(
            c,
            "GET http://127.0.0.1:{port}/x?y=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nProxy-Connection: keep-alive\r\n\r\n"
        )
        .unwrap();
        let mut resp = String::new();
        c.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("GET /x?y=1 HTTP/1.1\r\n"));
        assert!(resp.contains("\r\nConnection: close\r\n"));
        assert!(!resp.contains("Proxy-Connection"));
        let e = recv(&rx);
        assert_eq!(e.target, format!("127.0.0.1:{port}"));
        assert!(e.bytes_in.unwrap() > 0 && e.bytes_out.unwrap() > 0);
    }

    #[test]
    fn parses_authorities_and_rejects_bad_requests() {
        assert_eq!(
            split_authority("[::1]:8443", 443),
            Some(("::1".to_string(), 8443))
        );
        assert_eq!(
            split_authority("example.com", 443),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(split_authority("example.com:0", 443), None);
        assert_eq!(split_authority("a b:80", 80), None);
        assert_eq!(split_authority("::1", 80), None);

        let r = parse("CONNECT [::1]:443 HTTP/1.1\r\n").unwrap();
        assert_eq!(r.target(), "[::1]:443");
        let r = parse("GET http://user@Example.com HTTP/1.1\r\n").unwrap();
        assert_eq!((r.host.as_str(), r.port), ("Example.com", 80));
        let fwd = String::from_utf8(r.forward).unwrap();
        assert!(fwd.starts_with("GET / HTTP/1.1\r\nHost: Example.com\r\n"));

        assert!(parse("GET / HTTP/1.1\r\n").is_none());
        assert!(parse("GET https://example.com/ HTTP/1.1\r\n").is_none());
        assert!(parse("CONNECT example.com:443\r\n").is_none());
    }
}
