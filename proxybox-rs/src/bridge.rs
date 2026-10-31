//! Локальный HTTP-прокси, который туннелирует всё в вышестоящий SOCKS5/HTTP прокси.
//! Нужен браузерам: Chromium качает трафик в дочернем процессе, куда DLL не внедряется,
//! а флаг `--proxy-server` с socks5 требует от прокси remote-DNS, которого у бесплатных нет.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

/// Диагностический лог моста (dist\logs\bridge.log).
pub fn set_log_path(path: PathBuf) {
    let cell = LOG.get_or_init(|| Mutex::new(None));
    if let Ok(mut g) = cell.lock() {
        *g = Some(path);
    }
}

static LOG: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

fn log_line(line: &str) {
    let Some(cell) = LOG.get() else { return };
    let Ok(g) = cell.lock() else { return };
    let Some(path) = g.as_ref() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}

/// Порт локального моста для конкретного upstream-прокси (запускается один раз).
pub fn bridge_for(upstream: &str) -> Option<u16> {
    static MAP: OnceLock<Mutex<HashMap<String, u16>>> = OnceLock::new();
    let map = MAP.get_or_init(|| Mutex::new(HashMap::new()));

    if let Some(port) = map.lock().ok()?.get(upstream).copied() {
        return Some(port);
    }

    let listener = TcpListener::bind(("127.0.0.1", 0)).ok()?;
    let port = listener.local_addr().ok()?.port();
    let up = upstream.to_string();

    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let up = up.clone();
            thread::spawn(move || {
                let _ = handle(client, &up);
            });
        }
    });

    map.lock().ok()?.insert(upstream.to_string(), port);
    Some(port)
}

struct Upstream {
    scheme: String,
    host: String,
    port: u16,
    user: String,
    pass: String,
}

fn parse_upstream(raw: &str) -> Option<Upstream> {
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => ("http".to_string(), raw),
    };
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, rest),
    };
    let (host, port) = hostport.rsplit_once(':')?;
    let (user, pass) = match auth {
        Some(a) => match a.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (a.to_string(), String::new()),
        },
        None => (String::new(), String::new()),
    };
    Some(Upstream {
        scheme,
        host: host.to_string(),
        port: port.parse().ok()?,
        user,
        pass,
    })
}

/// Открывает TCP-соединение к цели через вышестоящий прокси.
fn connect_via(up: &Upstream, host: &str, port: u16) -> Option<TcpStream> {
    let proxy_addr = (up.host.as_str(), up.port).to_socket_addrs().ok()?.next()?;
    let mut s = TcpStream::connect_timeout(&proxy_addr, Duration::from_secs(10)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(20))).ok()?;

    if up.scheme.starts_with("socks5") {
        socks5_connect(&mut s, up, host, port)?;
    } else {
        http_connect(&mut s, up, host, port)?;
    }
    s.set_read_timeout(None).ok()?;
    s.set_write_timeout(None).ok()?;
    Some(s)
}

fn socks5_connect(s: &mut TcpStream, up: &Upstream, host: &str, port: u16) -> Option<()> {
    let auth = !up.user.is_empty();
    let greeting: &[u8] = if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    s.write_all(greeting).ok()?;

    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).ok()?;
    if rep[1] == 2 {
        if !auth {
            return None;
        }
        let mut buf = vec![1u8, up.user.len() as u8];
        buf.extend_from_slice(up.user.as_bytes());
        buf.push(up.pass.len() as u8);
        buf.extend_from_slice(up.pass.as_bytes());
        s.write_all(&buf).ok()?;
        let mut ar = [0u8; 2];
        s.read_exact(&mut ar).ok()?;
        if ar[1] != 0 {
            return None;
        }
    } else if rep[1] != 0 {
        return None;
    }

    let ip: std::net::Ipv4Addr = (host, port)
        .to_socket_addrs()
        .ok()?
        .find(|a| a.is_ipv4())?
        .ip()
        .to_string()
        .parse()
        .ok()?;

    let mut req = vec![5u8, 1, 0, 1];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).ok()?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).ok()?;
    if head[1] != 0 {
        return None;
    }
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).ok()?;
            l[0] as usize + 2
        }
        _ => return None,
    };
    let mut junk = vec![0u8; skip];
    s.read_exact(&mut junk).ok()?;
    Some(())
}

fn http_connect(s: &mut TcpStream, _up: &Upstream, host: &str, port: u16) -> Option<()> {
    let req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    s.write_all(req.as_bytes()).ok()?;

    let mut resp = Vec::new();
    let mut byte = [0u8; 1];
    while resp.len() < 4096 {
        s.read_exact(&mut byte).ok()?;
        resp.push(byte[0]);
        if resp.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&resp);
    if text.starts_with("HTTP/1.") && text.contains(" 200") {
        Some(())
    } else {
        None
    }
}

fn pipe(mut src: TcpStream, mut dst: TcpStream) {
    let mut buf = [0u8; 32768];
    loop {
        match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = dst.shutdown(std::net::Shutdown::Write);
}

fn handle(client: TcpStream, upstream_raw: &str) -> std::io::Result<()> {
    let up = match parse_upstream(upstream_raw) {
        Some(u) => u,
        None => return Ok(()),
    };

    let mut client = client;
    client.set_read_timeout(Some(Duration::from_secs(20)))?;
    client.set_nodelay(true).ok();

    // читаем заголовок запроса
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while head.len() < 16384 {
        if client.read(&mut byte)? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if head.len() < 4 {
        return Ok(());
    }

    let text = String::from_utf8_lossy(&head).to_string();
    let first_line = text.lines().next().unwrap_or("").to_string();
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Ok(());
    }
    let method = parts[0];
    let target = parts[1];

    let (host, port, rewritten) = if method.eq_ignore_ascii_case("CONNECT") {
        let (h, p) = split_host_port(target, 443);
        (h, p, None)
    } else {
        // absolute-form: http://host[:port]/path
        let without_scheme = target.split("://").nth(1).unwrap_or(target);
        let (hostport, path) = match without_scheme.find('/') {
            Some(i) => (&without_scheme[..i], &without_scheme[i..]),
            None => (without_scheme, "/"),
        };
        let (h, p) = split_host_port(hostport, 80);
        let new_line = format!("{method} {path} {}\r\n", parts[2]);
        let rest = text.split_once("\r\n").map(|(_, r)| r).unwrap_or("");
        (h, p, Some(format!("{new_line}{rest}")))
    };

    let mut upstream = match connect_via(&up, &host, port) {
        Some(s) => s,
        None => {
            log_line(&format!("{method} {host}:{port} -> upstream failed"));
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return Ok(());
        }
    };
    log_line(&format!("{method} {host}:{port} -> ok"));

    if method.eq_ignore_ascii_case("CONNECT") {
        client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
    } else {
        let out = rewritten.unwrap_or(text);
        upstream.write_all(out.as_bytes())?;
    }

    client.set_read_timeout(None).ok();
    let c2 = client.try_clone()?;
    let u2 = upstream.try_clone()?;
    thread::spawn(move || pipe(c2, u2));
    pipe(upstream, client);
    Ok(())
}

fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') => match p.parse() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (s.to_string(), default_port),
        },
        _ => (s.to_string(), default_port),
    }
}
