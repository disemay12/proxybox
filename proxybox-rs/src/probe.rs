//! РџСЂРѕРІРµСЂРєР° РїСЂРѕРєСЃРё Р±РµР· РІРЅРµС€РЅРёС… СѓС‚РёР»РёС‚: TCP-С…РµРЅРґС€РµР№Рє РґРѕ РїСЂРѕРєСЃРё, СЂРµР°Р»СЊРЅС‹Р№
//! HTTP GET С‡РµСЂРµР· С‚СѓРЅРЅРµР»СЊ Рё, РґР»СЏ SOCKS5, UDP ASSOCIATE.
//!
//! Р Р°РЅСЊС€Рµ РїСЂРѕРІРµСЂРєР° С„РѕСЂРєР°Р»Р° `curl.exe` РЅР° РєР°Р¶РґС‹Р№ РєР°РЅРґРёРґР°С‚; РЅР° 600 РїСЂРѕРєСЃРё СЌС‚Рѕ
//! 600 РїСЂРѕС†РµСЃСЃРѕРІ Рё Р·Р°РІРёСЃРёРјРѕСЃС‚СЊ РѕС‚ PATH. Р—РґРµСЃСЊ РІСЃС‘ РІ РїСЂРѕС†РµСЃСЃРµ Рё СЃ С‚Р°Р№РјР°СѓС‚Р°РјРё.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// РљСѓРґР° С…РѕРґРёРј Р·Р° РІРЅРµС€РЅРёРј IP. РџРѕСЂС‚ 80 вЂ” С‡С‚РѕР±С‹ РЅРµ С‚Р°С‰РёС‚СЊ TLS-Р±РёР±Р»РёРѕС‚РµРєСѓ.
pub const CHECK_HOST: &str = "api.ipify.org";
pub const CHECK_PORT: u16 = 80;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const IO_TIMEOUT: Duration = Duration::from_secs(6);
const UDP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct Check {
    pub ok: bool,
    pub ip: Option<String>,
    /// СЃСЂРµРґРЅРёР№ РѕС‚РІРµС‚ РїСЂРѕРєСЃРё, РјСЃ
    pub ms: u128,
    /// РїСЂРѕРєСЃРё РїРѕРґС‚РІРµСЂРґРёР» SOCKS5 UDP ASSOCIATE Р¶РёРІС‹Рј DNS-Р·Р°РїСЂРѕСЃРѕРј
    pub udp: bool,
    pub error: Option<String>,
}

impl Check {
    fn failed(error: impl Into<String>, ms: u128) -> Self {
        Self {
            ok: false,
            ip: None,
            ms,
            udp: false,
            error: Some(error.into()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Scheme {
    Http,
    Socks5,
}

#[derive(Clone, Debug)]
struct Target {
    scheme: Scheme,
    host: String,
    port: u16,
    user: String,
    pass: String,
}

/// `scheme://[user:pass@]host:port`, Р±РµР· СЃС…РµРјС‹ вЂ” http.
fn parse(raw: &str) -> Option<Target> {
    let raw = raw.trim();
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => match s.to_ascii_lowercase().as_str() {
            "socks5" | "socks5h" => (Scheme::Socks5, r),
            "http" | "https" => (Scheme::Http, r),
            _ => return None,
        },
        None => (Scheme::Http, raw),
    };
    let (auth, hostport) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, rest),
    };
    let (host, port) = hostport.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    let (user, pass) = match auth {
        Some(a) => match a.split_once(':') {
            Some((u, p)) => (u.to_string(), p.to_string()),
            None => (a.to_string(), String::new()),
        },
        None => (String::new(), String::new()),
    };
    Some(Target {
        scheme,
        host: host.to_string(),
        port,
        user,
        pass,
    })
}

fn tcp_to_proxy(t: &Target) -> Result<TcpStream, String> {
    let addr = (t.host.as_str(), t.port)
        .to_socket_addrs()
        .map_err(|e| format!("dns: {e}"))?
        .next()
        .ok_or("РїСЂРѕРєСЃРё РЅРµ СЂР°Р·СЂРµС€Р°РµС‚СЃСЏ")?;
    let s = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(IO_TIMEOUT)).ok();
    s.set_write_timeout(Some(IO_TIMEOUT)).ok();
    Ok(s)
}

fn read_exact_buf(s: &mut TcpStream, buf: &mut [u8]) -> Result<(), String> {
    s.read_exact(buf).map_err(|e| format!("read: {e}"))
}

fn socks5_greeting(s: &mut TcpStream, t: &Target) -> Result<(), String> {
    let auth = !t.user.is_empty();
    let greeting: &[u8] = if auth { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    s.write_all(greeting).map_err(|e| format!("write: {e}"))?;
    let mut rep = [0u8; 2];
    read_exact_buf(s, &mut rep)?;
    if rep[0] != 5 {
        return Err("socks5: bad version".into());
    }
    match rep[1] {
        0 => Ok(()),
        2 if auth => {
            let user = t.user.as_bytes();
            let pass = t.pass.as_bytes();
            if user.len() > 255 || pass.len() > 255 {
                return Err("socks5: СЃР»РёС€РєРѕРј РґР»РёРЅРЅС‹Р№ Р»РѕРіРёРЅ/РїР°СЂРѕР»СЊ".into());
            }
            let mut req = vec![1u8, user.len() as u8];
            req.extend_from_slice(user);
            req.push(pass.len() as u8);
            req.extend_from_slice(pass);
            s.write_all(&req).map_err(|e| format!("write: {e}"))?;
            let mut ar = [0u8; 2];
            read_exact_buf(s, &mut ar)?;
            if ar[1] != 0 {
                return Err("socks5: auth rejected".into());
            }
            Ok(())
        }
        2 => Err("socks5: РЅСѓР¶РµРЅ Р»РѕРіРёРЅ/РїР°СЂРѕР»СЊ".into()),
        m => Err(format!("socks5: РЅРµС‚ РјРµС‚РѕРґР° {m}")),
    }
}

/// Р—Р°РїСЂРѕСЃ SOCKS5 СЃ РґРѕРјРµРЅРЅС‹Рј РёРјРµРЅРµРј (ATYP=3): DNS СЂРµС€Р°РµС‚ РїСЂРѕРєСЃРё, Р»РѕРєР°Р»СЊРЅС‹Р№
/// СЂРµР·РѕР»РІ РЅРµ РЅСѓР¶РµРЅ вЂ” СЌС‚Рѕ Р¶Рµ Рё РµСЃС‚СЊ socks5h-СЃРµРјР°РЅС‚РёРєР°.
fn socks5_request(s: &mut TcpStream, cmd: u8, host: &str, port: u16) -> Result<(), String> {
    if host.len() > 255 {
        return Err("socks5: СЃР»РёС€РєРѕРј РґР»РёРЅРЅС‹Р№ С…РѕСЃС‚".into());
    }
    let mut req = vec![5u8, cmd, 0];
    let ip: Option<Ipv4Addr> = host.parse().ok();
    match ip {
        Some(ip) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        None => {
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).map_err(|e| format!("write: {e}"))?;
    read_reply(s)
}

fn read_reply(s: &mut TcpStream) -> Result<(), String> {
    let mut head = [0u8; 4];
    read_exact_buf(s, &mut head)?;
    if head[0] != 5 {
        return Err("socks5: bad version in reply".into());
    }
    if head[1] != 0 {
        return Err(format!("socks5: rep={}", head[1]));
    }
    match head[3] {
        1 => {
            let mut skip = [0u8; 6];
            read_exact_buf(s, &mut skip)?;
        }
        4 => {
            let mut skip = [0u8; 18];
            read_exact_buf(s, &mut skip)?;
        }
        3 => {
            let mut len = [0u8; 1];
            read_exact_buf(s, &mut len)?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            read_exact_buf(s, &mut skip)?;
        }
        a => return Err(format!("socks5: atyp={a}")),
    }
    Ok(())
}

fn http_connect(s: &mut TcpStream, t: &Target, host: &str, port: u16) -> Result<(), String> {
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if !t.user.is_empty() {
        let token = base64(format!("{}:{}", t.user, t.pass).as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        if buf.len() > 4096 {
            return Err("http: СЃР»РёС€РєРѕРј РґР»РёРЅРЅС‹Р№ РѕС‚РІРµС‚".into());
        }
        let n = s.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("http: РїСЂРѕРєСЃРё Р·Р°РєСЂС‹Р» СЃРѕРµРґРёРЅРµРЅРёРµ".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf);
    let code_ok = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .map(|c| (200..300).contains(&c))
        .unwrap_or(false);
    if !code_ok {
        let line = head.lines().next().unwrap_or("").trim().to_string();
        return Err(format!("http: {line}"));
    }
    Ok(())
}

fn handshake(s: &mut TcpStream, t: &Target, host: &str, port: u16) -> Result<(), String> {
    match t.scheme {
        Scheme::Socks5 => {
            socks5_greeting(s, t)?;
            socks5_request(s, 1, host, port)
        }
        Scheme::Http => http_connect(s, t, host, port),
    }
}

fn read_ip(s: &mut TcpStream) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let mut body_start = None;
    let mut want: Option<usize> = None;

    loop {
        if let Some(start) = body_start {
            let body_len = buf.len() - start;
            if let Some(want) = want {
                if body_len >= want {
                    break;
                }
            }
        }
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if body_start.is_none() {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        body_start = Some(pos + 4);
                        let head = String::from_utf8_lossy(&buf[..pos]);
                        want = head.lines().find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        });
                    }
                }
                if buf.len() > 64 * 1024 {
                    break;
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
            Err(e) => return Err(format!("read: {e}")),
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let body = match body_start {
        Some(start) => &text[start.min(text.len())..],
        None => text.as_ref(),
    };
    let ip = body.trim().lines().next().unwrap_or("").trim().to_string();
    if ip.parse::<Ipv4Addr>().is_ok() {
        Ok(ip)
    } else if text.starts_with("HTTP/") {
        Err(format!(
            "РЅРµ IP РІ РѕС‚РІРµС‚Рµ: {:?}",
            ip.chars().take(32).collect::<String>()
        ))
    } else {
        Err("РЅРµ HTTP-РѕС‚РІРµС‚".into())
    }
}

/// HTTP GET С‡РµСЂРµР· С‚СѓРЅРЅРµР»СЊ; РІРѕР·РІСЂР°С‰Р°РµС‚ РІРЅРµС€РЅРёР№ IP.
pub fn external_ip(raw: &str, timeout: Option<Duration>) -> Result<String, String> {
    let t = parse(raw).ok_or("РЅРµРІРµСЂРЅС‹Р№ Р°РґСЂРµСЃ РїСЂРѕРєСЃРё")?;
    let mut s = tcp_to_proxy(&t)?;
    if let Some(timeout) = timeout {
        s.set_read_timeout(Some(timeout)).ok();
        s.set_write_timeout(Some(timeout)).ok();
    }
    handshake(&mut s, &t, CHECK_HOST, CHECK_PORT)?;
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {CHECK_HOST}\r\nUser-Agent: proxybox\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    read_ip(&mut s)
}

/// РџРѕР»РЅР°СЏ РїСЂРѕРІРµСЂРєР°: IP С‡РµСЂРµР· С‚СѓРЅРЅРµР»СЊ + UDP ASSOCIATE РґР»СЏ socks5.
pub fn check(raw: &str) -> Check {
    let started = Instant::now();
    match external_ip(raw, None) {
        Ok(ip) => {
            let ms = started.elapsed().as_millis();
            let udp = parse(raw).map(|t| t.scheme == Scheme::Socks5).unwrap_or(false)
                && udp_associate(raw);
            Check {
                ok: true,
                ip: Some(ip),
                ms,
                udp,
                error: None,
            }
        }
        Err(e) => Check::failed(e, started.elapsed().as_millis()),
    }
}

/// UDP ASSOCIATE + Р¶РёРІРѕР№ DNS-Р·Р°РїСЂРѕСЃ С‡РµСЂРµР· СЂРµР»РµР№ РїСЂРѕРєСЃРё.
pub fn udp_associate(raw: &str) -> bool {
    let Some(t) = parse(raw) else { return false };
    if t.scheme != Scheme::Socks5 {
        return false;
    }
    let Ok(mut ctl) = tcp_to_proxy(&t) else {
        return false;
    };
    if socks5_greeting(&mut ctl, &t).is_err() {
        return false;
    }
    // ASSOCIATE Р±РµР· СѓРєР°Р·Р°РЅРёСЏ Р°РґСЂРµСЃР°: СЂРµР»РµР№ СЃРѕРѕР±С‰Р°РµС‚ СЃРІРѕР№
    if socks5_associate(&mut ctl).is_err() {
        return false;
    }
    let Some(relay) = associate_relay(&mut ctl, &t) else {
        return false;
    };

    let Ok(udp) = UdpSocket::bind("0.0.0.0:0") else {
        return false;
    };
    udp.set_read_timeout(Some(UDP_TIMEOUT)).ok();
    for target in [[8u8, 8, 8, 8], [1, 1, 1, 1]] {
        let mut packet = vec![0u8, 0, 0, 1];
        packet.extend_from_slice(&target);
        packet.extend_from_slice(&53u16.to_be_bytes());
        packet.extend_from_slice(&dns_query());
        if udp.send_to(&packet, relay).is_err() {
            continue;
        }
        let mut response = [0u8; 512];
        if matches!(udp.recv_from(&mut response), Ok((n, _)) if n > 10 && response[0] == 0) {
            return true;
        }
    }
    // control-РєР°РЅР°Р» Р·Р°РєСЂС‹РІР°РµРј С‚РѕР»СЊРєРѕ С‚РµРїРµСЂСЊ: РѕРЅ РґРµСЂР¶РёС‚ Р°СЃСЃРѕС†РёР°С†РёСЋ
    false
}

fn socks5_associate(s: &mut TcpStream) -> Result<(), String> {
    s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .map_err(|e| format!("write: {e}"))?;
    Ok(())
}

/// Р§РёС‚Р°РµС‚ BND.ADDR/BND.PORT РёР· РѕС‚РІРµС‚Р° РЅР° ASSOCIATE.
fn associate_relay(s: &mut TcpStream, t: &Target) -> Option<SocketAddr> {
    let mut head = [0u8; 4];
    s.read_exact(&mut head).ok()?;
    if head[0] != 5 || head[1] != 0 {
        return None;
    }
    let ip = match head[3] {
        1 => {
            let mut octets = [0u8; 4];
            s.read_exact(&mut octets).ok()?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        4 => {
            let mut octets = [0u8; 16];
            s.read_exact(&mut octets).ok()?;
            IpAddr::from(octets)
        }
        _ => return None,
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port).ok()?;
    let port = u16::from_be_bytes(port);
    let ip = match ip {
        IpAddr::V4(v4) if v4.is_unspecified() => {
            let host = (t.host.as_str(), t.port).to_socket_addrs().ok()?.next()?;
            host.ip()
        }
        other => other,
    };
    Some(SocketAddr::new(ip, port))
}

fn dns_query() -> Vec<u8> {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&[0, 1, 0, 1]);
    query
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn read_until_blank(s: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            if s.read_exact(&mut byte).is_err() {
                break;
            }
            buf.push(byte[0]);
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    /// Р¤РµР№РєРѕРІС‹Р№ HTTP-РїСЂРѕРєСЃРё: РѕС‚РІРµС‡Р°РµС‚ 200 РЅР° CONNECT Рё С‚РµР»РѕРј РЅР° GET.
    fn fake_http_proxy(body: &'static str, with_auth: bool) -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut client, _)) = listener.accept() {
                let head = read_until_blank(&mut client);
                if with_auth && !head.contains("Proxy-Authorization: Basic ") {
                    client
                        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                        .ok();
                    return;
                }
                if !head.starts_with("CONNECT ") {
                    return;
                }
                client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .ok();
                let _ = read_until_blank(&mut client);
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                client.write_all(reply.as_bytes()).ok();
            }
        });
        port
    }

    #[test]
    fn parses_schemes_auth_and_bare_host() {
        let t = parse("SOCKS5://user:pass@1.2.3.4:1080").unwrap();
        assert_eq!(t.scheme, Scheme::Socks5);
        assert_eq!((t.user.as_str(), t.pass.as_str()), ("user", "pass"));
        assert_eq!((t.host.as_str(), t.port), ("1.2.3.4", 1080));

        let t = parse("5.6.7.8:8080").unwrap();
        assert_eq!(t.scheme, Scheme::Http);

        assert!(parse("ftp://1.2.3.4:21").is_none());
        assert!(parse("1.2.3.4").is_none());
    }

    #[test]
    fn reads_external_ip_through_http_proxy() {
        let port = fake_http_proxy("203.0.113.7", false);
        let got = external_ip(&format!("http://127.0.0.1:{port}"), Some(Duration::from_secs(2)));
        assert_eq!(got.as_deref().ok(), Some("203.0.113.7"));
    }

    #[test]
    fn sends_proxy_authorization_when_credentials_given() {
        let port = fake_http_proxy("198.51.100.2", true);
        let got = external_ip(
            &format!("http://user:secret@127.0.0.1:{port}"),
            Some(Duration::from_secs(2)),
        );
        assert_eq!(got.as_deref().ok(), Some("198.51.100.2"));
    }

    #[test]
    fn rejects_non_ip_body() {
        let port = fake_http_proxy("<html>blocked</html>", false);
        let got = external_ip(&format!("http://127.0.0.1:{port}"), Some(Duration::from_secs(2)));
        assert!(got.is_err());
    }

    #[test]
    fn socks5_tunnel_without_auth_and_no_udp() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            // CONNECT
            if let Ok((mut client, _)) = listener.accept() {
                let mut greeting = [0u8; 3];
                client.read_exact(&mut greeting).unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                client.write_all(&[5, 0]).unwrap();
                let mut head = [0u8; 4];
                client.read_exact(&mut head).unwrap();
                assert_eq!(head, [5, 1, 0, 3]);
                let mut len = [0u8; 1];
                client.read_exact(&mut len).unwrap();
                let mut host_port = vec![0u8; len[0] as usize + 2];
                client.read_exact(&mut host_port).unwrap();
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .unwrap();
                let _ = read_until_blank(&mut client);
                let body = "203.0.113.9";
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                client.write_all(reply.as_bytes()).unwrap();
            }
            // UDP ASSOCIATE: РїСЂРѕРєСЃРё РѕС‚РєР°Р·С‹РІР°РµС‚
            if let Ok((mut client, _)) = listener.accept() {
                let mut greeting = [0u8; 3];
                client.read_exact(&mut greeting).unwrap();
                client.write_all(&[5, 0]).unwrap();
                let mut head = [0u8; 4];
                client.read_exact(&mut head).unwrap();
                assert_eq!(head[1], 3);
                client
                    .write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])
                    .unwrap();
            }
        });
        let c = check(&format!("socks5://127.0.0.1:{port}"));
        assert!(c.ok, "{:?}", c.error);
        assert_eq!(c.ip.as_deref(), Some("203.0.113.9"));
        assert!(!c.udp);
    }

    #[test]
    fn reports_failure_for_closed_port() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let c = check(&format!("http://127.0.0.1:{port}"));
        assert!(!c.ok);
        assert!(c.error.is_some());
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"user:secret"), "dXNlcjpzZWNyZXQ=");
    }
}
